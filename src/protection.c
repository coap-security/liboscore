#include <oscore/protection.h>

#include <assert.h>
#include <string.h>

#include <oscore_native/crypto.h>

/** Take the Partial IV from the OSCORE option and populate @ref
 * oscore_requestid_t from it (with is_first_use=false). Return true if
 * successful, or false if there was no PartIV in the option.
 *
 * This leaves request unmodified if no PartIV was present in the option. */
bool extract_requestid(const oscore_oscoreoption_t *option, oscore_requestid_t *request)
{
    uint8_t n = option->partial_iv_len;

    if (n == 0) {
        return false;
    }

    // Checked at instance creation; the assert here helps demonstrate that the
    // following memory access is safe.
    assert(n <= PIV_BYTES);

    request->used_bytes = n;
    // I trust the compiler will zero out the whole struct if that is more
    // efficient as it can see that the rest is overwritten later
    memset(request->bytes, 0, PIV_BYTES - n);
    request->is_first_use = false;
    uint8_t *dest = &request->bytes[PIV_BYTES - n];
    memcpy(dest, option->partial_iv, n);

    return true;
}

/** Return the number of bytes needed to (canonically) encode a positive
 * integer of value input, which is also the length of byte string / text
 * string / array headers. The input size must be expressible in CBOR, ie. be
 * expressible in 4 bytes at most. */
size_t cbor_intsize(size_t input) {
    if (input <= 23) {
        return 1;
    }
    if (input < 0x100) {
        return 2;
    }
#if SIZE_WIDTH <= 32
    return 3;
#else
    if (input < 0x10000) {
        return 3;
    }
    return 5;
#endif
}

/** Encode a number of bytes as a (canonical) CBOR positive integer, subject to
 * the same constraints as cbor_intsize. The type major value is added into the first byte. */
size_t cbor_intencode(size_t input, uint8_t buf[5], uint8_t type)
{
    size_t ret = cbor_intsize(input);
    if (ret == 1) {
        buf[0] = input % 256 + type;
    } else if (ret == 2) {
        buf[0] = 24 + type;
        buf[1] = input % 256;
    } else if (ret == 3) {
        buf[0] = 25 + type;
        buf[1] = (input << 8) % 256;
        buf[2] = input % 256;
    } else {
        buf[0] = 26 + type;
        buf[1] = (input << 24) % 256;
        buf[2] = (input << 16) % 256;
        buf[3] = (input << 8) % 256;
        buf[4] = input % 256;
    }
    return ret;
}

/** Return the number of bytes needed to encode the given input number as a
 * positive or negative integer. */
size_t cbor_signedintsize(int32_t input) {
    return cbor_intsize(input < 0 ? -1 - input : input);
}

/** Shorthand for cbor_intencode that sets type to 0x00 or 0x20 depending on
 * the sign, and adjust the value ccordingly to encode an integer. */
size_t cbor_signedintencode(int32_t input, uint8_t buf[5]) {
    return cbor_intencode(input < 0 ? -1 - input : input, buf, input < 0 ? 0x20 : 0x00);
}

struct aad_sizes {
    size_t class_i_length;
    size_t external_aad_length;
    size_t aad_length;
};

/** Determine the size of the complete encoded Encrypt0 objecet that
 * constitutes the AAD of a message.
 *
 * @param[in] secctx Security context from which to get a KID
 * @param[in] requester_role Role in @p secctx that created the request
 * @param[in] request The @ref oscore_requestid_t describing the request_piv
 * @param[in] class_i_source The outer message containing all class I options to be considered for this message
 *
 * @todo Actually use Class I options (currently, it is assumed that there are none)
 */
struct aad_sizes predict_aad_size(
        const oscore_context_t *secctx,
        enum oscore_context_role requester_role,
        oscore_requestid_t *request,
        oscore_crypto_aeadalg_t aeadalg,
        oscore_msg_native_t class_i_source
        )
{
    const uint8_t *request_kid; // ignored, but get_kid still wants to write somewhere
    size_t request_kid_len;
    oscore_context_get_kid(secctx, requester_role, &request_kid, &request_kid_len);

    struct aad_sizes ret;

    // FIXME gather thsi from class_i_source
    ret.class_i_length = 0;
    (void) class_i_source;

    int32_t numeric_identifier = 0;
    // error handling to follow when there are string-based algorithms
    // to test this with; until then, the estimate is infallible and errs when
    // feeding.
    oscore_crypto_aead_get_number(aeadalg, &numeric_identifier);

    ret.external_aad_length = \
            1 /* array length 5 */ +
            1 /* oscore version 1 */ +
            1 /* 1-long array of of */ +
                cbor_signedintsize(numeric_identifier) /* FIXME strings? */ +
            cbor_intsize(request_kid_len) + request_kid_len + /* request_kid */
            cbor_intsize(request->used_bytes) + request->used_bytes + /* request_piv */
            cbor_intsize(ret.class_i_length) + ret.class_i_length;
    ret.aad_length = \
            1 /* array length 3 */ +
            9 /* "Encrytp0" with length */ +
            1 /* empty string with length */ +
            cbor_intsize(ret.external_aad_length) + ret.external_aad_length;

    return ret;
}

/** Push the AAD for a given message into the en-/decryption state.
 *
 * @param[inout] feeder Function with a signature of @ref oscore_crypto_aead_encrypt_feed_aad and @ref oscore_crypto_aead_decrypt_feed_aaj
 * @param[inout] state AEAD en-/decryption state
 * @param[in] aad_sizes Predetermined sizes of the various AAD components
 * @param[in] secctx Security context from which to pick the sender role KID
 * @param[in] requester_role Role in @p secctx that created the request
 * @param[in] request The @ref oscore_requestid_t describing the request_piv
 * @param[in] class_i_source The outer message containing all class I options to be considered for this message
 *
 */
oscore_cryptoerr_t feed_aad(
        oscore_cryptoerr_t (*feeder)(void *, const uint8_t *, size_t),
        void *state,
        struct aad_sizes aad_sizes,
        const oscore_context_t *secctx,
        enum oscore_context_role requester_role,
        oscore_requestid_t *request,
        oscore_crypto_aeadalg_t aeadalg,
        oscore_msg_native_t class_i_source
        )
{
    oscore_cryptoerr_t err;
    uint8_t intbuf[5];

    // array length 3, "Encrypt0", h''
    err = feeder(state, (uint8_t*) "\x83\x68" "Encrypt0" "\x40", 11);
    if (oscore_cryptoerr_is_error(err)) { return err; }

    // full external AAD length
    err = feeder(state, intbuf, cbor_intencode(aad_sizes.external_aad_length, intbuf, 0x40));
    if (oscore_cryptoerr_is_error(err)) { return err; }

    // external AAD array start, constant OSCORE version 1, array of one element
    err = feeder(state, (uint8_t*) "\x85\x01\x81", 3);
    if (oscore_cryptoerr_is_error(err)) { return err; }

    // Used algorithm
    int32_t numeric_identifier = 0;
    err = oscore_crypto_aead_get_number(aeadalg, &numeric_identifier);
    if (oscore_cryptoerr_is_error(err)) { return err; }
    err = feeder(state, intbuf, cbor_signedintencode(numeric_identifier, intbuf));
    if (oscore_cryptoerr_is_error(err)) { return err; }

    // Request KID
    const uint8_t *request_kid;
    size_t request_kid_len;
    oscore_context_get_kid(secctx, requester_role, &request_kid, &request_kid_len);

    err = feeder(state, intbuf, cbor_intencode(request_kid_len, intbuf, 0x40));
    if (oscore_cryptoerr_is_error(err)) { return err; }
    err = feeder(state, request_kid, request_kid_len);
    if (oscore_cryptoerr_is_error(err)) { return err; }

    // Request PIV
    err = feeder(state, intbuf, cbor_intencode(request->used_bytes, intbuf, 0x40));
    if (oscore_cryptoerr_is_error(err)) { return err; }
    err = feeder(state, &request->bytes[PIV_BYTES - request->used_bytes], request->used_bytes);
    if (oscore_cryptoerr_is_error(err)) { return err; }

    // Class I options
    assert(aad_sizes.class_i_length == 0);
    // As long as that holds, the Class I source can be disregarded.
    (void) class_i_source;
    // 0 byte string
    err = feeder(state, (uint8_t*) "\x40", 1);

    return err;
}


/** Build a full IV from a partial IV, a security context pair and a sender
 * role
 *
 * @param[out] iv The output buffer
 * @param[in] requestid The request ID containing the partial IV data
 * @param[in] secctx The security context pair this is used with
 * @param[in] piv_role The role the creator of the Partial IV has in this security context
 * */
void build_iv(
        uint8_t iv[OSCORE_CRYPTO_AEAD_IV_MAXLEN],
        const oscore_requestid_t *requestid,
        const oscore_context_t *secctx,
        enum oscore_context_role piv_role
        )
{
    size_t iv_len = oscore_crypto_aead_get_ivlength(oscore_context_get_aeadalg(secctx));
    const uint8_t *common_iv = oscore_context_get_commoniv(secctx);

    assert(iv_len >= 7);
    assert(iv_len <= OSCORE_CRYPTO_AEAD_IV_MAXLEN);

    const uint8_t *id_piv;
    size_t id_piv_len;
    oscore_context_get_kid(secctx, piv_role, &id_piv, &id_piv_len);

    assert(id_piv_len <= iv_len - 6);

    iv[0] = id_piv_len;
    size_t pad1_len = iv_len - 6 - id_piv_len;
    memset(&iv[1], 0, pad1_len);
    memcpy(&iv[1 + pad1_len], id_piv, id_piv_len);
    memcpy(&iv[iv_len - PIV_BYTES], requestid->bytes, PIV_BYTES);

    for (size_t i = 0; i < iv_len; i++) {
        iv[i] ^= common_iv[i];
    }
}

bool oscore_oscoreoption_parse(oscore_oscoreoption_t *out, const uint8_t *input, size_t input_len)
{
    if (input_len != 0) {
        uint8_t header = input[0];
        if (header & 0xe0) {
            // Unknown extension bits
            return false;
        }
        uint8_t n = header & 0x07;
        if (n > PIV_BYTES) {
            // Reserved lengths
            return false;
        }
        out->partial_iv_len = n;
        out->partial_iv = n > 0 ? &input[1] : NULL;
        size_t tail_start = n + 1;

        if (header & 0x10) {
            // h=1: KID context present
            if (tail_start >= input_len) {
                return false;
            }

            out->kid_context_len = input[tail_start];
            out->kid_context = &input[tail_start + 1];

            // Not validating its value: KID context is opaque
            tail_start += input[tail_start] + 1;
        } else {
            out->kid_context = NULL;
        }

        if (header & 0x08) {
            // k=1: KID present
            if (tail_start > input_len) {
                return false;
            }

            // Not validating its value

            out->kid = &input[tail_start];
            out->kid_len = input_len - tail_start;
        } else {
            if (tail_start != input_len) {
                return false;
            }

            out->kid = NULL;
        }
    } else {
        out->partial_iv_len = 0;
        out->partial_iv = NULL;
        out->kid_context = NULL;
        out->kid = NULL;
    }

    return true;
}

void oscore_requestid_clone(oscore_requestid_t *dest, oscore_requestid_t *src)
{
    memcpy(dest, src, sizeof(oscore_requestid_t));
    dest->is_first_use = false;
}

/** Do all the decryption preparation common to @ref oscore_prepare_response
 * and @ref oscore_prepare_request
 *
 * This returns true if decryption was successful.
 */
bool _decrypt(
        oscore_msg_native_t protected,
        oscore_msg_protected_t *unprotected,
        oscore_context_t *secctx,
        enum oscore_context_role piv_kid,
        enum oscore_context_role request_kid
        )
{
    oscore_crypto_aeadalg_t aeadalg = oscore_context_get_aeadalg(secctx);
    size_t tag_length = oscore_crypto_aead_get_taglength(aeadalg);
    size_t minimum_ciphertext_length = 1 + tag_length;

    uint8_t *ciphertext;
    size_t ciphertext_length;
    oscore_msg_native_map_payload(protected, &ciphertext, &ciphertext_length);
    if (ciphertext_length < minimum_ciphertext_length) {
        // Ciphertext too short
        return false;
    }
    size_t plaintext_length = ciphertext_length - tag_length; // >= 1

    struct aad_sizes aad_sizes = predict_aad_size(secctx, request_kid, &unprotected->request_id, aeadalg, protected);

    uint8_t iv[OSCORE_CRYPTO_AEAD_IV_MAXLEN];
    build_iv(iv, &unprotected->partial_iv, secctx, piv_kid);

    oscore_cryptoerr_t err;
    oscore_crypto_aead_decryptstate_t dec;
    err = oscore_crypto_aead_decrypt_start(
            &dec,
            aeadalg,
            aad_sizes.aad_length,
            plaintext_length,
            iv,
            oscore_context_get_key(secctx, OSCORE_ROLE_RECIPIENT)
            );
    if (!oscore_cryptoerr_is_error(err)) {
        err = feed_aad(oscore_crypto_aead_decrypt_feed_aad, &dec, aad_sizes, secctx, request_kid, &unprotected->request_id, aeadalg, protected);
    }
    if (!oscore_cryptoerr_is_error(err)) {
        err = oscore_crypto_aead_decrypt_inplace(
                &dec,
                ciphertext,
                ciphertext_length);
    }

    if (oscore_cryptoerr_is_error(err)) {
        return false;
    }

    // FIXME all of that needs to be initialized
    unprotected->backend = protected;
    unprotected->flags = OSCORE_MSG_PROTECTED_FLAG_NONE;
    unprotected->tag_length = tag_length;
    unprotected->payload_offset = 0;

    return true;
}

enum oscore_unprotect_request_result oscore_unprotect_request(
        oscore_msg_native_t protected,
        oscore_msg_protected_t *unprotected,
        oscore_oscoreoption_t header,
        oscore_context_t *secctx,
        oscore_requestid_t *request_id
        )
{
    /* Comparing to the equivalent aiocoap code:
     *
     * * Not asserting anything about the request or response code properties;
     *   instead, all following steps make sure to always look into FLAG_REQUEST
     *   and not into the request code class (which is easy here as there's not
     *   even the API to decide that).
     *
     * * Not checking for the validity of the header, that was already done
     *   when it was created.
     *
     * * Not checking whether the given KID and the own recipient ID match;
     *   that's up to the caller, but if the caller errs, we make sure to
     *   always look into the provided security context and not what's in the
     *   header. If things then still work out, fine (the peers probably agree
     *   on some weird form of calling the contexts by a shorter name), but the
     *   assertion we give to the caller that the message was unprotected using
     *   the given context (which is then used to decide authorization) is
     *   upheld.
     */

    bool has_request_id = extract_requestid(&header, request_id);
    if (!has_request_id) {
        return OSCORE_UNPROTECT_REQUEST_INVALID;
    }

    // Some optimization was originally in place to avoid copying around the
    // request ID twice, but it turned out that the complexity of tracking
    // which to use was worse than a 6-byte copy one-byte-clear operation.
    oscore_requestid_clone(&unprotected->request_id, request_id);
    oscore_requestid_clone(&unprotected->partial_iv, request_id);

    bool success = _decrypt(protected, unprotected, secctx, OSCORE_ROLE_RECIPIENT, OSCORE_ROLE_RECIPIENT);

    if (!success)
        return OSCORE_UNPROTECT_REQUEST_INVALID;

    oscore_context_strikeout_requestid(secctx, request_id);

    return request_id->is_first_use ? OSCORE_UNPROTECT_REQUEST_OK : OSCORE_UNPROTECT_REQUEST_DUPLICATE;
}

enum oscore_unprotect_response_result oscore_unprotect_response(
        oscore_msg_native_t protected,
        oscore_msg_protected_t *unprotected,
        oscore_oscoreoption_t header,
        oscore_context_t *secctx,
        oscore_requestid_t *request_id
        )
{
    bool has_piv = extract_requestid(&header, &unprotected->partial_iv);
    enum oscore_context_role piv_kid;
    if (has_piv) {
        // This may be a bit confusing here: With a PIV attached, this means we
        // build the nonce in our role as recipient (using our recipient ID) --
        // but the PIV was created by the message's sender.
        piv_kid = OSCORE_ROLE_RECIPIENT;
    } else {
        oscore_requestid_clone(&unprotected->partial_iv, request_id);
        // Vice versa to above, here we're using our sender ID to build the
        // nonce -- but the recipient of the current message, us, created that
        // nonce originally.
        piv_kid = OSCORE_ROLE_SENDER;
    }
    oscore_requestid_clone(&unprotected->request_id, request_id);

    bool success = _decrypt(protected, unprotected, secctx, piv_kid, OSCORE_ROLE_SENDER);

    if (!success)
        return OSCORE_UNPROTECT_RESPONSE_INVALID;

    return OSCORE_UNPROTECT_RESPONSE_OK;
}

oscore_msg_native_t oscore_release_unprotected(
        oscore_msg_protected_t *unprotected
        )
{
    return unprotected->backend;
}

/** Do all the encryption preparation required for @ref oscore_prepare_response
 * and @ref oscore_prepare_request, except
 *
 * * initialization of the request_id and partial_iv fields
 * * setting the FLAG_REQUEST bit
 * * any modifications to the passed request_id (it's not even forwarded)
 * * setting the outer code
 */
enum oscore_prepare_result _prepare_encrypt(
        oscore_msg_native_t protected,
        oscore_msg_protected_t *unprotected,
        oscore_context_t *secctx
        )
{
    oscore_crypto_aeadalg_t aeadalg = oscore_context_get_aeadalg(secctx);
    size_t tag_length = oscore_crypto_aead_get_taglength(aeadalg);

    // Not checking message length against allocated length; that comparison
    // only makes sense when the outer options (esp. OSCORE) have been added
    // and we know that the remaining length is actually usable for the tag.
    // (Before that, we can't ask the backend whether the OSCORE option's
    // length will be removed from the usable payload or not).


    // Initialize everything except the previously initialized partial_iv and
    // request_id

    unprotected->backend = protected;
    unprotected->flags = OSCORE_MSG_PROTECTED_FLAG_WRITABLE | OSCORE_MSG_PROTECTED_FLAG_PENDING_OSCORE;
    unprotected->tag_length = tag_length;
    unprotected->payload_offset = 0;
    unprotected->secctx = secctx;
    unprotected->class_e.cursor = 0;
    unprotected->class_e.option_number = 0;

    return OSCORE_PREPARE_OK;
}

enum oscore_prepare_result oscore_prepare_response(
        oscore_msg_native_t protected,
        oscore_msg_protected_t *unprotected,
        oscore_context_t *secctx,
        oscore_requestid_t *request_id
        )
{
    // FIXME: Should we take the native message's code and set it as inner?
    // Users from libraries that set a code on creation may expect that, but
    // for others it's needless memory shoving.

    // memcpy legitimate (otherwise see oscore_requestid_clone) as the input
    // request ID's flag is cleared
    memcpy(&unprotected->request_id, request_id, sizeof(oscore_requestid_t));
    request_id->is_first_use = false;

    if (!unprotected->request_id.is_first_use) {
        bool ok = oscore_context_take_seqno(secctx, &unprotected->partial_iv);
        if (!ok) {
            return OSCORE_PREPARE_SECCTX_UNAVAILABLE;
        }
    } else {
        oscore_requestid_clone(&unprotected->partial_iv, &unprotected->request_id);
    }
    // OK because it has special semantics in a oscore_msg_protected_t.partial_iv
    unprotected->partial_iv.is_first_use = true;

    oscore_msg_native_set_code(protected, 0x45); // 2.05 Content

    return _prepare_encrypt(protected, unprotected, secctx);
    // Leaving the FLAG_REQUEST at 0 as it is
}

enum oscore_prepare_result oscore_prepare_request(
        oscore_msg_native_t protected,
        oscore_msg_protected_t *unprotected,
        oscore_context_t *secctx,
        oscore_requestid_t *request_id
        )
{
    bool ok = oscore_context_take_seqno(secctx, &unprotected->request_id);
    if (!ok) {
        return OSCORE_PREPARE_SECCTX_UNAVAILABLE;
    }

    // Caller gets the copy with the "can not reuse" setting
    oscore_requestid_clone(request_id, &unprotected->request_id);

    oscore_requestid_clone(&unprotected->partial_iv, &unprotected->request_id);
    // OK because it has special semantics in a oscore_msg_protected_t.partial_iv
    unprotected->partial_iv.is_first_use = true;

    oscore_msg_native_set_code(protected, 0x2); // POST

    enum oscore_prepare_result result = _prepare_encrypt(protected, unprotected, secctx);

    unprotected->flags |= OSCORE_MSG_PROTECTED_FLAG_REQUEST;

    return result;
}

enum oscore_finish_result oscore_encrypt_message(
        oscore_msg_protected_t *unprotected,
        oscore_msg_native_t *protected
        )
{
    const oscore_context_t *secctx = unprotected->secctx;
    oscore_crypto_aeadalg_t aeadalg = oscore_context_get_aeadalg(secctx);
    size_t tag_length = unprotected->tag_length;

    bool is_request = (unprotected->flags & OSCORE_MSG_PROTECTED_FLAG_REQUEST);

    enum oscore_context_role requester_role = is_request ? OSCORE_ROLE_SENDER : OSCORE_ROLE_RECIPIENT;
    enum oscore_context_role nonceprovider_role = is_request ?
                    OSCORE_ROLE_SENDER : (
                        unprotected->request_id.is_first_use ?
                        OSCORE_ROLE_RECIPIENT :
                        OSCORE_ROLE_SENDER
                    );

    // Make result available before the first error return
    *protected = unprotected->backend;

    // Checking for this allows some programming errors on the side of the
    // library user to be caught (in particular, using the unprotected message
    // again even though it is left uninitialized after this function).
    assert(unprotected->partial_iv.is_first_use);
    unprotected->partial_iv.is_first_use = false;

    uint8_t *ciphertext;
    size_t ciphertext_length;
    oscore_msg_native_map_payload(unprotected->backend, &ciphertext, &ciphertext_length);
    // FIXME: Revisit this when trimming is supported -- right now it just plain crops as little as possible
    if (ciphertext_length < tag_length) {
        // Ciphertext too short
        return OSCORE_FINISH_ERROR_SIZE;
    }
    size_t plaintext_length = ciphertext_length - tag_length; // >= 1

    // FIXME optimize this to happen while the message is being built
    struct aad_sizes aad_sizes = predict_aad_size(secctx, requester_role, &unprotected->request_id, aeadalg, unprotected->backend);

    uint8_t encrypt_iv[OSCORE_CRYPTO_AEAD_IV_MAXLEN];
    build_iv(encrypt_iv, &unprotected->partial_iv, secctx, nonceprovider_role);

    oscore_crypto_aead_encryptstate_t enc;
    oscore_cryptoerr_t err = oscore_crypto_aead_encrypt_start(
            &enc,
            oscore_context_get_aeadalg(secctx),
            aad_sizes.aad_length,
            plaintext_length,
            encrypt_iv,
            oscore_context_get_key(secctx, OSCORE_ROLE_SENDER)
            );

    if (!oscore_cryptoerr_is_error(err)) {
        err = feed_aad(
                oscore_crypto_aead_encrypt_feed_aad,
                &enc,
                aad_sizes,
                secctx,
                requester_role,
                &unprotected->request_id,
                aeadalg,
                unprotected->backend
                );
    }
    if (!oscore_cryptoerr_is_error(err)) {
        err = oscore_crypto_aead_encrypt_inplace(
                &enc,
                ciphertext,
                ciphertext_length);
    }

    if (oscore_cryptoerr_is_error(err)) {
        return OSCORE_FINISH_ERROR_CRYPTO;
    }

    return OSCORE_FINISH_OK;
}
