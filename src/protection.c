#include <oscore/protection.h>

#include <assert.h>

#include <oscore_native/crypto.h>

/** Take the Partial IV from the OSCORE option and populate @ref
 * oscore_request_t from it. Return true if successful, or false if there was
 * no PartIV in the option.
 *
 * This leaves request unmodified if no PartIV was present in the option. */
bool extract_requestid(const oscore_oscoreoption_t *option, oscore_requestid_t *request)
{
    if (option->option_length == 0) {
        return false;
    }

    size_t n = option->option[0] & 0x7;
    if (n == 0) {
        return false;
    }

    // Checked at instance creation; the assert here helps demonstrate that the
    // following memory access is safe.
    assert(n <= PIV_BYTES);

    request->used_bytes = n;
    // I trust the compiler will zero out the whole struct if that is more
    // efficient as it can see that the rest is overwritten later
    memset(request->partial_iv, 0, PIV_BYTES - n);
    request->is_first_use = false;
    uint8_t *dest = &request->partial_iv[PIV_BYTES - n];
    memcpy(dest, &option->option[1], n);

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
    } else if (ret == 3) {
        buf[0] = type;
        buf[1] = (input << 8) % 256;
        buf[2] = input % 256;
    } else {
        buf[0] = type;
        buf[1] = (input << 24) % 256;
        buf[2] = (input << 16) % 256;
        buf[3] = (input << 8) % 256;
        buf[4] = input % 256;
    }
    return ret;
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
        oscore_context_t *secctx,
        enum oscore_context_role requester_role,
        oscore_requestid_t *request,
        oscore_crypto_aeadalg_t aeadalg,
        oscore_msg_native_t class_i_source
        )
{
    uint8_t *request_kid; // ignored, but get_kid still wants to write somewhere
    size_t request_kid_len;
    oscore_context_get_kid(secctx, requester_role, &request_kid, &request_kid_len);

    struct aad_sizes ret;

    // FIXME gather thsi from class_i_source
    ret.class_i_length = 0;
    ret.external_aad_length = \
            1 /* array length 5 */ +
            1 /* oscore version 1 */ +
            cbor_intsize(aeadalg < 0 ? 1 - aeadalg : aeadalg) /* FIXME strings? */ + 
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

/** Push the AAD for a given message into the decryption state.
 *
 * @param[inout] state AEAD decryption state
 * @param[in] aad_sizes Predetermined sizes of the various AAD components
 * @param[in] secctx Security context from which to pick the sender role KID
 * @param[in] requester_role Role in @p secctx that created the request
 * @param[in] request The @ref oscore_requestid_t describing the request_piv
 * @param[in] class_i_source The outer message containing all class I options to be considered for this message
 *
 */
oscore_cryptoerr_t feed_aad(
        oscore_crypto_aead_decryptstate_t *state,
        struct aad_sizes aad_sizes,
        oscore_context_t *secctx,
        enum oscore_context_role requester_role,
        oscore_requestid_t *request,
        oscore_crypto_aeadalg_t aeadalg,
        oscore_msg_native_t class_i_source
        )
{
    oscore_cryptoerr_t err;
    uint8_t intbuf[5];

    // array length 3, "Encrypt0", h''
    err = oscore_crypto_aead_decrypt_feed_aad(state, (uint8_t*) "\x83\x68" "Encrypt0" "\x40", 11);
    if (!oscore_cryptoerr_is_error(err)) { return err; }

    // full external AAD length
    err = oscore_crypto_aead_decrypt_feed_aad(state, intbuf, cbor_intencode(aad_sizes.external_aad_length, intbuf, 0x40));
    if (!oscore_cryptoerr_is_error(err)) { return err; }

    // external AAD array start, constant OSCORE version 1
    err = oscore_crypto_aead_decrypt_feed_aad(state, (uint8_t*) "\x85\x01", 2);
    if (!oscore_cryptoerr_is_error(err)) { return err; }

    // Used algorithm
    // FIXME strings?
    err = oscore_crypto_aead_decrypt_feed_aad(state, intbuf, cbor_intencode(aeadalg < 0 ? 1 - aeadalg : aeadalg, intbuf, aeadalg < 0 ? 0x20 : 0x00));
    if (!oscore_cryptoerr_is_error(err)) { return err; }

    // Request KID
    uint8_t *request_kid;
    size_t request_kid_len;
    oscore_context_get_kid(secctx, requester_role, &request_kid, &request_kid_len);

    err = oscore_crypto_aead_decrypt_feed_aad(state, intbuf, cbor_intencode(request_kid_len, intbuf, 0x40));
    if (!oscore_cryptoerr_is_error(err)) { return err; }
    err = oscore_crypto_aead_decrypt_feed_aad(state, request_kid, request_kid_len);
    if (!oscore_cryptoerr_is_error(err)) { return err; }

    // Request PIV
    err = oscore_crypto_aead_decrypt_feed_aad(state, intbuf, cbor_intencode(request->used_bytes, intbuf, 0x40));
    if (!oscore_cryptoerr_is_error(err)) { return err; }
    err = oscore_crypto_aead_decrypt_feed_aad(state, &request->partial_iv[PIV_BYTES - request->used_bytes], request->used_bytes);
    if (!oscore_cryptoerr_is_error(err)) { return err; }

    // Class I options
    assert(aad_sizes.class_i_length == 0);
    // 0 byte string
    err = oscore_crypto_aead_decrypt_feed_aad(state, (uint8_t*) "\x40", 1);

    return err;
}


/** Build a full IV from a partial IV, a security context pair and a sender
 * role
 *
 * @param[out] iv The output buffer
 * @param[in] partiv The zero-padded partial IV
 * @param[in] secctx The security context pair this is used with
 * @param[in] piv_role The role the creator of the Partial IV has in this security context
 * */
void build_iv(
        uint8_t iv[OSCORE_CRYPTO_AEAD_IV_MAXLEN],
        const uint8_t partiv[PIV_BYTES],
        oscore_context_t *secctx,
        enum oscore_context_role piv_role
        )
{
    size_t iv_len = oscore_crypto_aead_get_ivlength(oscore_context_get_aeadalg(secctx));
    const uint8_t *common_iv = oscore_context_get_commoniv(secctx);

    assert(iv_len >= 7);
    assert(iv_len <= OSCORE_CRYPTO_AEAD_IV_MAXLEN);

    uint8_t *id_piv;
    size_t id_piv_len;
    oscore_context_get_kid(secctx, piv_role, &id_piv, &id_piv_len);

    assert(id_piv_len <= iv_len - 6);

    iv[0] = id_piv_len;
    size_t pad1_len = id_piv_len - 6;
    memset(&iv[1], 0, pad1_len);
    memcpy(&iv[1 + pad1_len], id_piv, id_piv_len);
    memcpy(&iv[iv_len - PIV_BYTES], partiv, PIV_BYTES);

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
        size_t tail_start = n + 1;

        if (header & 0x10) {
            // h=1: KID context present
            if (tail_start >= input_len) {
                return false;
            }

            // Not validating its value: KID context is opaque
            tail_start += input[tail_start];
        }

        if (header & 0x08) {
            // k=1: KID present
            if (tail_start > input_len) {
                return false;
            }
            // Not validating its value
        } else {
            if (tail_start != input_len) {
                return false;
            }
        }
    }

    out->option = input;
    out->option_length = input_len;
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
     *   instead, all following steps make sure to always look into is_request
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

    oscore_crypto_aeadalg_t aeadalg = oscore_context_get_aeadalg(secctx);
    size_t tag_length = oscore_crypto_aead_get_taglength(aeadalg); 
    size_t minimum_ciphertext_length = 1 + tag_length;

    uint8_t *ciphertext;
    size_t ciphertext_length;
    oscore_msg_native_map_payload(protected, &ciphertext, &ciphertext_length);
    if (ciphertext_length < minimum_ciphertext_length) {
        // Ciphertext too short
        return OSCORE_UNPROTECT_REQUEST_INVALID;
    }
    size_t plaintext_length = ciphertext_length - tag_length; // >= 1

    bool has_request_id = extract_requestid(&header, request_id);
    if (!has_request_id) {
        return OSCORE_UNPROTECT_REQUEST_INVALID;
    }

    struct aad_sizes aad_sizes = predict_aad_size(secctx, OSCORE_ROLE_RECIPIENT, request_id, aeadalg, protected);

    uint8_t iv[OSCORE_CRYPTO_AEAD_IV_MAXLEN];
    build_iv(iv, request_id->partial_iv, secctx, OSCORE_ROLE_RECIPIENT);

    oscore_cryptoerr_t err;
    oscore_crypto_aead_decryptstate_t dec;
    err = oscore_crypto_aead_decrypt_start(
            &dec,
            aeadalg,
            aad_sizes.aad_length,
            plaintext_length,
            iv,
            oscore_context_get_key(secctx, OSCORE_ROLE_SENDER)
            );
    if (!oscore_cryptoerr_is_error(err)) {
        err = feed_aad(&dec, aad_sizes, secctx, OSCORE_ROLE_RECIPIENT, request_id, aeadalg, protected);
    }
    if (!oscore_cryptoerr_is_error(err)) {
        err = oscore_crypto_aead_decrypt_inplace(
                &dec,
                ciphertext,
                ciphertext_length);
    }

    if (oscore_cryptoerr_is_error(err)) {
        return OSCORE_UNPROTECT_REQUEST_INVALID;
    }

    // FIXME continue here: check for partial IV, possibly promoting the request_id to have a is_first_use bit set
    return OSCORE_UNPROTECT_REQUEST_DUPLICATE;
}
