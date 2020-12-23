#include <assert.h>
#include <oscore/context_impl/primitive.h>

const size_t info_maxlen = 1 + \
    /* Assuming OSCORE_KEYID_MAXLEN is not >255 */ \
    2 + \
    OSCORE_KEYID_MAXLEN + \
    /* Same assumption */ \
    2 + \
    OSCORE_KEYIDCONTEXT_MAXLEN + \
    /* Assuming string algs are not supported */ \
    5 + \
    4 + \
    /* Assuming derived lengths all fit in a u16 */ \
    3;

extern size_t cbor_intencode(size_t input, uint8_t buf[5], uint8_t type);
extern size_t cbor_intsize(size_t input);

/** Build an `info` and derive a single output parameter.
 *
 * For an id_context of nil, put both id_context as NULL and id_context_len must be 0 */
static
oscore_cryptoerr_t _derive_single(
    struct oscore_context_primitive_immutables *context,
        oscore_crypto_hkdfalg_t alg,
        const uint8_t *salt,
        size_t salt_len,
        const uint8_t *ikm,
        size_t ikm_len,
        const uint8_t *id_context,
        size_t id_context_len,
        const uint8_t *id,
        size_t id_len,
        const uint8_t *type,
        size_t type_len,
        uint8_t *dest,
        size_t dest_len
        )
{
    int32_t numeric_alg = 0;
    /* FIXME just do preencoding */
    oscore_crypto_aead_get_number(context->aeadalg, &numeric_alg);
    uint32_t preencoded_alg = numeric_alg >= 0 ? numeric_alg : (-1 - numeric_alg);
    uint8_t preencoded_type = numeric_alg >= 0 ? 0x00 : 0x20;

    /* Note that while it'd be kind of possible to feed at least one of salt or
     * ikm in in a streaming fashion, feeding in info is really a no-go as is
     * read several times throughout the derivation -- potentially */

    /* Allocating on the careful sidesee @ref stack_allocation_sizes for
     * rationale. */
    uint8_t infobuf[info_maxlen];
    size_t infobuf_len = 1 + \
            cbor_intsize(id_len) + id_len + \
            cbor_intsize(id_context_len) + id_context_len + \
            cbor_intsize(preencoded_alg) + \
            cbor_intsize(type_len) + type_len + \
            cbor_intsize(dest_len);

    assert(infobuf_len < info_maxlen);

    uint8_t *cursor = infobuf;
    *(cursor++) = 0x85; /* list length 5 */
    cursor += cbor_intencode(id_len, cursor, 0x40);
    memcpy(cursor, id, id_len);
    cursor += id_len;
    if (id_context == NULL) {
        *(cursor++) = 0xf6 /* null */;
    } else {
        cursor += cbor_intencode(id_context_len, cursor, 0x40);
        memcpy(cursor, id_context, id_context_len);
        cursor += id_context_len;
    }
    cursor += cbor_intencode(preencoded_alg, cursor, preencoded_type);
    cursor += cbor_intencode(type_len, cursor, 0x60);
    memcpy(cursor, type, type_len);
    cursor += type_len;
    cursor += cbor_intencode(dest_len, cursor, 0x00);

    assert(&infobuf[infobuf_len] == cursor);
    /* Allow ditching all the cbor_intsize precalculation with NDEBUG */
    infobuf_len = cursor - &infobuf[0];

    return oscore_crypto_hkdf_derive(
            alg,
            salt, salt_len,
            ikm, ikm_len,
            infobuf, infobuf_len,
            dest, dest_len
            );
}

oscore_cryptoerr_t oscore_context_primitive_derive(
        struct oscore_context_primitive_immutables *context,
        oscore_crypto_hkdfalg_t alg,
        const uint8_t *salt,
        size_t salt_len,
        const uint8_t *ikm,
        size_t ikm_len,
        const uint8_t *id_context,
        size_t id_context_len
        )
{
    oscore_cryptoerr_t err;
    err = _derive_single(context, alg, salt, salt_len, ikm, ikm_len,
            id_context, id_context_len,
            context->sender_id, context->sender_id_len,
            (uint8_t*)"Key", 3,
            context->sender_key, oscore_crypto_aead_get_keylength(context->aeadalg));
    if (oscore_cryptoerr_is_error(err)) {
        return err;
    }

    err = _derive_single(context, alg, salt, salt_len, ikm, ikm_len,
            id_context, id_context_len,
            context->recipient_id, context->recipient_id_len,
            (uint8_t*)"Key", 3,
            context->recipient_key, oscore_crypto_aead_get_keylength(context->aeadalg));
    if (oscore_cryptoerr_is_error(err)) {
        return err;
    }

    err = _derive_single(context, alg, salt, salt_len, ikm, ikm_len,
            id_context, id_context_len,
            (uint8_t*)"", 0,
            (uint8_t*)"IV", 2,
            context->common_iv, oscore_crypto_aead_get_ivlength(context->aeadalg));

    return err;
}
