#include <assert.h>

#include <oscore_native/crypto.h>

#include <cose/crypto.h>

oscore_cryptoerr_t oscore_crypto_aead_from_number(oscore_crypto_aeadalg_t *alg, int32_t number)
{
    // Following libcose's practice to just numerically cast an int32_t to the enum
    if (cose_crypto_is_aead(number)) {
        *alg = number;
        return COSE_OK;
    } else {
        return COSE_ERR_NOTIMPLEMENTED;
    }
}

bool oscore_cryptoerr_is_error(oscore_cryptoerr_t err)
{
    return err != COSE_OK;
}

size_t oscore_crypto_aead_get_taglength(oscore_crypto_aeadalg_t alg)
{
    switch (alg) {
        case COSE_ALGO_CHACHA20POLY1305:
            return COSE_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES;
        default:
            return SIZE_MAX;
    }
}

oscore_cryptoerr_t oscore_crypto_aead_encrypt(
        oscore_crypto_aeadalg_t alg,
        uint8_t *buffer,
        size_t buffer_len,
        const uint8_t *aad,
        size_t aad_len,
        const uint8_t *iv,
        const uint8_t *key
        )
{
    size_t message_len = buffer_len - oscore_crypto_aead_get_taglength(alg);
    size_t modified_buffer_len = buffer_len;

    oscore_cryptoerr_t err = cose_crypto_aead_encrypt(
            // ciphertext
            buffer, &modified_buffer_len,
            // message
            buffer, message_len,
            // aad
            aad, aad_len,
            // nsec: No secret nonce used with OSCORE
            NULL,
            // npub: public nonce
            iv,
            key,
            alg
            );

    if (err == COSE_OK) {
        // With NDEBUG, the verbose setup above required for this should not have
        // any impact on final code.
        assert(buffer_len == modified_buffer_len);
    }

    return err;
}

oscore_cryptoerr_t oscore_crypto_aead_decrypt(
        oscore_crypto_aeadalg_t alg,
        uint8_t *buffer,
        size_t buffer_len,
        const uint8_t *aad,
        size_t aad_len,
        const uint8_t *iv,
        const uint8_t *key
        )
{
    size_t message_len = buffer_len - oscore_crypto_aead_get_taglength(alg);
    size_t modified_message_len = message_len;

    oscore_cryptoerr_t err = cose_crypto_aead_decrypt(
            // message space
            buffer, &modified_message_len,
            // ciphertext
            buffer, buffer_len,
            // aad
            aad, aad_len,
            // npub: public nonce
            iv,
            key,
            alg
            );

    if (err == COSE_OK) {
        // With NDEBUG, the verbose setup above required for this should not have
        // any impact on final code.
        assert(message_len == modified_message_len);
    }

    return err;
}
