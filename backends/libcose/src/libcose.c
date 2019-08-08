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

oscore_cryptoerr_t oscore_crypto_aead_encrypt_start(
        oscore_crypto_aead_encryptstate_t *state,
        oscore_crypto_aeadalg_t alg,
        size_t aad_len,
        uint8_t plaintext_len,
        const uint8_t *iv,
        const uint8_t *key
        )
{
    state->alg = alg;
    state->iv = iv;
    state->key = key;
    state->aad = malloc(aad_len);
    assert(state->aad != NULL);
    state->aad_cursor = state->aad;

    return COSE_OK;
}

oscore_cryptoerr_t oscore_crypto_aead_encrypt_feed_aad(
        oscore_crypto_aead_encryptstate_t *state,
        uint8_t *aad_chunk,
        size_t aad_chunk_len
        )
{
    memcpy(state->aad_cursor, aad_chunk, aad_chunk_len);
    state->aad_cursor += aad_chunk_len;

    return COSE_OK;
}

oscore_cryptoerr_t oscore_crypto_aead_encrypt_inplace(
        oscore_crypto_aead_encryptstate_t *state,
        uint8_t *buffer,
        size_t buffer_len
        )
{
    size_t message_len = buffer_len - oscore_crypto_aead_get_taglength(state->alg);
    size_t modified_buffer_len = buffer_len;

    oscore_cryptoerr_t err = cose_crypto_aead_encrypt(
            // ciphertext
            buffer, &modified_buffer_len,
            // message
            buffer, message_len,
            // aad
            state->aad, state->aad_cursor - state->aad,
            // nsec: No secret nonce used with OSCORE
            NULL,
            // npub: public nonce
            state->iv,
            state->key,
            state->alg
            );

    free(state->aad);

    if (err == COSE_OK) {
        // With NDEBUG, the verbose setup at the top required for this should
        // not have any impact on final code.
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
