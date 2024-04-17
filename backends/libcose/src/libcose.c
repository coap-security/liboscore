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

oscore_cryptoerr_t oscore_crypto_aead_get_number(oscore_crypto_aeadalg_t alg, int32_t *number)
{
    // Valid by the design of libcose's algorithm identifiers
    *number = alg;
    return COSE_OK;
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
#ifdef HAVE_ALGO_AESCCM_16_64_128
        case COSE_ALGO_AESCCM_16_64_128:
            return COSE_CRYPTO_AEAD_AESCCM_16_64_128_ABYTES;
#endif
        default:
            return SIZE_MAX;
    }
}

size_t oscore_crypto_aead_get_keylength(oscore_crypto_aeadalg_t alg)
{
    switch (alg) {
        case COSE_ALGO_CHACHA20POLY1305:
            return COSE_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES;
#ifdef HAVE_ALGO_AESCCM_16_64_128
        case COSE_ALGO_AESCCM_16_64_128:
            return COSE_CRYPTO_AEAD_AESCCM_16_64_128_KEYBYTES;
#endif
        default:
            return SIZE_MAX;
    }
}

size_t oscore_crypto_aead_get_ivlength(oscore_crypto_aeadalg_t alg)
{
    switch (alg) {
        case COSE_ALGO_CHACHA20POLY1305:
            return COSE_CRYPTO_AEAD_CHACHA20POLY1305_NONCEBYTES;
#ifdef HAVE_ALGO_AESCCM_16_64_128
        case COSE_ALGO_AESCCM_16_64_128:
            return COSE_CRYPTO_AEAD_AESCCM_16_64_128_NONCEBYTES;
#endif
        default:
            return SIZE_MAX;
    }
}

oscore_cryptoerr_t oscore_crypto_aead_encrypt_start(
        oscore_crypto_aead_encryptstate_t *state,
        oscore_crypto_aeadalg_t alg,
        size_t aad_len,
        size_t plaintext_len,
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

    // As the actua cranking of the AEAD mechanism only starts when all is
    // copied to the allocated memory, plaintext_len is ignored for now.
    (void) plaintext_len;

    return COSE_OK;
}

oscore_cryptoerr_t oscore_crypto_aead_encrypt_feed_aad(
        void *state,
        const uint8_t *aad_chunk,
        size_t aad_chunk_len
        )
{
    oscore_crypto_aead_encryptstate_t *encstate = state;

    memcpy(encstate->aad_cursor, aad_chunk, aad_chunk_len);
    encstate->aad_cursor += aad_chunk_len;

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

oscore_cryptoerr_t oscore_crypto_aead_decrypt_start(
        oscore_crypto_aead_decryptstate_t *state,
        oscore_crypto_aeadalg_t alg,
        size_t aad_len,
        size_t plaintext_len,
        const uint8_t *iv,
        const uint8_t *key
        )
{
    return oscore_crypto_aead_encrypt_start(state, alg, aad_len, plaintext_len, iv, key);
}

oscore_cryptoerr_t oscore_crypto_aead_decrypt_feed_aad(
        void *state,
        const uint8_t *aad_chunk,
        size_t aad_chunk_len
        )
{
    return oscore_crypto_aead_encrypt_feed_aad(state, aad_chunk, aad_chunk_len);
}

oscore_cryptoerr_t oscore_crypto_aead_decrypt_inplace(
        oscore_crypto_aead_encryptstate_t *state,
        uint8_t *buffer,
        size_t buffer_len
        )
{
    size_t message_len = buffer_len - oscore_crypto_aead_get_taglength(state->alg);
    size_t modified_message_len = message_len;

    oscore_cryptoerr_t err = cose_crypto_aead_decrypt(
            // message space
            buffer, &modified_message_len,
            // ciphertext
            buffer, buffer_len,
            // aad
            state->aad, state->aad_cursor - state->aad,
            // npub: public nonce
            state->iv,
            state->key,
            state->alg
            );

    free(state->aad);

    if (err == COSE_OK) {
        // With NDEBUG, the verbose setup above required for this should not have
        // any impact on final code.
        assert(message_len == modified_message_len);
    }

    return err;
}

oscore_cryptoerr_t oscore_crypto_hkdf_from_number(oscore_crypto_hkdfalg_t *alg, int32_t number)
{
    // Following libcose's practice to just numerically cast an int32_t to the enum
    if (cose_crypto_is_hkdf(number)) {
        *alg = number;
        return COSE_OK;
    } else {
        return COSE_ERR_NOTIMPLEMENTED;
    }
}

OSCORE_NONNULL
oscore_cryptoerr_t oscore_crypto_hkdf_derive(
        oscore_crypto_hkdfalg_t alg,
        const uint8_t *salt,
        size_t salt_len,
        const uint8_t *ikm,
        size_t ikm_len,
        const uint8_t *info,
        size_t info_len,
        uint8_t *out,
        size_t out_len
        )
{
    return cose_crypto_hkdf_derive(salt, salt_len, ikm, ikm_len, info, info_len, out, out_len, alg);
}
