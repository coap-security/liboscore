#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <oscore_native/crypto.h>

// keys happen to be derived as in RFC8613 C.1.1, but with ChaCha20/Poly1305
#define CHACHA_SENDER_KEY {213, 48, 30, 177, 141, 6, 120, 73, 149, 8, 147, 186, 42, 200, 145, 65, 124, 137, 174, 9, 223, 74, 56, 85, 170, 0, 10, 201, 255, 243, 135, 81}
#define CHACHA_COMMON_IV {100, 240, 189, 49, 77, 75, 224, 60, 39, 12, 43, 28}

// sender ID 03, secret "correct horse battery staple"
#define AESCCM_SENDER_KEY {119, 148, 122, 227, 70, 87, 45, 192, 116, 50, 219, 69, 190, 126, 239, 172}
#define AESCCM_COMMON_IV {11, 216, 46, 234, 187, 151, 85, 149, 207, 126, 20, 175, 68}

const size_t max_tag_length = 16;

struct testdata {
    oscore_crypto_aeadalg_t alg;
    const uint8_t *key;
    const uint8_t *nonce;
};

static const uint8_t chacha_key[] = CHACHA_SENDER_KEY;
// This happens to be the actually used IV for PIV 0 and the empty sender ID
static const uint8_t chacha_nonce[] = CHACHA_COMMON_IV;
static struct testdata chacha_data = {
    .alg = 24,
    .key = chacha_key,
    .nonce = chacha_nonce,
};

static const uint8_t aesccm_key[] = AESCCM_SENDER_KEY;
static const uint8_t aesccm_nonce[] = AESCCM_COMMON_IV;
static struct testdata aesccm_data = {
    .alg = 10,
    .key = aesccm_key,
    .nonce = aesccm_nonce,
};

const char message[] = "The quick brown fox jumps over the lazy dog.";

int test_with(struct testdata *data, int introduce_error)
{
    oscore_cryptoerr_t err;

    uint8_t arena[sizeof(message) + max_tag_length];
    memcpy(arena, message, sizeof(message));

    oscore_crypto_aeadalg_t alg;
    err = oscore_crypto_aead_from_number(&alg, data->alg);
    if (oscore_cryptoerr_is_error(err)) {
        return 1;
    }

    size_t tag_length = oscore_crypto_aead_get_taglength(alg);
    if (tag_length > max_tag_length) {
        return 2;
    }

    // This will need much more extensive testing with differently aligned AAD lengths
    uint8_t aad[] = {1, 2, 3, 4};

    oscore_crypto_aead_encryptstate_t encstate;
    err = oscore_crypto_aead_encrypt_start(
            &encstate,
            alg,
            sizeof(aad),
            sizeof(message),
            data->nonce,
            data->key
            );
    if (oscore_cryptoerr_is_error(err)) {
        return 30;
    }
    err = oscore_crypto_aead_encrypt_feed_aad(&encstate, aad, 2);
    if (oscore_cryptoerr_is_error(err)) return 31;
    err = oscore_crypto_aead_encrypt_feed_aad(&encstate, &aad[2], sizeof(aad) - 2);
    if (oscore_cryptoerr_is_error(err)) return 32;
    err = oscore_crypto_aead_encrypt_inplace(&encstate, arena, sizeof(message) + tag_length);
    if (oscore_cryptoerr_is_error(err)) return 33;

    assert(memcmp(message, arena, sizeof(message)) != 0);
    arena[0] ^= (introduce_error == 1);

    oscore_crypto_aead_decryptstate_t decstate;
    err = oscore_crypto_aead_decrypt_start(
            &decstate,
            alg,
            sizeof(aad),
            sizeof(message),
            data->nonce,
            data->key
            );
    if (oscore_cryptoerr_is_error(err)) return 40;
    err = oscore_crypto_aead_decrypt_feed_aad(&decstate, aad, 3);
    if (oscore_cryptoerr_is_error(err)) return 41;
    err = oscore_crypto_aead_decrypt_feed_aad(&decstate, &aad[3], sizeof(aad) - 3);
    if (oscore_cryptoerr_is_error(err)) return 42;
    err = oscore_crypto_aead_decrypt_inplace(&decstate, arena, sizeof(message) + tag_length);
    if (oscore_cryptoerr_is_error(err)) return 43;

    assert(memcmp(message, arena, sizeof(message)) == 0);

    return 0;
}

int testmain(int introduce_error)
{
    int ret;
    ret = test_with(&chacha_data, introduce_error == 1);
    if (ret != 0)
        return ret;
    ret = test_with(&aesccm_data, introduce_error > 1);
    return ret;
}
