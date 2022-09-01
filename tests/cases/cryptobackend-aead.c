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
    const uint8_t *expected_ciphertext;
};

static const uint8_t chacha_key[] = CHACHA_SENDER_KEY;
// This happens to be the actually used IV for PIV 0 and the empty sender ID
static const uint8_t chacha_nonce[] = CHACHA_COMMON_IV;
// Extracted using the libcose backend that a) tests against known vectors
// itself and b) has interoperated with aiocoap both on ChaCha and on AES-CCM.
// When adding new algorithms, the easiest way to get the initial vector is to
// set expected_ciphertext NULL, run in gdb until the inevitable segfault, go
// up to the test_with stackframe, `print sizeof(message) + tag_length` and use
// that value for `print/x arena[0]@61` or similar.
static const uint8_t chacha_expected_ciphertext[] = {0x9, 0x4a, 0xcb, 0x7a,
    0x92, 0xe7, 0x88, 0x6e, 0x21, 0x7f, 0x19, 0xac, 0xf6, 0x3d, 0xcd, 0x78,
    0xbb, 0xc1, 0x36, 0x5a, 0x26, 0x38, 0xb9, 0x63, 0xee, 0xa0, 0x88, 0x40,
    0xda, 0xa3, 0x9e, 0xbe, 0x7c, 0x9f, 0x2e, 0x75, 0xa5, 0xb4, 0xc0, 0xbc,
    0xe2, 0xb0, 0xb8, 0xfa, 0x21, 0xd3, 0x9e, 0x81, 0x52, 0x4d, 0x97, 0xd1,
    0x48, 0x1c, 0xd7, 0x2a, 0x2b, 0x94, 0xab, 0x2, 0xf1};
static struct testdata chacha_data = {
    .alg = 24,
    .key = chacha_key,
    .nonce = chacha_nonce,
    .expected_ciphertext = chacha_expected_ciphertext,
};

static const uint8_t aesccm_key[] = AESCCM_SENDER_KEY;
static const uint8_t aesccm_nonce[] = AESCCM_COMMON_IV;
// see chacha_expected_ciphertext for source
static const uint8_t aesccm_expected_ciphertext[] = {0xc8, 0xe3, 0x96, 0x8a,
    0xd0, 0x78, 0x7e, 0x0, 0xc8, 0x69, 0x82, 0x47, 0xe, 0xfe, 0x73, 0x99, 0x65,
    0x79, 0x86, 0xa9, 0xb6, 0x94, 0xf6, 0x66, 0xc9, 0xdf, 0x4f, 0x87, 0x64,
    0xae, 0xde, 0xca, 0x8e, 0xde, 0x1a, 0x48, 0x6f, 0xe0, 0x18, 0x31, 0x95,
    0xe3, 0xb7, 0x1f, 0x98, 0xea, 0xe, 0xe, 0xde, 0xfe, 0x3, 0x82, 0xd7};
static struct testdata aesccm_data = {
    .alg = 10,
    .key = aesccm_key,
    .nonce = aesccm_nonce,
    .expected_ciphertext = aesccm_expected_ciphertext,
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
    assert(memcmp(arena, data->expected_ciphertext, sizeof(message) + tag_length) == 0);
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
        return 100 + ret;
    ret = test_with(&aesccm_data, introduce_error > 1);
    if (ret != 0)
        return 200 + ret;
    return 0;
}
