#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <oscore_native/crypto.h>

// keys happen to be derived as in RFC8613 C.1.1, but with ChaCha20/Poly1305
#define SENDER_KEY {213, 48, 30, 177, 141, 6, 120, 73, 149, 8, 147, 186, 42, 200, 145, 65, 124, 137, 174, 9, 223, 74, 56, 85, 170, 0, 10, 201, 255, 243, 135, 81}
#define RECIPIENT_KEY {50, 136, 42, 28, 97, 144, 48, 132, 56, 236, 152, 230, 169, 50, 240, 32, 112, 143, 55, 57, 223, 228, 109, 119, 152, 155, 3, 155, 31, 252, 28, 172}
#define COMMON_IV {100, 240, 189, 49, 77, 75, 224, 60, 39, 12, 43, 28}

const size_t max_tag_length = 16;

const static uint8_t key[] = SENDER_KEY;
// This happens to be the actually used IV for PIV 0 and the empty sender ID
const static uint8_t nonce[] = COMMON_IV;

const char message[] = "The quick brown fox jumps over the lazy dog.";

int main()
{
    oscore_cryptoerr_t err;

    uint8_t arena[sizeof(message) + max_tag_length];
    memcpy(arena, message, sizeof(message));

    oscore_crypto_aeadalg_t chacha;
    err = oscore_crypto_aead_from_number(&chacha, 24);
    if (oscore_cryptoerr_is_error(err)) {
        return 1;
    }

    size_t tag_length = oscore_crypto_aead_get_taglength(chacha);
    if (tag_length > max_tag_length) {
        return 2;
    }

    uint8_t aad[] = {1, 2, 3, 4};
    err = oscore_crypto_aead_encrypt(
            chacha,
            arena, sizeof(message) + tag_length,
            aad, sizeof(aad),
            nonce,
            key
            );
    if (oscore_cryptoerr_is_error(err)) {
        return 3;
    }

    assert(memcmp(message, arena, sizeof(message)) != 0);

    err = oscore_crypto_aead_decrypt(
            chacha,
            arena, sizeof(message) + tag_length,
            aad, sizeof(aad),
            nonce,
            key
            );
    if (oscore_cryptoerr_is_error(err)) {
        return 4;
    }

    assert(memcmp(message, arena, sizeof(message)) == 0);
}
