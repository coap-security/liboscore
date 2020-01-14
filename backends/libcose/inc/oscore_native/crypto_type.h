#include <cose.h>

typedef cose_algo_t oscore_crypto_aeadalg_t;
typedef cose_algo_t oscore_crypto_hkdfalg_t;

typedef struct {
    oscore_crypto_aeadalg_t alg;
    // Buffer for AAD until the library has switched to some stream processing
    uint8_t *aad;
    // Write cursor inside the AAD (inside or at the end of the allocated aad area)
    uint8_t *aad_cursor;
    const uint8_t *iv;
    const uint8_t *key;
} oscore_crypto_aead_encryptstate_t;

typedef oscore_crypto_aead_encryptstate_t oscore_crypto_aead_decryptstate_t;

#define OSCORE_CRYPTO_AEAD_IV_MAXLEN ((size_t)13)

#define OSCORE_CRYPTO_AEAD_KEY_MAXLEN ((size_t)32)

typedef int oscore_cryptoerr_t;
