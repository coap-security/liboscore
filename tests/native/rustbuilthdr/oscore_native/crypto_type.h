typedef enum {OSCORE_CRYPTO_AEADALG_DONTCARE} oscore_crypto_aeadalg_t;

typedef struct {uint64_t unsure[100];} oscore_crypto_aead_encryptstate_t;
typedef oscore_crypto_aead_encryptstate_t oscore_crypto_aead_decryptstate_t;

typedef int32_t oscore_crypto_hkdfalg_t;
typedef enum {OSCORE_CRYPTOERR_DONTCARE} oscore_cryptoerr_t;

#define OSCORE_CRYPTO_AEAD_IV_MAXLEN ((size_t)13)
#define OSCORE_CRYPTO_AEAD_KEY_MAXLEN ((size_t)16)
