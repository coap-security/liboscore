#ifndef OSCORE_NATIVE_CRYPTO_H
#define OSCORE_NATIVE_CRYPTO_H

/** @file */

/** @ingroup oscore_native_api
 *  @addtogroup oscore_native_crypto Native cryptography API
 *
 *  @brief API which any native cryotography library provides to OSCORE
 *
 *  The below functions are tailored towards cryptography libraries that work
 *  in terms of COSE algorithms, because that's what OSCORE uses by specification.
 *  Cryptography libraries that do not "think" that way will likely implement
 *  most of the functions by a large switch statement that dispatches
 *  encryption and decryption into the appropriate (eg. AES-CCM) functions.
 *
 * @{
 */

#include <stdint.h>

#include <oscore_native/crypto_type.h>

oscore_cryptoerr_t oscore_crypto_aead_encrypt(oscore_crypto_cosealg_t alg, ...);
oscore_cryptoerr_t oscore_crypto_aead_decrypt(oscore_crypto_cosealg_t alg, ...);
bool oscore_crypto_aead_algorithm_implemented(oscore_crypto_cosealg_t alg);
// Missing: parameter extraction (Is that better done by filling up a struct, or by per-parameter extractors?)

/** @} */

#endif
