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

/** @brief Set up an algorithm descriptor from a numerically identified COSE
 * Algorithm
 *
 * @param[out] alg Output field for the algorithm
 * @param[in] number Algorithm number from IANA's COSE Algorithms registry
 *
 * If the number given is not an AEAD algorithm or not implemented, the
 * function must return an error; it may leave @p alg uninitialized or set it
 * arbitrarily in that case.
 *
 */
oscore_cryptoerr_t oscore_crypto_aead_from_number(oscore_crypto_aeadalg_t *alg, int32_t number);
/** @brief Set up an algorithm descriptor from a string-identified COSE
 * Algorithm
 *
 * @param[out] alg Output field for the algorithm
 * @param[in] string Algorithm name from IANA's COSE Algorithms registry, in
 *     UTF-8 encoding
 * @param[in] string_len Length of @p string
 *
 * If the number given is not an AEAD algorithm or not implemented, the
 * function must return an error; it may leave @p alg uninitialized or set it
 * arbitrarily in that case.
 *
 */
oscore_cryptoerr_t oscore_crypto_aead_from_string(oscore_crypto_aeadalg_t *alg, uint8_t *string, size_t string_len);

oscore_cryptoerr_t oscore_crypto_aead_encrypt(oscore_crypto_aeadalg_t alg, ...);
oscore_cryptoerr_t oscore_crypto_aead_decrypt(oscore_crypto_aeadalg_t alg, ...);

/** @brief Set up an algorithm descriptor from a numerically identified COSE
 * Direct Key with KDF
 *
 * @param[out] alg Output field for the algorithm
 * @param[in] number Algorithm number from IANA's COSE Algorithms registry
 *
 * If the number given is not an HKDF algorithm or not implemented, the
 * function must return an error; it may leave @p alg uninitialized or set it
 * arbitrarily in that case.
 *
 */
oscore_cryptoerr_t oscore_crypto_hkdf_from_number(oscore_crypto_hkdfalg_t *alg, int32_t number);
/** @brief Set up an algorithm descriptor from a string-identified COSE
 * Direct Key with KDF
 *
 * @param[out] alg Output field for the algorithm
 * @param[in] string Algorithm name from IANA's COSE Algorithms registry, in
 *     UTF-8 encoding
 * @param[in] string_len Length of @p string
 *
 * If the number given is not an HKDF algorithm or not implemented, the
 * function must return an error; it may leave @p alg uninitialized or set it
 * arbitrarily in that case.
 *
 */
oscore_cryptoerr_t oscore_crypto_hkdf_from_string(oscore_crypto_hkdfalg_t *alg, uint8_t *string, size_t string_len);

// Having info as a buffer is really inconvenient as I'd rather feed that slice
// by slice given it contains potentially long id / id_context. 
//
// running expand and extract independently would be nice as well, given it'd save a hashing step.
oscore_cryptoerr_t oscore_crypto_hkdf_derive(
		oscore_crypto_hkdfalg_t alg,
		const uint8_t *salt,
		size_t salt_len,
		const uint8_t *ikm,
		size_t ikm_length,
		const uint8_t *info,
		size_t info_length,
		uint8_t *out,
		size_t out_length
		);

/** @} */

#endif
