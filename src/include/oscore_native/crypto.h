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

/** @brief Get the tag length that is used for a particular algorithm
 *
 * @param[in] alg An AEAD algorithm
 * @return the length of the algorithm's tag, in bytes
 *
 * Implementers note: This function is easy enough to be infallible. As the
 * only way to obtain the backend's @ref oscore_crypto_aeadalg_t is through
 * @ref oscore_crypto_aead_from_number and @ref oscore_crypto_aead_from_string,
 * it can be sure that only values that were produced by that are around. If a
 * backend can still wind up in a situation where it doesn't know the tag
 * length, returning SIZE_MAX is a safe way to ensure that rather than
 * out-of-buffer writes, deterministic failure occurs.
 */
size_t oscore_crypto_aead_get_taglength(oscore_crypto_aeadalg_t alg);


/** @brief Encrypt a buffer in-place with an AEAD algorithm
 *
 * @param[in] alg The AEAD algorithm to use
 * @param[inout] buffer Memory location that contains the to-be-encrypted message and room for the tag
 * @param[in] buffer_len Length of the complete buffer (ie. length of the message plus tag length of the algorithm)
 * @param[in] aad Memory location that contains the AAD
 * @param[in] aad_len Length of the AAD
 * @param[in] iv Memory location of the (fully composed, full length for this algorithm) initialization vector (nonce)
 * @param[in] key Memory location of the encryption key (of the appropriate size for this algorithm)
 *
 * Note that while passing the message length might result in improvements to
 * the final machine code (especially when no link-time optimization is
 * performed), giving the whole buffer length should make memory access easier
 * to verify.
 */
oscore_cryptoerr_t oscore_crypto_aead_encrypt(
        oscore_crypto_aeadalg_t alg,
	uint8_t *buffer,
	size_t buffer_len,
	const uint8_t *aad,
	size_t aad_len,
	const uint8_t *iv,
	const uint8_t *key
	);

/** @brief Decrypt a buffer in-place with an AEAD algorithm
 *
 * @param[in] alg The AEAD algorithm to use
 * @param[inout] buffer Memory location that contains the ciphertext followed by the tag
 * @param[in] buffer_len Length of the complete buffer
 * @param[in] aad Memory location that contains the AAD
 * @param[in] aad_len Length of the AAD
 * @param[in] iv Memory location of the (fully composed, full length for this algorithm) initialization vector (nonce)
 * @param[in] key Memory location of the encryption key (of the appropriate size for this algorithm)
 *
 * When successful, the application can read find buffer_len minus @ref
 * oscore_crypto_aead_get_taglength(alg) bytes of plain text in the buffer, and
 * must disregard the trailing bytes.
 */
oscore_cryptoerr_t oscore_crypto_aead_decrypt(
        oscore_crypto_aeadalg_t alg,
	uint8_t *buffer,
	size_t buffer_len,
	const uint8_t *aad,
	size_t aad_len,
	const uint8_t *iv,
	const uint8_t *key
	);

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

/** Return true if an error type indicates an unsuccessful operation */
bool oscore_cryptoerr_is_error(oscore_cryptoerr_t);

/** @} */

#endif
