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
 *  Some aspects of these calls are tailored towards AEAD with streaming AAD.
 *  While there is no practical need for having the plain- and ciphertext
 *  processed as they come in (because acting on them would have severe
 *  security ramifications), AAD is unbounded when Class-I options are present,
 *  and not otherwise needed present in a contiguous buffer.
 *
 *  Many backends (even the currently used libCOSE, though there are efforts to
 *  change that) will not support that mode of operation. Those need to either
 *  allocate memory dynamically at the start of the AEAD operation (based on
 *  the known size of the AAD that is passed in), or set aside that memory in
 *  their @ref oscore_crypto_aead_encryptstate_t. (The memory size is a
 *  nonlinear function of the maximum key lengths and algorithms; 32 byte will
 *  often suffice as long as no Class-I options are present).
 *
 * @{
 */

#include <stdint.h>

#include <oscore/helpers.h>
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
OSCORE_NONNULL
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
OSCORE_NONNULL
oscore_cryptoerr_t oscore_crypto_aead_from_string(oscore_crypto_aeadalg_t *alg, const uint8_t *string, size_t string_len);

/** @brief Obtain the algorithms's numeric COSE identifier
 *
 * @param[in] alg Algorithm
 * @param[out] number Memory address to be populated with the COSE identifier
 *
 * Returns an OK value if a numeric identifier exists for the algorithm; if
 * not, a string identifier needs to exist.
 */
OSCORE_NONNULL
oscore_cryptoerr_t oscore_crypto_aead_get_number(oscore_crypto_aeadalg_t alg, int32_t *number);

/** @brief Obtain the algorithms's string COSE identifier
 *
 * @param[in] alg Algorithm
 * @param[out] string Memory address to be populated with the location of a COSE identifier
 * @param[out] string_len Memory address to be populated with the COSE identifier's length
 *
 * The memory location containing the string is expected to be static and constant.
 *
 * Returns an OK value if a string identifier exists for the algorithm; if
 * not, a numeric identifier needs to exist.
 */
OSCORE_NONNULL
oscore_cryptoerr_t oscore_crypto_aead_get_string(oscore_crypto_aeadalg_t alg, const char **number, size_t *string_len);

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

/** @brief Get the IV (initialization vector / nonce) length that is used for a particular algorithm
 *
 * @param[in] alg An AEAD algorithm
 * @return the length of the algorithm's IV, in bytes
 */
size_t oscore_crypto_aead_get_ivlength(oscore_crypto_aeadalg_t alg);

/** @brief Get the key length that is used for a particular algorithm
 *
 * @param[in] alg An AEAD algorithm
 * @return the length of the algorithm's keys, in bytes
 */
size_t oscore_crypto_aead_get_keylength(oscore_crypto_aeadalg_t alg);


/** @brief Start an AEAD encryption operation
 *
 * @param[out] state Encryption state to set up
 * @param[in] alg OSCORE AEAD algorithm that will be used
 * @param[in] aad_len Bytes of Additional Authenticated Data that will later fed into this encryption
 * @param[in] plaintext_len Bytes of plaintext that will later fed into this encryption
 * @param[in] iv Nonce used for this encryption (length depends on the algorithm)
 * @param[in] key Shared key used for this encryption (length depends on the algorithm)
 *
 * The construction of this encryption state must be followed up with exactly
 * as many bytes in @ref oscore_crypto_aead_encrypt_feed_aad calls, and an @ref
 * oscore_crypto_aead_encrypt_inplace call with a buffer of the given size.
 * 
 * There is no dedicated function to clean up the @ref state, that happens in
 * any function that ends an encryption operation (which is currently only @ref
 * oscore_crypto_aead_encrypt_inplace).
 *
 * Backends that implement streaming algorithms that do not need to know the
 * lengths in advance are free to ignore the provided lengths.
 *
 * @todo Document possible causes of unsuccessful operation in this and the
 * following methods, describe interaction with the state (the erring function
 * must do any cleanup, the caller can't keep using it), and think over whether
 * those may be doable in an infallible way if the oscore_crypto_aeadalg_t
 * construction has succeeded. (There needs to be an out-of-memory or
 * AAD-too-long condition for non-stream-AAD backends, but maybe the rest can
 * be documented to be infallible? What if the caller messes up lengths?)
 */
OSCORE_NONNULL
oscore_cryptoerr_t oscore_crypto_aead_encrypt_start(
        oscore_crypto_aead_encryptstate_t *state,
        oscore_crypto_aeadalg_t alg,
        size_t aad_len,
        size_t plaintext_len,
        const uint8_t *iv,
        const uint8_t *key
        );

/** @brief Provide Additional Authenticated Data (AAD) for an ongoing AEAD encryption operation
 *
 * @param[inout] state Encryption state to update
 * @param[in] aad_chunk Data to be processed as AAD
 * @param[in] aad_chunk_len Length of @param aad
 *
 * This advances the internal @ref state of the encryption by processing the
 * AAD. It may be called as many times with various non-zero lengths as the
 * caller wants, as long as the total number of bytes fed in is the aad_len
 * given in the initial @ref oscore_crypto_aead_encrypt_start call.
 *
 * Implementations of algorithms that do not process AAD byte-by-byte may need
 * to aggregate the AAD data in blocks and keep room for that with the @param
 * state. That case is common.
 *
 * Some backend libraries require the full AAD to be in contiguous memory.
 * Those can dynamically allocate memory at encryption start, or set aside a
 * limited buffer and refuse to operate on overly large AADs. That case is
 * common outside the embedded area where those allocations are affordable;
 * high-quality embedded libraries will make do with a block-sized buffer.
 *
 * Note that the @p state argument is a void pointer. This is necessary to
 * handle feeding into encryption and decryption states (which can be different
 * in some implementations) in an efficient and conformant way. (To the curious
 * reader, yours truly recommends the excellent summary of the situation [by
 * Adam Rosenfield](https://stackoverflow.com/questions/559581/casting-a-function-pointer-to-another-type)
 * about the incompatibility of `void*` and `struct*` pointers, and special
 * consideration for the comparatively exotic compilers in use for constrained
 * devices).
 */
oscore_cryptoerr_t oscore_crypto_aead_encrypt_feed_aad(
        void *state,
        const uint8_t *aad_chunk,
        size_t aad_chunk_len
        );

/** @brief Finish an AEAD encryption operation by encrypting a buffer in place and appending the tag
 *
 * @param[inout] state Encryption state use and finalize
 * @param[inout] buffer Memory location in which the plaintext is encrypted and the tag appended
 * @param[in] buffer_len Writable size of the buffer
 *
 * The @param buffer_len must be exactly the sum of the ``plaintext_len`` given
 * at setup, and the algorithm's tag length; the backends may rely on that. The
 * length is given explicitly to ensure that no writes happen outside the
 * provided buffer in case the involved parties disagree on any of the input
 * values, and to ease static analysis.
 *
 * The function reads the plaintext from @param buffer, writes the resulting
 * ciphertext to the same location, and writes the AEAD tag right after it to
 * the end of the buffer.
 */
OSCORE_NONNULL
oscore_cryptoerr_t oscore_crypto_aead_encrypt_inplace(
        oscore_crypto_aead_encryptstate_t *state,
        uint8_t *buffer,
        size_t buffer_len
        );

/** @brief Start an AEAD decryption operation
 *
 * This is fully analogous to @ref oscore_crypto_aead_encrypt_start; see there.
 *
 */
OSCORE_NONNULL
oscore_cryptoerr_t oscore_crypto_aead_decrypt_start(
        oscore_crypto_aead_decryptstate_t *state,
        oscore_crypto_aeadalg_t alg,
        size_t aad_len,
        size_t plaintext_len,
        const uint8_t *iv,
        const uint8_t *key
        );

/** @brief Provide Additional Authenticated Data (AAD) for an ongoing AEAD decryption operation
 *
 * This is fully analogous to @ref oscore_crypto_aead_decrypt_feed_aad; see there.
 */
oscore_cryptoerr_t oscore_crypto_aead_decrypt_feed_aad(
        void *state,
        const uint8_t *aad_chunk,
        size_t aad_chunk_len
        );

/** @brief Finish an AEAD decryption operation by decrypting a buffer that holds ciphertext followed by tag in place
 *
 * This is largely analogous to @ref oscore_crypto_aead_encrypt_inplace.
 *
 * @param[inout] state Decryption state use and finalize
 * @param[inout] buffer Memory location in which the concatenation of ciphertext and tag is stored, and where the plaintext will be written to
 * @param[in] buffer_len Readable size of the buffer (writes will happen to all places but usually not to the last tag bytes)
 *
 * The @param buffer_len must be exactly the sum of the ``plaintext_len`` given
 * at setup, and the algorithm's tag length; the backends may rely on that. The
 * length is given explicitly to ensure that no reads or writes happen outside
 * the provided buffer in case the involved parties disagree on any of the
 * input values, and to ease static analysis.
 *
 * The function reads the ciphertext and the tag from @param buffer, and writes
 * the resulting plaintext to the same location. Implementations usually leave
 * the tag bytes in place, but may leave them in any state.
 */
OSCORE_NONNULL
oscore_cryptoerr_t oscore_crypto_aead_decrypt_inplace(
        oscore_crypto_aead_decryptstate_t *state,
        uint8_t *buffer,
        size_t buffer_len
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
OSCORE_NONNULL
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
OSCORE_NONNULL
oscore_cryptoerr_t oscore_crypto_hkdf_from_string(oscore_crypto_hkdfalg_t *alg, uint8_t *string, size_t string_len);

// Having info as a buffer is really inconvenient as I'd rather feed that slice
// by slice given it contains potentially long id / id_context. 
//
// running expand and extract independently would be nice as well, given it'd save a hashing step.
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
		);

/** Return true if an error type indicates an unsuccessful operation */
bool oscore_cryptoerr_is_error(oscore_cryptoerr_t);

/** @} */

#endif
