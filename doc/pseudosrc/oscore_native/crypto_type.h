/** @file */

/** @ingroup oscore_native_types
 *  @addtogroup oscore_native_crypto_types Native cryptography types
 *  @{ */

/** @brief Type of COSE AEAD algorithms
 *
 * This can be an enum, an unsigned integer (typically used when
 * string-labelled algorithms are not supported anyway) or even a pointer to a
 * static key description.
 *
 * It must be defined in the backend's own ``oscore_native/crypto_type.h``.
 */
typedef int32_t oscore_crypto_aeadalg_t;

/** @brief State of an ongoing AEAD operation
 *
 * This contains all state that is held in an ongoing AEAD encrypt operation.
 * It is recommended to make this a struct or pointer to a fixed-size
 * allocation that is sufficiently large for all supported ciphers. That helps
 * avoiding unpleasant surprises in low-memory application situations after a
 * cipher suite change.
 *
 * See @ref oscore_crypto_aead_encrypt_start for details and usage.
 */
typedef struct {} oscore_crypto_aead_encryptstate_t;

/** @brief Type of COSE HKDF algorithms
 *
 * This describes a KDF that can be used as HKDF algorithm in an OSCORE
 * Security Context. It corresponds to a COSE "Direct Key with KDF" algorithm,
 * and is constructed from those.
 *
 * This can be an enum, an unsigned integer (typically used when
 * string-labelled algorithms are not supported anyway) or even a pointer to a
 * static key description.
 *
 * It must be defined in the backend's own ``oscore_native/crypto_type.h``.
 */
typedef int32_t oscore_crypto_hkdfalg_t;

/** @brief Error type for cryptography operaitons
 *
 * This error type is returned by operations on the cryptography backend, and
 * usually only evalued using the @ref oscore_cryptoerr_is_error function.
 *
 * It must be defined in the backend's own ``oscore_native/crypto_type.h``.
 */
typedef bool oscore_cryptoerr_t;

/** @} */
