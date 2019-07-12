/** @file */

/** @ingroup oscore_native_types
 *  @addtogroup oscore_native_crypto_types Native cryptography types
 *  @{ */

/** @brief Type of COSE algorithms
 *
 * This can be an enum, an unsigned integer (typically used when
 * string-labelled algorithms are not supported anyway) or even a pointer type.
 *
 * It must be defined in the backend's own ``oscore_native/crypto_type.h``.
 */
typedef int32_t oscore_crypto_cosealg_t;

/** @brief Error type for cryptography operaitons
 *
 * This error type is returned by operations on the cryptography backend, and
 * usually only evalued using the @ref oscore_cryptoerr_is_error function.
 *
 * It must be defined in the backend's own ``oscore_native/crypto_type.h``.
 */
typedef bool oscore_cryptoerr_t;

/** @} */
