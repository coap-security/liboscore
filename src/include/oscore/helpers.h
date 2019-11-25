#ifndef OSCORE_HELPERS_H
#define OSCORE_HELPERS_H

#include <stdint.h>
#include <stdbool.h>

/** @file */

/** @ingroup oscore_api
 *
 * @addtogroup oscore_helpers Generic OSCORE helper definitions
 *
 * @brief Data structures commonly used between different OSCORE components
 *
 * This section housed structures that can't reside in @ref oscore_protection
 * or @ref oscore_contextpair because they would create cyclic references
 * there.
 *
 * @{
 */

/** @brief The Partial IV length defined for OSCORE */
#define PIV_BYTES 5

/** @brief Number of bytes in the IV that are not usable for key IDs */
#define IV_KEYID_UNUSABLE (1 + PIV_BYTES)

/** @brief Maximum length of a Key ID
 *
 * This may be lower for particular algorithms (as they need space in their IV
 * length), but this size can be used when storing Key IDs.
 * */
#define OSCORE_KEYID_MAXLEN (OSCORE_CRYPTO_AEAD_IV_MAXLEN - IV_KEYID_UNUSABLE)

/** @brief Maximum lenfgth of a Key ID
 *
 * The length given here limits the length of KID context values that can be
 * processed. It also affects the lengths usable with B.2 negotiation.
 *
 * The value can be overridden at build time by predefining it to a numeric
 * value in the compiler invocation.
 * */
#ifndef OSCORE_KEYIDCONTEXT_MAXLEN
#define OSCORE_KEYIDCONTEXT_MAXLEN 16
#endif

/** @brief Message correlation data
 *
 * This type contains all the information that needs to be kept around to match
 * a request and a response. On the server side, it contains information on
 * whether the request's partial IV can be reused.
 *
 * @warning The Request ID does not keep a reference to the full security
 * context (but to parts of it). It is crucial that all calls in which an @ref
 * oscore_requestid_t is used are always done with the same security context.
 *
 * @warning A @ref oscore_requestid_t must never be copied around by the
 * application. If a copy is needed (eg. to build observation notifications
 * from), use the @ref oscore_requestid_clone function.
 *
 * @todo Decide whether it may be moved (as it may be part of the
 * invalidation-at-context-mutation game).
 */
typedef struct {
    /* it may be a good idea to instead reference the security context, and
     * optionally handle all context locking here and not in the message */

    /** @private The number of bytes in bytes */
    uint8_t used_bytes;
    /** @private The Partial IV, left-padded with zeros. */
    uint8_t bytes[PIV_BYTES];

    /** @private Whether a number was removed from the receive sequence window
     * for this particular IV */
    bool is_first_use;
} oscore_requestid_t;

/** @brief Portability helper for declaring pointers non-null
 *
 * Prefix this to a function signature to declare that none of its pointers
 * may ever be NULL pointers.
 */
#if defined(__GNUC__) || defined(__clang__)
#define OSCORE_NONNULL __attribute__((nonnull))
#else
#define OSCORE_NONNULL
#endif

/** @} */

#endif
