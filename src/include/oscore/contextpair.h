#ifndef OSCORE_CONTEXTPAIR_H
#define OSCORE_CONTEXTPAIR_H

#include <oscore_native/crypto.h>
#include <oscore/helpers.h>

/** @file */

/** @ingroup oscore_api
 *
 * @addtogroup oscore_contextpair OSCORE security context pairs API
 *
 * @brief API for manipulating security context pairs
 *
 * In this API, security contexts are modelled as pairs of sender and recipient
 * contexts to reduce the number of different objects to which pointers have to
 * be passed around. A @ref oscore_context_t thus describes the whole of a
 * sender and a recipient context (some of which may be shared among contexts
 * in the case of group communication contexts), and accessors functions
 * sometimes take a @ref oscore_context_role discriminator to access a
 * particular aspect.
 *
 * (In some implementations, eg. silent servers in group communication, an
 * aspect can be fully absent from a "pair").
 *
 * @{
 */

/** @brief Disambiguator between the sender and the recipient part of a context pair.
 *
 * Operations on a security context that can work on both aspects (eg. @ref
 * oscore_context_get_kid) take such an argument to know which part they work on.
 *
 */
enum oscore_context_role {
    /** Act on the sender part of the context pair */
    OSCORE_ROLE_SENDER,
    /** Act on the recipient part of the context pair */
    OSCORE_ROLE_RECIPIENT,
};

// FIXME
typedef struct {
    void *dummy;
} oscore_context_t;

oscore_crypto_aeadalg_t oscore_context_get_aeadalg(const oscore_context_t *secctx);

void oscore_context_get_kid(
        const oscore_context_t *secctx,
        enum oscore_context_role role,
        uint8_t **kid,
        size_t *kid_len
        );

const uint8_t *oscore_context_get_commoniv(const oscore_context_t *secctx);
const uint8_t *oscore_context_get_key(
        const oscore_context_t *secctx,
        enum oscore_context_role role
        );

/** @} */

#endif
