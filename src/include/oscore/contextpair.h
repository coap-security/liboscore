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

enum oscore_context_type {
    /** A simple, RAM-only, fully pre-derived security context */
    OSCORE_CONTEXT_PRIMITIVE,
};

// FIXME
typedef struct {
    enum oscore_context_type type;
    void *data;
} oscore_context_t;

/** @brief Determine whether a request is a replay, and strike it out of the replay window
 *
 * @param[inout] secctx Security context pair in which @p request_id is used
 * @param[input] request_id Request ID whose partial IV (and thus sequence number) to verify
 *
 * This function looks up whether the sequence number represented by @p
 * request_id was used before. If it was, or if it could not be determined
 * whether it was, its is_first_use bit is set to false. If this is a confirmed
 * first use of the sequence number, it is struck out of the replay window, and
 * the bit is set to true.
 */
OSCORE_NONNULL
void oscore_context_strikeout_requestid(
        oscore_context_t *secctx,
        oscore_requestid_t *request_id);

oscore_crypto_aeadalg_t oscore_context_get_aeadalg(const oscore_context_t *secctx);

OSCORE_NONNULL
void oscore_context_get_kid(
        const oscore_context_t *secctx,
        enum oscore_context_role role,
        uint8_t **kid,
        size_t *kid_len
        );

OSCORE_NONNULL
const uint8_t *oscore_context_get_commoniv(const oscore_context_t *secctx);

OSCORE_NONNULL
const uint8_t *oscore_context_get_key(
        const oscore_context_t *secctx,
        enum oscore_context_role role
        );

/** @} */

#endif
