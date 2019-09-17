#ifndef OSCORE_PROTECTION_H
#define OSCORE_PROTECTION_H

#include <stdint.h>

#include <oscore_native/message.h>
#include <oscore/message.h>
#include <oscore/helpers.h>
#include <oscore/contextpair.h>

/** @file */

/** @ingroup oscore_api
 *
 * @addtogroup oscore_protection OSCORE protection API
 *
 * @brief API for creating OSCORE messages from CoAP messages
 *
 * These functions create OSCORE messages (that can be used with the @ref
 * oscore_msg) from native messages (that were used with the @ref
 * oscore_native_msg). On reception, they decrypt the message and make it
 * viewable as a @ref oscore_msg_protected_t; on transmission, the outgoing
 * message buffer is wrapped in a @ref oscore_msg_protected_t so that options
 * can be written to it in the right places, and eventually encrypted before
 * transmission.
 *
 * @{
 */

/** @brief Pre-parsed OSCORE header information
 *
 * This type contains the information extracted from the OSCORE header.
 * Instances may only live as long as the message they belong to does and is
 * not moved in memory.
 *
 * When such a type was created, it was already verified that it is well-formed
 * and contains no unknown extension bits.
 *
 * Currently, it is a simple fat pointer, but that is subject to change as an
 * implementation detail.
 *
 */
typedef struct {
    const uint8_t *option;
    size_t option_length;
} oscore_oscoreoption_t;

/** @brief Parse an OSCORE option
 *
 * This reads a CoAP OSCORE option and creates an @ref oscore_oscoreoption_t
 * from it if it is well-formed and has no unknown or invalid fields.
 *
 * Typically this is used at initial processing of a message when its options
 * are first iterated over, and an OSCORE option is encountered.
 *
 * @param[out] out Uninitialized memory to parse the option into
 * @param[in] input OSCORE option encoded according to OSCORE Header Compression
 * @param[in] input_len Length of the encoded OSCORE option
 * @return true if the option could be parsed entirely.
 */
OSCORE_NONNULL
bool oscore_oscoreoption_parse(oscore_oscoreoption_t *out, const uint8_t *input, size_t input_len);

/** @brief Clone a request @ref oscore_requestid_t
 *
 * @param[out] dest Previously uninitialized memory location of the destination
 * @param[in] src Memory location of a source
 *
 * This copies message correlation data, but sets the new copy's "may reuse the
 * partial IV" flag to false, thus ensuring that at most one response is sent
 * using the client-provided nonce.
 */
OSCORE_NONNULL
void oscore_requestid_clone(oscore_requestid_t *dest, oscore_requestid_t *src);

/** @brief Results of unprotect request operations
 *
 * Users of the library should never check for identity to unsuccessful values,
 * as those may be extended in future to provide better debugging.
 * */
enum oscore_unprotect_request_result {
    /** Unprotection succeeded, and the Partial IV was not seen before */
    OSCORE_UNPROTECT_REQUEST_OK,
    /** Unprotection succeeded, but was a replay (possibly a second
     * transmission, when the underlying CoAP library does not perform
     * deduplication), or it could not be determined whehter it could have been
     * a replay or not. */
    OSCORE_UNPROTECT_REQUEST_DUPLICATE,
    /** Unprotection failed (because the message was tampered with, or
     * decryption was attempted with the wrong security context) */
    OSCORE_UNPROTECT_REQUEST_INVALID
};

/** @brief Request message decryption
 *
 * Unprotect a request message with a given security context.
 *
 * @param[in] protected A received request message
 * @param[out] unprotected A pre-allocated, uninitialized @ref oscore_msg_protected_t that will be made available on success
 * @param[in] header An @ref oscore_oscoreoption_t extracted from `message`
 * @param[inout] secctx The security context with which to decrypt (and by which to validate) the message
 * @param[out] request_id An uninitialized request ID that can later be used to protect the response
 *
 * @return OSCORE_UNPROTECT_REQUEST_OK if decryption and authentication
 * succeeded and the request could be verified and replay protection succeeded,
 * OSCORE_UNPROTECT_REQUEST_DUPLICATE if decryption and authentication
 * succeeded byt the replay protection indicates it could be a replay (or
 * replay protection is not set up correctly yet), and any other if
 * decryption/authentication failed.
 *
 * The OK and DUPLICATE results both count as successful in terms of
 * initialization: A message will be available in `unprotected`, but must only
 * be processed further if it is safe (in the CoAP/REST sense, ie. side effect
 * free; currently that's GET and FETCH requests).
 *
 * @note The result enum is used to reduce the risk of API users inadvertedly
 * processing replays. The information about whether a request was (possibly) a
 * duplicate or not is also encoded in request_id's "is first use" property,
 * but having a dedicated return value forces users to take a conscious
 * decision.
 */
OSCORE_NONNULL
enum oscore_unprotect_request_result oscore_unprotect_request(
        oscore_msg_native_t protected,
        oscore_msg_protected_t *unprotected,
        oscore_oscoreoption_t header,
        oscore_context_t *secctx,
        oscore_requestid_t *request_id
        );

/** @brief Results of unprotect response operations
 *
 * This is different from @ref oscore_unprotect_request_result in that no
 * replay protection is active in response processing, so there is no
 * "_DUPLICATE" outcome.
 *
 * Users of the library should never check for identity to unsuccessful values,
 * as those may be extended in future to provide better debugging.
 * */
enum oscore_unprotect_response_result {
    /** Unprotection succeeded */
    OSCORE_UNPROTECT_RESPONSE_OK,
    /** Unprotection failed (because the message was tampered with, or
     * decryption was attempted with the wrong security context) */
    OSCORE_UNPROTECT_RESPONSE_INVALID
};

/** @brief Response message decryption
 *
 * Unprotect a message with a given security context.
 *
 * @param[in] protected A received message
 * @param[out] unprotected A pre-allocated, uninitialized @ref oscore_msg_protected_t that will be made available on success
 * @param[in] header An @ref oscore_oscoreoption_t extracted from `message`
 * @param[inout] secctx The security context with which to decrypt (and by which to validate) the message
 * @param[in] request_id Matching information from the protect step of the request message.
 *
 * @return OSCORE_UNPROTECT_OK if decryption and authentication succeeded,
 * or any other if decryption/authentication failed.
 *
 */
enum oscore_unprotect_response_result oscore_unprotect_response(
        oscore_msg_native_t protected,
        oscore_msg_protected_t *unprotected,
        oscore_oscoreoption_t header,
        oscore_context_t *secctx,
        oscore_requestid_t *request_id
        );

/** @} */

#endif
