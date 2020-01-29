#ifndef OSCORE_CONTEXT_B1_H
#define OSCORE_CONTEXT_B1_H

#include <oscore/context_impl/primitive.h>

/** @file */

/** @ingroup oscore_contextpair
 *
 * @addtogroup oscore_context_b1 Security context with Appendix B.1 recovery
 *
 * @brief A pre-derived context implementation that occasionally needs to be persisted
 *
 * This security context contains a @ref oscore_context_primitive, along with
 * additional indicators for the mechanisms described in [Appendix B.1 of
 * RFC8613](https://tools.ietf.org/html/rfc8613#appendix-B.1).
 *
 * There are aspects to its use:
 *
 * * Peristence: Two aspects of the context can be persisted, the sequence
 *   number and the replay window. Persisting the sequence number is mandatory,
 *   the replay window optional. (Persisting spares a round trip during the
 *   first request to the server from that given security context).
 *
 *   * Sequence number persistence
 *
 *     * When a context is created, the application needs to provide the last
 *       persisted sequence number in a @ref oscore_context_b1_initialize call.
 *
 *     * After that, and repeatedly later on, the application should query the
 *       next sequence number to persist using the
 *       @ref oscore_context_b1_get_wanted call.  When it has persisted that
 *       number, it uses @ref oscore_context_b1_allow_high call to inform the
 *       context
 *       that that sequence number has been persisted.
 *
 *       Failure to do this often or fast enough results in temporary errors
 *       when sending messages, but does not endanger security. (In particular,
 *       no own messages can be sent until @ref oscore_context_b1_allow_high
 *       has been called).
 *
 *       Once @ref oscore_context_b1_allow_high has been called, @ref
 *       oscore_context_b1_initialize must not be called in subsequent
 *       startups with any value of @ref oscore_context_b1_allow_high from
 *       earlier calls.  This is crucial for security; failure to do this
 *       correctly typically results in nonce reuse and subsequent breach of
 *       the key.
 *
 *       A method to extract and persist the current sequence number at
 *       shutdown (in analogy to the below) would be possible (mostly the
 *       documentation would become more verbose), but is currently not
 *       implemented as the ill-effect of not recovering a precise sequence
 *       number is just the loss of some sequence number space, and not an
 *       additional round-trip.
 *
 *   * Replay window persistence (optional)
 *
 *     An application can use the @ref oscore_context_b1_replay_extract
 *     function to extract the 9 byte necessary to express the replay window
 *     state. After that call, it must not use the security context any more --
 *     this is typically done at a controlled device shutdown, or when entering
 *     a deep sleep state in which the security context's data is lost.
 *
 *     It can then use that persisted replay window state once (!) at the next
 *     startup using @ref oscore_context_b1_initialize. The data must be
 *     removed (or marked as deleted) in the persistent storage before that
 *     function is called.  Failure to do so affects security with the same
 *     results as above.
 *
 *     On startups that were not immediately preceded by an extraction, no
 *     replay window is reinjected. That is fine, and only results in an
 *     additional roundtrip for the first exchange message.
 *
 * * Application integration: libOSCORE can not manage the additional exchanges
 *   for replay window recovery on its own, as that would include sending
 *   messages on its own. It does, however, assist the application author in
 *   sending the right messages:
 *
 *   * A server whose replay window was not initialized will report the first
 *     received message as @ref OSCORE_UNPROTECT_REQUEST_DUPLICATE. Rather than
 *     erring out with an unprotected 4.01 Unauthorized message, the server can
 *     use @ref @@@_build_401echo to create a suitable response (which is a
 *     protected 4.01 with Echo option).
 *
 *     Alternatively, it may build its own response (which may be a 4.01, or
 *     even an actual result in case of safe requests) and include the echo
 *     value reported by @ref @@@_get_echo in it.
 *
 *   * A client that receives a 4.01 response with an Echo option needs to
 *     resubmit the request, and use any Echo value found in the response in
 *     its next request.
 *
 *     Providing additional helpers here is [being considered](https://gitlab.com/oscore/liboscore/issues/47),
 *     and would profit from user feedback.
 *
 *   Some steps are automated inside libOSCORE and do not need assistance from
 *   the application: When a replay window needs initialization, incoming
 *   messages are scanned for their Echo value. On a match, the replay window
 *   is initialized and the unprotect operation declared @ref
 *   OSCORE_UNPROTECT_REQUEST_OK (ie. not a duplicate).
 *
 * @{
 */

/** @brief Data for a security context that can perform B.1 recovery
 *
 * This must always be initialized using @ref oscore_context_b1_initialize.
 * (It will stay practically unusable until @ref oscore_context_b1_allow_high
 * has been called as well, but until then the context is technically
 * initialized, it's just that most operations will fail).
 * */
struct oscore_context_b1 {
    /** @brief Underlying primitive context.
     *
     * Having this as an inlined first struct member means that contextpair.h
     * cases that access a primitive context directly or through a B.1 context
     * may have different code, but can be collapsed by the compiler as both
     * access a primitive context directly behind the data pointer.
     * */
    struct oscore_context_primitive primitive;
    /** @private
     *
     * @brief Upper limit to sequence numbers
     *
     * The security context will not deal out any sequence numbers equal or
     * above this value.
     */
    uint64_t high_sequence_number;
    /** @private
     *
     * @brief Echo value to send out and recognize
     *
     * This is initialized to the current sequence number when first used --
     * which is != 0 because it's first used when a response is formed, and if
     * it needs to be used then that response already pulled out a sequence
     * number.
     */
    uint64_t echo_value;
};

/** @brief Persistable replay data of a B.1 context
 *
 * Such a datum can be extracted at shutdown using @ref
 * oscore_context_b1_replay_extract and used in @ref
 * oscore_context_b1_initialize once. Between those, it can be persisted in
 * arbitrary form.
 * */
struct oscore_context_b1_replaydata {
    uint64_t left_edge;
    uint32_t window;
};

/** @brief Initialize a B.1 context
 *
 * This is the way to initialize a @ref oscore_context_b1 struct. As a
 * precondition, all the key properties have to be set in the context's
 * primitive part; replay window and sequence number could be left
 * uninitialized there.
 *
 * @param[inout] secctx B.1 security context to initialize; must not be NULL,
 *     and must be partially initialized.
 * @param[in] seqno The last (and highest) value that was ever passed to a @ref
 *     oscore_context_b1_allow_high call to this context, or 0 for brand-new
 *     contexts.
 * @param[in] replaydata A struct previously obtained using
 *     @ref oscore_context_b1_replay_extract. Before this function is called,
 *     it must be ensuered that the same replaydata will not be passed in here
 *     again. Alternatively (ie. if replay extraction is not used, or if the
 *     extracted data has been removed before new one was extracted and
 *     persisted), NULL may be passed to start the Appendix B.1.2 recovery
 *     process.
 *
 */
void oscore_context_b1_initialize(
        struct oscore_context_b1 *secctx,
        uint64_t seqno,
        const struct oscore_context_b1_replaydata *replaydata
        );

/** @brief State to a B.1 context that sequence numbers up to excluding @p
 * seqno may be used freely
 *
 * This must be called before using the security context, and may be called at
 * any later time with any value equal to or larger than the previous value
 * passed with the same function. A convenient way to come up with such values
 * that do not change too frequently is using
 * @ref oscore_context_b1_get_wanted.
 *
 * This must only be called when it can be guaranteed that later calls to @ref
 * oscore_context_b1_initialize will not give any value persisted earlier than
 * @p seqno.
 *
 * @param[inout] secctx B.1 security context to update
 * @param[in] seqno The persistent sequence number limit
 *
 */
OSCORE_NONNULL
void oscore_context_b1_allow_high(
        struct oscore_context_b1 *secctx,
        uint64_t seqno
        );

/*** @brief The next sequence number a B.1 context wants to be allowed to use
 *
 * @param[in] secctx B.1 security context to query
 *
 * @return the sequence number that should be used on the next @ref
 * oscore_context_b1_allow_high call
 *
 * Note that this is a plain convenience function that implements static
 * increments of a default size, which are stepped whenever the previous
 * allocation is half used up. Applications are free to come up with their own
 * numbers based on predicted traffic, as long as the constraints of @ref
 * oscore_context_b1_allow_high are met.
 *
 */
OSCORE_NONNULL
uint64_t oscore_context_b1_get_wanted(
        struct oscore_context_b1 *secctx
        );

/** @} */

/** @brief Take the replay data of a security context for persistence
 *
 * @param[inout] secctx B.1 security context to shut down. This is marked inout
 *     as the security context is uninitialized after this.
 * @param[out] replaydata Location into which to move the replay window data.
 *
 * This function can be used during shutdown to take the security context's
 * replay window and make it available for the next startup.
 *
 * After calling this function, the security context must not be used any more;
 * instead, the same context can later be initialized using the extracted
 * replaydata in @ref oscore_context_b1_initialize.
 *
 */
OSCORE_NONNULL
void oscore_context_b1_replay_extract(
    struct oscore_context_b1 *secctx,
    struct oscore_context_b1_replaydata *replaydata
    );

#endif
