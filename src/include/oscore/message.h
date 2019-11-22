#ifndef OSCORE_MESSAGE_H
#define OSCORE_MESSAGE_H

/** @file */

/** @ingroup oscore_api
 *  @addtogroup oscore_msg OSCORE message API
 *
 *  @brief API for manipulating OSCORE messages
 *
 *  These functions implement the same abstract interface as @ref
 *  oscore_native_msg, but act on encrypted (more precisely: plaintext in
 *  preparation for encryption in place, or plaintext after in-place
 *  decryption) messages.
 *
 *  @note While in the backend interface there is a @ref oscore_msg_native_t
 *  type that is typically some kind of pointer and supplied directly to the
 *  @ref oscore_msg_native_set_code and similar functions, OSCORE's message
 *  type is a large struct and passed into the equivalent @ref
 *  oscore_msg_protected_set_code as a reference. This is because library parts
 *  other than the message API (for example the setup of an encrypted message),
 *  type needs to be allocated on the stack. The message API itself always uses
 *  it via pointers, so if you are looking for a precise equivalent to @ref
 *  oscore_msg_native_t, it's not `oscore_msg_protected_t` but
 *  `&oscore_msg_protected_t`.
 *
 *  @todo Link to "setup of an encrypted message" API
 *
 *  @{
 */

#include <stdint.h>
#include <oscore/helpers.h>
#include <oscore_native/message.h>
#include <oscore/contextpair.h>

/** @brief Tracking helper for CoAP-encoded option sequences
 *
 * This struct is used to keep track of the Class-E options being written
 * inside the plaintext, and can be used for tracking Class-I options as well.
 *
 * @private
 */
struct oscore_opttrack {
    size_t cursor;
    uint16_t option_number;
};

/** @brief Flags used inside OSCORE messages
 *
 * These flags keep some state about a message, especially about which fields
 * are initialized.
 *
 * This enum is used for flag value to be OR-ed together. Valid flag values may
 * be the union of several named enum states.
 *
 * @private
 */
enum oscore_msg_protected_flags {
    /** Empty flag value */
    OSCORE_MSG_PROTECTED_FLAG_NONE = 0,
    /** Message is writable. This means that all its writable-message-only
     * fields are initialized. It also means that the payload marker may not
     * have been set yet, and that the `class_e` member must be used to
     * determine the payload's position. */
    OSCORE_MSG_PROTECTED_FLAG_WRITABLE = 1 << 0,
};

/** @brief OSCORE protected CoAP message
 *
 * @todo This struct may need splitting up according to read/write state
 *
 * This structure represents a CoAP message built ready for in-place
 * encryption, or decrypted in-place. Its outer options are placed as options
 * of its backend. Its code, inner options, payload and padding for the AEAD
 * tag are placed in the backend's payload according to the OSCORE
 * specification.
 */
typedef struct {
    /** @brief Underlying CoAP message
     *
     * @private
     */
    oscore_msg_native_t backend;

    /** @brief Various flags, see @ref oscore_msg_protected_flags */
    enum oscore_msg_protected_flags flags;

    /** @brief Number of bytes at the end of backend's plaintext reserved for the tag
     *
     * This information is not available from the message alone as the message
     * stores no pointer to the context, and thus needs to be replicated here
     * for the message to be usable on its own. While the need to store this
     * information could be circumvented in received messages by truncating
     * them, messages being written require a place to store that datum.
     *
     * @private
     * */
    size_t tag_length;

    /** @brief Start of inner payload
     *
     * If not equal to zero, this gives the index in the backend's payload at
     * which the inner payload starts. (Typically that's the location after the
     * payload marker; when no payload is present, it is equal to the backend's
     * length).
     *
     * (Zero is a valid sentinel value because due to the presence of the inner
     * code, the inner payload can never start at offset 0).
     *
     * In writable messages, it being zero indicates that the inner payload has
     * not been mapped yet (and adding options therefore does not require
     * memmoving the payload, if implemented and enabled). In readable
     * messages, it being zero indicates that the inner options have not been
     * iterated over, and is used to memoize the payload's offset on the first
     * mapping.
     * */
    size_t payload_offset;

    //
    // only used in writable messages
    //

    // FIXME to be replaced by more sophisicaed typing?
    bool is_request;

    /** @brief Security context used for encryption
     *
     * This context pointer is only used for the (yet to be defined, FIXME)
     * constant properties of a security context. Its use does not preclude
     * simultaneous (even non-const) use of the same context for creating new
     * messages from it, but does require its immutable properties to stay
     * constant. (I.e. the context can't just be destroyed and another
     * recreated in its place).
     *
     */
    const oscore_context_t *secctx;

    /** @brief Partial IV assigned to this message
     *
     * This is only fully initialized on messages that can not reuse the
     * request_id.
     *
     * As an extra security against double encryption of a message, the
     * is_first_use flag is set to true in those cases until encryption is
     * performed.
     *
     * @private
     */
    oscore_requestid_t partial_iv;

    /** @brief Identification of the request
     *
     * In requests, this is identical to the partial_iv in its bytes (but not
     * in its is_first_use flag).
     *
     * Its is_first_use flag is set while the request ID can be used as an
     * implicit partial IV in a response, and never in a request.
     *
     * @private
     */
    oscore_requestid_t request_id;

    /** @brief Highest autooption number that has been written
     *
     * @see flush_autooptions_until
     *
     * @note The design of this as "has been written" (as opposed to "has not
     * been written yet") doesn't allow postponing option 0, but allows
     * expressing whether the last option has been written or not; given that
     * neither option is an autooption, this is kind of irrelevant.
     *
     * @private
     */
    uint16_t autooption_written;

    struct oscore_opttrack class_e;
} oscore_msg_protected_t;

/** @brief OSCORE message operation error type
 *
 * These errors are returned by functions manipulating a @ref oscore_msg_protected_t.
 */
typedef enum {
    /** Successful (no error) result */
    OK = 0,
    /** An underlying native CoAP function returned an error */
    NATIVE_ERROR,
    /** An argument passed to the function is invalid */
    INVALID_ARG_ERROR,
    /** The operation is not implemented yet */
    NOTIMPLEMENTED_ERROR,
    /** An inner option encoding was erroneous */
    INVALID_INNER_OPTION,
    /** An inacceptable outer option was erroneous */
    INVALID_OUTER_OPTION,
    /** An added option was out of supported sequence */
    OPTION_SEQUENCE,
    /** An added option is too large */
    OPTION_SIZE,
    /** Insufficient size of the backend message */
    MESSAGESIZE,
} oscore_msgerr_protected_t;

/** @brief Iterator (cursor) over a protected CoAP message
 */
typedef struct {
    uint16_t inner_peeked_optionnumber;
    /** @private
     *
     * @brief Pointer to the next available inner option value
     *
     * If this is NULL, the iterator was either just created, or it has run to
     * exhaustion.
     *
     */
    // FIXME document what's needed from the backends to justify keeping a
    // pointer to repeatedly mapped payloads ("MUST return the same memory area
    // if no writes happen in the meantime", where the presence of our iterator
    // guarantees we don't write ourselves), or just use an offset
    const uint8_t *inner_peeked_value;
    union {
        /** @private
         *
         * @brief Number of bytes available at @ref inner_peeked_value
         *
         * Valid if @ref inner_peeked_value is not NULL.
         *
         */
        size_t inner_peeked_value_len;
        /** @private
         *
         * @brief Reason why iteration was terminated
         *
         * Valid if @ref inner_peeked_value is NULL.
         */
        oscore_msgerr_protected_t inner_termination_reason;
    };

    oscore_msg_native_optiter_t backend;
    bool backend_exhausted;

    uint16_t backend_peeked_optionnumber;
    const uint8_t *backend_peeked_value;
    size_t backend_peeked_value_len;
} oscore_msg_protected_optiter_t;

/** Retrieve the inner CoAP code (request method or response code) from a protected message */
OSCORE_NONNULL
uint8_t oscore_msg_protected_get_code(oscore_msg_protected_t *msg);
/** Set the inner CoAP code (request method or response code) of a protected message */
OSCORE_NONNULL
void oscore_msg_protected_set_code(oscore_msg_protected_t *msg, uint8_t code);

/** @brief Append an option to a protected CoAP message
 *
 * @param[inout] msg Message to append to
 * @param[in] option_number Option number of the new option
 * @param[in] value Bytes to be added in the  new option
 * @param[in] value_len Number of bytes in the new option
 *
 * Depending on the option's protection class (U, I or E), the option is
 * included in the appropriate section of the message.
 *
 * Valid reasons for this to return an unsuccessful response include space
 * inside the message, options being written in the wrong order or payload
 * having been written to the message.
 */
oscore_msgerr_protected_t oscore_msg_protected_append_option(
        oscore_msg_protected_t *msg,
        uint16_t option_number,
        const uint8_t *value,
        size_t value_len
        );

/** @brief Update an single occurrence of an option in a protected CoAP message
 *
 * @param[inout] msg Message to update
 * @param[in] option_number Option number of the new option
 * @param[in] occurrence Index inside the list of options of the same option number to update (starting at zero)
 * @param[in] value Bytes to be added in the  new option
 * @param[in] value_len Number of bytes in the new option
 *
 * This may return unsuccessfully if there was no such option, or if the
 * @p value_len given is not equal to that option's length. Some options
 * require special handling by OSCORE (eg. the observation option) and can not
 * be updated this way.
 */
oscore_msgerr_protected_t oscore_msg_protected_update_option(
        oscore_msg_protected_t *msg,
        uint16_t option_number,
        size_t option_occurrence,
        const uint8_t *value,
        size_t value_len
        );

/** @brief Set up an iterator over a protected CoAP message
 *
 * Set up the previously uninitialized @p iter on which
 * @ref oscore_msg_protected_optiter_next can be called.
 *
 * @param[in] msg Message to iterate over
 * @param[out] iter Caller-allocated (previously unininitialized) iterator
 *     (cursor) to initialize
 *
 * Callers of this function must call @ref oscore_msg_protected_optiter_finish
 * when done (fetching any errors that occurred) and before attempting to alter
 * the message.
 */
OSCORE_NONNULL
void oscore_msg_protected_optiter_init(
        oscore_msg_protected_t *msg,
        oscore_msg_protected_optiter_t *iter
        );

/** @brief Iterate through options of a CoAP protected message
 *
 * @param[in] msg Message to iterate over
 * @param[inout] iter Iterator (cursor) that is read and incremented
 * @param[out] option_number Number of the read CoAP option
 * @param[out] value Data inside the read CoAP option
 * @param[out] value_len Number of bytes inside the read CoAP option
 *
 * If there is a next option to be read in the message, set @p value, @p
 * value_len and @p option_number to that option's data and return true.
 *
 * If the iterator has been exhausted or failed, return false.
 */
OSCORE_NONNULL
bool oscore_msg_protected_optiter_next(
        oscore_msg_protected_t *msg,
        oscore_msg_protected_optiter_t *iter,
        uint16_t *option_number,
        const uint8_t **value,
        size_t *value_len
        );

/** @brief Clean up an option iterator
 *
 * Close the iterator previously created by @ref oscore_msg_protected_optiter_init.
 *
 * @param[in] msg Message that was being iterated over
 * @param[inout] iter Iterator (cursor) that will not be used any more after
 *     this invocation
 *
 * If any errors were encountered during the iteration, they are returned from
 * this function. That is to keep the iteration loop simple, and to have a
 * clear place to handle clean-up. Errors can be encountered when inner options
 * are encoded invalidly, or when critical Class E options are present in the
 * outer options.
 */
OSCORE_NONNULL
oscore_msgerr_protected_t oscore_msg_protected_optiter_finish(
        oscore_msg_protected_t *msg,
        oscore_msg_protected_optiter_t *iter
        );

/** @brief Provide address and size information to writable payload
 *
 * @param[inout] msg Message whose payload is accessed
 * @param[out] payload Address where message payload can be written to
 * @param[out] payload_len Size of writable payload
 *
 * This modifies the message as it ends the possibility of adding options.
 *
 * This function can fail if the encoding of the inner options is erroneous (as
 * their encoding is not checked at decryption time). It will not fail if the
 * options have been iterated over successfully.
 *
 * It could be argued that this can be made infallible and could return
 * arbitrary zero-length memory as the semantics of the payload can't be
 * comprehended exhaustively having gone through the options. Given that this
 * has little cost and large benefits in debugging, this function is allowed an
 * error code.
 */
OSCORE_NONNULL
oscore_msgerr_protected_t oscore_msg_protected_map_payload(
        oscore_msg_protected_t *msg,
        uint8_t **payload,
        size_t *payload_len
        );

/** @brief Shorten the payload to a given length
 *
 * @param[inout] msg Message whose payload is accessed
 * @param[in] payload_len Size of writable payload
 *
 * Reduce the payload length of the message to the given size. This must only
 * be called after @ref oscore_msg_protected_map_payload invocations, and the
 * given size must be at most the @p payload_len obtained in that call.
 */
OSCORE_NONNULL
oscore_msgerr_protected_t oscore_msg_protected_trim_payload(
        oscore_msg_protected_t *msg,
        size_t payload_len
        );

/** Return true if an error type indicates an unsuccessful operation */
bool oscore_msgerr_protected_is_error(oscore_msgerr_protected_t);

/** @} */

#endif
