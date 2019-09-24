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

/** @brief OSCORE protected CoAP message
 *
 * @todo This struct may need splitting up according to read/write state
 */
typedef struct {
    oscore_msg_native_t backend;
    /** @brief Number of bytes at the end of backend's plaintext reserved for the tag
     *
     * This information is not available from the message alone as the message
     * stores no pointer to the context, and thus needs to be replicated here
     * for the message to be usable on its own. While the need to store this
     * information could be circumvented in received messages by truncating
     * them, messages being written require a place to store that datum.
     * */
    size_t tag_length;

    void *aad_state; // Only for writing
    uint16_t last_e_option; // Only for writing messages (otherwise it's in the iterator)
    uint16_t last_i_option; // like last_e_option
    uint16_t last_u_option; // like last_e_option
    uint8_t code; // Probably only for writing messages
    bool is_request; // May move into type state (as this'll need splitting up by read/write anyway)
    bool is_observation; // not sure yet when applicable
} oscore_msg_protected_t;

/** @brief Iterator (cursor) over a protected CoAP message
 */
typedef struct {
    uint16_t inner_peeked_optionnumber;
    const uint8_t *inner_peeked_value;
    size_t inner_peeked_value_len;
    oscore_msg_native_optiter_t backend;
    bool backend_exhausted;
    uint16_t backend_peeked_optionnumber;
    const uint8_t *backend_peeked_value;
    size_t backend_peeked_value_len;
} oscore_msg_protected_optiter_t;

/** @brief OSCORE message operation error type
 *
 * These errors are returned by functions manipulating a @ref oscore_msg_protected_t.
 */
typedef enum {
    /** Successful (no error) result */
    OK = 0,
    /** An underlying native CoAP function returned an error */
    NATIVE_ERROR,
} oscore_msgerr_protected_t;

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
 * when done and before attempting to alter the message.
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
 * If the iterator has been exhausted, return false.
 */
OSCORE_NONNULL
bool oscore_msg_protected_optiter_next(
        oscore_msg_protected_t msg,
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
 */
OSCORE_NONNULL
void oscore_msg_protected_optiter_finish(
        oscore_msg_protected_t msg,
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
 * This function can not fail, but it can return a zero length payload
 * indicating that there is insufficient remaining space in the allocated
 * message to send any non-zero payload.
 */
OSCORE_NONNULL
void oscore_msg_protected_map_payload(
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
