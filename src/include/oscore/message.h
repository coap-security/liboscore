#ifndef OSCORE_MESSAGE_H
#define OSCORE_MESSAGE_H

/** @file */

/** @ingroup oscore_native_api
 *  @addtogroup oscore_native_msg Native message API
 *
 * @brief API which any native CoAP library provides for OSCORE to manipulate
 * its messages
 *
 * Apart from implementing the below functions and making them available
 * through the linker, the backend needs to define the @group
 * oscore_native_msg_types types in its `oscore_native/msg_type.h` header file.
 *
 * If the implementer desires to implement oscore_msg_native functions as
 * static inline functions or even macros, it can set the
 * OSCORE_MSG_NATIVE_STATIC define and provide an equivalent definitions in an
 * `oscore_native/msg_full.h` file instead. That usage pattern is not
 * recommended; instead, link time optimization or similar should be used.
 *
 * @{
 */

#ifndef OSCORE_MSG_NATIVE_STATIC

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* This needs to define oscore_msg_native_t and oscore_msg_native_err_t */
#include <oscore_native/msg_type.h>

/** Retrieve the CoAP code (request method or response code) from a message */
uint8_t oscore_msg_native_get_code(oscore_msg_native_t msg);
/** Set the CoAP code (request method or response code) of a message */
void oscore_msg_native_set_code(oscore_msg_native_t msg, uint8_t code);

/** @brief Append an option to a CoAP message
 *
 * @param[inout] msg Message to append to
 * @param[in] option_number Option number of the new option
 * @param[in] value Bytes to be added in the  new option
 * @param[in] value_len Number of bytes in the new option
 *
 * Valid reasons for this to return an unsuccessful response include space
 * inside the message, options being written in the wrong order or the native
 * library's inability to add options after the payload has been accessed.
 */
oscore_msgerr_native_t oscore_msg_native_append_option(
        oscore_msg_native_t msg,
        uint16_t option_number,
        const uint8_t *value,
        size_t value_len
        );

/** @brief Update an single occurrence of an option in a CoAP message
 *
 * @param[inout] msg Message to update
 * @param[in] option_number Option number of the new option
 * @param[in] occurrence Index inside the list of options of the same option number to update (starting at zero)
 * @param[in] value Bytes to be added in the  new option
 * @param[in] value_len Number of bytes in the new option
 *
 * This may return unsuccessfully if there was no such option, or if the
 * @p value_len given is not equal to that option's length.
 */
oscore_msgerr_native_t oscore_msg_native_update_option(
        oscore_msg_native_t msg,
        uint16_t option_number,
        size_t option_occurrence,
        const uint8_t *value,
        size_t value_len
        );

/** @brief Set up an iterator over a CoAP message
 *
 * Set up the previously uninitialized @p iter on which
 * ``oscore_msg_native_optiter_next`` can be called.
 *
 * @param[in] msg Message to iterate over
 * @param[out] iter Caller-allocated (previously unininitialized) iterator
 *     (cursor) to initialize
 *
 * Callers of this function must call @ref oscore_msg_native_optiter_finish
 * when done and before attempting to alter the message.
 */
void oscore_msg_native_optiter_init(oscore_msg_native_t msg,
        oscore_msg_native_optiter_t *iter
        );

/** @brief Iterate through options of a CoAP message
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
 * If the iterator has been exhausted, return false; the iterator will then not
 * be called again.
 *
 * Native CoAP implementations that store options in their semantic form
 * internally (eg. options of type uint as uint32_t) may need to have a buffer
 * available inside the iterator into which that value gets serialized for the
 * duration of an iteration step. That overhead is considered acceptable here
 * as serialized storage of options is predominant in embedded libraries in
 * cases where an OSCORE library is useful.
 */
bool oscore_msg_native_optiter_next(
        oscore_msg_native_t msg,
        oscore_msg_native_optiter_t *iter,
        uint16_t *option_number,
        uint8_t *const *value,
        size_t *value_len
        );

/** @brief Clean up an option iterator
 *
 * Close the iterator previously created by @ref oscore_msg_native_optiter_init.
 *
 * @param[in] msg Message that was being iterated over
 * @param[inout] iter Iterator (cursor) that will not be used any more after
 *     this invocation
 *
 * Implementations will typically implement a no-op here if all the iterator
 * contains is pointers into the message. They need to take action here if they
 * use any form of read/write locking that prevents writes to a message while
 * it is being iterated over.
 */
void oscore_msg_native_optiter_finish(
        oscore_msg_native_t msg,
        oscore_msg_native_optiter_t *iter
        );

/** @brief Provide address and size information to writable payload
 *
 * @param[inout] msg Message whose payload is accessed
 * @param[out] payload Address where message payload can be written to
 * @param[out] payload_len Size of writable payload
 *
 * This may modify the message, as a message can keep track of whether its
 * payload has been written or not.
 *
 * This function can not fail, but it can return a zero length payload
 * indicating that there is insufficient remaining space in the allocated
 * message to send any non-zero payload.
 */
void oscore_msg_native_map_payload(
        oscore_msg_native_t msg,
        uint8_t **payload,
        size_t *payload_len
        );

/** @brief Shorten the payload to a given length
 *
 * @param[inout] msg Message whose payload is accessed
 * @param[in] payload_len Size of writable payload
 *
 * Reduce the payload length of the message to the given size. This must only
 * be called after @ref oscore_msg_native_map_payload invocations, and the
 * given size must be at most the @p payload_len obtained in that call.
 */
oscore_msgerr_native_t oscore_msg_native_trim_payload(
        oscore_msg_native_t msg,
        size_t payload_len
        );

/** Return true if an error type indicates an unsuccessful operation */
bool oscore_msgerr_native_is_error(oscore_msgerr_native_t);

#else

#include <oscore_native/msg_full.h>

#endif

/** @} */

#endif
