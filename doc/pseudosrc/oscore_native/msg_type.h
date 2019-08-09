/** @file */

/** @ingroup oscore_native_types
 *  @addtogroup oscore_native_msg_types Native message types
 *  @{ */

/** @brief Type of native CoAP messages
 *
 * This is usually a pointer type, but can easily be a fat pointer as well
 *
 * It must be defined in the backend's own ``oscore_native/msg_type.h`` file.
 */
typedef void *oscore_msg_native_t;

/** @brief Type of an iterator over a CoAP message's options
 *
 * This is typically a small struct containing pointer offsets; it is only used
 * in conjunction with the same message, and may rely on the message not being
 * modified while that iterator is in use.
 */
typedef struct { uint16_t option_number; size_t offset; } oscore_msg_native_optiter_t;

/** @brief Error type of fallible operations on CoAP messages
 *
 * This error type is returned by operations that can not be guaranteed to
 * succeed, like appending an optionto a CoAP message (which can run out of
 * allocated memory or fail because higher-number options have already been
 * stored in the message).
 *
 * It must be defined in the backend's own ``oscore_native/msg_type.h`` file.
 */
typedef int32_ oscore_msgerr_native_t;

/** @} */
