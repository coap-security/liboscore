/** Type of native CoAP messages
 *
 * This is usually a pointer type, but can easily be a fat pointer as well.
 */
typedef (void *) oscore_msg_native_t;

/** Error type of fallible operations on CoAP messages
 *
 * This error type is returned by operations that can not be guaranteed to
 * succeed, like appending an optionto a CoAP message (which can run out of
 * allocated memory or fail because higher-number options have already been
 * stored in the message).
 */
typedef i32 oscore_msgerr_native_t;
