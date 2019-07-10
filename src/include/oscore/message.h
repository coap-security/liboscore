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
 * `oscore_native/msg_full.h` file instead.
 *
 * @{
 */

#ifndef OSCORE_MSG_NATIVE_STATIC

#include <stdint.h>

/* This needs to define oscore_msg_native_t and oscore_msg_native_err_t */
#include <oscore_native/msg_type.h>

/** Retrieve the CoAP code (request method or response code) from a message */
uint8_t oscore_msg_native_get_code(oscore_msg_native_t msg);
/** Set the CoAP code (request method or response code) of a message */
void oscore_msg_native_set_code(oscore_msg_native_t msg, uint8_t code);

/** Return true if an error type indicates an unsuccessful operation */
bool oscore_msgerr_native_is_error(oscore_msgerr_native_t);

#else

#include <oscore_native/msg_full.h>

#endif

/** @} */

#endif
