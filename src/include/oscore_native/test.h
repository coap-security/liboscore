#ifndef OSCORE_NATIVE_TEST_H
#define OSCORE_NATIVE_TEST_H

/** @file */

/**
 * @ingroup oscore_native_api
 * @addtogroup oscore_native_test Native message test API
 *
 * These functions do not need to be implemented by each backend, but are
 * required to run some of the unit test functions and the back-end testing.
 *
 * Unlike the possibly performance critical message functions, this header does
 * not cater for backends that want to implement these functions in a `static
 * inline` fashion; the implementation needs to be linked in.
 *
 * @{
 */

#include <oscore_native/message.h>

/** @brief Allocate an empty ``oscore_msg_native_t``
 *
 * The new message must be empty and may have any code set. It needs to be
 * allocated large enough for the tests to be run. There is no hard boundary
 * for how large that is (if tests fail but allocating more memory makes them
 * work, it wasn't); as a rule of thumb, the tests will not create messages
 * that would not fit into a minimal IPv6 MTU (1280 bytes).
 *
 * The function may return NULL on failure to indicate that no memory could be
 * allocated.
 *
 * Systems without heap memory may have a small pool of messages available for
 * testing; even a size of 1 should allow running most tests.
 */
oscore_msg_native_t oscore_test_msg_create(void);

/** @brief Free a message previously allocated with ``oscore_test_msg_create``
 *
 * The test fixtures will call this on every created message.
 */
void oscore_test_msg_destroy(oscore_msg_native_t msg);

/** @} */

#endif
