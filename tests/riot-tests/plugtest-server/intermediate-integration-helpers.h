#ifndef INTERMEDIATE_INTEGRATION_HELPERS_H
#define INTERMEDIATE_INTEGRATION_HELPERS_H

/** @file
 *
 * @brief Helpers for intermediate-integration.h
 *
 * This file defines types typically needed to describe handlers. Putting them
 * inside intermediate-integration.h would create circular dependencies because
 * intermediate-integrations.h already pulls in those definitions to build the
 * handlerstate union.
 */

/** An observe option "stolen back" from gcoap, stored and passed on to the
 * handler to decide whether to accept the observation. See
 * https://github.com/RIOT-OS/RIOT/issues/12736 */
struct observe_option {
    /** Length of the data. Negative if absent. */
    int8_t length;
    uint8_t data[4];
};

#endif
