#include <stdbool.h>
#include <oscore/context_impl/primitive.h>
#include <net/gcoap.h>

/**
 * @file
 *
 * This is a simple ad-hoc flash memory backing for the data the demo
 * application needs to persist in order to be runnable without a computer
 * attached to it.
 *
 * The underlying flash mechanism is crude in that it mirrors the complete
 * flash area in RAM, always writes a full black to flash, uses duplication
 * rather than checksumming and can not recover from a write that is aborted by
 * loss of power during @ref persistence_commit call (resulting in loss of the
 * security context).
 *
 * None of these properties are desirable for a real-world application, but as
 * RIOT lacks a generic journaling configuration storage mechanism, actual
 * applications will have their own mechanisms for commissioning and
 * configuration anyway, which can then provide more elaborate persistence.
 */

/** Application-specific data that needs to persist through reboots */
struct persisted_data {
    /** IP, zone and port to send on/off commands to */
    sock_udp_ep_t target;
    /** Security context details of the user context as set up from the cmomand line  */
    struct oscore_context_primitive_immutables key;
    /** @p key contains usable material */
    bool key_good;
    /** Last value passwd to @ref oscore_context_b1_allow_high */
    uint64_t stored_sequence_number;
};

/** Configure an indefinitely read- and writable memory that can be persisted
 * later as well.
 *
 * If this returns true, data in it is actually valid (ie. was previously
 * written like that). */
bool persistence_init(struct persisted_data **data);

/** Write the memory area previously returned by persistence_init to flash.
 * Only returns on success. */
void persistence_commit(void);
