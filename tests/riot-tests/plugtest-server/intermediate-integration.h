#ifndef INTERMEDIATE_INTEGRATION_H
#define INTERMEDIATE_INTEGRATION_H

/** @file
 *
 * @brief A simple intermediate integration built on Gcoap
 *
 * Components in here implement a simple server-side intermediate integration,
 * that is, they handle the processing of incoming requests towards the Gcoap
 * API, and expect resource handlers to be implemented in a bespoke fashion (by
 * providing a parse and a build function together with a struct to carry over
 * data).
 *
 * It does not aim for generic usability, but can serve as a template for
 * building one. In particular, what would be expected as layering from a
 * generic implementation is violated in places where the completely static
 * security context of a plugtest server needs different treatment than the
 * read-write locked runtime mutable user context needs.
 */

#include <oscore/message.h>
#include <net/gcoap.h>

// Trigger all includes once and then have them not bother us any more when we're in the middle of a struct
#define RESOURCE(name, pathcount, path, handler_parse, handler_build, statetype)
#define PATH(...)
#include "resources.inc"
#undef RESOURCE
#undef PATH

/** Helper function for writing a simple text into a message, and trimming the message. */
bool set_message(oscore_msg_protected_t *out, const char *text);

struct handler {
    void (*parse)(/* not const because of memoization */ oscore_msg_protected_t *in, void *state);
    void (*build)(oscore_msg_protected_t *in, const void *state, const struct observe_option *outer_observe);
};

struct dispatcher_choice {
    /** Number of entries in path */
    size_t path_items;
    /** Path components */
    const char* const *path;
    struct handler handler;
};

struct dispatcher_config {
    /** Paths available to the dispatcher. Must hold several properties:
     * * Paths with shared prefixes must be grouped by prefix
     * * Resources right at a shared prefix path must come first in the list
     * * The strings in the shared prefixes must be pointer-identical
     * * The list must be terminated with an entry that has path_depth 0.
     */
    const struct dispatcher_choice *choices;
    /** Information about the picked choice carried around until it is used to
     * select the builder
     *
     * NULL is sentinel for not found */
    const struct dispatcher_choice *current_choice;
    union {
#define RESOURCE(name, pathcount, path, handler_parse, handler_build, statetype) statetype name;
#define PATH(...)
#include "resources.inc"
#undef RESOURCE
#undef PATH
    } handlerstate;
};

void dispatcher_parse(oscore_msg_protected_t *in, void *vstate);
void dispatcher_build(oscore_msg_protected_t *out, const void *vstate, const struct observe_option *outer_observe);

/** A gcoap handler that dispatches messages through the handlers desribed in
 *  resources.inc. It needs to be registered at the `/` resource, and does not
 *  support forwarding the message to a different handler in case it turns out
 *  not to be an OSCORE message. It does not create an implicit
 *  '/.well-known/core` listing of protected resources.
 *
 *  It considers any available security context sufficient for all operations
 *  on all resources.
 *
 *  The code for selecting a security context is intermingled with the rest of
 *  the processing for the time being; this is primarily due to the complexity
 *  of using an immutable security context (the plugtest's) along with the
 *  mutable user context.
 *
 * */
ssize_t oscore_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx);

#endif
