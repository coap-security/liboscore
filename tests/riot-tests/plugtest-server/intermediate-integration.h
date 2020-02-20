#include <oscore/message.h>
#include <net/gcoap.h>

// Trigger all includes once and then have them not bother us any more when we're in the middle of a struct
#define RESOURCE(name, pathcount, path, handler_parse, handler_build, statetype)
#define PATH(...)
#include "resources.inc"
#undef RESOURCE
#undef PATH

bool set_message(oscore_msg_protected_t *out, const char *text);

struct handler {
    void (*parse)(/* not const because of memoization */ oscore_msg_protected_t *in, void *state);
    void (*build)(oscore_msg_protected_t *in, const void *state);
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
void dispatcher_build(oscore_msg_protected_t *out, const void *vstate);

ssize_t _oscore(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx);
