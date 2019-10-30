#ifndef NANOCOAP_OSCORE_NATIVE_MSG_TYPE_H
#define NANOCOAP_OSCORE_NATIVE_MSG_TYPE_H

#include <net/nanocoap.h>

#include <stdbool.h>

/** Note that while a regular coap_pkt_t has its payload marker to the actual
 * payload on receipt and to the option write position on sending, this always
 * has uses the latter behavior.
 *
 * The pointer is wrapped in a struct to denote this difference
 * */
typedef struct {
    /** Pointer to the actual package */
    coap_pkt_t *pkt;
} oscore_msg_native_t;
typedef struct {
    coap_optpos_t pos;
    bool is_first;
} oscore_msg_native_optiter_t;
typedef ssize_t oscore_msgerr_native_t;

#endif
