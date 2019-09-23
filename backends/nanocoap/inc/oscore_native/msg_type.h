#ifndef NANOCOAP_OSCORE_NATIVE_MSG_TYPE_H
#define NANOCOAP_OSCORE_NATIVE_MSG_TYPE_H

#include <net/nanocoap.h>

#include <stdbool.h>

typedef coap_pkt_t *oscore_msg_native_t;
typedef struct {
    coap_optpos_t pos;
    bool is_first;
} oscore_msg_native_optiter_t;
typedef ssize_t oscore_msgerr_native_t;

#endif
