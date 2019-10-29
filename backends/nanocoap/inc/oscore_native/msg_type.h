#ifndef NANOCOAP_OSCORE_NATIVE_MSG_TYPE_H
#define NANOCOAP_OSCORE_NATIVE_MSG_TYPE_H

#include <net/nanocoap.h>

#include <stdbool.h>

typedef struct {
    /** Pointer to the actual package */
    coap_pkt_t *pkt;
    /** Set to true if pkt->payload{,_length} reflects the actual payload (as
     * it does in a received message), and to false if reflects the writable
     * portion of the message (as it does in a being-constructed message) */
    bool payload_is_real;
} oscore_msg_native_t;
typedef struct {
    coap_optpos_t pos;
    bool is_first;
} oscore_msg_native_optiter_t;
typedef ssize_t oscore_msgerr_native_t;

#endif
