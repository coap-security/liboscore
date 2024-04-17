/** @file
 *
 * Server side of an OSCORE plugtest server
 *
 * See https://github.com/EricssonResearch/OSCOAP for a description of the plug
 * tests executable with this.
 *
 * For setup, this relies on the common setup code in demo.[hc].
 *
 */

#ifndef PLUGTEST_SERVER_H
#define PLUGTEST_SERVER_H

#include <net/gcoap.h>
#include <oscore/message.h>

#include "intermediate-integration-helpers.h"

static const uint8_t ab_master_secret[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
static const uint8_t ab_master_salt[] = {158, 124, 169, 34, 35, 120, 99, 64};

#define D_SENDER_KEY {227, 154, 12, 124, 119, 180, 63, 3, 180, 179, 154, 185, 162, 104, 105, 159}
#define D_RECIPIENT_KEY {175, 42, 19, 0, 165, 233, 87, 136, 179, 86, 51, 110, 238, 205, 43, 146}
#define D_COMMON_IV {44, 165, 143, 184, 95, 241, 184, 28, 11, 113, 129, 184, 94}

ssize_t plugtest_nonoscore_hello(coap_pkt_t *pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx);

struct hello_state {
    bool code_ok;
    bool options_ok;
};

void hello_parse(oscore_msg_protected_t *in, void *vstate);
void hello_build(oscore_msg_protected_t *out, const void *vstate, const struct observe_option *outer_observe);
void observe1_parse(oscore_msg_protected_t *in, void *vstate);
void observe1_build(oscore_msg_protected_t *out, const void *vstate, const struct observe_option *outer_observe);
void hello2_parse(oscore_msg_protected_t *in, void *vstate);
void hello2_build(oscore_msg_protected_t *out, const void *vstate, const struct observe_option *outer_observe);
void hello3_parse(oscore_msg_protected_t *in, void *vstate);
void hello3_build(oscore_msg_protected_t *out, const void *vstate, const struct observe_option *outer_observe);
void hello6_parse(oscore_msg_protected_t *in, void *vstate);
void hello6_build(oscore_msg_protected_t *out, const void *vstate, const struct observe_option *outer_observe);
void hello7_parse(oscore_msg_protected_t *in, void *vstate);
void hello7_build(oscore_msg_protected_t *out, const void *vstate, const struct observe_option *outer_observe);
void delete_parse(oscore_msg_protected_t *in, void *vstate);
void delete_build(oscore_msg_protected_t *out, const void *vstate, const struct observe_option *outer_observe);

#endif
