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

#define D_SENDER_KEY {79, 177, 204, 118, 107, 180, 59, 3, 14, 118, 123, 233, 14, 12, 59, 241, 144, 219, 242, 68, 113, 65, 139, 251, 152, 212, 46, 145, 230, 180, 76, 252}
#define D_RECIPIENT_KEY {173, 139, 170, 28, 148, 232, 23, 226, 149, 11, 247, 99, 61, 79, 20, 148, 10, 6, 12, 149, 135, 5, 18, 168, 164, 11, 216, 42, 13, 221, 69, 39}
#define D_COMMON_IV {199, 178, 145, 95, 47, 133, 49, 117, 132, 37, 73, 212}

ssize_t plugtest_nonoscore_hello(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx);

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
