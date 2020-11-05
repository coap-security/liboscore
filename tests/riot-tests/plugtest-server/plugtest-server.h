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

#define B_SENDER_KEY {50, 136, 42, 28, 97, 144, 48, 132, 56, 236, 152, 230, 169, 50, 240, 32, 112, 143, 55, 57, 223, 228, 109, 119, 152, 155, 3, 155, 31, 252, 28, 172}
#define B_RECIPIENT_KEY {213, 48, 30, 177, 141, 6, 120, 73, 149, 8, 147, 186, 42, 200, 145, 65, 124, 137, 174, 9, 223, 74, 56, 85, 170, 0, 10, 201, 255, 243, 135, 81}
#define B_COMMON_IV {100, 240, 189, 49, 77, 75, 224, 60, 39, 12, 43, 28}


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
