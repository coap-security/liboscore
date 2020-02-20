/** @file
 *
 * Demo application, including plugtest server
 *
 * These files set up a RIOT application that runs both the plugtest server and
 * a few demo resources (</light>, </sensordata>).
 *
 * It uses the RIOT shell for configuration, the small persistens abstraction
 * from persistence.h to store confiugred options, and the
 * intermediate-integration.h mechanisms to dispatch OSCORE requests.
 * Furthermore, it contains commands to send CoAP messages to another
 * endpoint's </light> resource.
 */

#ifndef DEMO_SERVER_H
#define DEMO_SERVER_H

#include <oscore/message.h>
#include "persistence.h"

struct sensordata_blockopt {
    uint32_t num;
    uint8_t szx;
    uint8_t responsecode;
};

void sensordata_parse(oscore_msg_protected_t *in, void *vstate);
void sensordata_build(oscore_msg_protected_t *out, const void *vstate);
void light_parse(oscore_msg_protected_t *in, void *vstate);
void light_build(oscore_msg_protected_t *out, const void *vstate);

extern oscore_context_t secctx_b;
extern mutex_t secctx_b_usage;
extern oscore_context_t secctx_d;
extern mutex_t secctx_d_usage;
extern oscore_context_t secctx_u;
extern mutex_t secctx_u_usage;
extern int16_t secctx_u_change;
extern struct persisted_data *persist;

void userctx_maybe_persist(void);

#endif
