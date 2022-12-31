#include <periph/gpio.h>
#include <thread.h>
#include <oscore_native/message.h>
#include <oscore/contextpair.h>
#include <oscore/context_impl/primitive.h>
#include <oscore/context_impl/b1.h>
#include <oscore/protection.h>

#include <nanocoap_oscore_msg_conversion.h>

#include "plugtest-server.h"
#include "persistence.h"
#include "intermediate-integration.h"
#include "demo-server.h"

struct persisted_data *persist;

// Having _b and _d static is OK here because the gcoap thread will only process messages one at a time.
//
// They could be const if it were not for aeadalg that is set by the oscore_crypto_aead_from_number function.
// (In practical applications that's less of an issue, because *if* the whole primitive key is placed in flash memory at build time, the backend is usually known well enough to also have a known value here, whereas this demo expects to run on any backend)
//
// Context B: as specified in plug test description; to show how thigns can be used, this is not static but populated by a key derivation.
static struct oscore_context_primitive_immutables immutables_b = {
    .recipient_id_len = 0,
    .sender_id_len = 1,
    .sender_id = "\x01",
};
static struct oscore_context_primitive primitive_b = { .immutables = &immutables_b };
oscore_context_t secctx_b = {
    .type = OSCORE_CONTEXT_PRIMITIVE,
    .data = (void*)(&primitive_b),
};
mutex_t secctx_b_usage = MUTEX_INIT;

// Context D: as specified in plug test description (see B); to show how things can be used, this *is* static.
static struct oscore_context_primitive_immutables immutables_d = {
    .common_iv = D_COMMON_IV,

    .recipient_id_len = 0,
    .recipient_key = D_RECIPIENT_KEY,

    .sender_id_len = 1,
    .sender_id = "\x01",
    .sender_key = D_SENDER_KEY,
};
static struct oscore_context_primitive primitive_d = { .immutables = &immutables_d };
oscore_context_t secctx_d = {
    .type = OSCORE_CONTEXT_PRIMITIVE,
    .data = (void*)(&primitive_d),
};
mutex_t secctx_d_usage = MUTEX_INIT;

// User context: configurable from command-line, used in outgoing requests and also available at the server
static struct oscore_context_b1 context_u;
oscore_context_t secctx_u = {
    .type = OSCORE_CONTEXT_B1,
    .data = (void*)(&context_u),
};
mutex_t secctx_u_usage = MUTEX_INIT;
int16_t secctx_u_change = 0; // RW lock count, only to be changed while secctx_u_usage is kept. The variable keeps track of the number of readers (readers in RW-lock terminology; here it's "request_id objects out there"). A writer may change the context as a whole while keeping secctx_u_usage locked and secctx_u_change is 0.
uint8_t ctx_u_received_echo_data[32];
ssize_t ctx_u_received_echo_size = -1;

static uint64_t userctx_last_persisted;

/** Will be the demo application */

#include <led.h>

static bool ledstate = false;

void light_parse(oscore_msg_protected_t *in, void *vstate)
{
    uint16_t *responsecode = vstate;

    // This application is sloppily ignoring any set critical options, as well
    // as Content-Format and that like. A diligent application would go through
    // the options if those checks are not provided by the framework. As this
    // is both a demo of a simple framework (the minimal intermediate
    // integration) and a simple application (the blinking demo), those checks
    // are ignored.

    switch (oscore_msg_protected_get_code(in)) {
        case 1 /* GET */:
            *responsecode = 0x45 /* 2.05 Content */;
            break;
        case 3 /* PUT */:
            {
            uint8_t *payload;
            size_t payload_length;
            oscore_msgerr_protected_t err = oscore_msg_protected_map_payload(in, &payload, &payload_length);
            if (oscore_msgerr_protected_is_error(err)) {
                *responsecode = 0x80 /* 4.00 Bad Request */; // probably an option encoding error
                return;
            }
            if (payload_length == 2 && payload[1] == '\n') {
                // Allow trailing newline
                payload_length --;
            }
            if (payload_length == 1 && '0' <= payload[0] && payload[0] <= '1') {
                if (payload[0] == '1') {
                    LED_ON(0);
                    printf("LED switched to ON\n");
                    ledstate = true;
                } else {
                    LED_OFF(0);
                    printf("LED switched to OFF\n");
                    ledstate = false;
                }
                *responsecode = 0x44 /* 2.04 Changed */;
            } else {
                *responsecode = 0x80 /* 4.00 Bad Request */; // application level bad request
            }
            }
            break;
        default:
            *responsecode = 0x85 /* 4.05 Method Not Allowed */;
            break;
    }
}

void light_build(oscore_msg_protected_t *out, const void *vstate, const struct observe_option *outer_observe)
{
    (void)outer_observe;
    const uint16_t *responsecode = vstate;

    oscore_msg_protected_set_code(out, *responsecode);

    if (*responsecode == 0x45 /* 2.05 Content */) {
        uint8_t *payload;
        size_t payload_length;
        oscore_msgerr_protected_t err = oscore_msg_protected_map_payload(out, &payload, &payload_length);
        if (oscore_msgerr_protected_is_error(err)) {
            oscore_msg_protected_set_code(out, 0xa0 /* 5.00 Internal Error */);
            oscore_msg_protected_trim_payload(out, 0);
            return;
        }
        payload[0] = '0' + ledstate;
        oscore_msg_protected_trim_payload(out, 1);
    } else {
        oscore_msg_protected_trim_payload(out, 0);
    }
}

/** Parse @p msg's Block2 option into @p blockopt */
bool get_blockopt2(oscore_msg_protected_t *msg, struct sensordata_blockopt *blockopt)
{
    bool error = false;
    blockopt->num = 0;
    blockopt->szx = 6;

    oscore_msg_protected_optiter_t iter;
    uint16_t opt_num;
    const uint8_t *opt_val;
    size_t opt_len;
    oscore_msg_protected_optiter_init(msg, &iter);
    while (oscore_msg_protected_optiter_next(msg, &iter, &opt_num, &opt_val, &opt_len)) {
        if (opt_num != 23 /* Block2 */)
            continue;
        if (opt_len >= 4) {
            error = true;
            break;
        }
        network_uint32_t buf = { .u32 = 0 };
        memcpy(&buf.u8[4 - opt_len], opt_val, opt_len);
        uint32_t numeric = byteorder_ntohl(buf);
        blockopt->num = numeric >> 4;
        // ignoring the "M" bit
        blockopt->szx = numeric & 0x7;
        if (blockopt->szx == 7) {
            error = true;
            break;
        }
        break;
    }

    return oscore_msgerr_protected_is_error(oscore_msg_protected_optiter_finish(msg, &iter)) || error;
}

void sensordata_parse(oscore_msg_protected_t *in, void *vstate)
{
    struct sensordata_blockopt *state = vstate;

    // This application is sloppily ignoring any set critical options. A
    // diligent application would go through the options if those checks are
    // not provided by the framework. As this is both a demo of a simple
    // framework (the minimal intermediate integration) and a simple
    // application (the sensordata demo), those checks are ignored.

    if (oscore_msg_protected_get_code(in) != 1 /* GET */) {
        state->responsecode = 0x85 /* 4.05 Method Not Allowed */;
        return;
    }

    bool err = get_blockopt2(in, state);
    if (err)
        state->responsecode = 0x80 /* 4.00 Bad Option */;
    else
        state->responsecode = 0x45 /* 2.05 Content */;
}

const char message[] = "{\"data\": ["
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, "
"42]}";

void sensordata_build(oscore_msg_protected_t *out, const void *vstate, const struct observe_option *outer_observe)
{
    (void)outer_observe;
    struct sensordata_blockopt state = *(struct sensordata_blockopt*)vstate;

    oscore_msg_protected_set_code(out, state.responsecode);

    if (state.responsecode != 0x45 /* 2.05 Content */) {
        oscore_msg_protected_trim_payload(out, 0);
        return;
    }

    oscore_msgerr_protected_t err;
    // Will be overwritten later, but needs to be allocated now
    //
    // Could be optimized by reducing the size to whatever the block number
    // reduced to the lowest plausible buffer size needs to fit
    err = oscore_msg_protected_append_option(out, 23 /* Block 2 */, (uint8_t*)"XXXX", 4);

    uint8_t *payload;
    size_t payload_length;
    err = oscore_msg_protected_map_payload(out, &payload, &payload_length);

    if (oscore_msgerr_protected_is_error(err)) {
        oscore_msg_protected_set_code(out, 0xa0 /* 5.00 Internal Error */);
        oscore_msg_protected_trim_payload(out, 0);
        return;
    }

    size_t blocksize;
    while (true) {
        blocksize = 1 << (state.szx + 4);

        if (blocksize > payload_length) {
            assert(state.szx >= 1); // because such small a buffer is never allocated
            state.szx --;
            state.num <<= 1;
        } else {
            break;
        }
    }
    size_t start = blocksize * state.num;
    size_t end = start + blocksize;

    uint8_t *data = (uint8_t*)&message;
    size_t data_length = strlen(message);

    if (start > data_length) {
        oscore_msg_protected_set_code(out, 0x80 /* 4.00 Bad Request */);
        // FIXME: Remove Block option
        oscore_msg_protected_trim_payload(out, 0);
        return;
    }

    size_t actual_size = data_length - start;
    if (actual_size > blocksize)
        actual_size = blocksize;

    memcpy(payload, &data[start], actual_size);
    oscore_msg_protected_trim_payload(out, actual_size);

    bool m = end < data_length;
    uint32_t block2 = state.szx | (m << 3) | (state.num << 4);
    network_uint32_t buf = byteorder_htonl(block2);
    err = oscore_msg_protected_update_option(out, 23 /* Block2 */, 0, buf.u8, 4);

    // Very elaborate constant propagation could remove this.
    if (oscore_msgerr_protected_is_error(err)) {
        oscore_msg_protected_set_code(out, 0xa0 /* 5.00 Internal Error */);
        oscore_msg_protected_trim_payload(out, 0);
    }
}

/** End of demo application */

static ssize_t _riot_board_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;
    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
    size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

    /* write the RIOT board name in the response buffer */
    if (pdu->payload_len >= strlen(RIOT_BOARD)) {
        memcpy(pdu->payload, RIOT_BOARD, strlen(RIOT_BOARD));
        return resp_len + strlen(RIOT_BOARD);
    }
    else {
        puts("gcoap_cli: msg buffer too small");
        return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
    }
}

static const coap_resource_t _resources[] = {
    /* This index (0) is used by the notify mechanism, don't move it around without updating there */
    { "/", COAP_POST | COAP_FETCH, oscore_handler, NULL },
    { "/oscore/hello/coap", COAP_GET, plugtest_nonoscore_hello, NULL },
    { "/riot/board", COAP_GET, _riot_board_handler, NULL },
    // FIXME: This creates an artefact entry in .well-known/core
};

static gcoap_listener_t _listener = {
    &_resources[0],
    ARRAY_SIZE(_resources),
    NULL,
    NULL,
    NULL
};

/** Data allocated by send_static_request that needs to be available during
 * response processing */
struct static_request_data {
    /** Mutex that's released by the response handler as the last action,
     * indicating that send_static_request may terminate and thus free the
     * static_request_data from the stack */
    mutex_t done;
    /** Correlation data with which to verify the AEAD */
    oscore_requestid_t request_id;
};

static void handle_static_response(const struct gcoap_request_memo *memo, coap_pkt_t *pdu, const sock_udp_ep_t *remote)
{
    struct static_request_data *request_data = memo->context;
    // don't care, didn't send multicast
    (void)remote;

    if (memo->state != GCOAP_MEMO_RESP) {
        printf("Request returned without a response\n");
        goto error;
    }

    oscore_oscoreoption_t header;

    // This is nanocoap's shortcut (compare to unprotect-demo, where we iterate through the outer options)
    uint8_t *header_data;
    ssize_t header_size = coap_opt_get_opaque(pdu, 9, &header_data);
    if (header_size < 0) {
        printf("No OSCORE option in response!\n");
        goto error;
    }
    bool parsed = oscore_oscoreoption_parse(&header, header_data, header_size);
    if (!parsed) {
        printf("OSCORE option unparsable\n");
        goto error;
    }

    // FIXME: this should be in a dedicated parsed_pdu_to_oscore_msg_native_t process
    // (and possibly foolishly assuming that there is a payload marker)
    pdu->payload --;
    pdu->payload_len ++;
    oscore_msg_native_t pdu_read = { .pkt = pdu };

    oscore_msg_protected_t msg;

    if (mutex_trylock(&secctx_u_usage) != 1)  {
        // Could just as well block, but I prefer this for its clearer error behavior
        printf("Can't unprotect response, security context in use\n");
        goto error;
    }
    enum oscore_unprotect_response_result success = oscore_unprotect_response(pdu_read, &msg, &header, &secctx_u, &request_data->request_id);
    secctx_u_change -= 1;
    mutex_unlock(&secctx_u_usage);

    if (success == OSCORE_UNPROTECT_RESPONSE_OK) {
        uint8_t code = oscore_msg_protected_get_code(&msg);
        if (code == 0x81 /* 4.01 Unauthorized */) {
            oscore_msg_protected_optiter_t iter;
            uint16_t opt_num;
            const uint8_t *opt_val;
            size_t opt_len;
            oscore_msg_protected_optiter_init(&msg, &iter);
            while (oscore_msg_protected_optiter_next(&msg, &iter, &opt_num, &opt_val, &opt_len)) {
                if (opt_num == 252 /* Echo */ && opt_len < sizeof(ctx_u_received_echo_data)) {
                    memcpy(ctx_u_received_echo_data, opt_val, opt_len);
                    ctx_u_received_echo_size = opt_len;
                    printf("Stored %d bytes of Echo option for the next attempt\n", opt_len);
                }
            };
            (void)oscore_msg_protected_optiter_finish(&msg, &iter);
            printf("Result: 4.01 Unauthorized\n");
        } else if (code == 0x44 /* 2.04 Changed */)
            printf("Result: Changed\n");
        else
            printf("Unknown code in result: %d.%02d\n", code >> 5, code & 0x1f);
    } else {
        printf("Error unprotecting response\n");
    }

    mutex_unlock(&request_data->done);
    return;

error:
    // Can't postpone locking here, need to block in order to keep state required for clean-up
    mutex_lock(&secctx_u_usage);
    secctx_u_change -= 1;
    mutex_unlock(&secctx_u_usage);
    mutex_unlock(&request_data->done);
}

/** Blockingly send @p value to the configured remote resource */
static void send_static_request(char value) {
    // This is largely inspired by the gcoap_cli_cmd example code

    uint8_t buf[GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    oscore_msg_protected_t oscmsg;

    struct static_request_data request_data = { .done = MUTEX_INIT_LOCKED };

    if (persist->target.port == 0) {
        printf("No remote configured\n");
        return;
    }

    if (!persist->key_good) {
        printf("No security context configured\n");
        return;
    }

    // Can't pre-set a path, the request must be empty at protection time
    int err;
    err = gcoap_req_init(&pdu, buf, sizeof(buf), 0x02 /* POST */, NULL);
    if (err != 0) {
        printf("Failed to initialize request\n");
        return;
    }
    // Because we can, and because having CONs when used with a server that
    // doesn't really do storing deduplication leads to test-worthy responses
    // when the first ACK is lost
    coap_hdr_set_type(pdu.hdr, COAP_TYPE_CON);

    // FIXME use conversion
    oscore_msg_native_t native = { .pkt = &pdu };

    if (mutex_trylock(&secctx_u_usage) != 1)  {
        // Could just as well block, but I prefer this for its clearer error behavior
        printf("Can't send request, security context in use\n");
        return;
    }
    secctx_u_change += 1;

    // Ensure we have sequence numbers for this. Placing it here is slightly
    // sub-optimal (as it might block before transmission), but doing this in a
    // more clever way (eg. by calling it before the both successful and
    // unsuccessful returns, after sending, and possibly with some tweaking to
    // be more eager to write to flash when there is time to spare) would make
    // the demo code more complex.
    userctx_maybe_persist();

    if (oscore_prepare_request(native, &oscmsg, &secctx_u, &request_data.request_id) != OSCORE_PREPARE_OK) {
        mutex_unlock(&secctx_u_usage);
        printf("Failed to prepare request encryption\n");
        return;
    }

    mutex_unlock(&secctx_u_usage);

    oscore_msg_protected_set_code(&oscmsg, 0x03 /* PUT */);
    
    oscore_msgerr_protected_t oscerr;
    oscerr = oscore_msg_protected_append_option(&oscmsg, 11 /* Uri-Path */, (uint8_t*)"light", 5);
    if (oscore_msgerr_protected_is_error(oscerr)) {
        printf("Failed to add option\n");
        goto error;
    }

    if (ctx_u_received_echo_size != -1) {
        oscerr = oscore_msg_protected_append_option(&oscmsg, 252 /* Echo */, ctx_u_received_echo_data, ctx_u_received_echo_size);
        if (oscore_msgerr_protected_is_error(oscerr)) {
            printf("Failed to add option\n");
            goto error;
        }
        // Don't try more often than once
        ctx_u_received_echo_size = -1;
    }

    uint8_t *payload;
    size_t payload_length;
    oscerr = oscore_msg_protected_map_payload(&oscmsg, &payload, &payload_length);
    if (oscore_msgerr_protected_is_error(oscerr)) {
        printf("Failed to map payload\n");
        goto error;
    }
    *payload = value;

    oscerr = oscore_msg_protected_trim_payload(&oscmsg, 1);
    if (oscore_msgerr_protected_is_error(oscerr)) {
        printf("Failed to truncate payload\n");
        goto error;
    }

    oscore_msg_native_t pdu_write_out;
    if (oscore_encrypt_message(&oscmsg, &pdu_write_out) != OSCORE_FINISH_OK) {
        // see FIXME in oscore_encrypt_message description
        assert(false);
    }

    // PDU is usable now again and can be sent

    int bytes_sent = gcoap_req_send(buf, pdu.payload - (uint8_t*)pdu.hdr + pdu.payload_len, &persist->target, handle_static_response, &request_data);
    if (bytes_sent <= 0) {
        printf("Error sending\n");
    }

    // It was locked originally; waiting for the response handler to unlock it
    // so that we may free the request_id
    mutex_lock(&request_data.done);

    return;

error:
    {}
    // FIXME: abort encryption (but no PDU recovery and PDU freeing necessary on this backend as it's all stack allocated)
}

#include "shell.h"
#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

static int cmdline_on(int argc, char **argv) {
    (void)argc;
    (void)argv;

    send_static_request('1');
    return 0;
}

static int cmdline_off(int argc, char **argv) {
    (void)argc;
    (void)argv;

    send_static_request('0');
    return 0;
}

static int cmdline_target(int argc, char **argv) {
    if (argc != 4) {
        printf("Usage: target IP ZONE PORT\n");
        return 1;
    }

    ipv6_addr_t addr;

    persist->target.netif = atoi(argv[2]);
    if (!ipv6_addr_from_str(&addr, argv[1])) {
        printf("IP address invalid\n");
        persist->target.port = 0;
        return 1;
    }
    memcpy(&persist->target.addr.ipv6[0], &addr.u8[0], sizeof(addr.u8));
    persist->target.port = atoi(argv[3]);

    persist->target.family = AF_INET6;

    if (gnrc_netif_get_by_pid(persist->target.netif) == NULL) {
        printf("Zone identifier invalid\n");
        persist->target.port = 0;
        return 1;
    }

    persistence_commit();

    return 0;
}

static bool parse_singlehex(char hex, uint8_t *target) {
    if ('0' <= hex && hex <= '9') {
        *target = hex - '0';
        return true;
    }
    if ('a' <= hex && hex <= 'f') {
        *target = hex - 'a' + 10;
        return true;
    }
    if ('A' <= hex && hex <= 'F') {
        *target = hex - 'A' + 10;
        return true;
    }
    return false;
}

/*** Expect len bytes of hex data at the null-terminated hex string, parse them
 * into data and return true on success
 *
 * A single trailing '-' is accepted as to make the entry of '-' for a
 * zero-byte string easier.
 * */
static bool parse_hex(char *hex, size_t len, uint8_t *data) {
    uint8_t acc;
    while (len) {
        if (!parse_singlehex(*hex++, &acc))
            return false;
        *data = acc << 4;
        if (!parse_singlehex(*hex++, &acc))
            return false;
        *data |= acc;
        len --;
        data ++;
    }
    if (len == 0 && *hex == '-')
        hex ++;
    return *hex == 0;
}

static bool parse_i64(char *chars, int64_t *out) {
    char *end = NULL;
    *out = strtoll(chars, &end, 10);
    if (*end != ' ' && *end != '\0' && *end != '\n')
        return false;
    return true;
}

static int cmdline_userctx(int argc, char **argv) {
    if (argc < 7 || argc == 9 || argc > 10)
        return printf("Usage: userctx alg sender-id recipient-id common-iv sender-key recipient-key [seqno [replay-left replay-window]]\nAll keys and IDs in contiguous hex; alg, seqno and replay-left are decimal.\n");

    int ret = 0;

    if (mutex_trylock(&secctx_u_usage) != 1)
        return printf("Can't change user context while the context is in active use.\n");
    if (secctx_u_change != 0)  {
        printf("Can't change user context while %d request_ids are in flight.\n", secctx_u_change);
        mutex_unlock(&secctx_u_usage);
        return 1;
    }

    persist->key_good = false;
    userctx_last_persisted = -1;

    int64_t aeadalgbuf;
    if (!parse_i64(argv[1], &aeadalgbuf))
        ret = printf("Algorithm number was not a number\n");
    if (oscore_cryptoerr_is_error(oscore_crypto_aead_from_number(&persist->key.aeadalg, aeadalgbuf)))
        ret = printf("Algorithm is not a known AEAD algorithm\n");

    persist->key.sender_id_len = strlen(argv[2]) / 2;
    if (persist->key.sender_id_len > OSCORE_KEYID_MAXLEN)
        ret = printf("Sender ID too long\n");
    if (!parse_hex(argv[2], persist->key.sender_id_len, persist->key.sender_id))
        ret = printf("Invalid Sender ID\n");

    persist->key.recipient_id_len = strlen(argv[3]) / 2;
    if (persist->key.recipient_id_len > OSCORE_KEYID_MAXLEN)
        ret = printf("Recipient ID too long\n");
    if (!parse_hex(argv[3], persist->key.recipient_id_len, persist->key.recipient_id))
        ret = printf("Invalid Recipient ID\n");

    if (!parse_hex(argv[4], oscore_crypto_aead_get_ivlength(persist->key.aeadalg), persist->key.common_iv))
        ret = printf("Invalid Commmon IV\n");

    if (!parse_hex(argv[5], oscore_crypto_aead_get_keylength(persist->key.aeadalg), persist->key.sender_key))
        ret = printf("Invalid Sender Key'\n");

    if (!parse_hex(argv[6], oscore_crypto_aead_get_keylength(persist->key.aeadalg), persist->key.recipient_key))
        ret = printf("Invalid Recipient Key\n");

    int64_t seqno_start;
    if (argc > 7) {
        if (!parse_i64(argv[7], &seqno_start) || seqno_start < 0 || seqno_start >= OSCORE_SEQNO_MAX)
            ret = printf("Invalid sequence number\n");
    } else {
        seqno_start = 0;
    }

    struct oscore_context_b1_replaydata replaydata;
    bool replaydata_given = false;
    if (argc > 8) {
        int64_t edgebuffer;
        replaydata_given = true;
        if (!parse_i64(argv[8], &edgebuffer) || edgebuffer < 0 || edgebuffer >= OSCORE_SEQNO_MAX) {
            ret = printf("Invalid replay left edge\n");
            replaydata_given = false;
        }
        replaydata.left_edge = edgebuffer;
        if (!parse_hex(argv[9], 4, (void*)&replaydata.window)) {
            ret = printf("Invalid replay window\n");
            replaydata_given = false;
        }
    }

    oscore_context_b1_initialize(&context_u, &persist->key, seqno_start, replaydata_given ? &replaydata : NULL);

    if (ret == 0) {
        persist->key_good = true;
        ctx_u_received_echo_size = -1;
        // Not "maybe": with userctx_last_persisted just set to -1, this will
        // *for sure* take some numbers, and we want that because it'll get the
        // new configuration actually commmitted to flash.
        userctx_maybe_persist();
    }

    mutex_unlock(&secctx_u_usage);
    return ret;
}

/** Print the @p n bytes from @p data in hex, preceded by a blank, such that it
 * can be copy-pasted to parse_hex */
static void print_hex(size_t n, uint8_t *data) {
    printf(" ");
    if (n == 0) {
        printf("-");
        return;
    }
    while (n > 0) {
        printf("%02x", *data);
        n --;
        data ++;
    }
}

static int cmdline_userctx_shutdown(int argc, char **argv) {
    (void)argv;
    if (argc != 1)
        return printf("Usage: userctx\n");

    if (mutex_trylock(&secctx_u_usage) != 1)
        return printf("Can't change user context while the context is in active use.\n");
    if (secctx_u_change != 0)  {
        printf("Can't change user context while %d request_ids are in flight.\n", secctx_u_change);
        mutex_unlock(&secctx_u_usage);
        return 1;
    }

    if (!persist->key_good)
        return printf("User context is not in a valid state.\n");

    persist->key_good = false;

    printf("User context is shut down.\n");
    printf("You can resume it once with the following command:\n");
    printf("userctx %d ", persist->key.aeadalg);
    print_hex(persist->key.sender_id_len, persist->key.sender_id);
    print_hex(persist->key.recipient_id_len, persist->key.recipient_id);
    print_hex(oscore_crypto_aead_get_ivlength(persist->key.aeadalg), persist->key.common_iv);
    print_hex(oscore_crypto_aead_get_keylength(persist->key.aeadalg), persist->key.sender_key);
    print_hex(oscore_crypto_aead_get_keylength(persist->key.aeadalg), persist->key.recipient_key);

    struct oscore_context_b1_replaydata replaydata;
    oscore_context_b1_replay_extract(&context_u, &replaydata);

    printf(" %llu", context_u.primitive.sender_sequence_number);
    if (replaydata.left_edge != OSCORE_SEQNO_MAX) {
        // Could be persisted, but the command line interface will refuse
        // loading seqno_max and expect it to be absent
        printf(" %llu", replaydata.left_edge);
        print_hex(4, (uint8_t*)&replaydata.window);
    }

    printf("\n\nOnce you entered that, you must not enter it again, but only enter what the running process's output tells you to.\n");

    mutex_unlock(&secctx_u_usage);
    return 0;
}

static int cmdline_notify(int argc, char **argv) {
    if (argc != 2 || argv[1][0] == '-') {
        printf("Usage: %s off|<word>\n", argv[0]);
        return 1;
    }

    oscore_msgerr_protected_t oscerr;
    uint8_t buf[GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;

    // This is largely following the sequence of send_static_request

    int err;
    err = gcoap_obs_init(&pdu, buf, sizeof(buf), &_resources[0]);
    if (err != 0) {
        printf("Failed to initialize request (probably no observation active)\n");
        return 1;
    }

    oscore_msg_native_t native;
    struct observe_option outer_observe;
    uint8_t *outer_observe_ptr;
    oscore_msg_native_from_gcoap_outgoing(&native, &pdu, &outer_observe.length, &outer_observe_ptr);
    if (outer_observe.length > 0) {
        memcpy(outer_observe.data, outer_observe_ptr, outer_observe.length);
    }

    oscore_msg_protected_t oscmsg;
    // This is about an obsevation for context B -- FIXME ensure the sender ID only ever gets set for that
    // (or if it's for u, see the secctx_u_change below)
    if (mutex_trylock(&secctx_b_usage) != 1)  {
        // Could just as well block, but I prefer this for its clearer error behavior
        printf("Can't send request, security context in use\n");
        return 1;
    }

    // FIXME if this were ever to be used with a secctx u, changing the key
    // material would need to clear all request memos (or be disallowed while
    // an observation is active)
    //
    // secctx_u_change ?
    userctx_maybe_persist();
    extern bool observation_id_valid;
    extern oscore_requestid_t observation_id;
    if (!observation_id_valid) {
        printf("No observation was recorded by the observe1_build handler\n");
        return 1;
    }
    if (oscore_prepare_response(native, &oscmsg, &secctx_b, &observation_id) != OSCORE_PREPARE_OK) {
        mutex_unlock(&secctx_b_usage);
        printf("Failed to prepare request encryption\n");
        return 1;
    }
    mutex_unlock(&secctx_b_usage);

    size_t text_length = strlen(argv[1]);
    uint8_t *text = (uint8_t*)argv[1];

    if (text_length == 3 && memcmp(text, "off", 3) == 0) {
        /* As requested in the plugtest specs; "off" us used as a shorthand as
         * it's readable with a single argument */
        text = (uint8_t*)"Terminate Observe";
        text_length = strlen((char*)text);
        oscore_msg_protected_set_code(&oscmsg, 0xa0 /* 5.00 Internal Server Error */);
    } else {
        oscore_msg_protected_set_code(&oscmsg, 0x45 /* 2.05 Content */);
        oscerr = oscore_msg_protected_append_option(&oscmsg, 6 /* Observe */, outer_observe.data, outer_observe.length);
        if (oscore_msgerr_protected_is_error(oscerr)) {
            printf("Failed to set Observe option\n");
            goto error;
        }
    }

    uint8_t *payload;
    size_t payload_length;
    oscerr = oscore_msg_protected_map_payload(&oscmsg, &payload, &payload_length);
    if (oscore_msgerr_protected_is_error(oscerr)) {
        printf("Failed to map payload\n");
        goto error;
    }

    if (payload_length < text_length) {
        printf("Message too short for allocated memory\n");
        goto error;
    }
    memcpy(payload, text, text_length);

    oscerr = oscore_msg_protected_trim_payload(&oscmsg, text_length);
    if (oscore_msgerr_protected_is_error(oscerr)) {
        printf("Unexpected failure to trim payload\n");
        goto error;
    }

    oscore_msg_native_t pdu_write_out;
    if (oscore_encrypt_message(&oscmsg, &pdu_write_out) != OSCORE_FINISH_OK) {
        // see FIXME in oscore_encrypt_message description
        assert(false);
    }

    // PDU is usable now again and can be sent

    int bytes_sent = gcoap_obs_send(buf, pdu.payload - (uint8_t*)pdu.hdr + pdu.payload_len, &_resources[0]);
    if (bytes_sent <= 0) {
        printf("Error sending\n");
    }
    return 0;

error:
    // FIXME: abort encryption (but no PDU recovery and PDU freeing necessary on this backend as it's all stack allocated)

    return 1;
}

// This is a brutally inefficient task as it constantly polls the buttons --
// but at the same time it is easily portable. Don't run any power measurements
// while this is running.
static void *interactive_thread(void *arg) {
    (void)arg;
#ifdef BTN0_PIN
    bool old = false;
    while (true) {
        bool new = !gpio_read(BTN0_PIN);
        if (new != old) {
            send_static_request('0' + new);
        };
        old = new;
    }
    return NULL;
#else
    printf("Can't execute interactive demo for lack of hardware button\n");
    return NULL;
#endif
}

char interactive_thread_stack[THREAD_STACKSIZE_MAIN];

/** Ask the user to persist some data. Call this while you hold the secctx_u lock.
 *
 * Ideally, this would be called in idle times after requests were sent, or in
 * a mixture of time- and event-based calls. Failure to call this often enough
 * results in encryption errors, as no sequence numbers are available.
 *
 * Note that due to the default oscore_context_b1_get_wanted function that is
 * used, there is always some reserve in sequence numbers, so cases of actually
 * running out are unlikely.
 * */
void userctx_maybe_persist(void) {
    if (!persist->key_good)
        return;

    uint64_t wanted = oscore_context_b1_get_wanted(&context_u);
    if (wanted == userctx_last_persisted)
        return;

    persist->stored_sequence_number = wanted;
    persistence_commit();

    printf("\nThe user context was persisted to flash memory, and will resume at sender sequence number %" PRIu64 ":\n", wanted);

    oscore_context_b1_allow_high(&context_u, wanted);
    userctx_last_persisted = wanted;
}

static const shell_command_t shell_commands[] = {
    { "on", "Set the configured OSCORE remote resource to 1", cmdline_on },
    { "off", "Set the configured OSCORE remote resource to 0", cmdline_off },
    {"target", "Set the IP and port to which to send on and off requests", cmdline_target },
    {"userctx", "Reset the user context with new key material", cmdline_userctx },
    {"userctx-shutdown", "Switch off the user context but allow resuming it later", cmdline_userctx_shutdown },
    {"notify", "Emit a notification from the /oscore/observe1 resource", cmdline_notify },
    { NULL, NULL, NULL }
};

int main(void)
{
    bool flash_valid = persistence_init(&persist);

    if (flash_valid) {
        oscore_context_b1_initialize(&context_u, &persist->key, persist->stored_sequence_number, NULL);
        printf("Loaded data from flash. Target is %s, keys are %s\n",
                persist->target.port == 0 ? "unset" : "set",
                persist->key_good ? "valid" : "invalid"
              );
        // Not calling userctx_maybe_persist here, as that would result in a
        // flash write right after power-up. There's no need for that -- when
        // OSCORE traffic arrives or is sent, room will be made in the sequence numbers.

        // No need to unlock secctx_u_usage, we didn't grab it in the first
        // place as this is startup code anyway
    } else {
        printf("No valid data loaded from flash\n");
        persist->target.port = 0;
        persist->key_good = false;
    }

    bool plugtest_available = true;

    oscore_cryptoerr_t oscerr;
    oscerr = oscore_crypto_aead_from_number(&immutables_b.aeadalg, 10);
    // Not having the plugtest context available is not expected
    if (oscore_cryptoerr_is_error(oscerr)) {
        puts("Plugtest server unavailable for lack of AEAD algorithm support.");
        plugtest_available = false;
    }

    oscore_crypto_hkdfalg_t hkdfalg;
    if (plugtest_available) {
        oscerr = oscore_crypto_hkdf_from_number(&hkdfalg, 5); /* or -10? */
        if (oscore_cryptoerr_is_error(oscerr)) {
            puts("Plugtest server unavailable for lack of HKDF algorithm support.");
            plugtest_available = false;
        }
    }

    if (plugtest_available) {
        // Algorithm and IDs are already set; sender, recipient key and common IV can be derived
        oscerr = oscore_context_primitive_derive(&immutables_b,
                hkdfalg,
                ab_master_salt, sizeof(ab_master_salt),
                ab_master_secret, sizeof(ab_master_secret),
                NULL, 0
                );
        // Nothing can't easily go wrong here
        assert(!oscore_cryptoerr_is_error(oscerr));

        oscerr = oscore_crypto_aead_from_number(&immutables_d.aeadalg, 10);
        // would have broken before
        assert(!oscore_cryptoerr_is_error(oscerr));
    }

    if (!plugtest_available) {
        mutex_lock(&secctx_b_usage);
        mutex_lock(&secctx_d_usage);
    }

    gcoap_register_listener(&_listener);

    thread_create(interactive_thread_stack, sizeof(interactive_thread_stack),
                            THREAD_PRIORITY_IDLE - 1, THREAD_CREATE_STACKTEST,
                            interactive_thread, NULL, "interactive");

    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    // larger than usual to accomodate key entry
    char line_buf[512];

    puts("Running OSCORE plugtest server");
    shell_run(shell_commands, line_buf, sizeof(line_buf));

    return 0;
}
