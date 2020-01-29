#include <net/gcoap.h>
#include <periph/gpio.h>
#include <oscore_native/message.h>
#include <oscore/message.h>
#include <oscore/contextpair.h>
#include <oscore/context_impl/primitive.h>
#include <oscore/context_impl/b1.h>
#include <oscore/protection.h>

static ssize_t _hello(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;

    static const char echo_response[] = "Hello World!";

    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
    size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);
    memcpy(pdu->payload, echo_response, strlen(echo_response));
    resp_len += strlen(echo_response);

    return resp_len;
}

#define B_SENDER_KEY {50, 136, 42, 28, 97, 144, 48, 132, 56, 236, 152, 230, 169, 50, 240, 32, 112, 143, 55, 57, 223, 228, 109, 119, 152, 155, 3, 155, 31, 252, 28, 172}
#define B_RECIPIENT_KEY {213, 48, 30, 177, 141, 6, 120, 73, 149, 8, 147, 186, 42, 200, 145, 65, 124, 137, 174, 9, 223, 74, 56, 85, 170, 0, 10, 201, 255, 243, 135, 81}
#define B_COMMON_IV {100, 240, 189, 49, 77, 75, 224, 60, 39, 12, 43, 28}


#define D_SENDER_KEY {79, 177, 204, 118, 107, 180, 59, 3, 14, 118, 123, 233, 14, 12, 59, 241, 144, 219, 242, 68, 113, 65, 139, 251, 152, 212, 46, 145, 230, 180, 76, 252}
#define D_RECIPIENT_KEY {173, 139, 170, 28, 148, 232, 23, 226, 149, 11, 247, 99, 61, 79, 20, 148, 10, 6, 12, 149, 135, 5, 18, 168, 164, 11, 216, 42, 13, 221, 69, 39}
#define D_COMMON_IV {199, 178, 145, 95, 47, 133, 49, 117, 132, 37, 73, 212}

// Having _b and _d static is OK here because the gcoap thread will only process messages one at a time
// Context B: as specified in plug test description (therefore hard-coded; outside the plug tests, this must only be done only when one of the recovery mechanisms of the OSCORE specification appendix B or equivalent are used).
static struct oscore_context_primitive primitive_b = {
    .aeadalg = 24,
    .common_iv = B_COMMON_IV,

    .recipient_id_len = 0,
    .recipient_key = B_RECIPIENT_KEY,

    .sender_id_len = 1,
    .sender_id = "\x01",
    .sender_key = B_SENDER_KEY,
};
static oscore_context_t secctx_b = {
    .type = OSCORE_CONTEXT_PRIMITIVE,
    .data = (void*)(&primitive_b),
};
static mutex_t secctx_b_usage = MUTEX_INIT;

// Context D: as specified in plug test description (see B)
static struct oscore_context_primitive primitive_d = {
    .aeadalg = 24,
    .common_iv = D_COMMON_IV,

    .recipient_id_len = 0,
    .recipient_key = D_RECIPIENT_KEY,

    .sender_id_len = 1,
    .sender_id = "\x01",
    .sender_key = D_SENDER_KEY,
};
static oscore_context_t secctx_d = {
    .type = OSCORE_CONTEXT_PRIMITIVE,
    .data = (void*)(&primitive_d),
};
static mutex_t secctx_d_usage = MUTEX_INIT;

// User context: configurable from command-line, used in outgoing requests and also available at the server
static struct oscore_context_b1 context_u;
static oscore_context_t secctx_u = {
    .type = OSCORE_CONTEXT_B1,
    .data = (void*)(&context_u),
};
static bool secctx_u_good = false;
static mutex_t secctx_u_usage = MUTEX_INIT;
int16_t secctx_u_change = 0; // RW lock count, only to be changed while secctx_u_usage is kept. The variable keeps track of the number of readers (readers in RW-lock terminology; here it's "request_id objects out there"). A writer may change the context as a whole while keeping secctx_u_usage locked and secctx_u_change is 0.

struct handler {
    void (*parse)(/* not const because of memoization */ oscore_msg_protected_t *in, void *state);
    void (*build)(oscore_msg_protected_t *in, const void *state);
};

/** Write @p text into @p msg and return true on success */
static bool set_message(oscore_msg_protected_t *out, const char *text)
{
    uint8_t *payload;
    size_t payload_length;
    size_t printed = 0;
    oscore_msgerr_native_t err = oscore_msg_protected_map_payload(out, &payload, &payload_length);
    if (oscore_msgerr_protected_is_error(err)) {
        return false;
    }

    printed = snprintf((char*)payload, payload_length, "%s", text);
    if (printed > payload_length) {
        return false;
    }
    err = oscore_msg_protected_trim_payload(out, printed);
    if (oscore_msgerr_protected_is_error(err)) {
        return false;
    }

    return true;
}

/** Return true only if exactly the options present in the messages have their
 * respective bit set in expected_options, and dump the options on stdout in
 * either case. (expected_options can't be -1). */
static bool options_are_as_expected(oscore_msg_protected_t *msg, uint64_t expected_options) {
    uint64_t seen = 0;

    oscore_msg_protected_optiter_t iter;
    uint16_t opt_num;
    const uint8_t *opt_val;
    size_t opt_len;
    oscore_msg_protected_optiter_init(msg, &iter);
    while (oscore_msg_protected_optiter_next(msg, &iter, &opt_num, &opt_val, &opt_len)) {
        printf("Checking option %d: \"", opt_num);
        for (size_t j = 0; j < opt_len; ++j) {
            if (opt_val[j] >= 32 && opt_val[j] < 127) {
                printf("%c", opt_val[j]);
            } else {
                printf("\\x%02x", opt_val[j]);
            }
        }
        printf("\"\n");

        if (opt_num >= 64) {
            printf("Option was high and unexpected\n");
            seen = -1;
        } else {
            if (((1 << opt_num) & expected_options) == 0) {
                printf("Option was unexpected\n");
            }
            seen |= 1 << opt_num;
        }
    }
    return seen == expected_options;
}

struct hello_state {
    bool code_ok;
    bool options_ok;
};

static void hello_parse(oscore_msg_protected_t *in, void *vstate)
{
    struct hello_state *state = vstate;
    state->options_ok = options_are_as_expected(in, 1 << 11 /* Uri-Path */);
    state->code_ok = oscore_msg_protected_get_code(in) == 1 /* GET */;
}

static void hello_build(oscore_msg_protected_t *out, const void *vstate)
{
    const struct hello_state *state = vstate;

    if (!state->code_ok) {
        oscore_msg_protected_set_code(out, 0x85 /* 4.05 Method Not Allowed */);
        goto error2;
    }

    oscore_msg_protected_set_code(out, 0x45 /* 2.05 content */);

    oscore_msgerr_protected_t err = oscore_msg_protected_append_option(out, 12 /* content-format */, (uint8_t*)"", 0);
    if (oscore_msgerr_protected_is_error(err))
        goto error;

    if (!set_message(out, state->options_ok ? "Hello World!" : "Hello Unexpected!"))
        goto error;

    return;

error:
    oscore_msg_protected_set_code(out, 0xa0 /* 5.00 internal error */);
error2:
    // not unwinding any option, there's no API for that and it doesn't really matter
    oscore_msg_protected_trim_payload(out, 0);
}

static void hello2_parse(oscore_msg_protected_t *in, void *vstate)
{
    struct hello_state *state = vstate;
    state->options_ok = options_are_as_expected(in, (1 << 11 /* Uri-Path */) | (1 << 15 /* Uri-Query */));
    state->code_ok = oscore_msg_protected_get_code(in) == 1 /* GET */;
}

static void hello2_build(oscore_msg_protected_t *out, const void *vstate)
{
    const struct hello_state *state = vstate;

    if (!state->code_ok) {
        oscore_msg_protected_set_code(out, 0x85 /* 4.05 Method Not Allowed */);
        goto error2;
    }

    oscore_msg_protected_set_code(out, 0x45 /* 2.05 content */);

    oscore_msgerr_protected_t err;
    err = oscore_msg_protected_append_option(out, 4 /* ETag */, (uint8_t*)"\x2b", 1);
    if (oscore_msgerr_protected_is_error(err))
        goto error;

    err = oscore_msg_protected_append_option(out, 12 /* content-format */, (uint8_t*)"", 0);
    if (oscore_msgerr_protected_is_error(err))
        goto error;

    if (!set_message(out, state->options_ok ? "Hello World!" : "Hello Unexpected!"))
        goto error;

    return;

error:
    oscore_msg_protected_set_code(out, 0xa0 /* 5.00 internal error */);
error2:
    // not unwinding any option, there's no API for that and it doesn't really matter
    oscore_msg_protected_trim_payload(out, 0);
}

static void hello3_parse(oscore_msg_protected_t *in, void *vstate)
{
    struct hello_state *state = vstate;
    state->options_ok = options_are_as_expected(in, (1 << 11 /* Uri-Path */) | (1 << 17 /* Accept */));
    state->code_ok = oscore_msg_protected_get_code(in) == 1 /* GET */;
}

static void hello3_build(oscore_msg_protected_t *out, const void *vstate)
{
    const struct hello_state *state = vstate;

    if (!state->code_ok) {
        oscore_msg_protected_set_code(out, 0x85 /* 4.05 Method Not Allowed */);
        goto error2;
    }

    oscore_msg_protected_set_code(out, 0x45 /* 2.05 content */);

    oscore_msgerr_protected_t err;
    err = oscore_msg_protected_append_option(out, 12 /* content-format */, (uint8_t*)"", 0);
    if (oscore_msgerr_protected_is_error(err))
        goto error;

    err = oscore_msg_protected_append_option(out, 14 /* Max-Age */, (uint8_t*)"\x05", 1);
    if (oscore_msgerr_protected_is_error(err))
        goto error;

    if (!set_message(out, state->options_ok ? "Hello World!" : "Hello Unexpected!"))
        goto error;

    return;

error:
    oscore_msg_protected_set_code(out, 0xa0 /* 5.00 internal error */);
error2:
    // not unwinding any option, there's no API for that and it doesn't really matter
    oscore_msg_protected_trim_payload(out, 0);
}

static void hello6_parse(oscore_msg_protected_t *in, void *vstate)
{
    struct hello_state *state = vstate;
    state->options_ok = options_are_as_expected(in, (1 << 11 /* Uri-Path */) | (1 << 12 /* Content-Format */));
    state->code_ok = oscore_msg_protected_get_code(in) == 2 /* POST */;
    /* FIXME check payload */
}

static void hello6_build(oscore_msg_protected_t *out, const void *vstate)
{
    const struct hello_state *state = vstate;

    if (!state->code_ok) {
        oscore_msg_protected_set_code(out, 0x85 /* 4.05 Method Not Allowed */);
        goto error2;
    }

    oscore_msg_protected_set_code(out, 0x44 /* 2.04 Changed */);

    oscore_msgerr_protected_t err;
    err = oscore_msg_protected_append_option(out, 12 /* content-format */, (uint8_t*)"", 0);
    if (oscore_msgerr_protected_is_error(err))
        goto error;

    if (!set_message(out, state->options_ok ? "\x4a" : "Would have been 0x4a if options matched"))
        goto error;

    return;

error:
    oscore_msg_protected_set_code(out, 0xa0 /* 5.00 internal error */);
error2:
    // not unwinding any option, there's no API for that and it doesn't really matter
    oscore_msg_protected_trim_payload(out, 0);
}

static void hello7_parse(oscore_msg_protected_t *in, void *vstate)
{
    struct hello_state *state = vstate;
    state->options_ok = options_are_as_expected(in, (1 << 11 /* Uri-Path */) | (1 << 12 /* Content-Format */) |  (1 << 1 /* If-Match */));
    state->code_ok = oscore_msg_protected_get_code(in) == 3 /* PUT */;
    /* FIXME check payload */
}

static void hello7_build(oscore_msg_protected_t *out, const void *vstate)
{
    const struct hello_state *state = vstate;

    if (!state->code_ok) {
        oscore_msg_protected_set_code(out, 0x85 /* 4.05 Method Not Allowed */);
    } else if (state->options_ok) {
        // For test 9
        oscore_msg_protected_set_code(out, 0x44 /* 2.04 Changed */);
    } else {
        // For test 10 -- FIXME this could be sharper, but hey it's enough to
        // pass, and we're not checking every detail of the requests anyway
        oscore_msg_protected_set_code(out, 0x8c /* 4.12 Precondition Failed */);
    }

    oscore_msg_protected_trim_payload(out, 0);
}

static void delete_parse(oscore_msg_protected_t *in, void *vstate)
{
    struct hello_state *state = vstate;
    state->options_ok = options_are_as_expected(in, (1 << 11 /* Uri-Path */));
    state->code_ok = oscore_msg_protected_get_code(in) == 4 /* DELETE */;
}

static void delete_build(oscore_msg_protected_t *out, const void *vstate)
{
    const struct hello_state *state = vstate;

    if (!state->code_ok) {
        oscore_msg_protected_set_code(out, 0x85 /* 4.05 Method Not Allowed */);
    } else if (state->options_ok) {
        // For test 9
        oscore_msg_protected_set_code(out, 0x42 /* 2.02 Deleted */);
    } else {
        oscore_msg_protected_set_code(out, 0x80 /* 4.00 Bad Request */);
    }

    oscore_msg_protected_trim_payload(out, 0);
}

/** Will be the demo application */

#include <led.h>

static bool ledstate = false;

static void light_parse(oscore_msg_protected_t *in, void *vstate)
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
                    ledstate = true;
                } else {
                    LED_OFF(0);
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

static void light_build(oscore_msg_protected_t *out, const void *vstate)
{
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

struct sensordata_blockopt {
    uint32_t num;
    uint8_t szx;
    uint8_t responsecode;
};

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

static void sensordata_parse(oscore_msg_protected_t *in, void *vstate)
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

static void sensordata_build(oscore_msg_protected_t *out, const void *vstate)
{
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
#include "plugtest-resources.inc"
#undef RESOURCE
#undef PATH
    } handlerstate;
};

static void dispatcher_parse(oscore_msg_protected_t *in, void *vstate)
{
    struct dispatcher_config *config = vstate;
    config->current_choice = &config->choices[0];
    size_t path_depth = 0;
    // During this function, current_choice and path_depth always indicate a
    // plausible-as-of-now option: inside current_choice, path_depth option
    // components have already been seen.

    oscore_msg_protected_optiter_t iter;
    uint16_t opt_num;
    const uint8_t *opt_val;
    size_t opt_len;
    oscore_msg_protected_optiter_init(in, &iter);
    while (oscore_msg_protected_optiter_next(in, &iter, &opt_num, &opt_val, &opt_len)) {
        if (opt_num == 11 /* Uri-Path */) {
            while (path_depth == config->current_choice->path_items /* no additional path component accepted */ ||
                    strlen(config->current_choice->path[path_depth]) != opt_len /* or the new one doesn't fit */ ||
                    memcmp(config->current_choice->path[path_depth], opt_val, opt_len) != 0)
            {
                // Current item is not suitable, try advancing or break with error
                const struct dispatcher_choice *next = config->current_choice + 1;
                if (next->path_items == 0 /* reached the end of the list */ ||
                        next->path_items < path_depth /* already used path is certainly not a shared prefix */ ||
                        memcmp(next->path, config->current_choice->path, path_depth * sizeof(char **)) != 0 /* already used path is not a shared prefix */
                    ) {
                    config->current_choice = NULL;
                    return;
                }
                // OK, the next is at least as well-suited as the current one was, retry
                config->current_choice += 1;
            }

            // All fits, accept the option
            path_depth += 1;
        }
    }

    if (path_depth != config->current_choice->path_items) {
        // Path fits but we'd have expected more path options
        config->current_choice = NULL;
        return;
    }

    // Casting via void into any member's type is OK according to https://stackoverflow.com/questions/24010052/pointer-to-union-member
    void *data = &config->handlerstate;
    config->current_choice->handler.parse(in, data);
}

static void dispatcher_build(oscore_msg_protected_t *out, const void *vstate) {
    const struct dispatcher_config *config = vstate;

    if (config->current_choice == NULL) {
        oscore_msg_protected_set_code(out, 0x84 /* 4.04 Not Found */);
        oscore_msg_protected_trim_payload(out, 0);
        return;
    }

    const void *data = &config->handlerstate;
    config->current_choice->handler.build(out, data);
}

#define RESOURCE(name, pathcount, path, handler_parse, handler_build, statetype) static const char* const name[pathcount] = path;
#define PATH(...) { __VA_ARGS__ }
#include "plugtest-resources.inc"
#undef RESOURCE
#undef PATH
static struct dispatcher_choice plugtest_choices[] = {
#define RESOURCE(name, pathcount, path, handler_parse, handler_build, statetype) { pathcount, name, { handler_parse, handler_build } },
#define PATH(...)
#include "plugtest-resources.inc"
#undef RESOURCE
#undef PATH
    { 0, NULL, { NULL, NULL } },
};
static struct dispatcher_config  plugtest_config = {
    .choices = plugtest_choices,
    // state is initialized for whatever is just parsing
};


static ssize_t _oscore(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;

    enum oscore_unprotect_request_result oscerr;
    oscore_oscoreoption_t header;
    oscore_requestid_t request_id;
    const char *errormessage;
    uint8_t errorcode = COAP_CODE_INTERNAL_SERVER_ERROR;
    mutex_t *secctx_lock = NULL;

    // This is nanocoap's shortcut (compare to unprotect-demo, where we iterate through the outer options)
    uint8_t *header_data;
    ssize_t header_size = coap_opt_get_opaque(pdu, 9, &header_data);
    if (header_size < 0) {
        errormessage = "No OSCORE option found";
        // Having a </> resource in parallel to OSCORE is not supported here.
        errorcode = COAP_CODE_PATH_NOT_FOUND;
        goto error;
    }
    bool parsed = oscore_oscoreoption_parse(&header, header_data, header_size);
    if (!parsed) {
        errormessage = "OSCORE option unparsable";
        errorcode = COAP_CODE_BAD_OPTION;
        goto error;
    }

    // FIXME: this should be in a dedicated parsed_pdu_to_oscore_msg_native_t process
    // (and possibly foolishly assuming that there is a payload marker)
    pdu->payload --;
    pdu->payload_len ++;
    oscore_msg_native_t pdu_read = { .pkt = pdu };

    oscore_msg_protected_t incoming_decrypted;
    oscore_context_t *secctx;
    // FIXME accessing private fields without accessor
    if (header.kid_context != NULL &&
            header.kid_context_len == 8 &&
            memcmp(header.kid_context, "\x37\xcb\xf3\x21\x00\x17\xa2\xd3", 8) == 0 &&
            header.kid != NULL &&
            header.kid_len == 0
            // && memcmp(header.kid, "", 0) == 0
            )
    {
        secctx = &secctx_d;
        secctx_lock = &secctx_d_usage;
    } else if (
            header.kid_context == NULL &&
            header.kid != NULL &&
            header.kid_len == 0
            // && memcmp(header.kid, "", 0) == 0
            )
    {
        secctx = &secctx_b;
        secctx_lock = &secctx_b_usage;
    } else if (
            // Strictly speaking this is racing against changesin he context
            // protected by secctx_u_change, but only until it's locked (or
            // denied) a few lines later -- what could possibly go wrong?
            // (FIXME as always after these words)
            secctx_u_good &&
            header.kid != NULL &&
            header.kid_len == context_u.primitive.recipient_id_len &&
            memcmp(header.kid, &context_u.primitive.recipient_id, context_u.primitive.recipient_id_len) == 0
            )
    {
        secctx = &secctx_u;
        secctx_lock = &secctx_u_usage;
    } else {
        errormessage = "No security context found";
        errorcode = COAP_CODE_UNAUTHORIZED;
        goto error;
    }

    if (mutex_trylock(secctx_lock) != 1) {
        errormessage = "Security context in use";
        // FIXME add Max-Age: 0
        errorcode = COAP_CODE_SERVICE_UNAVAILABLE;
        secctx_lock = NULL; // Don't unlock secctx_u_change in the error path
        goto error;
    }

    if (secctx_lock == &secctx_u_usage) {
        secctx_u_change += 1;
    }

    oscerr = oscore_unprotect_request(pdu_read, &incoming_decrypted, header, secctx, &request_id);
    mutex_unlock(secctx_lock);

    if (oscerr != OSCORE_UNPROTECT_REQUEST_OK) {
        if (oscerr == OSCORE_UNPROTECT_REQUEST_DUPLICATE) {
            errormessage = "Unprotect failed, it's a duplicate";
            errorcode = COAP_CODE_UNAUTHORIZED;
        } else {
            errormessage = "Unprotect failed";
            errorcode = COAP_CODE_BAD_REQUEST;
        }
        goto error;
    }

    // Deferring to the dispatcher for actual resource handling
    dispatcher_parse(&incoming_decrypted, &plugtest_config);

    // Anything we were trying to learn from the incoming message needs to be
    // copied to the stack by now.
    oscore_msg_native_t pdu_read_out = oscore_release_unprotected(&incoming_decrypted);

    assert(pdu_read_out.pkt == pdu);

    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);

    enum oscore_prepare_result oscerr2;
    oscore_msg_native_t pdu_write = { .pkt = pdu };
    oscore_msg_protected_t outgoing_plaintext;
    if (mutex_trylock(secctx_lock) != 1) {
        errormessage = "Context not available for response";
        errorcode = COAP_CODE_SERVICE_UNAVAILABLE;
        goto error;
    }
    oscerr2 = oscore_prepare_response(pdu_write, &outgoing_plaintext, secctx, &request_id);
    if (secctx_lock == &secctx_u_usage) {
        secctx_u_change -= 1;
    }
    mutex_unlock(secctx_lock);
    if (oscerr2 != OSCORE_PREPARE_OK) {
        errormessage = "Context not usable";
        errorcode = COAP_CODE_SERVICE_UNAVAILABLE;
        goto error;
    }

    secctx_lock = NULL; // Don't unlock secctx_u_change in the error path

    // Deferring to the dispatcher again for actual response building
    dispatcher_build(&outgoing_plaintext, &plugtest_config);

    enum oscore_finish_result oscerr4;
    oscore_msg_native_t pdu_write_out;
    oscerr4 = oscore_encrypt_message(&outgoing_plaintext, &pdu_write_out);
    if (oscerr4 != OSCORE_FINISH_OK) {
        errormessage = "Error finishing";
        // FIXME verify that this truncates the response
        goto error;
    }
    assert(pdu == pdu_write_out.pkt);

    // FIXME we'll have to pick that from pdu, or make the oscore_msg_native_t enriched by a length
    return (pdu->payload - buf) + pdu->payload_len;

error:
    if (secctx_lock == &secctx_u_usage) {
        // Rather block the Gcoap thread than making secctx_u unchangable for good
        mutex_lock(&secctx_u_usage);
        secctx_u_change -= 1;
        mutex_unlock(&secctx_u_usage);
    }
    printf("Error: %s\n", errormessage);
    return gcoap_response(pdu, buf, len, errorcode);
}

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
    { "/", COAP_POST | COAP_FETCH, _oscore, NULL },
    { "/oscore/hello/coap", COAP_GET, _hello, NULL },
    { "/riot/board", COAP_GET, _riot_board_handler, NULL },
    // FIXME: This creates an artefact entry in .well-known/core, and at the
    // same time makes / unusable for anything else
};

static gcoap_listener_t _listener = {
    &_resources[0],
    ARRAY_SIZE(_resources),
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

sock_udp_ep_t static_request_target = { .port = 0 };

static void handle_static_response(const struct gcoap_request_memo *memo, coap_pkt_t *pdu, const sock_udp_ep_t *remote)
{
    struct static_request_data *request_data = memo->context;
    // don't care, didn't send multicast
    (void)remote;

    if (memo->state != GCOAP_MEMO_RESP) {
        printf("Request returned without a response\n");
        return;
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
    enum oscore_unprotect_response_result success = oscore_unprotect_response(pdu_read, &msg, header, &secctx_u, &request_data->request_id);
    secctx_u_change -= 1;
    mutex_unlock(&secctx_u_usage);

    if (success == OSCORE_UNPROTECT_RESPONSE_OK) {
        uint8_t code = oscore_msg_protected_get_code(&msg);
        if (code == 0x44 /* 2.04 Changed */)
            printf("Result: Changed\n");
        else
            printf("Unknown code in result: %d.%d\n", code >> 5, code & 0x1f);
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

    if (static_request_target.port == 0) {
        printf("No remote configured\n");
        return;
    }

    if (!secctx_u_good) {
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

    int bytes_sent = gcoap_req_send(buf, pdu.payload - (uint8_t*)pdu.hdr + pdu.payload_len, &static_request_target, handle_static_response, &request_data);
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

    static_request_target.netif = atoi(argv[2]);
    if (!ipv6_addr_from_str(&addr, argv[1])) {
        printf("IP address invalid\n");
        static_request_target.port = 0;
        return 1;
    }
    memcpy(&static_request_target.addr.ipv6[0], &addr.u8[0], sizeof(addr.u8));
    static_request_target.port = atoi(argv[3]);

    static_request_target.family = AF_INET6;

    if (gnrc_netif_get_by_pid(static_request_target.netif) == NULL) {
        printf("Zone identifier invalid\n");
        static_request_target.port = 0;
        return 1;
    }

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
        printf("Can't change user context while request_ids are in flight.\n");
        mutex_unlock(&secctx_u_usage);
        return 1;
    }

    secctx_u_good = false;

    int64_t aeadalgbuf;
    if (!parse_i64(argv[1], &aeadalgbuf))
        ret = printf("Algorithm number was not a number\n");
    if (oscore_cryptoerr_is_error(oscore_crypto_aead_from_number(&context_u.primitive.aeadalg, aeadalgbuf)))
        ret = printf("Algorithm is not a known AEAD algorithm\n");

    context_u.primitive.sender_id_len = strlen(argv[2]) / 2;
    if (context_u.primitive.sender_id_len > OSCORE_KEYID_MAXLEN)
        ret = printf("Sender ID too long\n");
    if (!parse_hex(argv[2], context_u.primitive.sender_id_len, context_u.primitive.sender_id))
        ret = printf("Invalid Sender ID\n");

    context_u.primitive.recipient_id_len = strlen(argv[3]) / 2;
    if (context_u.primitive.recipient_id_len > OSCORE_KEYID_MAXLEN)
        ret = printf("Recipient ID too long\n");
    if (!parse_hex(argv[3], context_u.primitive.recipient_id_len, context_u.primitive.recipient_id))
        ret = printf("Invalid Recipient ID\n");

    if (!parse_hex(argv[4], oscore_crypto_aead_get_ivlength(context_u.primitive.aeadalg), context_u.primitive.common_iv))
        ret = printf("Invalid Commmon IV\n");

    if (!parse_hex(argv[5], oscore_crypto_aead_get_keylength(context_u.primitive.aeadalg), context_u.primitive.sender_key))
        ret = printf("Invalid Sender Key'\n");

    if (!parse_hex(argv[6], oscore_crypto_aead_get_keylength(context_u.primitive.aeadalg), context_u.primitive.recipient_key))
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

    oscore_context_b1_initialize(&context_u, seqno_start, replaydata_given ? &replaydata : NULL);

    if (ret == 0)
        secctx_u_good = true;

    mutex_unlock(&secctx_u_usage);
    return ret;
}

static int cmdline_interactive(int argc, char **argv) {
    (void)argc;
    (void)argv;
#ifdef BTN0_PIN
    bool old = false;
    int remaining = 10;
    while (remaining) {
        bool new = !gpio_read(BTN0_PIN);
        if (new != old) {
            send_static_request('0' + new);
            remaining --;
        };
        old = new;
    }
    return 0;
#else
    printf("Can't execute interactive demo for lack of hardware button\n");
    return 1;
#endif
}

static const shell_command_t shell_commands[] = {
    { "on", "Set the configured OSCORE remote resource to 1", cmdline_on },
    { "off", "Set the configured OSCORE remote resource to 0", cmdline_off },
    {"target", "Set the IP and port to which to send on and off requests", cmdline_target },
    {"userctx", "Reset the user context with new key material", cmdline_userctx },
    { "interactive", "Poll the first hardware button to send 10 on/off commands via OSCORE when pressed", cmdline_interactive },
    { NULL, NULL, NULL }
};

int main(void)
{
    gcoap_register_listener(&_listener);

    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    // larger than usual to accomodate key entry
    char line_buf[512];

    puts("Running OSCORE plugtest server");
    shell_run(shell_commands, line_buf, sizeof(line_buf));

    return 0;
}
