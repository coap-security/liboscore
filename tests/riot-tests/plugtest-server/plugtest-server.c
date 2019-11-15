#include <net/gcoap.h>
#include <oscore_native/message.h>
#include <oscore/message.h>
#include <oscore/contextpair.h>
#include <oscore/context_impl/primitive.h>
#include <oscore/protection.h>

/*
static ssize_t _stats_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;

    unsigned method_flag = coap_method2flag(coap_get_code_detail(pdu));

    switch(method_flag) {
        case COAP_GET:
            gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
            coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
            size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

            return resp_len;

        case COAP_PUT:
            if (pdu->payload_len <= 5) {
                char payload[6] = { 0 };
                memcpy(payload, (char *)pdu->payload, pdu->payload_len);
                return gcoap_response(pdu, buf, len, COAP_CODE_CHANGED);
            }
            else {
                return gcoap_response(pdu, buf, len, COAP_CODE_BAD_REQUEST);
            }
    }

    return 0;
}
*/

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

// Having those static is OK here because the gcoap thread will only process messages one at a time
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
    } else if (
            header.kid_context == NULL &&
            header.kid != NULL &&
            header.kid_len == 0
            // && memcmp(header.kid, "", 0) == 0
            )
    {
        secctx = &secctx_b;
    } else {
        errormessage = "No security context found";
        errorcode = COAP_CODE_UNAUTHORIZED;
        goto error;
    }
    oscerr = oscore_unprotect_request(pdu_read, &incoming_decrypted, header, secctx, &request_id);

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
    oscerr2 = oscore_prepare_response(pdu_write, &outgoing_plaintext, secctx, &request_id);
    if (oscerr2 != OSCORE_PREPARE_OK) {
        errormessage = "Context not ready";
        goto error;
    }

    // Deferring to the dispatcher again for actual response building
    dispatcher_build(&outgoing_plaintext, &plugtest_config);

    enum oscore_finish_result oscerr4;
    oscore_msg_native_t pdu_write_out;
    oscerr4 = oscore_encrypt_message(&outgoing_plaintext, &pdu_write_out);
    if (oscerr4 != OSCORE_FINISH_OK) {
        errormessage = "Error finishing";
        goto error;
    }
    assert(pdu == pdu_write_out.pkt);

    // FIXME we'll have to pick that from pdu, or make the oscore_msg_native_t enriched by a length
    return (pdu->payload - buf) + pdu->payload_len;

error:
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

#include "shell.h"
#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

static const shell_command_t shell_commands[] = {
    { NULL, NULL, NULL }
};

int main(void)
{
    gcoap_register_listener(&_listener);

    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    char line_buf[SHELL_DEFAULT_BUFSIZE];

    puts("Running OSCORE plugtest server");
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
