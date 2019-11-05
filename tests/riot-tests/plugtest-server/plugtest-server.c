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

#define SENDER_KEY {50, 136, 42, 28, 97, 144, 48, 132, 56, 236, 152, 230, 169, 50, 240, 32, 112, 143, 55, 57, 223, 228, 109, 119, 152, 155, 3, 155, 31, 252, 28, 172}
#define RECIPIENT_KEY {213, 48, 30, 177, 141, 6, 120, 73, 149, 8, 147, 186, 42, 200, 145, 65, 124, 137, 174, 9, 223, 74, 56, 85, 170, 0, 10, 201, 255, 243, 135, 81}
#define COMMON_IV {100, 240, 189, 49, 77, 75, 224, 60, 39, 12, 43, 28}

// Having those static is OK here because the gcoap thread will only process messages one at a time
static struct oscore_context_primitive primitive = {
    .aeadalg = 24,
    .common_iv = COMMON_IV,

    .recipient_id_len = 0,
    .recipient_key = RECIPIENT_KEY,

    .sender_id_len = 1,
    .sender_id = "\x01",
    .sender_key = SENDER_KEY,
};
static oscore_context_t secctx = {
    .type = OSCORE_CONTEXT_PRIMITIVE,
    .data = (void*)(&primitive),
};

static ssize_t _oscore(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;

    enum oscore_unprotect_request_result oscerr;
    oscore_oscoreoption_t header;
    oscore_requestid_t request_id;
    const char *errormessage;

    // This is nanocoap's shortcut (compare to unprotect-demo, where we iterate through the outer options)
    uint8_t *header_data;
    ssize_t header_size = coap_opt_get_opaque(pdu, 9, &header_data);
    if (header_size < 0) {
        errormessage = "No OSCORE option found";
        goto error;
    }
    bool parsed = oscore_oscoreoption_parse(&header, header_data, header_size);
    if (!parsed) {
        errormessage = "OSCORE option unparsable";
        goto error;
    }

    // FIXME: this should be in a dedicated parsed_pdu_to_oscore_msg_native_t process
    // (and possibly foolishly assuming that there is a payload marker)
    pdu->payload --;
    pdu->payload_len ++;
    oscore_msg_native_t pdu_read = { .pkt = pdu };

    oscore_msg_protected_t incoming_decrypted;
    // FIXME: THis is short-cutting through a lookup process that should
    // actually be there to find the right secctx from the header
    oscerr = oscore_unprotect_request(pdu_read, &incoming_decrypted, header, &secctx, &request_id);

    if (oscerr != OSCORE_UNPROTECT_REQUEST_OK) {
        if (oscerr == OSCORE_UNPROTECT_REQUEST_DUPLICATE) {
            errormessage = "Unprotect failed, it's a duplicate";
        } else {
            errormessage = "Unprotect failed";
        }
        goto error;
    }

    // For lack of full integration, we now manually implement a resource dispatch
    oscore_msg_protected_optiter_t iter;
    uint16_t opt_num;
    const uint8_t *opt_val;
    size_t opt_len;
    oscore_msg_protected_optiter_init(&incoming_decrypted, &iter);
    while (oscore_msg_protected_optiter_next(&incoming_decrypted, &iter, &opt_num, &opt_val, &opt_len)) {
        printf("Reading option %d: \"", opt_num);
        for (size_t j = 0; j < opt_len; ++j) {
            if (opt_val[j] >= 32 && opt_val[j] < 127) {
                printf("%c", opt_val[j]);
            } else {
                printf("\\x%02x", opt_val[j]);
            }
        }
        printf("\"\n");
    }
    oscore_msg_protected_optiter_finish(&incoming_decrypted, &iter);

    // Anything we were trying to learn from the incoming message needs to be
    // copied to the stack by now.
    oscore_msg_native_t pdu_read_out = oscore_release_unprotected(&incoming_decrypted);

    assert(pdu_read_out.pkt == pdu);

    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);

    enum oscore_prepare_result oscerr2;
    oscore_msg_native_t pdu_write = { .pkt = pdu };
    oscore_msg_protected_t outgoing_plaintext;
    oscerr2 = oscore_prepare_response(pdu_write, &outgoing_plaintext, &secctx, &request_id);
    if (oscerr2 != OSCORE_PREPARE_OK) {
        errormessage = "Context not ready";
        goto error;
    }

    // Set outer options: none

    // Set code
    oscore_msg_protected_set_code(&outgoing_plaintext, COAP_CODE_CONTENT);

    // Set inner options
    oscore_msgerr_protected_t oscerr3;
    oscerr3 = oscore_msg_protected_append_option(&outgoing_plaintext, 12, (uint8_t*)"", 0);
    if (oscore_msgerr_protected_is_error(oscerr3)) {
        errormessage = "Failed to add content format";
        goto error;
    }

    uint8_t *payload;
    size_t payload_length;
    size_t printed = 0;
    oscerr3 = oscore_msg_protected_map_payload(&outgoing_plaintext, &payload, &payload_length);
    if (oscore_msgerr_protected_is_error(oscerr3)) {
        errormessage = "Failed to map message";
        goto error;
    }

    printed = snprintf((char*)payload, payload_length, "Hello World!");

    oscerr3 = oscore_msg_protected_trim_payload(&outgoing_plaintext, printed);
    if (oscore_msgerr_protected_is_error(oscerr3)) {
        errormessage = "Failed to trim message";
        goto error;
    }

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
    // FIXME do error coes right
    printf("Error: %s\n", errormessage);
    return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
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
    { "/", COAP_GET | COAP_POST, _oscore, NULL },
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

int main(void)
{
    gcoap_register_listener(&_listener);

    puts("Running OSCORE plugtest server");

    /* setup is over, coap server will run indefinitely */
    return 0;
}
