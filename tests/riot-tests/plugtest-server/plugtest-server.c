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

// Having those static is OK here because the gcoap thread will only process messages one at a time
static struct oscore_context_primitive primitive = {
    .aeadalg = 24,
    .common_iv = "d\xf0\xbd" "1MK\xe0<'\x0c+\x1c",

    .recipient_id_len = 0,
    .recipient_key = "\xd5" "0\x1e\xb1\x8d\x06xI\x95\x08\x93\xba*\xc8\x91" "A|\x89\xae\t\xdfJ8U\xaa\x00\n\xc9\xff\xf3\x87Q",
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

    // FIXME: THis is short-cutting through a lookup process that should
    // actually be there to find the right secctx from the header

    oscore_msg_protected_t incoming_decrypted;
    oscerr = oscore_unprotect_request(pdu, &incoming_decrypted, header, &secctx, &request_id);

    if (oscerr != OSCORE_UNPROTECT_REQUEST_OK && oscerr != OSCORE_UNPROTECT_REQUEST_DUPLICATE) {
        errormessage = "Unprotect failed";
        goto error;
    }

    printf("Wow it got decoded\n");
    if (oscerr == OSCORE_UNPROTECT_REQUEST_DUPLICATE) {
        printf("It's a duplicate though\n");
    }

    (void)buf;
    (void)len;
    return 0;

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
