#include "intermediate-integration.h"

#include <oscore/protection.h>
#include <oscore/context_impl/b1.h>

/** Write @p text into @p msg and return true on success */
bool set_message(oscore_msg_protected_t *out, const char *text)
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

void dispatcher_parse(oscore_msg_protected_t *in, void *vstate)
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

void dispatcher_build(oscore_msg_protected_t *out, const void *vstate) {
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
#include "resources.inc"
#undef RESOURCE
#undef PATH
static struct dispatcher_choice plugtest_choices[] = {
#define RESOURCE(name, pathcount, path, handler_parse, handler_build, statetype) { pathcount, name, { handler_parse, handler_build } },
#define PATH(...)
#include "resources.inc"
#undef RESOURCE
#undef PATH
    { 0, NULL, { NULL, NULL } },
};
static struct dispatcher_config  plugtest_config = {
    .choices = plugtest_choices,
    // state is initialized for whatever is just parsing
};


ssize_t _oscore(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
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
            persist->key_good &&
            header.kid != NULL &&
            header.kid_len == persist->key.recipient_id_len &&
            memcmp(header.kid, &persist->key.recipient_id, persist->key.recipient_id_len) == 0
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

        // Give the persistence layer a chance to allocate numbers that'll be
        // needed for pulling an Echo number or responding with an own sequence
        // number.
        userctx_maybe_persist();
    }

    oscerr = oscore_unprotect_request(pdu_read, &incoming_decrypted, header, secctx, &request_id);

    bool respond_401echo = secctx_lock == &secctx_u_usage && \
            oscore_context_b1_process_request(
                    secctx,
                    &incoming_decrypted,
                    &oscerr,
                    &request_id
                    );

    mutex_unlock(secctx_lock);

    // If we wanted to be absolutely sure that no operation fails, we could
    // call userctx_maybe_persist here as well -- but because the
    // implementation uses the default oscore_context_b1_get_wanted which
    // ensures that there are K/2 numbers left, the above invocation suffices.
    // if (secctx_lock == &secctx_u_usage) userctx_maybe_persist();

    if (!respond_401echo && oscerr != OSCORE_UNPROTECT_REQUEST_OK) {
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
    if (!respond_401echo)
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
    if (respond_401echo) {
        if (oscore_context_b1_build_401echo(
                    pdu_write,
                    secctx,
                    &request_id)) {
            secctx_u_change -= 1;
            mutex_unlock(secctx_lock);
            return (pdu->payload - buf) + pdu->payload_len;
        } else {
            errormessage = "Failed to build 4.01 response";
            errorcode = COAP_CODE_SERVICE_UNAVAILABLE;
            mutex_unlock(secctx_lock);
            goto error;
        }
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
