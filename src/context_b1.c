#include <oscore/contextpair.h>
#include <oscore/context_impl/b1.h>

#define K 100

void oscore_context_b1_initialize(
        struct oscore_context_b1 *secctx,
        const struct oscore_context_primitive_immutables *immutables,
        uint64_t seqno,
        const struct oscore_context_b1_replaydata *replaydata
        )
{
    secctx->primitive.immutables = immutables;
    secctx->primitive.sender_sequence_number = seqno;
    // ie. that would be the next, but it's not usable yet
    secctx->high_sequence_number = seqno;

    secctx->echo_value_populated = 0;

    if (replaydata == NULL) {
        secctx->primitive.replay_window_left_edge = OSCORE_SEQNO_MAX;
    } else {
        secctx->primitive.replay_window_left_edge = replaydata->left_edge;
        secctx->primitive.replay_window = replaydata->window;
    }
}


void oscore_context_b1_allow_high(
        struct oscore_context_b1 *secctx,
        uint64_t seqno
        )
{
    secctx->high_sequence_number = seqno;
}

uint64_t oscore_context_b1_get_wanted(
        struct oscore_context_b1 *secctx
        )
{
    if (secctx->primitive.sender_sequence_number - secctx->high_sequence_number < K / 2) {
        return secctx->high_sequence_number + K;
    }
    return secctx->high_sequence_number;
}

void oscore_context_b1_replay_extract(
    struct oscore_context_b1 *secctx,
    struct oscore_context_b1_replaydata *replaydata
    )
{
    replaydata->left_edge = secctx->primitive.replay_window_left_edge;
    replaydata->window = secctx->primitive.replay_window;
}


void oscore_context_b1_get_echo(
        oscore_context_t *secctx,
        size_t *value_length,
        uint8_t **value
        )
{
    if (secctx->type != OSCORE_CONTEXT_B1) {
        *value_length = 0;
        // Slightly odd, but we don't want to return NULL (someone could
        // memcpy) and we don't want to assert (as it's a clear user error) and
        // we don't want to report an error (as really nothing else can go
        // wrong), and that's the only value we have at hand and know to be
        // good for dereferencing a zero-size slice from.
        // FIXME introduce optional usage error callback
        *value = (void*)secctx;
    }

    struct oscore_context_b1 *b1 = secctx->data;

    *value = b1->echo_value;
    if (b1->echo_value_populated != 0) {
        *value_length = b1->echo_value_populated;
        return;
    }

    if (b1->primitive.replay_window_left_edge == OSCORE_SEQNO_MAX) {
        oscore_requestid_t buf;
        bool success = oscore_context_take_seqno(secctx, &buf);
        if (success) {
            memcpy(b1->echo_value, &buf.bytes, PIV_BYTES);
            b1->echo_value_populated = buf.used_bytes;
            *value_length = buf.used_bytes;
        } else {
            *value_length = 0;
        }
    }
}

bool oscore_context_b1_process_request(
        oscore_context_t *secctx,
        oscore_msg_protected_t *request,
        enum oscore_unprotect_request_result *unprotectresult,
        oscore_requestid_t *request_id
        )
{
    if (secctx->type != OSCORE_CONTEXT_B1) {
        // This is a usage error.
        // FIXME introduce optional usage error callback
        return false;
    }
    struct oscore_context_b1 *b1 = secctx->data;
    if (*unprotectresult != OSCORE_UNPROTECT_REQUEST_DUPLICATE ||
            b1->primitive.replay_window_left_edge != OSCORE_SEQNO_MAX)
        return false;

    size_t echo_length;
    uint8_t *echo_value;
    oscore_context_b1_get_echo(secctx, &echo_length, &echo_value);
    if (echo_length == 0) {
        // Keep the lack of available sequence numbers from resulting in a
        // request recognized as fresh
        return true;
    }

    bool result = true;
    oscore_msg_protected_optiter_t iter;
    uint16_t opt_num;
    const uint8_t *opt_val;
    size_t opt_len;
    oscore_msg_protected_optiter_init(request, &iter);
    while (oscore_msg_protected_optiter_next(request, &iter, &opt_num, &opt_val, &opt_len)) {
        if (opt_num == 540 /* Echo */ &&
                opt_len == echo_length &&
                memcmp(opt_val, echo_value, echo_length) == 0) {
            // Matches, and replay window was previously checked to be uninitialized
            b1->primitive.replay_window_left_edge = \
                              request_id->bytes[4] + \
                              request_id->bytes[3] * ((int64_t)1 << 8) + \
                              request_id->bytes[2] * ((int64_t)1 << 16) + \
                              request_id->bytes[1] * ((int64_t)1 << 24) + \
                              request_id->bytes[0] * ((int64_t)1 << 32);
            b1->primitive.replay_window = 0;
            request_id->is_first_use = true;
            *unprotectresult = OSCORE_UNPROTECT_REQUEST_OK;
            result = false;
            break;
        }
    }
    // Ignoring the result -- if the Echo option was good, it's fine for here
    // and whoever parses the rest of the message will deal with its garbled
    // contents.
    (void)oscore_msg_protected_optiter_finish(request, &iter);

    return result;
}

bool oscore_context_b1_build_401echo(
        oscore_msg_native_t message,
        oscore_context_t *secctx,
        oscore_requestid_t *request_id
        )
{
    enum oscore_prepare_result oscerr;
    oscore_msg_protected_t outgoing_plaintext;

    oscerr = oscore_prepare_response(message, &outgoing_plaintext, secctx, request_id);
    if (oscerr != OSCORE_PREPARE_OK) {
        return false;
    }

    oscore_msg_protected_set_code(&outgoing_plaintext, 0x81 /* 4.01 Unauthorized */);

    size_t echo_size;
    uint8_t *echo_value;
    oscore_context_b1_get_echo(secctx, &echo_size, &echo_value);

    oscore_msgerr_protected_t err = oscore_msg_protected_append_option(
            &outgoing_plaintext,
            540 /* Echo */,
            echo_value,
            echo_size
            );
    if (oscore_msgerr_protected_is_error(err))
        return false;

    oscore_msg_protected_trim_payload(&outgoing_plaintext, 0);

    enum oscore_finish_result oscerr2;
    oscore_msg_native_t pdu_write_out;
    oscerr2 = oscore_encrypt_message(&outgoing_plaintext, &pdu_write_out);
    if (oscerr2 != OSCORE_FINISH_OK)
        return false;

    return true;
}
