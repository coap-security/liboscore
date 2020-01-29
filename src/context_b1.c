#include <oscore/contextpair.h>
#include <oscore/context_impl/b1.h>

#define K 100

void oscore_context_b1_initialize(
        struct oscore_context_b1 *secctx,
        uint64_t seqno,
        const struct oscore_context_b1_replaydata *replaydata
        )
{
    secctx->primitive.sender_sequence_number = seqno;
    secctx->high_sequence_number = seqno;

    // Still unusable, until allow_high has been called -- only then we know
    // that we won't be called again with the very same arguments.
    secctx->echo_value = 0;

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
