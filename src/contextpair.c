#include <oscore/contextpair.h>
#include <oscore/context_impl/primitive.h>

oscore_crypto_aeadalg_t oscore_context_get_aeadalg(const oscore_context_t *secctx)
{
    switch (secctx->type) {
    case OSCORE_CONTEXT_PRIMITIVE:
        {
            struct oscore_context_primitive *primitive = secctx->data;
            return primitive->aeadalg;
        }
    default:
        abort();
    }
}

void oscore_context_get_kid(
        const oscore_context_t *secctx,
        enum oscore_context_role role,
        uint8_t **kid,
        size_t *kid_len
        )
{
    switch (secctx->type) {
    case OSCORE_CONTEXT_PRIMITIVE:
        {
            struct oscore_context_primitive *primitive = secctx->data;
            if (role == OSCORE_ROLE_RECIPIENT) {
                *kid = primitive->recipient_id;
                *kid_len = primitive->recipient_id_len;
            } else {
                *kid = primitive->sender_id;
                *kid_len = primitive->sender_id_len;
            }
            return;
        }
    default:
        abort();
    }
}

const uint8_t *oscore_context_get_commoniv(const oscore_context_t *secctx)
{
    switch (secctx->type) {
    case OSCORE_CONTEXT_PRIMITIVE:
        {
            struct oscore_context_primitive *primitive = secctx->data;
            return primitive->common_iv;
        }
    default:
        abort();
    }
}
const uint8_t *oscore_context_get_key(
        const oscore_context_t *secctx,
        enum oscore_context_role role
        )
{
    switch (secctx->type) {
    case OSCORE_CONTEXT_PRIMITIVE:
        {
            struct oscore_context_primitive *primitive = secctx->data;
            if (role == OSCORE_ROLE_RECIPIENT)
                return primitive->recipient_key;
            else
                return primitive->sender_key;
        }
    default:
        abort();
    }
}

/** @brief Strike out the left edge number from the replay window */
// Like all context_primitive specifics, this is on the path to refactoring
// once we know what's actually needed where
static void roll_window(struct oscore_context_primitive *ctx) {
    bool left_edge_is_seen = true;
    // This could be phrased more efficiently by using an instruction for
    // counting of the left-most digit ones (typically CLZ), but that's not
    // generally portable, and a smart compiler (nb: currently none of the
    // godbolt ones is) would figure that out anyway.

    // FIXME This definitely needs a unit test (and another look at whether it
    // does the right thing, before that).
    while (left_edge_is_seen) {
        left_edge_is_seen = ctx->replay_window >> 31;
        ctx->replay_window <<= 1;
        ctx->replay_window_left_edge += 1;
    }
}

void oscore_context_strikeout_requestid(
        oscore_context_t *secctx,
        oscore_requestid_t *request_id)
{
    switch (secctx->type) {
    case OSCORE_CONTEXT_PRIMITIVE:
        {
            struct oscore_context_primitive *primitive = secctx->data;
            // request_id->partial_iv is documented to always be zero-padded
            int64_t numeric = request_id->partial_iv[4] + \
                              request_id->partial_iv[3] * ((int64_t)1 << 8) + \
                              request_id->partial_iv[2] * ((int64_t)1 << 16) + \
                              request_id->partial_iv[1] * ((int64_t)1 << 24) + \
                              request_id->partial_iv[0] * ((int64_t)1 << 32);

            // FIXME add a fast path for > 65 jumps -- that'll probably make
            // the below easier and make us refactor roll_window into a
            // roll_window_by_atleast

            // We can keep comparing here as all is signed and the possible
            // input magnitudes come nowhere near over-/underflowing
            while (numeric - primitive->replay_window_left_edge > 32) {
                // Strike out unseen number as a far larger one is coming in
                roll_window(primitive);
            }

            bool is_first;

            if (numeric < primitive->replay_window_left_edge) {
                is_first = false;
            } else if (numeric == primitive->replay_window_left_edge) {
                is_first = true;
                roll_window(primitive);
            } else {
                uint32_t mask = 1 << (32 - (numeric - primitive->replay_window_left_edge));
                is_first = (mask & primitive->replay_window) == 0;
                primitive->replay_window |= mask;
            }

            request_id->is_first_use = is_first;
            return;
        }
    default:
        abort();
    }
}
