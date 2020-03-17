#include <oscore/contextpair.h>
#include <oscore/context_impl/primitive.h>
#include <oscore/context_impl/b1.h>

#include <stdlib.h>

/* Given a PRIMITIVE or B1 context, return a pointer to its actual primitive
 * payload.
 *
 * From the construction of the B1 struct, this function has identical results
 * for either case, but it lets the compiler prove that rather than relying on
 * a developer to enforce it.
 * */
static struct oscore_context_primitive *find_primitive(const oscore_context_t *secctx) {
    switch (secctx->type) {
    case OSCORE_CONTEXT_PRIMITIVE:
        {
            struct oscore_context_primitive *primitive = secctx->data;
            return primitive;
        }
    case OSCORE_CONTEXT_B1:
        {
            struct oscore_context_b1 *b1 = secctx->data;
            return &b1->primitive;
        }
    default:
        abort();
    }
}

oscore_crypto_aeadalg_t oscore_context_get_aeadalg(const oscore_context_t *secctx)
{
    switch (secctx->type) {
    case OSCORE_CONTEXT_PRIMITIVE:
    case OSCORE_CONTEXT_B1:
        {
            struct oscore_context_primitive *primitive = find_primitive(secctx);
            return primitive->immutables->aeadalg;
        }
    default:
        abort();
    }
}

void oscore_context_get_kid(
        const oscore_context_t *secctx,
        enum oscore_context_role role,
        const uint8_t **kid,
        size_t *kid_len
        )
{
    switch (secctx->type) {
    case OSCORE_CONTEXT_PRIMITIVE:
    case OSCORE_CONTEXT_B1:
        {
            struct oscore_context_primitive *primitive = find_primitive(secctx);
            if (role == OSCORE_ROLE_RECIPIENT) {
                *kid = primitive->immutables->recipient_id;
                *kid_len = primitive->immutables->recipient_id_len;
            } else {
                *kid = primitive->immutables->sender_id;
                *kid_len = primitive->immutables->sender_id_len;
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
    case OSCORE_CONTEXT_B1:
        {
            struct oscore_context_primitive *primitive = find_primitive(secctx);
            return primitive->immutables->common_iv;
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
    case OSCORE_CONTEXT_B1:
        {
            struct oscore_context_primitive *primitive = find_primitive(secctx);
            if (role == OSCORE_ROLE_RECIPIENT)
                return primitive->immutables->recipient_key;
            else
                return primitive->immutables->sender_key;
        }
    default:
        abort();
    }
}

bool oscore_context_take_seqno(
        oscore_context_t *secctx,
        oscore_requestid_t *request_id
        )
{
    switch (secctx->type) {
    case OSCORE_CONTEXT_PRIMITIVE:
    case OSCORE_CONTEXT_B1:
        {
            struct oscore_context_primitive *primitive = find_primitive(secctx);
            uint64_t seqno = primitive->sender_sequence_number;
            if (seqno >= OSCORE_SEQNO_MAX) {
                return false;
            }
            if (secctx->type == OSCORE_CONTEXT_B1) {
                struct oscore_context_b1 *b1 = secctx->data;
                if (seqno >= b1->high_sequence_number) {
                    return false;
                }
            }
            primitive->sender_sequence_number = seqno + 1;
            request_id->is_first_use = true;
            request_id->bytes[0] = (seqno >> 32) & 0xff;
            request_id->bytes[1] = (seqno >> 24) & 0xff;
            request_id->bytes[2] = (seqno >> 16) & 0xff;
            request_id->bytes[3] = (seqno >> 8) & 0xff;
            request_id->bytes[4] = seqno & 0xff;
            request_id->used_bytes = request_id->bytes[0] != 0 ? 5 :
                                     request_id->bytes[1] != 0 ? 4 :
                                     request_id->bytes[2] != 0 ? 3 :
                                     request_id->bytes[3] != 0 ? 2 :
                                     1; // The 0th sequence number explicitly has length 1 as well.
            return true;
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

/** @brief Remove the @par n (>= 1) sequence numbers starting at
 * replay_window_left_edge from the window, rolling on the window in case the
 * next number was already used. */
static void advance_window(struct oscore_context_primitive *ctx, size_t n)
{
    ctx->replay_window_left_edge += n;
    if (n > 32) {
        ctx->replay_window = 0;
        return;
    }
    bool needs_roll = ctx->replay_window & (((uint32_t)1) << (32 - n));
    ctx->replay_window <<= n;
    if (needs_roll) {
        roll_window(ctx);
    }
}

void oscore_context_strikeout_requestid(
        oscore_context_t *secctx,
        oscore_requestid_t *request_id)
{
    switch (secctx->type) {
    case OSCORE_CONTEXT_PRIMITIVE:
    // Needs no special-casing as strike-out of an uninitialized context will
    // always fail the first test.
    case OSCORE_CONTEXT_B1:
        {
            struct oscore_context_primitive *primitive = find_primitive(secctx);
            // request_id->partial_iv is documented to always be zero-padded
            int64_t numeric = request_id->bytes[4] + \
                              request_id->bytes[3] * ((int64_t)1 << 8) + \
                              request_id->bytes[2] * ((int64_t)1 << 16) + \
                              request_id->bytes[1] * ((int64_t)1 << 24) + \
                              request_id->bytes[0] * ((int64_t)1 << 32);

            // We can keep comparing here as all is signed and the possible
            // input magnitudes come nowhere near over-/underflowing
            int64_t necessary_shift = numeric - primitive->replay_window_left_edge - 32;
            if (necessary_shift >= 1) {
                advance_window(primitive, necessary_shift);
            }

            bool is_first;

            if (numeric < primitive->replay_window_left_edge) {
                is_first = false;
            } else if (numeric == primitive->replay_window_left_edge) {
                is_first = true;
                roll_window(primitive);
            } else {
                uint32_t mask = ((uint32_t)1) << (32 - (numeric - primitive->replay_window_left_edge));
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
