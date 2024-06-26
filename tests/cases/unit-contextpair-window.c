#include <stdbool.h>
#include <oscore_native/platform.h>

#include <oscore/contextpair.h>
#include <oscore/context_impl/primitive.h>

const int OK = 0;
const int ERR = 1;

struct number {
    uint64_t seqno;
    bool expect_success;
    bool terminator;
};

static oscore_requestid_t requestid_from_u64(uint64_t seqno)
{
    assert(seqno < 0x10000000000);
    oscore_requestid_t result = {
        .used_bytes = 42,
        .is_first_use = false,
        .bytes = {(seqno >> 32) & 0xff, (seqno >> 24) & 0xff, (seqno >> 16) & 0xff, (seqno >> 8) & 0xff, seqno & 0xff},
    };
    return result;
}

static int test_sequence(
        oscore_context_t *ctx, 
        struct number *numbers
        )
{

    for (; numbers->terminator == false; ++numbers) {
        oscore_requestid_t id = requestid_from_u64(numbers->seqno);
        oscore_context_strikeout_requestid(ctx, &id);
        if (id.is_first_use != numbers->expect_success) {
            return ERR;
        }
    }
    return OK;
}


static int test_sequence_from_zero_expecting(
        struct number *numbers,
        int64_t left_edge,
        uint32_t final_window
        )
{
    int result;
    struct oscore_context_primitive primitive = {
        .replay_window_left_edge = 0,
    };
    oscore_context_t secctx = {
        .type = OSCORE_CONTEXT_PRIMITIVE,
        .data = (void*)(&primitive),
    };

    result = test_sequence(&secctx, numbers);

    if (left_edge != primitive.replay_window_left_edge) {
        return ERR;
    }

    if (final_window != primitive.replay_window) {
        return ERR;
    }

    return result;
}

int testmain(int introduce_error)
{
    int result = OK;

    struct number small_linear[] = {
        { 0, true },
        { 0, false },
        { 1, true },
        { 1, false },
        { 2, true },
        { 2, false },
        { .terminator = true },
    };

    result |= test_sequence_from_zero_expecting(small_linear, 3, 0) << 0;

    struct number small_with_gap[] = {
        { 0, true },
        { 0, false },
        { 2, true },
        { 2, false },
        { .terminator = true },
    };

    result |= test_sequence_from_zero_expecting(small_with_gap, 1, 0x80000000) << 1;

    // Large enough to occupy even the highest bytes
    uint64_t high = introduce_error ? 0 : 70000000000;

    struct number warp_up[] = {
        { 0, true },
        { 0, false },
        { 2, true },
        { 2, false },
        { high, true },
        { high, false },
        { high - 10, true },
        { high - 10, false },
        // Just below the limit
        { high - 33, false },
        { high - 32, true },
        { high - 32, false },
        { high + 10, true },
        { high + 10, false },
        // Freshly below the limit
        { high - 30, false },
        { high + 12 - 31, true },
        { high + 12 - 31, false },
        { .terminator = true },
    };

    /* Admittedly, the 0x20100401 value was not explicitly expected but
     * extracted as the currently produced value -- but it seems plausible,
     * having seen a few messages around the limit. */
    result |= test_sequence_from_zero_expecting(warp_up, high + 11 - 32 - 1, 0x20100401) << 2;

    return result;
}
