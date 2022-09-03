#include <stdbool.h>
#include <assert.h>

#include <oscore/contextpair.h>
#include <oscore/context_impl/primitive.h>

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

static void test_sequence(
        oscore_context_t *ctx, 
        struct number *numbers
        )
{
    for (; numbers->terminator == false; ++numbers) {
        oscore_requestid_t id = requestid_from_u64(numbers->seqno);
        oscore_context_strikeout_requestid(ctx, &id);
        assert(id.is_first_use == numbers->expect_success);
    }
}


static void test_sequence_from_zero_expecting(
        struct number *numbers,
        int64_t left_edge,
        uint32_t final_window
        )
{
    struct oscore_context_primitive primitive = {
        .replay_window_left_edge = 0,
    };
    oscore_context_t secctx = {
        .type = OSCORE_CONTEXT_PRIMITIVE,
        .data = (void*)(&primitive),
    };

    test_sequence(&secctx, numbers);
}

int testmain(int introduce_error)
{
    (void) introduce_error;

    struct number small_linear[] = {
        { 0, true },
        { 0, false },
        { 1, true },
        { 1, false },
        { 2, true },
        { 2, false },
        { .terminator = true },
    };

    test_sequence_from_zero_expecting(small_linear, 3, 0);

    struct number small_with_gap[] = {
        { 0, true },
        { 0, false },
        { 2, true },
        { 2, false },
        { .terminator = true },
    };

    test_sequence_from_zero_expecting(small_with_gap, 1, 0x80000000);

    // Large enough to occupy even the highest bytes
    uint64_t high = 70000000000;

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

    test_sequence_from_zero_expecting(warp_up, high + 11 - 32, 0x80000000);

    return 0;
}
