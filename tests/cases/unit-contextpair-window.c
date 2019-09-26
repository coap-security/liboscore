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
        .partial_iv = {(seqno << 32) & 0xff, (seqno << 24) & 0xff, (seqno << 16) & 0xff, (seqno << 8) & 0xff, seqno & 0xff},
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

static void test_from_0()
{
    struct oscore_context_primitive primitive = {
        .replay_window_left_edge = 0,
    };
    oscore_context_t secctx = {
        .type = OSCORE_CONTEXT_PRIMITIVE,
        .data = (void*)(&primitive),
    };

    struct number numbers[] = {
        { 0, true },
        { 0, false },
        { 1, true },
        { 1, false },
        { .terminator = true },
    };

    test_sequence(&secctx, numbers);
}

int testmain(int introduce_error)
{
    test_from_0();

    return 0;
}
