#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <oscore_native/message.h>
#include <oscore_native/test.h>

int main()
{
    oscore_msgerr_native_t err;

    oscore_msg_native_t msg = oscore_test_msg_create();
    oscore_msg_native_set_code(msg, 1 /* GET */);

    err = oscore_msg_native_append_option(
            msg,
            11,
            (uint8_t*)".well-known",
            11);
    assert(!oscore_msgerr_native_is_error(err));

    err = oscore_msg_native_append_option(
            msg,
            11,
            (uint8_t*)"core",
            4);
    assert(!oscore_msgerr_native_is_error(err));

    // enough added, now verify it can be read back

    uint8_t returned = oscore_msg_native_get_code(msg);
    assert(returned == 1 /* GET */);

    oscore_msg_native_optiter_t iter;
    oscore_msg_native_optiter_init(msg, &iter);

    bool next_exists;
    uint16_t number;
    const uint8_t *value;
    size_t value_length;
    next_exists = oscore_msg_native_optiter_next(msg, &iter, &number, &value, &value_length);
    assert(next_exists);
    assert(number == 11);
    assert(value_length == 11);
    assert(memcmp(value, ".well-known", 11) == 0);

    next_exists = oscore_msg_native_optiter_next(msg, &iter, &number, &value, &value_length);
    assert(next_exists);
    assert(number == 11);
    assert(value_length == 4);
    assert(memcmp(value, "core", 4) == 0);

    next_exists = oscore_msg_native_optiter_next(msg, &iter, &number, &value, &value_length);
    assert(!next_exists);

    oscore_msg_native_optiter_finish(msg, &iter);

    oscore_test_msg_destroy(msg);

    return returned == 1 ? 0 : 1;
}
