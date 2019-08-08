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
            12,
            (uint8_t*)"",
            0);
    assert(!oscore_msgerr_native_is_error(err));

    // Don't be confused if things start to break here: This test is violating
    // the options-in-sequence requirement, and any directly serializing
    // library will fail here

    err = oscore_msg_native_append_option(
            msg,
            11,
            (uint8_t*)".well-known",
            11);
    assert(!oscore_msgerr_native_is_error(err));

    err = oscore_msg_native_append_option(
            msg,
            11,
            (uint8_t*)"XXXX",
            4);
    assert(!oscore_msgerr_native_is_error(err));

    err = oscore_msg_native_update_option(
        msg,
        11,
        1,
        (uint8_t*)"core",
        4);
    assert(!oscore_msgerr_native_is_error(err));

    uint8_t *payload;
    size_t payload_len;
    oscore_msg_native_map_payload(msg, &payload, &payload_len);
    assert(payload_len > 3);
    memcpy(payload, "odd to set a payload on a GET", 3);
    err = oscore_msg_native_trim_payload(msg, 3);
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
    assert(number == 12);
    assert(value_length == 0);

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

    uint8_t *out_payload;
    size_t out_payload_len;
    oscore_msg_native_map_payload(msg, &out_payload, &out_payload_len);
    assert(out_payload_len == 3);
    assert(memcmp(out_payload, "odd", 3) == 0);

    oscore_test_msg_destroy(msg);

    return returned == 1 ? 0 : 1;
}
