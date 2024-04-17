#include <stdio.h>
#include <oscore_native/platform.h>

#define returning_assert(cond) if(!(cond)) { return 1; }

#include <oscore_native/message.h>
#include <oscore_native/test.h>

int testmain(int introduce_error)
{
    oscore_msgerr_native_t err;

    oscore_msg_native_t msg = oscore_test_msg_create();
    oscore_msg_native_set_code(msg, 1 /* GET */);

    err = oscore_msg_native_append_option(
            msg,
            11,
            (uint8_t*)".well-known",
            11);
    returning_assert(!oscore_msgerr_native_is_error(err));

    err = oscore_msg_native_append_option(
            msg,
            11,
            (uint8_t*)"XXXX",
            4);
    returning_assert(!oscore_msgerr_native_is_error(err));

    err = oscore_msg_native_update_option(
        msg,
        11,
        1,
        (uint8_t*)"core",
        4 - (introduce_error == 1));
    returning_assert(!oscore_msgerr_native_is_error(err));

    err = oscore_msg_native_append_option(
            msg,
            12,
            (uint8_t*)"",
            0);
    returning_assert(!oscore_msgerr_native_is_error(err));

    uint8_t *payload;
    size_t payload_len;
    oscore_msg_native_map_payload(msg, &payload, &payload_len);
    returning_assert(payload_len > 3);
    memcpy(payload, "odd to set a payload on a GET", 3);
    err = oscore_msg_native_trim_payload(msg, 3);
    returning_assert(!oscore_msgerr_native_is_error(err));

    // enough added, now verify it can be read back

    uint8_t returned = oscore_msg_native_get_code(msg);
    returning_assert(returned == 1 /* GET */);

    oscore_msg_native_optiter_t iter;
    oscore_msg_native_optiter_init(msg, &iter);

    bool next_exists;
    uint16_t number;
    const uint8_t *value;
    size_t value_length;

    next_exists = oscore_msg_native_optiter_next(msg, &iter, &number, &value, &value_length);
    returning_assert(next_exists);
    returning_assert(number == 11);
    returning_assert(value_length == 11);
    returning_assert(memcmp(value, ".well-known", 11) == 0);

    next_exists = oscore_msg_native_optiter_next(msg, &iter, &number, &value, &value_length);
    returning_assert(next_exists);
    returning_assert(number == 11);
    returning_assert(value_length == 4);
    returning_assert(memcmp(value, "core", 4) == 0);

    next_exists = oscore_msg_native_optiter_next(msg, &iter, &number, &value, &value_length);
    returning_assert(next_exists);
    returning_assert(number == 12);
    returning_assert(value_length == 0);

    next_exists = oscore_msg_native_optiter_next(msg, &iter, &number, &value, &value_length);
    returning_assert(!next_exists);

    err = oscore_msg_native_optiter_finish(msg, &iter);
    returning_assert(!oscore_msgerr_native_is_error(err));

    uint8_t *out_payload;
    size_t out_payload_len;
    err = oscore_msg_native_map_payload(msg, &out_payload, &out_payload_len);
    returning_assert(!oscore_msgerr_native_is_error(err));
    returning_assert(out_payload_len == 3);
    returning_assert(memcmp(out_payload, "odd", 3) == 0);

    oscore_test_msg_destroy(msg);

    return returned == 1 ? 0 : 1;
}
