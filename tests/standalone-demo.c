#include <stdio.h>
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

    uint8_t returned = oscore_msg_native_get_code(msg);
    printf("Code fetched back as %d\n", returned);

    oscore_test_msg_destroy(msg);

    return returned == 1 ? 0 : 1;
}
