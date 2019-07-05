#include <stdio.h>

#include <oscore/message.h>
#include <oscore/test.h>

int main()
{
    oscore_msg_native_t *msg = oscore_test_msg_create();
    oscore_msg_native_set_code(msg, 1 /* GET */);
    uint8_t returned = oscore_msg_native_get_code(msg);
    printf("Code fetched back as %d", returned);

    return returned == 1 ? 0 : 1;
}
