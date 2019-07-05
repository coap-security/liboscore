#include <oscore/message.h>

uint8_t oscore_msg_native_get_code(oscore_msg_native_t *msg)
{
    return msg->code;
}

void oscore_msg_native_set_code(oscore_msg_native_t *msg, uint8_t code)
{
    msg->code = code;
}
