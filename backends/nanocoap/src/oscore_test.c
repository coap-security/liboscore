#include <net/nanocoap.h>

#include <oscore_native/test.h>

#include <stdlib.h>

#define MESSAGE_DEFAULT_SIZE 1024

static bool is_allocated = false;
static coap_pkt_t the_message;
static oscore_msg_native_t the_enhanced_message;
static uint8_t the_buffer[MESSAGE_DEFAULT_SIZE];

oscore_msg_native_t oscore_test_msg_create(void)
{
    if (is_allocated) {
        abort();
    }

    the_message.hdr = (coap_hdr_t *)the_buffer;
    ssize_t hdr_result = coap_build_hdr(the_message.hdr, COAP_TYPE_NON, NULL, 0, 0, 0);
    if (hdr_result <= 0) {
        abort();
    }
    coap_pkt_init(&the_message, the_buffer, MESSAGE_DEFAULT_SIZE, hdr_result);

    is_allocated = true;

    the_enhanced_message.pkt = &the_message;

    return the_enhanced_message;
}

void oscore_test_msg_destroy(oscore_msg_native_t message)
{
    if (!is_allocated) {
        abort();
    }
    is_allocated = false;

    // As there is only one ever, the argument itself can be ignored.
    (void)message;
}
