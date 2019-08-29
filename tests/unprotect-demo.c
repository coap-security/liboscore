#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <oscore_native/message.h>
#include <oscore_native/test.h>
#include <oscore/protection.h>
#include <oscore/contextpair.h>

int main()
{
    oscore_msgerr_native_t msgerr;

    // The message in C.4
    oscore_msg_native_t msg = oscore_test_msg_create();
    msgerr = oscore_msg_native_append_option(
            msg,
            9,
            (uint8_t*)"\x09\x14",
            2);
    assert(!oscore_msgerr_native_is_error(msgerr));

    uint8_t *payload;
    size_t payload_len;
    oscore_msg_native_map_payload(msg, &payload, &payload_len);
    assert(payload_len >= 13);
    memcpy(payload, "\x61\x2f\x10\x92\xf1\x77\x6f\x1c\x16\x68\xb3\x82\x5e", 13);
    msgerr = oscore_msg_native_trim_payload(msg, 13);
    assert(!oscore_msgerr_native_is_error(msgerr));

    enum oscore_unprotect_request_result oscerr;

    // Uninitialized values to be populated
    oscore_oscoreoption_t header;
    oscore_requestid_t request_id;
    oscore_msg_protected_t unprotected;

    bool found_oscoreoption = false;
    oscore_msg_native_optiter_t iter;
    oscore_msg_native_optiter_init(msg, &iter);
    while (!found_oscoreoption) {
        uint16_t number;
        const uint8_t *value;
        size_t value_length;
        bool next_exists = oscore_msg_native_optiter_next(msg, &iter, &number, &value, &value_length);
        if (!next_exists) {
            break;
        }
        if (number == 9) {
            found_oscoreoption = true;
            bool parsed = oscore_oscoreoption_parse(&header, value, value_length);
            assert(parsed);
        }
    }
    assert(found_oscoreoption);

    oscore_context_t *secctx = NULL;
    oscerr = oscore_unprotect_request(msg, &unprotected, header, secctx, &request_id);

    assert(oscerr == OSCORE_UNPROTECT_REQUEST_DUPLICATE);

    oscore_test_msg_destroy(msg);
    return 0;
}
