#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <oscore_native/message.h>
#include <oscore_native/test.h>
#include <oscore/protection.h>
#include <oscore/contextpair.h>
#include <oscore/context_impl/primitive.h>
#include <oscore/message.h>

int testmain(int introduce_error)
{
    oscore_msgerr_native_t msgerr;

    struct oscore_context_primitive primitive = {
        .aeadalg = 24,
        .common_iv = "d\xf0\xbd" "1MK\xe0<'\x0c+\x1c",

        .recipient_id_len = 0,
        .recipient_key = "\xd5" "0\x1e\xb1\x8d\x06xI\x95\x08\x93\xba*\xc8\x91" "A|\x89\xae\t\xdfJ8U\xaa\x00\n\xc9\xff\xf3\x87Q",
    };
    oscore_context_t secctx = {
        .type = OSCORE_CONTEXT_PRIMITIVE,
        .data = (void*)(&primitive),
    };

    // A message from plugtest example 1 with ChaCha algorithm
    oscore_msg_native_t msg = oscore_test_msg_create();
    msgerr = oscore_msg_native_append_option(
            msg,
            9,
            (uint8_t*)"\x09\x00",
            2);
    assert(!oscore_msgerr_native_is_error(msgerr));

    uint8_t *payload;
    size_t payload_len;
    oscore_msg_native_map_payload(msg, &payload, &payload_len);
    assert(payload_len >= 32);
    memcpy(payload, "\x5c\x94\xc1\x29\x80\xfd\x93\x68\x4f\x37\x1e\xb2\xf5\x25\xa2\x69\x3b\x47\x4d\x5e\x37\x16\x45\x67\x63\x74\xe6\x8d\x4c\x20\x4a\xdb", 32);
    payload[0] ^= (introduce_error == 1);
    msgerr = oscore_msg_native_trim_payload(msg, 32);
    assert(!oscore_msgerr_native_is_error(msgerr));

    enum oscore_unprotect_request_result oscerr;
    oscore_msgerr_protected_t oscmsgerr;

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

    oscerr = oscore_unprotect_request(msg, &unprotected, header, &secctx, &request_id);

    assert(oscerr == OSCORE_UNPROTECT_REQUEST_OK);

    assert(oscore_msg_protected_get_code(&unprotected) == 1);

    oscore_msg_protected_optiter_t i_iter;
    oscore_msg_protected_optiter_init(&unprotected, &i_iter);
    uint16_t opt_num;
    const uint8_t *opt_val;
    size_t opt_len;

    // Test all options one after the other

    bool next_ok;
    next_ok = oscore_msg_protected_optiter_next(&unprotected, &i_iter, &opt_num, &opt_val, &opt_len);
    assert(next_ok && opt_num == 11 && opt_len == 6 && memcmp(opt_val, "oscore", 6) == 0);
    next_ok = oscore_msg_protected_optiter_next(&unprotected, &i_iter, &opt_num, &opt_val, &opt_len);
    assert(next_ok && opt_num == 11 && opt_len == 5 && memcmp(opt_val, "hello", 5) == 0);
    next_ok = oscore_msg_protected_optiter_next(&unprotected, &i_iter, &opt_num, &opt_val, &opt_len);
    assert(next_ok && opt_num == 11 && opt_len == 1 && *opt_val == '1');
    next_ok = oscore_msg_protected_optiter_next(&unprotected, &i_iter, &opt_num, &opt_val, &opt_len);
    assert(!next_ok);

    oscmsgerr = oscore_msg_protected_optiter_finish(&unprotected, &i_iter);
    assert(!oscore_msgerr_protected_is_error(oscmsgerr));

    uint8_t *p_payload;
    size_t p_payload_len;
    oscmsgerr = oscore_msg_protected_map_payload(&unprotected, &p_payload, &p_payload_len);
    assert(!oscore_msgerr_protected_is_error(oscmsgerr));
    assert(p_payload_len == 0);
    
    oscore_test_msg_destroy(msg);
    return 0;
}
