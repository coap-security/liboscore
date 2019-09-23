#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <oscore_native/message.h>

uint8_t oscore_msg_native_get_code(oscore_msg_native_t msg)
{
    // The get_code / set_code helpers all try to transform the code into the
    // concatenated decimal form of the dotted representation
    return msg->hdr->code;
}

void oscore_msg_native_set_code(oscore_msg_native_t msg, uint8_t code)
{
    msg->hdr->code = code;
}

oscore_msgerr_native_t oscore_msg_native_append_option(
        oscore_msg_native_t msg,
        uint16_t option_number,
        const uint8_t *value,
        size_t value_len
        )
{
    ssize_t result = coap_opt_add_opaque(msg, option_number, value, value_len);
    if (result > 0)
        return 0;

    return result;
}

bool oscore_msgerr_native_is_error(oscore_msgerr_native_t err)
{
    return err != 0;
}

void oscore_msg_native_optiter_init(oscore_msg_native_t msg,
        oscore_msg_native_optiter_t *iter
        )
{
    // No properties of msg go into the iterator setup as long as it needs the
    // is_first property
    (void)msg;

    iter->is_first = true;
}

bool oscore_msg_native_optiter_next(
        oscore_msg_native_t msg,
        oscore_msg_native_optiter_t *iter,
        uint16_t *option_number,
        const uint8_t **value,
        size_t *value_len
        )
{
    ssize_t length = coap_opt_get_next(
            msg,
            &iter->pos,
            (uint8_t **)value,
            iter->is_first
            );
    if (length < 0) {
        return false;
    }

    *value_len = length;
    *option_number = iter->pos.opt_num;

    iter->is_first = false;

    return true;
}

void oscore_msg_native_optiter_finish(
        oscore_msg_native_t msg,
        oscore_msg_native_optiter_t *iter
        )
{
    // no-op: we didn't allocate anything for iteration
    (void)msg;
    (void)iter;
}

oscore_msgerr_native_t oscore_msg_native_update_option(
        oscore_msg_native_t msg,
        uint16_t option_number,
        size_t option_occurrence,
        const uint8_t *value,
        size_t value_len
        )
{
    coap_optpos_t iter;
    bool is_first = true;
    uint8_t *iter_value;

    while (true) {
        ssize_t length = coap_opt_get_next(
                msg,
                &iter,
                &iter_value,
                is_first
                );
        is_first = false;
        if (length < 0) {
            // Especially, that can be "Not found until end of iteration"
            return length;
        }
        if (iter.opt_num == option_number) {
            if (option_occurrence > 0) {
                option_occurrence -= 1;
            } else {
                // Found

                // length was shown to be positive, so it can be cast into
                // the unsigned type safely
                if (value_len != (size_t)length) {
                    return -EBADMSG;
                }

                // Be liberal and accept user provided NULL values for zero-length references
                if (value_len != 0) {
                    memcpy(iter_value, value, value_len);
                }
                return 0;
            }
        }
    }
}

void oscore_msg_native_map_payload(
        oscore_msg_native_t msg,
        uint8_t **payload,
        size_t *payload_len
        )
{
    *payload = msg->payload;
    *payload_len = msg->payload_len;
}

oscore_msgerr_native_t oscore_msg_native_trim_payload(
        oscore_msg_native_t msg,
        size_t payload_len
        )
{
    if (payload_len > msg->payload_len) {
        return true;
    }

    msg->payload_len = payload_len;
    return false;
}
