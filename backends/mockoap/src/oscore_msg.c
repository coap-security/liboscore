#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <oscore_native/message.h>

uint8_t oscore_msg_native_get_code(oscore_msg_native_t msg)
{
    return msg->code;
}

void oscore_msg_native_set_code(oscore_msg_native_t msg, uint8_t code)
{
    msg->code = code;
}

oscore_msgerr_native_t oscore_msg_native_append_option(
        oscore_msg_native_t msg,
        uint16_t option_number,
        const uint8_t *value,
        size_t value_len
        )
{
    struct mock_opt *opt = malloc(sizeof(struct mock_opt));
    assert(opt != NULL);
    uint8_t *opt_data = malloc(value_len);
    assert(opt_data != NULL);

    memcpy(opt_data, value, value_len);

    opt->next = NULL;
    opt->number = option_number;
    opt->data = opt_data;
    opt->data_len = value_len;

    uint16_t last_number = 0;

    struct mock_opt **ptr = &msg->option;
    while (*ptr != NULL) {
        last_number = (*ptr)->number;
        ptr = &(*ptr)->next;
    }
    *ptr = opt;

    if (last_number > option_number) {
        fprintf(stderr, "mockoap warning: Options were not added in sequence\n");
    }

    // never fails -- we just assert our memory
    return false;
}

bool oscore_msgerr_native_is_error(oscore_msgerr_native_t err)
{
    return err;
}

void oscore_msg_native_optiter_init(oscore_msg_native_t msg,
        oscore_msg_native_optiter_t *iter
        )
{
    *iter = msg->option;
}

bool oscore_msg_native_optiter_next(
        oscore_msg_native_t msg,
        oscore_msg_native_optiter_t *iter,
        uint16_t *option_number,
        const uint8_t **value,
        size_t *value_len
        )
{
    if (*iter == NULL) {
        return false;
    }

    struct mock_opt *o = *iter;

    *option_number = o->number;
    *value = o->data;
    *value_len = o->data_len;

    *iter = o->next;

    return true;
}

void oscore_msg_native_optiter_finish(
        oscore_msg_native_t msg,
        oscore_msg_native_optiter_t *iter
        )
{
    // no-op: we didn't allocate anything for iteration
}

oscore_msgerr_native_t oscore_msg_native_update_option(
        oscore_msg_native_t msg,
        uint16_t option_number,
        size_t option_occurrence,
        const uint8_t *value,
        size_t value_len
        )
{
    size_t remaining = option_occurrence;
    for (struct mock_opt *o = msg->option; o != NULL; o = o->next) {
        if (o->number != option_number) {
            continue;
        }

        if (remaining > 0) {
            remaining -= 1;
            continue;
        }

        if (o->data_len != value_len) {
            return true;
        }

        memcpy(o->data, value, value_len);
        return false;
    }
    return true;
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
