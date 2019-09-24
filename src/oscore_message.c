#include <assert.h>
#include <oscore/message.h>
#include <oscore_native/message.h>

typedef enum {
    /** Place this in Class E unconditionally, and refuse to decrypt messages
     * with this as an outer option
     *
     * This includes all Class E+U options like the Block options, as they need
     * to be resolved (and removed) by the underlying CoAP library.
     * */
    ONLY_E,
    // We could also have a "ONLY_E_IGNORE_OUTER" where the iterator silently
    // disregards outer options.

    /** Place this in Class U unconditionally. Inner options of this type are
     * still accepted, and both the outer and inner values are reported when
     * iterating over options. */
    PRIMARILY_U,
    /** Place this in Class I unconditionally, and (by design of the AAD)
     * refuse to decrypt messages where they were altered. Inner options of
     * this type are still accepted, and both the outer and inner values are
     * reported when iterating over options. */
    PRIMARILY_I,

    // We could have an "ONLY_[UI]_IGNORE_INNER", but I don't see where that'd
    // make sense.

    /** None of the slotted behaviors fits, this option needs special care (eg.
     * Observe) */
    HARDCODED,

} option_behavior;

/**
 * Parses a CoAP option. The return value indicates success.
 *
 * @param[in] option A pointer to the option which should be parsed
 * @param[out] delta The delta value (used to calculate the option number) of the option
 * @param[out] value A pointer to the option value
 * @param[out] value_len The length of the option value
 * @return true, if the option was parsed, false if either a payload marker or an invalid byte was encountered
 */
static bool parse_option(
        const uint8_t *option,
        uint16_t *delta,
        const uint8_t **value,
        size_t *value_len
        )
{
    if (*option == 0xFF) {
        return false; // Found payload marker, nothing to do
    }

    uint16_t d = *option >> 4u;
    uint16_t l = *option & 0x0Fu;
    option++;

    if (d == 15 || l == 15) {
        return false; // Protocol error
    }

    if (d == 13) {
        d += *option;
        option += 1;
    } else if (d == 14) {
        d += (option[0] << 8u) + option[1] + 255;
        option += 2;
    }

    if (l == 13) {
        l += *option;
        option += 1;
    } else if (l == 14) {
        l += (option[0] << 8u) + option[1] + 255;
        option += 2;
    }

    *delta = d;
    *value_len = l;
    *value = option;
    return true;
}

/**
 * Reads the next inner option into the iterator, starting from the first if
 * value is NULL initially. If there is none, the value is set to NULL.
 */
static void optiter_peek_inner_option(
        const oscore_msg_protected_t *msg,
        oscore_msg_protected_optiter_t *iter
)
{
    uint8_t *payload;
    size_t payload_len;
    oscore_msg_native_map_payload(msg->backend, &payload, &payload_len);
    payload_len -= msg->tag_length;

    const uint8_t *cursor_inner;
    if (iter->inner_peeked_value == NULL) {
        // If no option was read yet, start at the beginning (2nd byte).
        cursor_inner = payload + 1;
    } else {
        cursor_inner = iter->inner_peeked_value + iter->inner_peeked_value_len;
    }

    if (cursor_inner == payload + payload_len) {
        // End of inner payload reached without payload marker
        iter->inner_peeked_value = NULL;
        return;
    }

    uint16_t delta;
    if (parse_option(
            cursor_inner,
            &delta,
            &iter->inner_peeked_value,
            &iter->inner_peeked_value_len
        )) {
        if (iter->inner_peeked_value_len > (iter->inner_peeked_value - payload) + payload_len) {
            // Option length exceeds payload length, abort immediately
            iter->inner_peeked_value = NULL;
        } else {
            iter->inner_peeked_optionnumber += delta;
        }
    } else {
        // End of inner payload reached with payload marker, or invalid option
        // encountered
        iter->inner_peeked_value = NULL;
    }
}

uint8_t oscore_msg_protected_get_code(oscore_msg_protected_t *msg) {
    uint8_t *payload;
    size_t payload_len;
    oscore_msg_native_map_payload(msg->backend, &payload, &payload_len);

    assert(payload_len);
    return payload[0];
}

void oscore_msg_protected_set_code(oscore_msg_protected_t *msg, uint8_t code) {
    uint8_t *payload;
    size_t payload_len;
    oscore_msg_native_map_payload(msg->backend, &payload, &payload_len);

    assert(payload_len);
    payload[0] = code;
}

void oscore_msg_protected_optiter_init(
        oscore_msg_protected_t *msg,
        oscore_msg_protected_optiter_t *iter
        )
{
    iter->inner_peeked_optionnumber = 0;
    iter->inner_peeked_value = NULL;
    iter->backend_exhausted = false;
    oscore_msg_native_optiter_init(msg->backend, &iter->backend);

    // Have a first peek at the options
    optiter_peek_inner_option(msg, iter);
    iter->backend_exhausted = !oscore_msg_native_optiter_next(
            msg->backend,
            &iter->backend,
            &iter->backend_peeked_optionnumber,
            &iter->backend_peeked_value,
            &iter->backend_peeked_value_len);
}

bool oscore_msg_protected_optiter_next(
        oscore_msg_protected_t msg,
        oscore_msg_protected_optiter_t *iter,
        uint16_t *option_number,
        const uint8_t **value,
        size_t *value_len
        )
{
    if (iter->inner_peeked_value == NULL && iter->backend_exhausted) {
        return false;
    }

    // Determine next option
    bool next_is_inner;
    if (iter->backend_exhausted) {
        next_is_inner = true;
    } else if (iter->inner_peeked_value == NULL) {
        next_is_inner = false;
    } else {
        // Return options ordered by option number
        next_is_inner = iter->inner_peeked_optionnumber <
                iter->backend_peeked_optionnumber;
    }

    // Return current inner/outer option and peek at next one.
    if (next_is_inner) {
        *option_number = iter->inner_peeked_optionnumber;
        *value = iter->inner_peeked_value;
        *value_len = iter->inner_peeked_value_len;
        optiter_peek_inner_option(&msg, iter);
    } else {
        *option_number = iter->backend_peeked_optionnumber;
        *value = iter->backend_peeked_value;
        *value_len = iter->backend_peeked_value_len;
        iter->backend_exhausted =
                !oscore_msg_native_optiter_next(msg.backend,
                        &iter->backend,
                        &iter->backend_peeked_optionnumber,
                        &iter->backend_peeked_value,
                        &iter->backend_peeked_value_len);
    }

    return true;
}

void oscore_msg_protected_optiter_finish(
        oscore_msg_protected_t msg,
        oscore_msg_protected_optiter_t *iter
        )
{
    oscore_msg_native_optiter_finish(msg.backend, &iter->backend);
}

void oscore_msg_protected_map_payload(
        oscore_msg_protected_t *msg,
        uint8_t **payload,
        size_t *payload_len
        )
{
    uint8_t *p;
    size_t native_payload_len;
    oscore_msg_native_map_payload(msg->backend, &p, &native_payload_len);
    uint8_t *native_payload_end = p + (native_payload_len - msg->tag_length);

    p++; // Skip Code

    uint16_t delta; // Ignored
    size_t value_len;
    while (parse_option(p, &delta, (const uint8_t**)&p, &value_len)) {
        p += value_len;
        if (p >= native_payload_end) {
            // No Payload (but possibly over-long option)
            // FIXME: for the over-long option part, see below about error cases
            *payload = native_payload_end;
            *payload_len = 0;
            return;
        }
    }
    if (*p == 0xFF) {
        p++; // Skip Payload marker
        *payload = p;
        *payload_len = native_payload_end - p;
    } else {
        // FIXME: This is an error case, but the API does not allow passing
        // errors back here -- primarily because an application can not
        // reliably make sense of the payload before having gone through all
        // (possibly critical) options, in which case the error would have
        // popped up earlier. (Possible mitigations: API change, documentation
        // pointing to previous option iteration)
        *payload = p;
        *payload_len = 0;
    }
}
