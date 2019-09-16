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
bool parse_option(
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
 * Reads the current inner option and advances the iterator cursor. If there is
 * no more current option, the current inner option number is set to 0 and
 * nothing else is modified.
 *
 * @param[in] msg Message to iterate over
 * @param[in,out] iter Iterator (cursor) that is read and incremented
 * @param[out] value Data inside the read CoAP option
 * @param[out] value_len Number of bytes inside the read CoAP option
 */
void optiter_inner_next(
        oscore_msg_protected_t *msg,
        oscore_msg_protected_optiter_t *iter,
        const uint8_t **value,
        size_t *value_len
)
{
    uint8_t *payload;
    size_t payload_len;
    oscore_msg_native_map_payload(msg->backend, &payload, &payload_len);

    if (payload_len <= iter->cursor_inner) {
        // End of payload reached
        // should not be reached if optiter_peek_inner_number was used before
        iter->optionnumber_inner = 0;
        return;
    }

    uint16_t delta; // Ignored, treated in optiter_peek_inner_number
    if (parse_option(&payload[iter->cursor_inner], &delta, value, value_len)) {
        iter->cursor_inner = *value - payload + *value_len;
        // Assert that option value does not overrun payload
        assert(payload_len >= iter->cursor_inner);
    } else {
        // Current option is invalid
        // should not be reached if optiter_peek_inner_number was used before
        iter->optionnumber_inner = 0;
    }
}

/**
 * Reads the next inner option number into the iterator without advancing the
 * cursor. If there is none, the number is set to 0.
 */
void optiter_peek_inner_number(
        oscore_msg_protected_t *msg,
        oscore_msg_protected_optiter_t *iter
)
{
    uint8_t *payload;
    size_t payload_len;
    oscore_msg_native_map_payload(msg->backend, &payload, &payload_len);

    if (payload_len <= iter->cursor_inner) {
        // End of payload reached
        iter->optionnumber_inner = 0;
        return;
    }

    uint16_t delta;
    const uint8_t *value; // Ignored, only the delta value is needed
    size_t value_len; // Ignored again
    if (parse_option(&payload[iter->cursor_inner], &delta, &value, &value_len)) {
        iter->optionnumber_inner += delta;
    } else {
        // Current option is invalid
        iter->optionnumber_inner = 0;
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
    iter->cursor_inner = 1;
    iter->optionnumber_inner = 0;
    iter->backend_exhausted = false;
    oscore_msg_native_optiter_init(msg->backend, &iter->backend);
}

bool oscore_msg_protected_optiter_next(
        oscore_msg_protected_t msg,
        oscore_msg_protected_optiter_t *iter,
        uint16_t *option_number,
        const uint8_t **value,
        size_t *value_len
        )
{
    if (iter == NULL) {
        return false;
    }

    if (iter->optionnumber_inner == 0 && iter->backend_exhausted) {
        return false;
    }

    // First time the iterator is used, peek at both inner and outer options
    if (iter->optionnumber_inner == 0 && iter->backend_peeked_optionnumber == 0) {
        optiter_peek_inner_number(&msg, iter);
        iter->backend_exhausted =
                !oscore_msg_native_optiter_next(msg.backend,
                        &iter->backend,
                        &iter->backend_peeked_optionnumber,
                        &iter->backend_peeked_value,
                        &iter->backend_peeked_value_len);
    }

    // Determine next option
    bool next_is_inner = false;
    if (iter->backend_exhausted) {
        if (iter->optionnumber_inner == 0) {
            return false;
        }
        next_is_inner = true;
    } else if (iter->optionnumber_inner > 0) {
        // Return options ordered by option number
        next_is_inner = iter->optionnumber_inner < iter->backend_peeked_optionnumber;
    }

    // Return current inner/outer option and peek at next one.
    if (next_is_inner) {
        *option_number = iter->optionnumber_inner;
        optiter_inner_next(&msg, iter, value, value_len);
        optiter_peek_inner_number(&msg, iter);
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
    uint8_t *native_payload_end = p + native_payload_len;

    p++; // Skip Code

    uint16_t delta; // Ignored
    size_t value_len;
    while (parse_option(p, &delta, (const uint8_t**)&p, &value_len)) {
        p += value_len;
        if (p == native_payload_end) {
            // No Payload
            *payload = NULL;
            *payload_len = 0;
            return;
        }
        assert(p < native_payload_end);
    }
    if (*p == 0xFF) {
        p++; // Skip Payload marker
        *payload = p;
        *payload_len = native_payload_end - p;
    }
}
