#include <assert.h>
#include <string.h>
#include <oscore/message.h>
#include <oscore_native/message.h>

typedef enum {
    /** Place this in Class E unconditionally, and refuse to decrypt messages
     * with this as an outer option
     *
     * This includes all Class E+U options like the Block options or Echo, as
     * they need to be resolved (and removed) by the underlying CoAP library.
     * */
    ONLY_E,

    /** Place this in Class E unconditionally. If it turns up as outer options,
     * they are silently ignored.
     *
     * This includes options that are added for the benefit of, or by,
     * intermediaries, like the Max-Age and the ETag option.
     *
     * For backends that do not strip options like Block1 or Block2 on outer
     * reassembly but leave any of them in the reassembled messages, those
     * options can be classified as ``ONLY_E_IGNORE_OUTER``; that is not done
     * in general, as the presence of an outer Block option usually indicates
     * that no reassembly was executed, and unprotection of the partial message
     * is bound to fail.
     */
    ONLY_E_IGNORE_OUTER,

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
 * Returns the behaviour (U, I, E, special) for a given option number.
 */
static option_behavior get_option_behaviour(uint16_t option_number) {
    switch (option_number) {
        case 1: // If-Match
        case 5: // If-None-Match
        case 8: // Location-Path
        case 11: // Uri-Path
        case 12: // Content-Format
        case 15: // Uri-Query
        case 17: // Accept
        case 20: // Location-Query
        case 23: // Block2
        case 27: // Block1
        case 28: // Size2
        case 60: // Size1
            return ONLY_E;
        case 4: // ETag
        case 14: // Max-Age
            return ONLY_E_IGNORE_OUTER;
        case 3: // Uri-Host
        case 7: // Uri-Port
        case 39: // Proxy-Scheme
            return PRIMARILY_U;
        case 6: // Observe
        case 9: // OSCORE
        case 35: // Proxy-Uri
        case 258: // No-Response
            return HARDCODED;
        default:
            return HARDCODED;
    }
}

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

uint8_t oscore_msg_protected_get_code(oscore_msg_protected_t *msg)
{
    uint8_t *payload;
    size_t payload_len;
    oscore_msg_native_map_payload(msg->backend, &payload, &payload_len);

    assert(payload_len);
    return payload[0];
}

void oscore_msg_protected_set_code(oscore_msg_protected_t *msg, uint8_t code)
{
    uint8_t *payload;
    size_t payload_len;
    oscore_msg_native_map_payload(msg->backend, &payload, &payload_len);

    assert(payload_len);
    payload[0] = code;
}

oscore_msgerr_protected_t oscore_msg_protected_append_option(
        oscore_msg_protected_t *msg,
        uint16_t option_number,
        const uint8_t *value,
        size_t value_len
        )
{
    option_behavior behavior = get_option_behaviour(option_number);
    if (behavior == PRIMARILY_U) {
        oscore_msgerr_native_t err = oscore_msg_native_append_option(
                msg->backend,
                option_number,
                value,
                value_len
        );
        return oscore_msgerr_native_is_error(err) ? NATIVE_ERROR : OK;
    } else if (behavior == ONLY_E || behavior == ONLY_E_IGNORE_OUTER) {
        // FIXME: append inner option.
        //  Detect overrun into payload with payload marker - but what if there
        //  isn't any payload yet? Should oscore_msg_protected_map_payload
        //  create the marker once the payload is accessed?
        (void)value; // prevent identical branch warning
        return NOTIMPLEMENTED_ERROR;
    } else {
        // FIXME: handle special options
        return NOTIMPLEMENTED_ERROR;
    }
}

oscore_msgerr_protected_t oscore_msg_protected_update_option(
        oscore_msg_protected_t *msg,
        uint16_t option_number,
        size_t option_occurrence,
        const uint8_t *value,
        size_t value_len
        )
{
    option_behavior behavior = get_option_behaviour(option_number);
    if (behavior == PRIMARILY_U) {
        oscore_msgerr_native_t err = oscore_msg_native_update_option(
                msg->backend,
                option_number,
                option_occurrence,
                value,
                value_len
        );
        return oscore_msgerr_native_is_error(err) ? NATIVE_ERROR : OK;
    } else if (behavior == ONLY_E || behavior == ONLY_E_IGNORE_OUTER) {
        oscore_msg_protected_optiter_t iter = {
                .inner_peeked_optionnumber = 0,
                .inner_peeked_value = NULL
        };
        while (true) {
            optiter_peek_inner_option(msg, &iter);
            if (iter.inner_peeked_value == NULL) {
                // Requested option was not found
                return INVALID_ARG_ERROR;
            }
            if (iter.inner_peeked_optionnumber != option_number) {
                continue;
            }

            if (option_occurrence == 0) {
                // Requested option found, now check the length
                if (value_len != iter.inner_peeked_value_len) {
                    return INVALID_ARG_ERROR;
                }
                memcpy((uint8_t *)iter.inner_peeked_value, value, value_len);
                return OK;
            }
            option_occurrence--;
        }
    } else {
        // FIXME: handle special options
        return NOTIMPLEMENTED_ERROR;
    }
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

oscore_msgerr_protected_t oscore_msg_protected_trim_payload(
        oscore_msg_protected_t *msg,
        size_t payload_len
        )
{
    uint8_t *p;
    size_t inner_payload_len;
    oscore_msg_protected_map_payload(msg, &p, &inner_payload_len);

    if (payload_len > inner_payload_len) {
        // Cannot extend the payload
        return INVALID_ARG_ERROR;
    }
    if (payload_len == inner_payload_len) {
        // Nothing to do
        return OK;
    }

    size_t native_payload_len;
    oscore_msg_native_map_payload(msg->backend, &p, &native_payload_len);
    native_payload_len -= inner_payload_len - payload_len;
    oscore_msgerr_native_t err;
    err = oscore_msg_native_trim_payload(msg->backend, native_payload_len);
    return oscore_msgerr_native_is_error(err) ? NATIVE_ERROR : OK;
}

bool oscore_msgerr_protected_is_error(oscore_msgerr_protected_t error)
{
    return error != OK;
}
