#include <assert.h>
#include <string.h>
#include <oscore/message.h>
#include <oscore_native/message.h>

enum option_behavior {
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

};

/**
 * Returns the behaviour (U, I, E, special) for a given option number.
 */
static enum option_behavior get_option_behaviour(uint16_t option_number) {
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
        case 258: // No-Response
        case 252: // Echo
            return ONLY_E_IGNORE_OUTER;
        case 3: // Uri-Host
        case 7: // Uri-Port
        case 39: // Proxy-Scheme
            return PRIMARILY_U;
        case 6: // Observe
        case 9: // OSCORE
        case 35: // Proxy-Uri
            return HARDCODED;
        default:
            return HARDCODED;
    }
}

/** Maximum option number (for use with @ref flush_autooptions_*_until) */
#define OPTNUM_MAX 0xffff

#define OPTPART_OFFSET_1BYTE 13
#define OPTPART_OFFSET_2BYTE 269
#define OPTPART_FLAG_1BYTE 13
#define OPTPART_FLAG_2BYTE 14

/** Length of the extended option delta or option length encoding for the given
 * @p value */
static uint8_t _optpart_length(uint16_t value) {
    return (value >= OPTPART_OFFSET_1BYTE) + (value >= OPTPART_OFFSET_2BYTE);
}

/** Encode an option @p delta and a @p size into a @p buffer, and return the
 * number of bytes written (which is `1 + _optpart_length(delta) +
 * _optpart_length(size)`) */
static size_t _optparts_encode(uint8_t *buffer, uint16_t delta, uint16_t size) {
    uint8_t deltalen = _optpart_length(delta);
    uint8_t sizelen = _optpart_length(size);

    uint8_t *startbuffer = buffer;
    buffer ++;

    switch (deltalen) {
        case 0:
            *startbuffer = delta << 4;
            break;
        case 1:
            *startbuffer = OPTPART_FLAG_1BYTE << 4;
            delta -= OPTPART_OFFSET_1BYTE;
            *buffer++ = delta;
            break;
        case 2:
            *startbuffer = OPTPART_FLAG_2BYTE << 4;
            delta -= OPTPART_OFFSET_2BYTE;
            *buffer++ = delta >> 8;
            *buffer++ = delta;
            break;
    }
    switch (sizelen) {
        case 0:
            *startbuffer |= size;
            break;
        case 1:
            *startbuffer |= OPTPART_FLAG_1BYTE;
            size -= OPTPART_OFFSET_1BYTE;
            *buffer++ = size;
            break;
        case 2:
            *startbuffer |= OPTPART_FLAG_2BYTE;
            size -= OPTPART_OFFSET_2BYTE;
            *buffer++ = size >> 8;
            *buffer++ = size;
            break;
    }
    return buffer - startbuffer;
}

/** Like @ref oscore_msg_protected_append_option, but without flushing any
 * autooptions, and going into an inner option unconditionally.
 *
 * This is not currently public, but may be eligible for the public API with
 * the adequate warnings about preferably using the regular append_option. */
oscore_msgerr_protected_t oscore_msg_protected_append_option_inner(
        oscore_msg_protected_t *msg,
        uint16_t option_number,
        const uint8_t *value,
        size_t value_len
        )
{
        if (option_number < msg->class_e.option_number) {
            return OPTION_SEQUENCE;
        }
        if (msg->payload_offset != 0) {
            // FIXME (but probably more "extend me"): Allow this case, set the
            // payload_offset right after, and move any existing memory. (That
            // should be optional, as this behavior is sufficient in most
            // applications other than OSCORE-in-OSCORE).
            return OPTION_SEQUENCE;
        }

        uint8_t *payload;
        size_t payload_length;
        oscore_msgerr_native_t err = oscore_msg_native_map_payload(msg->backend, &payload, &payload_length);
        if (oscore_msgerr_native_is_error(err)) {
            return NATIVE_ERROR;
        }

        uint16_t delta = option_number - msg->class_e.option_number;
        size_t total_length = value_len + 1 + \
                              _optpart_length(delta) + \
                              _optpart_length(value_len);

        if (
                /* can't be expressed in encoded options */
                value_len > UINT16_MAX
                ||
                /* overflow occurred -- after the above, this can only happen where size_t == uint16_t */
                total_length < value_len
                ||
                /* Regular 'option too long' */
                total_length > payload_length - msg->class_e.cursor - 1
                ) {
            return OPTION_SIZE;
        }
        size_t opthead = _optparts_encode(&payload[1 + msg->class_e.cursor], delta, value_len);
        if (value_len) {
            memcpy(&payload[1 + msg->class_e.cursor + opthead], value, value_len);
        }

        msg->class_e.cursor += opthead + value_len;
        msg->class_e.option_number = option_number;
        return OK;
}

/** @brief Set autogenerated outer options on a message up to and including a given number
 *
 * @param[inout] msg The message to work on
 * @param[in] optnum The option number up to and including which all autogenerated options will be written
 * @return OK if the option(s) could be added, any error depending on the failure cause
 *
 * This starts the generation of outer options in a message up to
 * the a given point, and is typically called when a library user appends a
 * higher outer option then the last written one. In particular, this generates
 *
 * * the OSCORE option
 * */
OSCORE_NONNULL
oscore_msgerr_protected_t flush_autooptions_outer_until(oscore_msg_protected_t *msg, uint16_t optnum)
{
    // FIXME this will be used both by protection.c and oscore_message.c, and
    // thus finally does need the introduction of a private header section (or
    // having private functions in the general headers)

    if (msg->flags & OSCORE_MSG_PROTECTED_FLAG_PENDING_OSCORE && optnum >= 9) {
        msg->flags &= ~OSCORE_MSG_PROTECTED_FLAG_PENDING_OSCORE;

        // Write OSCORE option

        uint8_t optionbuffer[1 + PIV_BYTES + 1 + OSCORE_KEYIDCONTEXT_MAXLEN + OSCORE_KEYID_MAXLEN];
        size_t optionlength = 0;

        uint8_t n;
        oscore_requestid_t *piv_source;
        if (msg->request_id.is_first_use && !(msg->flags & OSCORE_MSG_PROTECTED_FLAG_REQUEST)) {
            n = 0;
        } else {
            piv_source = msg->request_id.is_first_use ? &msg->request_id : &msg->partial_iv;
            n = piv_source->used_bytes;
        }
        // In multicast responses, that'd be set as well.
        // FIXME any other situation? probably context dependent -- ask context?
        bool k = msg->flags & OSCORE_MSG_PROTECTED_FLAG_REQUEST;

        // FIXME ask context for kidcontext
        bool h = 0;

        optionbuffer[0] = n | (k << 3) | (h << 4);
        optionlength = 1;
        if (n != 0) {
            memcpy(&optionbuffer[optionlength], &piv_source->bytes[PIV_BYTES - n], n);
            optionlength += n;
        }

        assert(h == 0); // set s and kid context here

        if (k) {
            const uint8_t *kid;
            size_t kid_length;
            oscore_context_get_kid(msg->secctx, OSCORE_ROLE_SENDER, &kid, &kid_length);
            memcpy(&optionbuffer[optionlength], kid, kid_length);
            optionlength += kid_length;
        }

        if (optionlength == 1 && optionbuffer[0] == 0) {
            // The typical response option is encoded in zero length
            optionlength = 0;
        }

        oscore_msgerr_native_t err;
        err = oscore_msg_native_append_option(msg->backend, 9, optionbuffer, optionlength);
        if (oscore_msgerr_native_is_error(err))
            return NATIVE_ERROR;
    }

    return OK;
}

/** @brief Set autogenerated inner options on a message up to and including a given number
 *
 * @param[inout] msg The message to work on
 * @param[in] optnum The option number up to and including which all autogenerated options will be written
 * @return OK if the option(s) could be added, any error depending on the failure cause
 *
 * This starts the generation of inner options in a message up to
 * the a given point, and is typically called when a library user appends a
 * higher inner option then the last written one. In particular, this generates
 *
 * * the inner Observe option
 * */
OSCORE_NONNULL
oscore_msgerr_protected_t flush_autooptions_inner_until(oscore_msg_protected_t *msg, uint16_t optnum)
{
    if (msg->flags & (OSCORE_MSG_PROTECTED_FLAG_PENDING_OBSERVE_0 | OSCORE_MSG_PROTECTED_FLAG_PENDING_OBSERVE_1)
            && optnum >= 9)
    {
        msg->flags &= ~(OSCORE_MSG_PROTECTED_FLAG_PENDING_OBSERVE_0 | OSCORE_MSG_PROTECTED_FLAG_PENDING_OBSERVE_1);

        // Write inner Observe option as requested by flags

        // The same buffer can be used either way; to emit a value 0, it's just
        // used at zero length.
        static uint8_t optionbuffer[] = {1};
        size_t optionlength = (msg->flags & OSCORE_MSG_PROTECTED_FLAG_PENDING_OBSERVE_1) ? 1 : 0;

        oscore_msgerr_native_t err;
        err = oscore_msg_protected_append_option_inner(msg, 6 /* Observe */, optionbuffer, optionlength);
        if (oscore_msgerr_native_is_error(err))
            return NATIVE_ERROR;
    }

    return OK;
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

/** Indicate in the given @msg that the inner payload starts @length bytes into
 * the outer payload.
 *
 * This can be called whenever the length of the inner options becomes known
 * through iteration.
 */
// FIXME: This has a side effect even if it is not wanted, which when the
// protected message's options are iterated over before payload is intended to
// be added (eg. when updating an option before rendering the payload).
// Consider catering for that, eg. by using a different sentinel payload_offset
// in writable messages and only replacing it with the "please populate me" 0
// sentinel at oscore_msg_protected_map_payload time.
static void optiter_maybe_set_payload_length(
        oscore_msg_protected_t *msg,
        size_t length
        )
{
    if (msg->payload_offset == 0) {
        msg->payload_offset = length;
    } else {
        assert(length == msg->payload_offset);
    }
}

/**
 * Reads the next inner option into the iterator, starting from the first if
 * value is NULL initially. If there is none, the value is set to NULL.
 */
// FIXME Will this properly stop in a writable message?
static void optiter_peek_inner_option(
        oscore_msg_protected_t *msg,
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
        iter->inner_termination_reason = OK;

        optiter_maybe_set_payload_length(msg, payload_len);
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
            iter->inner_termination_reason = INVALID_INNER_OPTION;
        } else {
            iter->inner_peeked_optionnumber += delta;
        }
    } else {
        // End of inner payload reached with payload marker, or invalid option
        // encountered
        iter->inner_peeked_value = NULL;
        if (*cursor_inner == 0xff) {
            iter->inner_termination_reason = OK;

            optiter_maybe_set_payload_length(msg, cursor_inner + 1 - payload);
        } else {
            iter->inner_termination_reason = INVALID_INNER_OPTION;
        }
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
    oscore_msgerr_protected_t flusherr;

    enum option_behavior behavior = get_option_behaviour(option_number);
    if (behavior == PRIMARILY_U || option_number == 6 /* Observe */) {
        flusherr = flush_autooptions_outer_until(msg, option_number);
        if (flusherr != OK) {
            return flusherr;
        }

        if (option_number == 6) {
            /* Store the data to be flushed later with the autooptions */
            if (value_len == 0 || !(msg->flags & OSCORE_MSG_PROTECTED_FLAG_REQUEST)) {
                /* In responses, the inner value is always 0 */
                msg->flags |= OSCORE_MSG_PROTECTED_FLAG_PENDING_OBSERVE_0;
            } else {
                /* It's an observe cancellation */
                msg->flags |= OSCORE_MSG_PROTECTED_FLAG_PENDING_OBSERVE_1;
            }
        }

        oscore_msgerr_native_t err = oscore_msg_native_append_option(
                msg->backend,
                option_number,
                value,
                value_len
        );
        return oscore_msgerr_native_is_error(err) ? NATIVE_ERROR : OK;
    } else if (behavior == ONLY_E || behavior == ONLY_E_IGNORE_OUTER) {
        flusherr = flush_autooptions_inner_until(msg, option_number);
        if (flusherr != OK) {
            return flusherr;
        }

        return oscore_msg_protected_append_option_inner(msg, option_number, value, value_len);
    } else {
        // FIXME: handle special options
        return NOTIMPLEMENTED_ERROR;
    }
}

// FIXME: This will only work if the options have been put in here by the
// library (which is typically the case for being-sent messages that are the
// ones being updated as well). That may not even need to be changed, just
// documented.
oscore_msgerr_protected_t oscore_msg_protected_update_option(
        oscore_msg_protected_t *msg,
        uint16_t option_number,
        size_t option_occurrence,
        const uint8_t *value,
        size_t value_len
        )
{
    enum option_behavior behavior = get_option_behaviour(option_number);
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
        // Actually we only need those values, consider making them into a
        // separate struct and making optiter_peek_inner_option take a pointer
        // to that -- but that's more a small optimization rather than a FIXME
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
                if (value_len != 0) {
                    memcpy((uint8_t *)iter.inner_peeked_value, value, value_len);
                } else {
                    // Updating a known-to-be zero-length option with new empty
                    // values is admittedly unexpected, but the condition is
                    // still in here to avoid UB when it does happen -- and
                    // user-facing interfaces are documented to be tolerant of
                    // zero-length NULL arrays.
                }
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
    // No need to set inner_termination_reason here as
    // optiter_peek_inner_option does not access it but will set it one way or
    // the other
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

/** Set all iterator and message properties to the given error reasons, and
 * return like oscore_msg_protected_optiter_next should after having
 * encountered such an error */
static bool optiter_abort(
        oscore_msg_protected_t *msg,
        oscore_msg_protected_optiter_t *iter,
        oscore_msgerr_protected_t reason
        )
{
    // Not storing the error anyhere
    (void)msg;

    iter->backend_exhausted = true;
    iter->inner_peeked_value = NULL;
    iter->inner_termination_reason = reason;

    return false;
}

bool oscore_msg_protected_optiter_next(
        oscore_msg_protected_t *msg,
        oscore_msg_protected_optiter_t *iter,
        uint16_t *option_number,
        const uint8_t **value,
        size_t *value_len
        )
{
    while (true) {
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

        if (next_is_inner) {
            *option_number = iter->inner_peeked_optionnumber;
        } else {
            *option_number = iter->backend_peeked_optionnumber;
        }

        enum option_behavior class = get_option_behaviour(*option_number);
        bool skip = false;
        // Default behvior is not to skip but to emit; common behaviors are to
        // skip the option, or to abort iteration altogether.
        switch (class) {
        case ONLY_E:
            if (!next_is_inner) {
                return optiter_abort(msg, iter, INVALID_OUTER_OPTION);
            }
            break;
        case ONLY_E_IGNORE_OUTER:
            if (!next_is_inner) {
                skip = true;
            };
            break;
        case PRIMARILY_U:
        case PRIMARILY_I:
            break;
        case HARDCODED:
            switch (*option_number) {
            case 6: // Observe
                if (next_is_inner) {
                    // FIXME let responders peek into the sequence number
                } else {
                    skip = true;
                }
                break;
            case 9: // OSCORE
                if (next_is_inner) {
                    // Nested OSCORE is not allowed per specification
                    return optiter_abort(msg, iter, INVALID_INNER_OPTION);
                } else {
                    skip = true;
                }
                break;
            case 35: // Proxy-Uri
                // Might be kind of acceptable as an inner option, but it's not
                // specified that way
                return optiter_abort(msg, iter, INVALID_OUTER_OPTION);
            default:
                return optiter_abort(msg, iter, NOTIMPLEMENTED_ERROR);
            }
            break;
        }

        if (!skip) {
            // Return current inner/outer option
            if (next_is_inner) {
                *value = iter->inner_peeked_value;
                *value_len = iter->inner_peeked_value_len;
            } else {
                *value = iter->backend_peeked_value;
                *value_len = iter->backend_peeked_value_len;
            }
            // ... but don't actually *return* yet as the peeking still has to be done
        }

        // Peek at next one.
        if (next_is_inner) {
            optiter_peek_inner_option(msg, iter);
        } else {
            iter->backend_exhausted =
                    !oscore_msg_native_optiter_next(msg->backend,
                            &iter->backend,
                            &iter->backend_peeked_optionnumber,
                            &iter->backend_peeked_value,
                            &iter->backend_peeked_value_len);
        }

        if (!skip) {
            return true;
        }
    }
}

oscore_msgerr_protected_t oscore_msg_protected_optiter_finish(
        oscore_msg_protected_t *msg,
        oscore_msg_protected_optiter_t *iter
        )
{
    oscore_msgerr_native_t native_error;
    native_error = oscore_msg_native_optiter_finish(msg->backend, &iter->backend);
    if (oscore_msgerr_native_is_error(native_error)) {
        // This is rather unlikely to happen given that by the time OSCORE
        // processing has started, the underlying message's plaintext has
        // already been mapped successfully, and with the current CoAP
        // encodings the backend's options must have been parsable in order to
        // find that, but asserting this here would cause applications to
        // presumably successfully read options from messages transported on
        // future CoAP encodings that might be transported differently.
        return NATIVE_ERROR;
    }

    return iter->inner_peeked_value == NULL ? iter->inner_termination_reason : OK;
}

oscore_msgerr_protected_t oscore_msg_protected_map_payload(
        oscore_msg_protected_t *msg,
        uint8_t **payload,
        size_t *payload_len
        )
{
    oscore_msgerr_native_t err = oscore_msg_native_map_payload(msg->backend, payload, payload_len);
    if (oscore_msgerr_native_is_error(err)) {
        return NATIVE_ERROR;
    }

    if (msg->flags & OSCORE_MSG_PROTECTED_FLAG_WRITABLE) {
        // Code and any written options; inner payload marker not considered as not necessarily present
        size_t start_bytes = 1 + msg->class_e.cursor;
        if (start_bytes + msg->tag_length > *payload_len) {
            return MESSAGESIZE;
        }

        *payload_len -= start_bytes + msg->tag_length;

        if (*payload_len > 0) {
            // Set inner payload marker, and compensate for it
            (*payload)[start_bytes] = 0xff;
            start_bytes += 1;
            *payload_len -= 1;
        }

        *payload += start_bytes;

        // Mark the payload as possibly written-to
        msg->payload_offset = start_bytes;

        return OK;
    }

    if (msg->payload_offset == 0) {
        // Run through the inner options

        // This is a stripped-down version of running through all the options
        // which only reads the inner ones, saving possibly costly calls to the
        // backend library. We only do this for the
        // optiter_maybe_set_payload_length side effect.
        oscore_msg_protected_optiter_t iter = {
                .inner_peeked_optionnumber = 0,
                .inner_peeked_value = NULL
        };
        do {
            optiter_peek_inner_option(msg, &iter);
        } while (iter.inner_peeked_value != NULL);
        if (iter.inner_termination_reason != OK) {
            // Can't map payload if options are unreadable
            return iter.inner_termination_reason;
        }
    }
    assert(msg->payload_offset != 0);

    // Memoized value in place

    size_t total_delta = msg->payload_offset + msg->tag_length;

    assert(total_delta <= *payload_len);
    *payload += msg->payload_offset;
    *payload_len -= total_delta;
    return OK;
}

oscore_msgerr_protected_t oscore_msg_protected_trim_payload(
        oscore_msg_protected_t *msg,
        size_t payload_len
        )
{
    oscore_msgerr_protected_t flusherr;
    // Flush out options now -- otherwise we'd have truncated the underlying message too far
    flusherr = flush_autooptions_outer_until(msg, OPTNUM_MAX);
    if (flusherr != OK) {
        return flusherr;
    }
    flusherr = flush_autooptions_outer_until(msg, OPTNUM_MAX);
    if (flusherr != OK) {
        return flusherr;
    }

    oscore_msgerr_native_t err = oscore_msg_native_trim_payload(msg->backend,
            // code
            1 +
            // class-E options
            msg->class_e.cursor +
            // inner payload marker
            (payload_len > 0) +
            // inner payload
            payload_len +
            // tag
            msg->tag_length);

    return oscore_msgerr_native_is_error(err) ? NATIVE_ERROR : OK;
}

bool oscore_msgerr_protected_is_error(oscore_msgerr_protected_t error)
{
    return error != OK;
}
