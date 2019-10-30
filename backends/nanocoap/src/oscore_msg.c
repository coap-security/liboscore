#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <oscore_native/message.h>

/** Access the coapk_pkt pointer inside a oscore_msg_native_t.
 *
 * Doing this through a function makes it easy to move the implementation back
 * and forth between the native type being just a pointer and being a poiner
 * with additional metadata.
 *
 */
static inline coap_pkt_t *_pkt(oscore_msg_native_t msg) {
    return msg.pkt;
}

uint8_t oscore_msg_native_get_code(oscore_msg_native_t msg)
{
    // The get_code / set_code helpers all try to transform the code into the
    // concatenated decimal form of the dotted representation
    return _pkt(msg)->hdr->code;
}

void oscore_msg_native_set_code(oscore_msg_native_t msg, uint8_t code)
{
    _pkt(msg)->hdr->code = code;
}

oscore_msgerr_native_t oscore_msg_native_append_option(
        oscore_msg_native_t msg,
        uint16_t option_number,
        const uint8_t *value,
        size_t value_len
        )
{
#ifndef OSCORE_NANOCOAP_MEMMOVE_MODE
    if (msg.payload_is_real) {
        return -ENOSPC;
    }
#else
    // Dipping into nanocoap internals due to the understandable lack of a
    // predictor for payload after option addition.
    //
    // Underflow is ignored here as it results in harmless wrong size
    // estimations and a later error by nanocoap
    uint16_t delta = option_number - (_pkt(msg)->options_len
            ? _pkt(msg)->options[_pkt(msg)->options_len - 1].opt_num : 0);
    size_t optionlength = value_len + 1 + \
                                (delta >= 13) + (delta >= 269) + \
                                (value_len >= 13) + (value_len >= 269);
    uint8_t *predicted_payload = NULL;
    size_t predicted_length = 0;
    if (optionlength <= _pkt(msg)->payload_len) {
        predicted_length = _pkt(msg)->payload_len - optionlength;
        predicted_payload = _pkt(msg)->payload + optionlength;
        memmove(predicted_payload, _pkt(msg)->payload, predicted_length);
    }
#endif

    ssize_t result = coap_opt_add_opaque(_pkt(msg), option_number, value, value_len);
    if (result > 0) {
#ifdef OSCORE_NANOCOAP_MEMMOVE_MODE
        assert(_pkt(msg)->payload == predicted_payload);
        assert(_pkt(msg)->payload_len == predicted_length);
#endif
        return 0;
    }

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
            _pkt(msg),
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

oscore_msgerr_native_t oscore_msg_native_optiter_finish(
        oscore_msg_native_t msg,
        oscore_msg_native_optiter_t *iter
        )
{
    // no-op: we didn't allocate anything for iteration
    (void)msg;
    (void)iter;

    // Infallible: Options are parsed and if need be rejected as a message on
    // reception
    return 0;
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
                _pkt(msg),
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

oscore_msgerr_native_t oscore_msg_native_map_payload(
        oscore_msg_native_t msg,
        uint8_t **payload,
        size_t *payload_len
        )
{
#ifndef OSCORE_NANOCOAP_MEMMOVE_MODE
    if (!msg.payload_is_real) {
        // This'd be going the strict route
        msg.payload_is_real = true;
        if (_pkt(msg)->payload_len > 0) {
            _pkt(msg)->payload[0] = 0xff;
            _pkt(msg)->payload ++;
            _pkt(msg)->payload_len --;
        }
    }
#endif

    *payload = _pkt(msg)->payload;
    *payload_len = _pkt(msg)->payload_len;

#ifdef OSCORE_NANOCOAP_MEMMOVE_MODE
    if (!msg.payload_is_real && _pkt(msg)->payload_len != 0) {
        **payload = 0xff;
        (*payload) ++;
        (*payload_len) --;
    }
#endif

    // Infallible: Options are parsed and if need be rejected as a message on
    // reception
    return 0;
}

oscore_msgerr_native_t oscore_msg_native_trim_payload(
        oscore_msg_native_t msg,
        size_t payload_len
        )
{
    if (!msg.payload_is_real && payload_len > 0) {
        payload_len ++;
    }

    if (payload_len > _pkt(msg)->payload_len) {
        return true;
    }

    _pkt(msg)->payload_len = payload_len;
    return false;
}
