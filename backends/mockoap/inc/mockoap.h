#ifndef MOCKAOP_MOCKOAP_H
#define MOCKAOP_MOCKOAP_H

/** MoCKoAP: the simplest non-functional CoAP library that can be a backend
 * to the OSCORE library
 *
 * This library does not provide any serialization of CoAP messages, let alone
 * transport. It does not re-order options but will silently accept smaller
 * option numbers for later options. It makes heavy use of heap allocated
 * memory. Its only purpose is to serve as a reference and mocking backend to
 * the OSCORE library.
 */

/** A CoAP message
 *
 * There are few direct functions for manipulating mock messages; the
 * every-day functions of manipulating code, payload and options are
 * implemented directly in their bindings for OSCORE's generic CoAP API.
 *
 * No functions are provided to act on messages, not even to create them; that
 * functionality is directly implemented in the OSCORE library backend
 * implememntation.
 */
struct mock_message {
    uint8_t code;
    uint8_t *payload;
    struct mock_opt *option;
};

/** A part of a CoAP message representing a single option
 *
 * Options for a singly linked list of values that can not be shared among
 * messages; they are destroyed by their owning message.
 */
struct mock_opt {
    struct mock_opt *next;
    uint16_t number;
    uint8_t *data;
};

#endif
