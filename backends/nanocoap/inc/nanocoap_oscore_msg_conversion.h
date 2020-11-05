#ifndef NANOCOAP_OSCORE_CONVERSION_H
#define NANOCOAP_OSCORE_CONVERSION_H

/** Initialize a native message from an incoming PDU.
 *
 * This needs an explicit conversion because the payload pointer is rewound for
 * consistency within the libOSCORE nanocoap bindings.
 *
 * @pre @p incoming has nonempty payload, and its `payload` member points to
 * the byte after the payload marker.
 *
 * @param[out] msg The OSCORE message to be initialized.
 * @param[in] incoming The nanocoap PDU that contains the protected message (the pointer is stored inside @p msg)
 *
 */
OSCORE_NONNULL void oscore_msg_native_from_nanocoap_incoming(oscore_msg_native_t *msg, coap_pkt_t *incoming);

/** Initialize a native message from an outgoing PDU prepared through Gcoap.
 *
 * Apart from initializing the @p msg, this also rewinds the outer Observe
 * option that Gcoap places in `gcoap_resp_init` or `gcoap_obs_init` -- if the
 * observe value is really to be set, the user needs to copy it out of the
 * message buffer where it is left unmodified in this function, and later add
 * it through `oscore_msg_protected_append_option` which places the value in
 * the outer option and places an inner option though autooptions.
 *
 * @param[out] msg The message to be initialized.
 * @param[in] pkt The nanocoap PDU into which the protected message will be constructed (the pointer is stored inside @p msg)
 * @param[out] observe_length Output field populated with the length of @p observe_data, or a negative value if no Observe option was prepopulated.
 * @param[out] observe_data Output field populated with a pointer inside the @p pkt message at the start of the Observe option data.
 *
 */
OSCORE_NONNULL void oscore_msg_native_from_gcoap_outgoing(oscore_msg_native_t *msg, coap_pkt_t *pkt, int8_t *observe_length, uint8_t **observe_data);

#endif
