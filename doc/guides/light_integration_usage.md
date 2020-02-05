@page light_integration_usage Using light integration in application development

This guide accompanies you step by step through writing an OSCORE protected application
using only light integration,
that is,
by directly using the protected message and context APIs of libOSCORE.

Please note that for most regular applications,
even on devices with very limited resources,
using a fully integrated CoAP library will give you a better experience,
both in terms of development effort
and in terms of mistakes that can be made that might affect the security of the complete system.

If full integration is not available for your platform yet,
but your application is simple enough,
you may want to go for the server provided as part of intermediate integration instead.

Applications should be built directly on the light integration layer only

* when exploring OSCORE extensions outside of the scope currently implemented,
* when critical performance boundaries are to be overcome that can not be overcome by optimizing the full integration layer alone, and benchmarks are available to support that, or
* in preparation of writing full integration for a CoAP library, or of other frameworks that build on top of libOSCORE.

Server side processing
----------------------

The general steps required of a server are, in that sequence:

<!-- When editing here, also keep structbased_integration in sync -->

* Receive a request message
* Resolve any preprocessing outside OSCORE (eg. reassemble a block-wise request, if supported)
* @ref oscore_oscoreoption_parse "Identify and parse its OSCORE header"
* Look up a context based on information from the header
* @ref oscore_unprotect_request "Decrypt the message"
* @ref oscore_msg "Read the message"
* @ref oscore_release_unprotected "Discard the received message"
* Allocate a response message
* @ref oscore_prepare_response "Prepare encryption of the message"
* @ref oscore_msg "Populate the message"
* @ref oscore_encrypt_message "Finish encryption"
* Send the message

Two aspects of this sequence may vary depending on the underlying CoAP library:

* Discard the received message before composing the response:

  This is the most strict sequence that caters for CoAP libraries with only a single message buffer.
  On less constrained devices, the response preparation can be started earlier,
  and both messages are available at the same time.

* Prepare encryption before populating the message:

  This sequence is used in the common case when the underlying CoAP library expects options to be added sequentially
  and the application puts in the options in ascending sequence.

  For applications with struct-based messages,
  the message is populated first, and encryption is only prepared just before the CoAP library serializes the message;
  see @ref structbased_integration for details.

The step of decrypting the request message is noteworthy here because it has @ref oscore_unprotect_request_result "three possible outcomes":
"OK", "invalid" and "duplicate".
When running on CoAP libraries that [do not perform message deduplication because they only allow idempotent handlers](https://tools.ietf.org/html/rfc7252#section-4.5),
lost responses to CON messages will result in retransmissions being processed anew at the server,
triggering the replay protection.
An application can decide to answer duplicate requests the same way as it answers to OK requests;
the request ID handling of libOSCORE will ensure that the sender's nonce is not reused in that case.
The threat that the application does need to assess on its own is that of actually processing a request twice --
which does no harm if the application,
by the CoAP library's requirements,
only implements idempotent handlers.

When the server is using a @ref oscore_context_b1 "B.1 context",
requests may also show as duplicate after start-up.
The application should use @ref oscore_context_b1_process_request on all incoming requests as described there,
and build its response using @ref oscore_context_b1_build_401echo if so indicated.

Client side processing
----------------------

The general steps for OSCORE clients are rather similar:

* Prepare a request message, initialized with a destination address
* @ref oscore_prepare_request "Prepare encryption of the request"
* @ref oscore_msg "Populate the request message"
* @ref oscore_encrypt_message "Finish encryption"
* Send the request

In the course of message preparation, the client allocates a @ref oscore_requestid_t "request ID"
and has it populated by @ref oscore_prepare_request.
That data, along with a way to find the original security context,
needs to be carried along until the response arrives
(or until the end of the observation established with the request).

When a response arrives, those data[1] are used as inputs in the next steps:

* @ref oscore_unprotect_response "Decrypt the response"
* @ref oscore_msg "Read and process the response"
* @ref oscore_release_unprotected "Free the decrypted message"

Unlike in the server case,
there are no checks for duplicate messages:
The response either decrypts correctly
(indicating that it is a response to the sent request),
or decryption fails
(which does not happen in the common cases).

If the server is using [OSCORE Appendix B.1 recovery](https://tools.ietf.org/html/rfc8613#appendix-B.1),
the client may see a 4.01 Unauthorized code after decryption, and an Echo option.
In such a case, the request was not processed by the server yet,
and the client should repeat the request with the provided Echo option inside the new request.

[1]: As weak references are uncommon in embedded development,
the security context might have been altered the send and the receive steps --
the @ref design_thread "call sequence requirements" only preclude modification between paired decrypt/encrypt steps on the server side.
While still preferably avoided,
such alterations will not result in nonce reuse and will thus not comporimise the key integrity.


Context creation and management
-------------------------------

The creation of a security context is up to the application;
typically, those are derived from master key and salt externally
(see @ref demo "the demos" for examples)
and then stored in a @ref oscore_context_b1 "B.1 context",
which allows the security context to be persisted and resumed from.

In server side processing,
the security context for decryption is picked by comparing the
@ref oscore_oscoreoption_t "details of the OSCORE option"
with the recipient key ID of the stored security context.
Some metadata about that security context should be available for the request processing stage,
as that will typically need to decide whether the authentication provided by OSCORE is sufficient to authorize the requested access.

In client side processing,
the application needs to provide a security context to use the same way as it provides a destination address for the message.
Many applications are expected to create security contexts per communication peer,
and can thus arrive at a suitable security context from a destination address.

