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

* Receive a request message
* Resolve any preprocessing outside OSCORE (eg. reassemble a block-wise request, if supported)
* Identify its OSCORE header
* Look up a context based on information from the header
* Decrypt the message
* Read the message
* Discard the received message
* Start composing a response message
* Prepare encryption of the message
* Populate the message
* Finish encryption
* Send the message

Two aspects of this sequence may vary depending on the underlying CoAP library:

* Discard the received message before composing the response:

  This is the most strict sequence that caters for CoAP libraries with only a single message buffer.
  On less constrained devices, the response preparation can be started earlier,
  and both messages are available at the same time.

* Prepare encryption before populating the message before populating:

  This sequence is used in the common case when the underlying CoAP library expects options to be added sequentially,
  and the application puts in the options in ascending sequence.
  When applications are allowed to enter options in arbitrary sequence
  (which is more common on platforms with dynamic allocations,
  as well as in CoAP libraries whose limited set and size of options comes pre-allocated in the message),
  the sequence is inverted: The message is populated first,
  then the encryption process is started,
  and then the pre-populated options are moved out of the message one by one
  and fed back the message,
  at which time it is decided where exactly the option is placed.
  Alternatively, encryption can be delayed to serialization time for those cases.

@FIXME This part of the documentation is incomplete.

... link @ref oscore_protection

Context creation and management
-------------------------------
