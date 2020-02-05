@page structbased_integration Intregrating with struct-based CoAP libraries

When integrating with a CoAP library that provides a fully parsed view of CoAP messages in the form of a struct
(as opposed to libraries that assist an application in iterating over and writing to a CoAP message buffer),
several difficulties arise, such as:

* How do I implement @ref oscore_msg_native_optiter_next without duplicating the option number mapping?
* Why do I need to encode my struct's values to it whenever the application looks at them?
* Why do my applications suddenly need to care about the sequence of access to CoAP options?

Rather than facing those problems head-on, it is recommended to move the point of integration:
Instead of placing libOSCORE between the application user and the struct access,
it should be placed inside the message (de)serializer.
Every CoAP library, at some point,
populates a struct from the sequence of encoded options,
and creates an ascending sequence of options from the struct.

This is where libOSCORE is best integrated.

In struct-based libraries, this part is often not pubic,
which means that even light integration needs to be patched into the library rather than on top of it.
(If this sounds intrusive, think of it this way: No new option can even be added to such a library without patching it there.)
In return, full integration is much easier there, as it can be dispatched directly at the one point where serialization happens,
rather than needing to be dispatched whenever an application adds an option.

With this, the sequence of @ref light_integration_usage is enacted differently:

<!-- When editing here, also keep light_integration_usage in sync -->

* Receive a request message
* Resolve any preprocessing outside OSCORE (eg. reassemble a block-wise request, if supported)
* Identify its OSCORE header
* Look up a context based on information from the header
* Decrypt the message
* *Read the message through libOSCORE and parse it into a struct*
* Discard the received message *buffer*
* Read the message *struct*
* Populate a response message *struct*
* Allocate a response *buffer*
* Prepare encryption of the message
* *Serialize the message into libOSCORE, which in term writes it into the buffer*
* Finish encryption
* Send the message

Like with all full integrations, the decision of whether to encrypt a message (and in which security context) needs to be taken inside the integration.
In servers, that decision is trivial (but in return, the application might need to be informed of the security context a request arrived on).
In clients, that decision can be policy-based (particular remotes have security contexts) or passed in an extension to the remote address.

Applications in such scenarios will barely need an changes to them except configuring or reading a message's security context.
One noteworthy requirement that is imposed on applications in such a setup is that the remote needs to be fully known by the time a request is serialized;
in the struct-based CoAP libraries considered so far, this has always been a requirement already.
