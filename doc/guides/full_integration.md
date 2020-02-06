@page full_integration Full integration implementation guide

This guide is written for CoAP library authors
who want to make OSCORE available for effortless usage through their library.
It assumes that light integration is already available for the CoAP library.
It is recommended to implement a small application using that light integration manually,
as implementing full integration is largely an automation therof,
and familiarity with the use of light integration is a practical prerequisite.

As with all integration guides,
steps are probably different for @ref structbased_integration "struct-based message libraries, so see there as well".

More so than on other integration pages,
things here are only rough guidance:
Many aspects of integration depend on the library libOSCORE is integrated with.
If a piece of advice seems unsuitable to a library,
better not follow it,
and share your findings [on the issue tracker](https://gitlab.com/oscore/liboscore/issues).

Message operation dispatch
--------------------------

A CoAP library with full integration for libOSCORE can pass both unprotected and protected messages through its applications.

The challenge in implementing this is to extend the library's original native message in such a way
that it can refer to either the underlying transport message,
or to an OSCORE message atop such a message.
In all code paths where an application operates on a message,
the operation needs to be dispatched either through the @ref oscore_msg,
or through the @ref oscore_native_msg
(or the functions in whose terms that is implemented).
The implementation must allow addressing the OSCORE message
as well as the native message backing it
simultaneously,
for otherwise any function in the @ref oscore_native_msg would recurse infinitely.

In languages with dynamic dispatch and/or generics,
this is often trivial. In C, different approaches are viable:

One approach is using tagged pointers,
where the reference-to-a-message that is typically passed into native library functions
is a struct of an enum and a union data pointer,
or an optimization thereof.
Data for OSCORE (the @ref oscore_msg_protected_t) and the native message can thus be accessed independently,
even when they occupy a shared struct that makes allocation easy.

Another useful approach is using tagged unions.
A native message is either a "real" message,
or it contains a @ref oscore_msg_protected_t
(along with its pointer to a backing message).

Tagged unions with both the OSCORE and the underlying part in the same struct are possible,
but comparatively hard to manage as they need slightly different treatment of messages
depending on whether or not there is an OSCORE part next to them
(for that information needs to be available to prevent duplicate initialization of the OSCORE part, as well as for cleanup purposes).

Tagged unions where the OSCORE and the underlying part are allocate separately
are easier to manage when dynamic memory management is used anyway,
or when message allocation pools are available.

Which is more suitable largely depends on the conventions
and the memory management methods
of the native library.


Remote and context selection
----------------------------

Interaction between the application and the security context happens at two places:

In servers, the application will need to determine whether the request came via OSCORE,
and if so, whether its security context is authorized.

In clients, the application needs to specify which address the request goes to.
In some setups, the application does not need to make a conscious choice here,
as the security context is picked as a function of the server that is accessed
(and at most, the application selects whether or not to use protection at all).
In others, the application explicitly selects a security context with the address
(for example in LwM2M, where both are configured next to each other).

It is expected that in most cases,
the data structure that represents the "remote address"
can be extended by a pointer to the security context
or metadata about it.

Server side processing
----------------------

Server side processing in full integration stacks
place the steps outlined in @ref light_integration_usage inside their primary incoming request handler.

When, in the "Identify and parse [the] OSCORE header" step,
an OSCORE option is found,
then its steps continue to "Decrypt the message",
after which the @ref oscore_msg_protected_t is wrapped into an (OSCORE-transported) native message;
that message is passed to the application for reading
with some indication of the security context attached to it.
Likewise, the prepared response message is wrapped for writing.

Otherwise, the native message is sent through the application.

Client side processing
----------------------

Client side processing in full integration stacks
is likewise aligned to the @ref light_integration_usage steps.

Integrations that did not originally consider different transports may face an application-visible change here:
The remote address (or at least the type thereof)
needs to be set before any other operations on the message
that might concern libOSCORE.

At the beginning of a request
there needs to be the selection of a security context.
Some applications might do explicitly using a new function the CoAP library needs to provide.
In other cases, this happens implicitly based on the configured remote address.
Either way, the native message is set up to use OSCORE,
and the CoAP library calls @ref oscore_prepare_request.

From that point,
all the application's writes to the request option
are dispatched through libOSCORE.

When the application passes its message to the CoAP library for sending,
the library @ref oscore_encrypt_message "finishes the encryption"
and stores the security context reference as well as the request ID
as part of the pending request data
(that which otherwise contains the token and the application callback and data).

When a response is received
and a security context / request ID pair was stored for it,
the library @ref oscore_unprotect_response "decrypts the message"
and hands the requester a message for access to the @ref oscore_msg_protected_t.
If a message without an OSCORE option was returned,
that message should not be handed to the caller in the same fashion,
as an application developer might not even check for the message type.

Eventually, the OSCORE message is @ref oscore_release_unprotected "finished"
when the native message is released by the application code that created the request.

Implementations
---------------

There are currently no libraries with full integration into libOSCORE;
RIOT's nanocoap / Gcoap is being worked on.
