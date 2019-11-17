@page integration_levels Levels of library integration

As libOSCORE implements an OSCORE layer in a portable way,
it interfaces with several components around it.
Depending on which interfaces are implemented in any given CoAP library,
several patterns of usage are available.
Those patterns of usage are described as integration levels here,
and are called "light integration", "intermediate integration" and "full integration" here.

Light integration
-----------------

(Renaming to "Basic integration" is being considered).

Light integration describes the most basic way of interacting with libOSCORE.
It only requires a basic CoAP library
(as well as one for cryptographic primitives)
to be made available to libOSCORE.

These underlying libraries are called the native CoAP and cryptography libraries,
and are selected at build time.

It is possible, but not generally recommended, to build applications directly on this,
as those applications need to drive libOSCORE through every step of the encryption and decryption process,
as that is both tedious and error-prone.
In return, the application gets full control of the OSCORE steps,
and may perform optimizations that can not easily be done otherwise.

Applications built on this level are not portable,
and depend both on a particular underlying CoAP library and libOSCORE in their code.

### Further documentation

* To implement light integration for an existing CoAP library, see the @ref light_integration.
* To write an application based on light integration, carefully read @ref light_integration_usage

Full integration
----------------

Full integration describes an interaction pattern with libOSCORE
where a CoAP library implements the steps of light integration,
but transparently passes on interactions with messages to OSCORE protected messages.

Applications built on this pattern do not interact with libOSCORE directly,
but see regular messages of their CoAP library.
They can query or set the security context of a message
in a similar way as they set the remote address in any message
(and thus contain clauses like "if security context is not whitelisted, return 4.01"),
or are even ignorant of the security context if their access control happens inside their CoAP library
(and list their resources as "`/door/lock` requires a security context of at least X to GET, and of at least Y to PUT").

Applications built on this pattern are tightly coupled to the CoAP library used,
but can be made to switch between security mechanisms with little or no effort
depending on the CoAP library's abstractions.
This is also the easiest way to provide end-to-end security
for applications that previously did not implement any high-level security schemes.

This is the recommended way of building applications
on platforms that have a powerful and stable CoAP library.

### Further documentation

* To implement full integration into an existing CoAP library, see the @ref full_integration.
* To use a fully integrated library, follow documentation provided with the library. (@FIXME There is none yet, for lack of a fully integrated library)

Intermediate integration
------------------------

(Renaming to "Sideways integration" is being considered).

Code that orchestrates and simplifies libOSCORE steps
but does not provide the original native CoAP's interfaces again
is called intermediate integration.

Such code can range from the narrow-purpose helpers to REST frameworks.
All of those provide an interface like the one of a CoAP library to the application,
but not the native one's.

Intermediate integration modules need to be glued to the native CoAP library's message reception and transmission mechanisms.
Not all modules are necessarily compatible with all native libraries:
For example, a server module that offers the application read access to the incoming message
and at the same time write access to the outgoing message
can not be implemented on a native library that only has a single message buffer.

Applications built on intermediate integrations are generally portable across CoAP libraries,
provided glue code between the module and the CoAP library exists.

Using libOSCORE in this way is recommended for applications written with the explicit intention of porting them between CoAP libraries (like the plug test server shipped with libOSCORE),
or when full integration is not available on a platform.

### Further documentation

Intermediate integration modules differ too widely to give general recommendations on how to implement them.
The @ref light_integration_usage guide can be used as a starting point, as an intermediate implementation module is basically the generalization of a light-integration application.

APIs and integration levels
---------------------------

The interface the native CoAP library needs to implement for all levels of integration
is the @ref oscore_native_msg;
libOSCORE provides the @ref oscore_msg which is intentionally similar;
@ref message_api explains a bit more about those two.

With full integration in place, the stack around libOSCORE looks like this:

    +---------------------------+
    |                           |
    |        Application        |
    |                           |
    +----[original CoAP API]----+
    |                           |
    |    Native CoAP library    |
    |                           |
    +----[libOSCORE CoAP API]---+---------+
    |                                     |
    |             libOSCORE               |
    |                                     |
    +-[nat. crypto API]-+----[native CoAP API]---+
    |                   |                        |
    |  Native crypto l. |  Native CoAP library   |
    |                   |                        |
    +-------------------+------------------------+

The application only sees the native library's API,
and may not even be aware that it is using OSCORE.

Note that the native CoAP library is used in two ways here:
libOSCORE accesses the native library through the @ref oscore_native_msg defined by libOSCORE.
The application uses the original API of that library instead, which is was designed by that library's authors.

In contrast, applications built on light integration interact both with libOSCORE and the native library:

                    +----------------------------+
                    |                            |
                    |         Application        |
                    |                            |
    +---------------+[libOSCORE CoAP API]-+      |
    |                                     |      |
    |             libOSCORE               |      |
    |                                     |      |
    +-[nat. crypto API]-+----[native CoAP API]---+
    |                   |                        |
    |  Native crypto l. |  Native CoAP library   |
    |                   |                        |
    +-------------------+------------------------+

The application typically needs to access functions of the native CoAP library that are not expressed in the @ref oscore_native_msg
(for example to send and receive messages), which are not depicted here.
@FIXME (With possible renaming of the "native" parts, that might become more usable in the illustration).

With sideways integration in place, the picture looks similar to the light integration case,
but the integration module takes the application's place:

                    +----------------------------+
                    |                            |
                    |         Application        |
                    |                            |
                    +-------[bespoke API]--------+
                    |                            |
                    |     Intermediate module    |
                    |                            |
    +---------------+[libOSCORE CoAP API]-+      |
    |                                     |      |
    |             libOSCORE               |      |
    |                                     |      |
    +-[nat. crypto API]-+----[native CoAP API]---+
    |                   |                        |
    |  Native crypto l. |  Native CoAP library   |
    |                   |                        |
    +-------------------+------------------------+

Currently implemented integrations
----------------------------------

* Crypto bindings for the libcose library are shipped with libOSCORE.
* A native CoAP API binding for nanocoap is shipped with libOSCORE,
  enabling light integration on RIOT-OS.
* An intermediate module for server operation is being actively worked on.
  It provides a push-based API for applications that can be implemented as simple state machines,
  and is used in the plugtest server as well as upcoming demos.
* Full integration into the nanocoap/Gcoap ecosystem of RIOT-OS is being planned.
