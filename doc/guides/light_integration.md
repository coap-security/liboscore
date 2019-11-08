@page light_integration Light integration implementation guide

"Light integration" in the context of this library means that
the @ref oscore_native_msg API is implemented for the CoAP library,
and that a suitable @ref oscore_native_crypto implementation is available.

The to-be implemented functions purely deal with the manipulation of CoAP messages.
No API for the creating, receiving, sending or finalizing CoAP messages is asked for;
these operations will be performed by the application in accordance with the idioms of the library.
The guide @ref message_api explains some of the background behind that API.

(There exists a module for creating and finalizing (but not sending or receiving) CoAP messages
called @ref coap_naitive_test.
This is useful to implement as it allows running some of the backend tests.)

As CoAP libraries often come integrated with an embedded operating system
or embedded development platform,
integration of the CoAP stack is described here along with other integrations
like the crypto backends or the build system.

Files involved
--------------

Typically, a light integration backend contains two or three files:

* `oscore_native/msg_type.h`:
  This file defines the types used for messages and error codes.

  All the types described in @ref oscore_native_msg_types need to be defined in there.
  Most of the time those should be easy -- @ref oscore_msg_native_t can be typedef'd to be a pointer to a native message structure, and @ref oscore_msgerr_native_t can be identical to the native error type.

  This file needs to be available to libOSCORE for inclusion under this paht and name the when it gets built.

* `mycoaplibrary_oscore_msg.c`:
  This file contains implementations of all functions described in @ref oscore_native_msg.

  The resulting symbols must be made available to libOSCORE at link time.

* `mycoaplibrary_oscore_msg_conversion.h`:
  If the conversion between the actual native message type and @ref oscore_msg_native_t is more involved than just using a type alias,
  for example if a message's length is always transported in parralel to the actual native message type
  and @ref oscore_msg_native_t points to a helper struct that binds them together,
  the creation and dissolution of such helpers can happen here

  libOSCORE itself does not care for or depend on this;
  if it is used, it needs to be available for inclusion by the application.

If those files are integrated in the CoAP library's source code,
they probably have suitable locations there.
If they are to be shipped with libOSCORE or in a dedicated glue code bundle,
a structure like the one used by the nanocoap implementatino is recommended:

    backends/nanocoap/
    ├── README.md
    ├── inc
    │   ├── nanocoap_oscore_msg_conversion.c  # not actually present there
    │   └── oscore_native
    │       └── msg_type.h
    └── src
        ├── nanocoap_oscore_msg.c # @FIXME actually named oscore_msg.c
        └── oscore_test.c

### Cryptography backends

As many platforms provide their own, possibly hardware accelerated, implementations of cryptographic primitives,
those operations are accessed through an API layer similar to the native message API.

Wrapping those is analogous the above,
and consists of providing a `oscore_native/crypto_type.h` header providing the @ref oscore_native_crypto_types as well as some size definitions needed for OSCORE internal structs,
and implementing the @ref oscore_native_crypto.

On platforms that do not readily have those primitives available,
the existing libcose wrapper provides a convenient existing implementation.

Building
--------

libOSCORE has no dedicated build system,
and expects to be built by the application.
either as a static library or directly as object files.

Usually, the application and libOSCORE can be compiled with the same set of compiler flags.
These need to specifiy several directories for the include path:

* `src/include/` which includes all header files of libOSCORE itself
* the CoAP backend's `inc/` directory
* the crypto backend's `inc/` directory

Compilation and linking is required for

* `src/*.c` including all of OSCORE's own code
* the CoAP backend's `src/*.c`
* the crypto backend's `src/*.c`

which may be built into a static library or linked in as individual object files.

It is recommended to employ link time optimization.

Testing
-------

@FIXME The test cases described in `tests/cases/` can be run on any platform that has the @ref coap_naitive_test implemened.
See `tests/riot-tests/` and `tests/native/` for examples of how they can be executed.
