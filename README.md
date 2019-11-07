libOSCORE: An OSCORE implementation (not only) for embedded systems
===================================================================

The libOSCORE library is
a portable implementation of [OSCORE (RFC8613)]
usable for embedded devices.

OSCORE is a method of protecting (ie. encrypting and verifying)
exchanges of [CoAP] messages (network traffic between typical IoT devices)
against eavesdropping or manipulation
in an end-to-end fashion
without sacrificing the compactness of the messages and protocol implementations.

This implementation aims to be usable on various platforms, especially embedded ones;
it achieves this by describing its requirements towards the used platform's CoAP implementation
with a small generic API that can then be implemented by different CoAP libraries,
for example [RIOT-OS]'s gcoap.
By the choice of programming language (C),
the avoidance of dynamic memory allocation
as well as the extensive use of in-place operations,
it is suitable for the smallest class of devices that are capable of IP traffic
and of performing cryptographic operations at all.

[OSCORE (RFC8613)]: https://tools.ietf.org/html/rfc8613
[CoAP]: https://coap.technology/
[RIOT-OS]: https://riot-os.org/

State of the project
--------------------

The library is nearing completion of the basic features,
and an implemenation of the OSCORE [plug test] server
is usable on RIOT-OS,
even though it does not pass all the tests yet.

[plug test]: https://ericssonresearch.github.io/OSCOAP/

Use and documentation
---------------------

Documentation entry points are split into different use cases:

* Use in fully integrated CoAP libraries:
  
  As a user of a CoAP library with full integration,
  you will have little direct interaction with this library,
  as all OSCORE operations are handled by your CoAP library;
  see its documentation in the integrations list below.

  Implementers of CoAP libraries that want to provide full integration
  can read about the process in the [full integration guide].

* Use with lightly integrated CoAP libraries:

  When full integration is not available on a plaform,
  not feasible or undesirable for a particular application,
  liboscore can be used directly by the application.

  Writing applications that way is a very manual process,
  which gives good opportunities for tuning and optimization,
  but at the same time is tedious and error-prone.

  The guide "[Using light integration in application development]"
  describe the steps in developing applications that way.

  Library authors wishing to provide light integration
  should consult the [light integration guide].

* Intermediate integration – using libOSCORE as a CoAP library

  For quick tests, demos and as a getting-started point,
  libOSCORE plans to ship a partial CoAP server implementation.
  This builds on any existing light CoAP integration
  and needs to be registered as the FETCH and POST handler
  of the underlying CoAP server.
  From there, it dispatches requests into per-resource handlers
  and implements error handling.

  The intermediate integration server is very limited in its capabilities:
  it will not be able to offer opportunistic protection
  (ie. serve OSCORE requests to resources that do not require it),
  and only supports pre-allcoated resource handlers.
  Its intended use are demos runnable across different backends
  (like the plug test server).
  For more advanced applications,
  please use full library integration
  or build (and consider publishing) a more powerful dispatcher.

[full integration guide]: https://oscore.gitlab.io/liboscore/md_doc_guides_full_integration.html
[Using light integration in application development]: https://oscore.gitlab.io/liboscore/md_doc_guides_light_integration_usage.html
[light integration guide]: https://oscore.gitlab.io/liboscore/md_doc_guides_light_integration.html

Library integrations
--------------------

CoAP libraries with planned integration:

* [RIOT-OS] - tracked at [11761]
* MoCkoAP – an internal minimal CoAP library used as a mock-up in tests
* [libcose] – providing the required crypto primitives

Potential future candidates:
(No implementation is being planned right now,
but they are being looked into for portability)

* [libcoap]
* [wakaama]
* [OpenSSL]
* bindings into the [Rust] programming language

[RIOT-OS]: http://riot-os.org/
[libcose]: https://github.com/bergzand/libcose
[11761]: https://github.com/RIOT-OS/RIOT/issues/11761
[libcoap]: https://libcoap.net/
[wakaama]: https://github.com/eclipse/wakaama
[OpenSSL]: https://www.openssl.org/
[Rust]: https://www.rust-lang.org/

Links
-----

* [Source code](https://gitlab.com/oscore/liboscore) and issue tracker
* [Documentation](https://oscore.gitlab.io/liboscore/) entry point
* [RFC8613](https://tools.ietf.org/html/rfc8613]) (the OSCORE specification)

License
-------

Copyright 2019 Christian Amsüss and Ericsson AB

Licensed under the terms of the 3-clause BSD license as described in the LICENSE file.
