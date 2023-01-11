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
The article [OSCORE: A look at the new IoT security protocol] provides a newcomer friendly summary.

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
[OSCORE: A look at the new IoT security protocol]: https://www.ericsson.com/en/blog/2019/11/oscore-iot-security-protocol
[RIOT-OS]: https://riot-os.org/

State of the project
--------------------

The library is feature complete
and an implemenation of the OSCORE [plug test] server
is usable on RIOT-OS,
even though it does not pass all the tests yet.

[plug test]: https://ericssonresearch.github.io/OSCOAP/

Use and documentation
---------------------

The libOSCORE library can be used in different ways depending on the support of the underlying CoAP library.

The [integration levels] guide gives an overview of the possibilities,
and also serves as a starting point into the rest of the documentation.

For a quick start, some examples and demos cover the common use cases:

* [Running the plug test server on RIOT on Linux]
* [Exchanging data between Particle Xenon boards over 6LoWPAN]
* [Pulling data from devices in the field (by example of the FIT/IoT-Lab testbed) into an application]

Please note that the examples currently use what is described as "intermediate integration" (see [integration levels]) in their code.
For high-level applications, it is recommended to use full integration,
but that level is not even provided for the RIOT platform yet.

[Running the plug test server on RIOT on Linux]: https://oscore.gitlab.io/liboscore/demo_plugtest_linux.html
[Exchanging data between Particle Xenon boards over 6LoWPAN]: https://oscore.gitlab.io/liboscore/demo_peertopeer.html
[Pulling data from devices in the field (by example of the FIT/IoT-Lab testbed) into an application]: https://oscore.gitlab.io/liboscore/demo_iotlab.html
[integration levels]: https://oscore.gitlab.io/liboscore/integration_levels.html

Library integrations
--------------------

Libraries with planned integration:

* [RIOT-OS] - light integration available; full integration tracked at [11761]
* MoCkoAP – an internal minimal CoAP library used as a mock-up in tests
* [libcose] – providing the required crypto primitives
* [Rust] integration
  * liboscore-cryptobackend – providing a (configurable) variety of crypto primitives
  * liboscore-msgbackend – implementing libOSCORE's message accessors on the [coap-message] traits
  * liboscore-backends-standalone – build infrastructure for using the Rust cryptobackend from a C application
  * liboscore – high level Rust abstractions

Potential future candidates:
(No implementation is being planned right now,
but they are being looked into for portability)

* [libcoap]
* [wakaama]
* [OpenSSL]

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
