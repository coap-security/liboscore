An OSCORE implementation
========================

This repository contains code developed to be
a portable implementation of OSCORE_
usable for embedded devices.

OSCORE is a method of protecting (ie. encrypting and verifying)
exchanges of CoAP_ messages (network traffic between typical IoT devices)
against eavesdropping or manipulation
in an end-to-end fashion
without sacrificing the compactness of the messages and protocol implementations.

This implementation aims to be usable as a generic implementation;
it achieves this by describing its requirements towards the used CoAP library
with a small generic API that can then be implemented by different CoAP libraries,
for example RIOT-OS's gcoap.
By the choice of programming language (C),
the avoidance of dynamic memory allocation
as well as the extensive use of in-place operations,
it is suitable for the smallest class of devices that are capable of IP traffic
and of performing cryptographic operations at all.

Use and documentation
---------------------

Documentation entry points are split into different use cases:

* Use in fully integrated CoAP libraries:
  
  You will little direct interaction with this library
  as all OSCORE operations are handled by your CoAP library;
  see its documentation.

  TBD (link into documentation of full-integration libraries,
  and list of interactions still expected there,
  probably only context setup)

* Use with lightly integrated CoAP libraries:

  TBD (link into documentation -- contexts, request and response walk-throughs)

* Building library integration:

  TBD (link into documentation -- "how to wrap")

.. _OSCORE: https://tools.ietf.org/html/draft-ietf-core-object-security-16#section-8.1
.. _CoAP: https://coap.technology/
