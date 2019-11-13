@page message_api Message API background

CoAP messages are accessed using two different interfaces in this library:
when the application (or a more high-level library) manipulates to-be-encrypted or decrypted messages (@ref oscore_msg),
and when this library builds the encrypted message (@ref oscore_native_msg)
(or reads an incoming message for decryption).
For how this fits into the larger scheme of library integration, see @ref integration_levels.

These two APIs are intentionally similar,
as they reflect what is considered to be a suitable minimal API towards CoAP messages:
It allows setting and getting the CoAP code (the request method or response code),
reading, appending and updating options,
and reading and writing the payload.

That message API is intentionally limited;
for example, it does not contain methods for removing options,
and updates to option values can only happen if the new value has the exact same size as the old one.
These limits are to ensure that it can be implemented even on the most resource-constrained backends,
which often serialize added options right into a transmit buffer.
It does not contain any operations for serializing and deserializing the higher-level option values like uint or block options.

Option and payload sequences
----------------------------

There is some flexibility for CoAP implementations in how strict to be with respect to the insertion of options;
for the purpose of this discussion, we'll classify them as

* *lax*: CoAP options and payload can be set in any sequence,
* *strict-options-lax-payload*: CoAP options must be provided in ascending sequence,
  but writing the payload does not preclude adding more options, and
* *strict*: CoAP options must be provided in ascending sequence,
  and no options can be added after writing to the payload has started;

where *strict* is often found in very resource-constrained backends,
and *strict-options-lax-payload* can often be emulated there at the cost of moving data around in memory
(but emulating it is still easier to do than emulating *lax*,
which would not only mean moving around data but also re-calculating previously encoded options,
which changes their encoded lengths).

Applications that use them can be classified in a similar fashion to write

* *arbitrarily*,
* *in-sequence*,
* *in-sequence*

Additionally, as options in OSCORE are not written in the same sequence as in regular CoAP,
we can also describe applications as

* *in-oscore-sequence*: applications that produce OSCORE Class-U/I options first,
  and Class-E options later.
  (Note that *in-sequence* server applications are also often *in-oscore-sequence*,
  as most response options are Class-E;
  a notable exception are observations).

The OSCORE library tries to make the best possible use of the backend capabilities,
and allows the following combinations
(of server behavior in columns and client behavior in rows):

.                    |  lax      | strict-options-lax-payload    | strict
-------------------- | --------- | ----------------------------- | ----------------
arbitrary            | manual[1] | no                            | no
in-sequence          | yes       | yes[2]                        | no
in-oscore-sequence   | yes       | yes                           | yes

The properties are documented in the respective backend's documentation.
There is no explicit build-time configuration of those properties --
when a server tries to add options out of order on a server that does not support arbitrary access options,
the backend's error will occur just as if the application had itself entered options in the wrong sequence.

[1]: On arbitrary-sequence platforms, the unprotected messages are typically built before the encryption step starts,
and then fed into the OSCORE encryption in the right seequence;
see [issue 35](https://gitlab.com/oscore/liboscore/issues/35) for library extension ideas that would make those more convenient to work with.

[2]: Even on a *strict-options-lax-payload* backend, the OSCORE-wrapped message behaves in a *strict-options* fashion.
No currently known applications other than OSCORE itself have a strong need utilizing the lax-payload aspect;
if you do, please voice your need at [issue 36](https://gitlab.com/oscore/liboscore/issues/36).

@section oscore_specific_native_requirements OSCORE-specific requirements inside the native message API

While most of the CoAP APIs is quite general,
there are exceptional requirements currently in the native API description purely for the benefit of OSCORE --
they make little sense outside this use case,
but are expected to be trivial to provide and simplify libOSCORE's work quite a bit:

* @ref oscore_msg_native_optiter_next:
  The `uint8_t` memory slice produced when iterating over a native message's OSCORE option
  must stay valid for as long as the message is not modifed.
  (The usual requirement is that it is valid until the next item is pulled from the iterator).

  This is trivially fulfilled for backends that store options in their serialized form.
  Backends that store option values in their semantic form may, in general, use a per-iterator buffer to serialize the semantic into the binary form.
  As such a backend's semantic form is anyway determined by the OSCORE library used,
  this library demands that the form be as an opaque string, into which a pointer can be returned.

* Introducing a requirement to allow and preserve writes to the first byte of the payload even in the strict case is being considered (but currently not required).
