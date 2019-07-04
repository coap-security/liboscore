Messages
========

Structs and methods for CoAP messages.
Those will need to be present twice,
once operating on the underlying CoAP library's messages (``osc_msg_native_``)
and once operating on an OSCORE message (``osc_msg_encrypted_``)

* ``osc_msg_native_t``: A type provided by the native library.
* ``osc_msg_encrypted_t``: A type provided by the OSCORE library.

  It contains an ``osc_msg_native_t`` as well as pointers inside there ("how many U options have we written, how many E options have we written") as well as some other state (eg. the hash state of the external AAD that'll be updated when I options are added).

  The expectation is that the message is built in-place, with the to-be-encrypted data in the very place where its ciphertext will be.
  For this to work we'll need to demand that either
  * options arrive in the right sequence *even w/rt OSCORE* (ie. Class-E always after Class-U), or
  * that the native library is ready to add options even if payload was entered. (That'll require memmove-ing, but no recalculation of option numbers.)
  Probably we'll support both.

* For every message type:

  * ``_{get,set}_code``
  * ``_append_option`` (asserting that no later options have been written, and possiblty that payload has not been written / see "in-place buildability")
  * ``_update_option`` (asserting that the option has previously been added with that very length. Useful to provide, we probably won't need the native version as we should know all that goes into the OSCORE option by the time we'll need to inject it into the message)
  * ``_iter_options`` (a pair of "set up an iterator" / "get the next pointers" functions or possibly macros)
  * ``_map_payload`` ("give me pointers to the area into which I can put my payload, or read payload from", possibly with a dedicated method for read-only messages)
  * ``_trim_payload`` (truncate the message to the given length)
  * possibly some rewind savepointing (useful in existing libraries to just set 5.03 in error cases when building the payload failed; unencrypted that's rather trivial truncation, here it'd mean having slightly bigger savepoints that contain copies of some ``osc_msg_encrypted_t`` data like the Class-I snapshot)

Encrypt / decrypt
=================

Moving between native and encrypted messages runs through encryption and decryption functions below, many of which also take a security context pointer.

* ``osc_requestid_t`` contains all message identity passed around from (un)protecting a request to (un)protecting a response (like aiocoap's RequestIdentifiers; among other things, this contains a flag of whether the flag about whether the response can re-use the request's PIV because it was just freshly struck out of the replay window)
  * ``osc_requestid_clone`` that copies over a requestid but clears the copy's "can re-use" flag because it's a copy -- for use with storing the requestid of an observation, or if an underlying retransmitting CoAP library prefers to re-compute the response for any retransmissions rather than storing the full response.

* ``osc_msg_unprotect_request`` takes a native message and, if successfully decrypted, returns (C: populates a caller-allocated pointer to) an ``osc_msg_encrypted_t`` (from which the application can read) and a requestid
    * possibly a ``_finish`` function that allows clean re-claiming of the consumed native message
* ``osc_msg_protect_response`` takes a native empty pre-allocated message and a requestid and returns an ``osc_msg_encrypted_t`` into which the response can be written.
    * a ``_finish`` function that does encryption and returns the original native message for sending
* ``osc_msg_protect_request`` (name to be enhanced) that takes a native empty message and returns an ``osc_msg_encrypted_t`` to be populated and a requestid to be kept around.
    * a ``_finish`` function actually does the encryption and produces a native message to be sent (possibly, that and not protect_request produces the requestid)
* ``osc_msg_unprotect_response`` takes a native message and a requestid and, if successfully decrypted, returns an ``osc_msg_encrypted_t`` that can be read.
    * Like with ``osc_msg_unprotect_request``, a finish function should probably go with it

(better names may be ``decrypt`` (with ``cleanup``?) / ``prepare_encrypt`` / ``finish_encrypt``)


Context creation 
================

(details still open)

* create a new context from concrete inputs (with a big warning that never may the same material be put in there twice)
    * with no persistence
    * sender sequence number persistence (full or K-style)
    * receive window persistence (full or Echo recovery)

Context lookup
==============

(deep integration; details very open)

Primitive mapping
=================

Some of them may have sensible default implementations inside the library (CoAP helpers),
for others that'd be risky (AES etc) but an external library can be used as fallback.

* security primitives
    * AES
    * SHA
* CBOR (?; may not be enough to not warrant hard-coding)
* ``osc_helper_encode_option(target_buf, target_len, last_optno, option_buf, option_len)`` and a suitable decoder

Others
======

* "build a reply out of the failure result of ``osc_msg_unprotect_request`` -- initially that spares the users the hassle of setting the right codes for different failure modes; later this is where receive window recovery using Echo is implemented
