Messages
========

Structs and methods for CoAP messages.
Those will need to be present twice,
once operating on the underlying CoAP library's messages (``osc_msg_native_``)
and once operating on an OSCORE message (``osc_msg_encrypted_``)

* ``osc_msg_native_t``: A type provided by the native library.
* ``osc_msg_encrypted_t``: A type provided by the OSCORE library.

  It contains an ``osc_msg_native_t`` as well as pointers inside there ("how many U options have we written (esp. for tracking whether the OSCORE option has been written), how many E options have we written (esp. for tracking whether the inner Observe option has been written))") as well as some other state (eg. the hash state of the external AAD that'll be updated when I options are added).

  The expectation is that the message is built in-place, with the to-be-encrypted data in the very place where its ciphertext will be.
  For this to work we'll need to demand that either
  * options arrive in the right sequence *even w/rt OSCORE* (ie. Class-E always after Class-U), or
  * that the native library is ready to add options even if payload was entered. (That'll require memmove-ing, but no recalculation of option numbers.)
  Probably we'll support both.

* For every message type:

  * ``_{get,set}_code``
  * ``_append_option`` (asserting that no later options have been written, and possiblty that payload has not been written / see "in-place buildability")
      * When options are appended to an encrypted_t, then happens the decision to write it into the underlying native (U) message, the inner message (E), the AAD state (I) or whehter maybe now it's time to add another option (eg. jsut before the first option after the OSCORE number is written to U, then the OSCORE option gets written in there)
  * ``_update_option`` (asserting that the option has previously been added with that very length. Useful to provide, we probably won't need the native version as we should know all that goes into the OSCORE option by the time we'll need to inject it into the message)
  * ``_iter_options`` (a pair of "set up an iterator" / "get the next pointers" functions or possibly macros)
  * ``_map_payload`` ("give me pointers to the area into which I can put my payload, or read payload from", possibly with a dedicated method for read-only messages)
  * ``_trim_payload`` (truncate the message to the given length)
  * possibly some rewind savepointing (useful in existing libraries to just set 5.03 in error cases when building the payload failed; unencrypted that's rather trivial truncation, here it'd mean having slightly bigger savepoints that contain copies of some ``osc_msg_encrypted_t`` data like the Class-I snapshot)
  * possibly a function to estimate the remaining payload size if payload were added now

Encrypt / decrypt
=================

Moving between native and encrypted messages runs through encryption and decryption functions below, many of which also take a security context pointer.

* ``osc_requestid_t`` contains all message identity passed around from (un)protecting a request to (un)protecting a response (like aiocoap's RequestIdentifiers; among other things, this contains a flag of whether the flag about whether the response can re-use the request's PIV because it was just freshly struck out of the replay window)
  * ``osc_requestid_clone`` that copies over a requestid but clears the copy's "can re-use" flag because it's a copy -- for use with storing the requestid of an observation, or if an underlying retransmitting CoAP library prefers to re-compute the response for any retransmissions rather than storing the full response.
  * possibly distinguish between incoming and outgoing messages on type level

* ``osc_msg_unprotect_request`` takes a native message and, if successfully decrypted, returns (C: populates a caller-allocated pointer to) an ``osc_msg_encrypted_t`` (from which the application can read) and a requestid
    * cater for any synthetic observe number to be extracted, either by a dedicated access function or by synthesizing an Observe option when an iterater over the unprotected message gets to it. Preferably it'll be the former, given that different transports have different rules for re-ordering anyway (eg. TCP has no numbers in there either).
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
      * back-end must implement a "request value to be set to"-function, and must call "value has been set to"-function later
      * alternatively, have back-ends implement the full K mechanism all on their own, and provide a demo implementation with the context lookup methods
    * receive window persistence (full or Echo recovery)
* look up details from a context:
    * description (a void pointer set by the application)
    * default host name?
    * number of remaining IVs
* per-type interactions
    * B1 K-side: maybe call-back for offering that a K-bumping request would make sense now b/c it could be served with a bulk flash operation (K values would need a threshold setting then)

Context lookup
==============

(deep integration; details open)

* a function that, given a native message, extracts the KID and ID context (cf. aiocoap's verify_start)
* guidance documentation for deep integration libraries on how to store contexts in an own data structure and look them up
    * This avoids having to manage callbacks from inside this library, and allows better integration with the native CoAP library's take on threads. If the environment is callback-friendly, the deep-integration wrapper can take the verify_start data and call an application provided function if that works in that setup, or look into its own static context store. Starting any callbacks from here has the additional advantage that additional information from the native library like the remote address can be included, which are invisible to this library.
    * This needs to emphasise that how KID and ID-Context are handled depends on the types of security contexts in there; for example, any ID-Context on a B2 KID would need to return the generic B2 context at lookup.
* a simple in-RAM minimal storage for no-persistance contexts
    * or one for B2 contexts that is split in a persistable (just-memcpy-to-save) and an ephemeral (do-not-memcpy) part
    * and possibly one for B1 that requires a back-end flash storage API

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
* similarly, provide guidance for client side. If a client received a response that contains a protected Echo, the library will unprotect it but return neither a "unprotection failed" error nor an unprotected fake-5.03 but an additional "unprotection indicated you must retry".
    * The server's Echo value will either live in that return code (but we aren't Rust to make it a valued Enum...), or the context has a limited field for the next Echo value demanded by the server.
