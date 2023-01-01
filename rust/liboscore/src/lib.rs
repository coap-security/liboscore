#![no_std]
// We need these linked in
extern crate liboscore_cryptobackend;
extern crate liboscore_msgbackend;

use core::mem::MaybeUninit;

// FIXME: pub only for tests?
pub mod raw;

mod impl_message;
pub use impl_message::ProtectedMessage;

mod oscore_option;
pub use oscore_option::OscoreOption;

mod algorithms;
pub use algorithms::{AeadAlg, AlgorithmNotSupported, HkdfAlg};

mod primitive;
pub use primitive::{DeriveError, PrimitiveContext, PrimitiveImmutables};

// FIXME we should carry the context around, but that'd require it to have a shared portion that we
// can then clone and combine with the oscore_requestid_t.
pub fn protect_request<'a, 'b, R>(
    request: &'a mut coap_message_utils::inmemory_write::Message<'b>,
    ctx: &mut PrimitiveContext,
    writer: impl FnOnce(&mut ProtectedMessage) -> R,
) -> (raw::oscore_requestid_t, R) {
    liboscore_msgbackend::with_inmemory_as_msg_native(request, |msg| {
        let mut plaintext = MaybeUninit::uninit();
        let mut request_data = MaybeUninit::uninit();
        // Safety: Everything that needs to be initialized is
        let prepare_ok = unsafe {
            raw::oscore_prepare_request(
                msg,
                plaintext.as_mut_ptr(),
                ctx.as_mut(),
                request_data.as_mut_ptr(),
            )
        };
        if prepare_ok != raw::oscore_prepare_result_OSCORE_PREPARE_OK {
            todo!("Error handling")
        }
        // Safety: Initialized after successful return
        let plaintext = unsafe { plaintext.assume_init() };
        let request_data = unsafe { request_data.assume_init() };

        let mut plaintext = crate::ProtectedMessage::new(plaintext);
        let user_carry = writer(&mut plaintext);
        let mut plaintext = plaintext.into_inner();

        let mut returned_msg = MaybeUninit::uninit();
        // Safety: Everything that needs to be initialized is
        let finish_ok =
            unsafe { raw::oscore_encrypt_message(&mut plaintext, returned_msg.as_mut_ptr()) };
        if finish_ok != raw::oscore_finish_result_OSCORE_FINISH_OK {
            todo!("Error handling")
        }
        // We're discarding the native message that's in returned_msg. If it were owned (which
        // would be a valid choice for with_inmemory_write), the closure might be required to
        // return it, but it currently isn't.

        (request_data, user_carry)
    })
}

// request being MutableWritableMessage: See unprotect_response
pub fn unprotect_request<R>(
    request: &mut coap_message_utils::inmemory_write::Message<'_>,
    oscoreoption: OscoreOption<'_>, // Here's where we need to cheat a bit: We both take the message
    // writably, *and* we take data out of that message through
    // another pointer. This is legal because we don't alter any
    // option values, or more precisely, we don't alter the OSCORE
    // option's value, but yet it's slightly uncomfortable (and
    // users may need to resort to unsafe to call this).
    ctx: &mut PrimitiveContext,
    reader: impl FnOnce(&ProtectedMessage) -> R,
) -> (raw::oscore_requestid_t, R) {
    liboscore_msgbackend::with_inmemory_as_msg_native(request, |nativemsg| {
        let mut plaintext = MaybeUninit::uninit();
        let mut request_data = MaybeUninit::uninit();
        let decrypt_ok = unsafe {
            raw::oscore_unprotect_request(
                nativemsg,
                plaintext.as_mut_ptr(),
                &oscoreoption.into_inner(),
                ctx.as_mut(),
                request_data.as_mut_ptr(),
            )
        };
        // Here is where we could the mutable part of the ctx, if that were a thing
        match decrypt_ok {
            raw::oscore_unprotect_request_result_OSCORE_UNPROTECT_REQUEST_OK => {
                let plaintext = unsafe { plaintext.assume_init() };
                let request_data = unsafe { request_data.assume_init() };

                let plaintext = ProtectedMessage::new(plaintext);

                let user_data = reader(&plaintext);

                unsafe { raw::oscore_release_unprotected(&mut plaintext.into_inner()) };

                (request_data, user_data)
            }
            _ => {
                todo!("Request is not OK or not fresh (and currently we don't have a way to downgrade the app credentials to not-fresh, and we don't do B.1 recovery either)")
            }
        }
    })
}

/// Protect an OSCORE response
///
/// Note that we're not consuming the correlation data, but merely take a `&mut` to it: This allows
/// multiple responses, which are handled correctly (in that the later context takes a new sequence
/// number) by libOSCORE.
pub fn protect_response<'a, 'b, R>(
    response: &'a mut coap_message_utils::inmemory_write::Message<'b>,
    ctx: &mut PrimitiveContext,
    correlation: &mut raw::oscore_requestid_t,
    writer: impl FnOnce(&mut ProtectedMessage) -> R,
) -> R {
    liboscore_msgbackend::with_inmemory_as_msg_native(response, |nativemsg| {
        let mut plaintext = MaybeUninit::uninit();
        // Safety: Everything that needs to be initialized is
        let prepare_ok = unsafe {
            raw::oscore_prepare_response(
                nativemsg,
                plaintext.as_mut_ptr(),
                ctx.as_mut(),
                correlation,
            )
        };
        if prepare_ok != raw::oscore_prepare_result_OSCORE_PREPARE_OK {
            todo!("Error handling")
        }
        // Safety: Initialized after successful return
        let plaintext = unsafe { plaintext.assume_init() };

        let mut plaintext = crate::ProtectedMessage::new(plaintext);
        let user_data = writer(&mut plaintext);
        let mut plaintext = plaintext.into_inner();

        let mut returned_msg = MaybeUninit::uninit();
        // Safety: Everything that needs to be initialized is
        let finish_ok =
            unsafe { raw::oscore_encrypt_message(&mut plaintext, returned_msg.as_mut_ptr()) };
        if finish_ok != raw::oscore_finish_result_OSCORE_FINISH_OK {
            todo!("Error handling")
        }
        // We're discarding the native message that's in returned_msg. If it were owned (which
        // would be a valid choice for with_inmemory_write), the closure might be required to
        // return it, but it currently isn't.

        user_data
    })
}

// Note that yes we really need this to be a MutableWritableMessage and not just a ReadableMessage,
// because we decrypt in place. (A narrower set of requirements,
// "ReadableMessageWithMutablePayload", would suffice, but none such trait is useful outside of
// here ... though, for CBOR decoding, maybe, where we memmove around indefinite length strings
// into place?).
pub fn unprotect_response<R>(
    response: &mut coap_message_utils::inmemory_write::Message<'_>,
    ctx: &mut PrimitiveContext,
    oscoreoption: OscoreOption<'_>,
    correlation: &mut raw::oscore_requestid_t,
    reader: impl FnOnce(&ProtectedMessage) -> R,
) -> R {
    liboscore_msgbackend::with_inmemory_as_msg_native(response, |nativemsg| {
        let mut plaintext = MaybeUninit::uninit();
        let decrypt_ok = unsafe {
            raw::oscore_unprotect_response(
                nativemsg,
                plaintext.as_mut_ptr(),
                &oscoreoption.into_inner(),
                ctx.as_mut(),
                correlation,
            )
        };
        match decrypt_ok {
            raw::oscore_unprotect_request_result_OSCORE_UNPROTECT_REQUEST_OK => {
                let plaintext = unsafe { plaintext.assume_init() };

                let plaintext = ProtectedMessage::new(plaintext);

                let user_data = reader(&plaintext);

                unsafe { raw::oscore_release_unprotected(&mut plaintext.into_inner()) };

                user_data
            }
            e => {
                todo!("Unprotecting response failed: {e:?}")
            }
        }
    })
}
