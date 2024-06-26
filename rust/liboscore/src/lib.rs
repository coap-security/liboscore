#![no_std]
// We need these linked in
extern crate liboscore_cryptobackend;
extern crate liboscore_msgbackend;

use core::mem::MaybeUninit;

mod platform;

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

#[non_exhaustive]
#[derive(Debug, Copy, Clone)]
pub enum PrepareError {
    /// The security context can not provide protection for this message
    SecurityContextUnavailable,
}

impl PrepareError {
    /// Construct a Rust error type out of the C type
    ///
    /// This returns a result to be easily usable with the `?` operator.
    fn new(input: raw::oscore_prepare_result) -> Result<(), Self> {
        match input {
            raw::oscore_prepare_result_OSCORE_PREPARE_OK => Ok(()),
            raw::oscore_prepare_result_OSCORE_PREPARE_SECCTX_UNAVAILABLE => {
                Err(PrepareError::SecurityContextUnavailable)
            }
            _ => unreachable!(),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Copy, Clone)]
pub enum FinishError {
    Size,
    Crypto,
}

impl FinishError {
    /// Construct a Rust error type out of the C type
    ///
    /// This returns a result to be easily usable with the `?` operator.
    fn new(input: raw::oscore_finish_result) -> Result<(), Self> {
        match input {
            raw::oscore_finish_result_OSCORE_FINISH_OK => Ok(()),
            raw::oscore_finish_result_OSCORE_FINISH_ERROR_SIZE => Err(FinishError::Size),
            raw::oscore_finish_result_OSCORE_FINISH_ERROR_CRYPTO => Err(FinishError::Crypto),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ProtectError {
    Prepare(PrepareError),
    Finish(FinishError),
}

impl From<PrepareError> for ProtectError {
    fn from(e: PrepareError) -> Self {
        ProtectError::Prepare(e)
    }
}

impl From<FinishError> for ProtectError {
    fn from(e: FinishError) -> Self {
        ProtectError::Finish(e)
    }
}

#[non_exhaustive]
#[derive(Debug, Copy, Clone)]
pub enum UnprotectRequestError {
    Duplicate,
    Invalid,
}

impl UnprotectRequestError {
    /// Construct a Rust error type out of the C type
    ///
    /// This returns a result to be easily usable with the `?` operator.
    fn new(input: raw::oscore_unprotect_request_result) -> Result<(), Self> {
        match input {
            raw::oscore_unprotect_request_result_OSCORE_UNPROTECT_REQUEST_OK => Ok(()),
            raw::oscore_unprotect_request_result_OSCORE_UNPROTECT_REQUEST_DUPLICATE => {
                Err(UnprotectRequestError::Duplicate)
            }
            raw::oscore_unprotect_request_result_OSCORE_UNPROTECT_REQUEST_INVALID => {
                Err(UnprotectRequestError::Invalid)
            }
            _ => unreachable!(),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Copy, Clone)]
pub enum UnprotectResponseError {
    Invalid,
}

impl UnprotectResponseError {
    /// Construct a Rust error type out of the C type
    ///
    /// This returns a result to be easily usable with the `?` operator.
    fn new(input: raw::oscore_unprotect_response_result) -> Result<(), Self> {
        match input {
            raw::oscore_unprotect_response_result_OSCORE_UNPROTECT_RESPONSE_OK => Ok(()),
            raw::oscore_unprotect_response_result_OSCORE_UNPROTECT_RESPONSE_INVALID => {
                Err(UnprotectResponseError::Invalid)
            }
            _ => unreachable!(),
        }
    }
}

// FIXME we should carry the context around, but that'd require it to have a shared portion that we
// can then clone and combine with the oscore_requestid_t.
pub fn protect_request<'a, 'b, R>(
    request: impl liboscore_msgbackend::WithMsgNative,
    ctx: &mut PrimitiveContext,
    writer: impl FnOnce(&mut ProtectedMessage) -> R,
) -> Result<(raw::oscore_requestid_t, R), ProtectError> {
    request.with_msg_native(|msg| {
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
        PrepareError::new(prepare_ok)?;
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
        FinishError::new(finish_ok)?;
        // We're discarding the native message that's in returned_msg. If it were owned (which
        // would be a valid choice for with_inmemory_write), the closure might be required to
        // return it, but it currently isn't.

        Ok((request_data, user_carry))
    })
}

// request being MutableWritableMessage: See unprotect_response
pub fn unprotect_request<R>(
    request: impl liboscore_msgbackend::WithMsgNative,
    oscoreoption: OscoreOption<'_>, // Here's where we need to cheat a bit: We both take the message
    // writably, *and* we take data out of that message through
    // another pointer. This is legal because we don't alter any
    // option values, or more precisely, we don't alter the OSCORE
    // option's value, but yet it's slightly uncomfortable (and
    // users may need to resort to unsafe to call this).
    ctx: &mut PrimitiveContext,
    reader: impl FnOnce(&ProtectedMessage) -> R,
) -> Result<(raw::oscore_requestid_t, R), UnprotectRequestError> {
    request.with_msg_native(|nativemsg| {
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
        // We could introduce extra handling of Invalid if our handlers had a notion of being (even
        // security-wise) idempotent, or if we supported B.1 recovery here.
        UnprotectRequestError::new(decrypt_ok)?;

        let plaintext = unsafe { plaintext.assume_init() };
        let request_data = unsafe { request_data.assume_init() };

        let plaintext = ProtectedMessage::new(plaintext);

        let user_data = reader(&plaintext);

        unsafe { raw::oscore_release_unprotected(&mut plaintext.into_inner()) };

        Ok((request_data, user_data))
    })
}

/// Protect an OSCORE response
///
/// Note that we're not consuming the correlation data, but merely take a `&mut` to it: This allows
/// multiple responses, which are handled correctly (in that the later context takes a new sequence
/// number) by libOSCORE.
pub fn protect_response<'a, 'b, R>(
    response: impl liboscore_msgbackend::WithMsgNative,
    ctx: &mut PrimitiveContext,
    correlation: &mut raw::oscore_requestid_t,
    writer: impl FnOnce(&mut ProtectedMessage) -> R,
) -> Result<R, ProtectError> {
    response.with_msg_native(|nativemsg| {
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
        PrepareError::new(prepare_ok)?;
        // Safety: Initialized after successful return
        let plaintext = unsafe { plaintext.assume_init() };

        let mut plaintext = crate::ProtectedMessage::new(plaintext);
        let user_data = writer(&mut plaintext);
        let mut plaintext = plaintext.into_inner();

        let mut returned_msg = MaybeUninit::uninit();
        // Safety: Everything that needs to be initialized is
        let finish_ok =
            unsafe { raw::oscore_encrypt_message(&mut plaintext, returned_msg.as_mut_ptr()) };
        FinishError::new(finish_ok)?;
        // We're discarding the native message that's in returned_msg. If it were owned (which
        // would be a valid choice for with_inmemory_write), the closure might be required to
        // return it, but it currently isn't.

        Ok(user_data)
    })
}

// Note that yes we really need this to be a MutableWritableMessage and not just a ReadableMessage,
// because we decrypt in place. (A narrower set of requirements,
// "ReadableMessageWithMutablePayload", would suffice, but none such trait is useful outside of
// here ... though, for CBOR decoding, maybe, where we memmove around indefinite length strings
// into place?).
pub fn unprotect_response<R>(
    response: impl liboscore_msgbackend::WithMsgNative,
    ctx: &mut PrimitiveContext,
    oscoreoption: OscoreOption<'_>,
    correlation: &mut raw::oscore_requestid_t,
    reader: impl FnOnce(&ProtectedMessage) -> R,
) -> Result<R, UnprotectResponseError> {
    response.with_msg_native(|nativemsg| {
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
        UnprotectResponseError::new(decrypt_ok)?;

        let plaintext = unsafe { plaintext.assume_init() };

        let plaintext = ProtectedMessage::new(plaintext);

        let user_data = reader(&plaintext);

        unsafe { raw::oscore_release_unprotected(&mut plaintext.into_inner()) };

        Ok(user_data)
    })
}
