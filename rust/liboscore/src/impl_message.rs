use core::mem::MaybeUninit;

use crate::raw;

pub struct ProtectedMessage(core::cell::UnsafeCell<raw::oscore_msg_protected_t>);

impl ProtectedMessage {
    // FIXME do we want to construct them like that?
    pub fn new(msg: raw::oscore_msg_protected_t) -> Self {
        ProtectedMessage(core::cell::UnsafeCell::new(msg))
    }

    pub fn into_inner(mut self) -> raw::oscore_msg_protected_t {
        // Once we convert it out, all write operations are done, but libOSCORE expects an empty
        // payload to be set, which coap-message 0.3 does not always provide.
        if unsafe { (*self.0.get()).payload_offset } == 0 {
            use coap_message::MutableWritableMessage;
            self.truncate(0)
                .expect("Truncation to zero is always successful");
        }

        self.0.into_inner()
    }
}

impl coap_message::ReadableMessage for ProtectedMessage {
    type Code = u8;
    type MessageOption<'a> = MessageOption<'a>;
    type OptionsIter<'a> = OptionsIter<'a>;
    fn code(&self) -> u8 {
        unsafe { raw::oscore_msg_protected_get_code(self.0.get()) }
    }
    fn payload(&self) -> &[u8] {
        unsafe {
            let mut payload = MaybeUninit::uninit();
            let mut payload_len = MaybeUninit::uninit();
            let err = raw::oscore_msg_protected_map_payload(
                self.0.get(),
                payload.as_mut_ptr(),
                payload_len.as_mut_ptr(),
            );
            assert!(!raw::oscore_msgerr_protected_is_error(err));
            core::slice::from_raw_parts(payload.assume_init(), payload_len.assume_init())
        }
    }
    fn options(&self) -> OptionsIter {
        unsafe {
            let mut iter = MaybeUninit::uninit();
            // Cast: see payload()
            raw::oscore_msg_protected_optiter_init(self.0.get(), iter.as_mut_ptr());
            let iter = iter.assume_init();
            OptionsIter {
                msg: Some(&self.0),
                iter,
            }
        }
    }
}

pub struct MessageOption<'a> {
    num: u16,
    val: &'a [u8],
}

impl<'a> coap_message::MessageOption for MessageOption<'a> {
    fn number(&self) -> u16 {
        self.num
    }

    fn value(&self) -> &[u8] {
        self.val
    }
}

pub struct OptionsIter<'a> {
    // a None here indicates that there was an error in the option encoding of the message;
    // consequently, we need to produce erroneous options to conform with coap-message's view of
    // fauly messages.
    msg: Option<&'a core::cell::UnsafeCell<raw::oscore_msg_protected_t>>,
    iter: raw::oscore_msg_protected_optiter_t,
}

const OPTION_INVALID: u16 = u16::MAX;

impl<'a> Iterator for OptionsIter<'a> {
    type Item = MessageOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.msg.is_none() {
            return Some(MessageOption {
                num: OPTION_INVALID,
                val: &[],
            });
        }
        unsafe {
            let mut num = MaybeUninit::uninit();
            let mut val = MaybeUninit::uninit();
            let mut val_len = MaybeUninit::uninit();
            let next_exists = raw::oscore_msg_protected_optiter_next(
                self.msg.unwrap().get(),
                &mut self.iter,
                num.as_mut_ptr(),
                val.as_mut_ptr(),
                val_len.as_mut_ptr(),
            );
            if !next_exists {
                let msg = self.msg.take().unwrap();
                let err = raw::oscore_msg_protected_optiter_finish(msg.get(), &mut self.iter);
                if raw::oscore_msgerr_protected_is_error(err) {
                    return Some(MessageOption {
                        num: OPTION_INVALID,
                        val: &[],
                    });
                } else {
                    return None;
                }
            }
            let num = num.assume_init();
            let val = val.assume_init();
            let val_len = val_len.assume_init();
            let val = core::slice::from_raw_parts(val, val_len);
            Some(MessageOption { num, val })
        }
    }
}

impl<'a> Drop for OptionsIter<'a> {
    fn drop(&mut self) {
        if let Some(msg) = self.msg.take() {
            // The iterator was not exhausted, so we don't need to report that something was odd
            // (because not even all options have been read)
            unsafe { raw::oscore_msg_protected_optiter_finish(msg.get(), &mut self.iter) };
        }
    }
}

/// The error libOSCORE operations on messages produce
///
/// This currently carries an internal C error with the invariant that it is not OK (but without
/// the optimization that'd make its Option equally sized, for the OK representation is not
/// guaranteed).
#[derive(Debug)]
#[allow(dead_code)] // Yes we carry it *only* for the Debug derive
pub struct OscoreError(raw::oscore_msgerr_protected_t);

impl coap_message::error::RenderableOnMinimal for OscoreError {
    type Error<IE: coap_message::error::RenderableOnMinimal + core::fmt::Debug> = IE;
    fn render<M: coap_message::MinimalWritableMessage>(
        self,
        msg: &mut M,
    ) -> Result<(), Self::Error<M::UnionError>> {
        use coap_message::Code;
        msg.set_code(Code::new(coap_numbers::code::INTERNAL_SERVER_ERROR)?);
        Ok(())
    }
}

fn convert_error(original: raw::oscore_msgerr_protected_t) -> Result<(), OscoreError> {
    if unsafe { raw::oscore_msgerr_protected_is_error(original) } {
        Err(OscoreError(original))
    } else {
        Ok(())
    }
}

impl From<core::convert::Infallible> for OscoreError {
    fn from(other: core::convert::Infallible) -> Self {
        match other {}
    }
}

impl coap_message::MinimalWritableMessage for ProtectedMessage {
    type AddOptionError = OscoreError;
    type SetPayloadError = OscoreError;
    type UnionError = OscoreError;

    type Code = u8;
    type OptionNumber = u16;

    fn set_code(&mut self, code: u8) {
        unsafe { raw::oscore_msg_protected_set_code(self.0.get(), code) }
    }

    fn add_option(&mut self, number: u16, value: &[u8]) -> Result<(), OscoreError> {
        convert_error(unsafe {
            raw::oscore_msg_protected_append_option(
                self.0.get(),
                number,
                value.as_ptr(),
                value.len(),
            )
        })
    }

    fn set_payload(&mut self, payload: &[u8]) -> Result<(), OscoreError> {
        let mut buffer_start = MaybeUninit::uninit();
        let mut buffer_len = MaybeUninit::uninit();

        convert_error(unsafe {
            raw::oscore_msg_protected_map_payload(
                self.0.get(),
                buffer_start.as_mut_ptr(),
                buffer_len.as_mut_ptr(),
            )
        })?;

        let buffer = unsafe {
            core::slice::from_raw_parts_mut(buffer_start.assume_init(), buffer_len.assume_init())
        };
        buffer
            .get_mut(..payload.len())
            .ok_or(OscoreError(raw::oscore_msgerr_protected_t_MESSAGESIZE))?
            .copy_from_slice(payload);

        convert_error(unsafe {
            raw::oscore_msg_protected_trim_payload(self.0.get(), payload.len())
        })
    }
}

impl coap_message::MutableWritableMessage for ProtectedMessage {
    fn available_space(&self) -> usize {
        // It'd be tempting to calculate this through payload().len(), but then libOSCORE considers
        // the payload mapped, and any later option adding would be a sequence violation.
        //
        // So we're using the fact that we're really internal to libOSCORE, and dip into fields.
        // Conveniently, this only needs to be correct in the "good" case, so we can just provide a
        // good guess (because nothing can rely on this for unsafe stuff anyway).

        // Safety: We're only accessing things inside this function, while we're not mutating
        // (which we know not to happen because ProtectedMessage is not Sync).
        let msg = unsafe { &*self.0.get() };

        let mut outer_payload = MaybeUninit::uninit();
        let mut outer_payload_len = MaybeUninit::uninit();
        // FIXME: In C, msg_backend_t is implicitly Clone. How do we make it clone most easily
        // here?
        let msg_backend_copy = unsafe { core::ptr::read(&msg.backend) };
        let err = unsafe {
            raw::oscore_msg_native_map_payload(
                msg_backend_copy,
                outer_payload.as_mut_ptr(),
                outer_payload_len.as_mut_ptr(),
            )
        };
        assert!(!unsafe { raw::oscore_msgerr_native_is_error(err) });
        let outer_payload_len = unsafe { outer_payload_len.assume_init() };
        let mut autooptions_len: usize = 0;
        if msg.class_e.option_number < 6
        /* Observe */
        {
            autooptions_len += 2; // Counting only one of the two occurrences, for if the user sets
                                  // one, they account for the other
        }
        if msg.class_e.option_number < 9
        /* OSCORE */
        {
            // bindgen can't evaluate that for us, expanded manually (assuming the Rust version of
            // the cryptobackend):
            let oscore_crypto_aead_iv_maxlen: usize = 13;
            // bindgen can't evaluate that for us, expanded manually:
            let keyid_maxlen = oscore_crypto_aead_iv_maxlen - raw::IV_KEYID_UNUSABLE as usize;
            // Conservative estimate based on the buffer size inside flush_autooptions_outer_until
            autooptions_len += 1
                + 1
                + raw::PIV_BYTES as usize
                + 1
                + raw::OSCORE_KEYIDCONTEXT_MAXLEN as usize
                + keyid_maxlen;
        }
        outer_payload_len - autooptions_len - 2 - msg.class_e.cursor - msg.tag_length
    }

    fn payload_mut_with_len(&mut self, length: usize) -> Result<&mut [u8], OscoreError> {
        self.truncate(length)?;
        let mut payload = MaybeUninit::uninit();
        let mut payload_len = MaybeUninit::uninit();
        convert_error(unsafe {
            raw::oscore_msg_protected_map_payload(
                self.0.get(),
                payload.as_mut_ptr(),
                payload_len.as_mut_ptr(),
            )
        })?;
        Ok(unsafe {
            core::slice::from_raw_parts_mut(payload.assume_init(), payload_len.assume_init())
        })
    }

    fn truncate(&mut self, len: usize) -> Result<(), OscoreError> {
        convert_error(unsafe { raw::oscore_msg_protected_trim_payload(self.0.get(), len) })
    }

    fn mutate_options<F: FnMut(u16, &mut [u8])>(&mut self, mut f: F) {
        // This implementation is a bit more limited than what oscore_msg_protected_update_option
        // can do, but it should suffice for all practical purposes.
        unsafe {
            let mut iter = MaybeUninit::uninit();
            raw::oscore_msg_protected_optiter_init(self.0.get(), iter.as_mut_ptr());
            let mut iter = iter.assume_init();
            loop {
                let mut num = MaybeUninit::uninit();
                let mut val = MaybeUninit::uninit();
                let mut val_len = MaybeUninit::uninit();
                let next_exists = raw::oscore_msg_protected_optiter_next(
                    self.0.get(),
                    &mut iter,
                    num.as_mut_ptr(),
                    val.as_mut_ptr(),
                    val_len.as_mut_ptr(),
                );
                if !next_exists {
                    // No way to handle errors, but there shouldn't be any given that we're
                    // building this message
                    raw::oscore_msg_protected_optiter_finish(self.0.get(), &mut iter);
                    return;
                }
                // FIXME SAFETY: This cast is *actually* just valid for inner options, where we
                // have mutable access (for outer options, the interface might simply not hold, and
                // we can't emulate because we can't allocate a buffer to run the function on to
                // see then whether we should call the update). Enhanced interfaces on the
                // coap-message side should fix that.
                let val = val.assume_init() as *mut _;
                let val_len = val_len.assume_init();
                let num = num.assume_init();
                let val = core::slice::from_raw_parts_mut(val, val_len);
                f(num, val);
            }
        }
    }
}
