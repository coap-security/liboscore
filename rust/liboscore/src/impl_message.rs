use core::mem::MaybeUninit;

use crate::raw;

pub struct ProtectedMessage(core::cell::UnsafeCell<raw::oscore_msg_protected_t>);

impl ProtectedMessage {
    // FIXME do we want to construct them like that?
    pub fn new(msg: raw::oscore_msg_protected_t) -> Self {
        ProtectedMessage(core::cell::UnsafeCell::new(msg))
    }

// That's gonna be tricky; let's see first whether we'll have good lifetimes for secctx & co.
// Possibly, we'll need to do this two-phased with an intermediary object, because we need a &mut
// to the secctx that later only becomes a &, or more precisely, the secctx has an exclusive part
// we need only during this function, and a shared one we need longer.
//     pub fn unprotect_request(
//         msg: raw::oscore_msg_native_t,
//         header: crate::OscoreOption,
//         secctx
//     ) -> Result<Self, ()>
//     {
//         todo!()
//     }
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
            let err = raw::oscore_msg_protected_map_payload(self.0.get(), payload.as_mut_ptr(), payload_len.as_mut_ptr());
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
    val: &'a [u8]
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
            return Some(MessageOption { num: OPTION_INVALID, val: &[] })
        }
        unsafe {
            let mut num = MaybeUninit::uninit();
            let mut val = MaybeUninit::uninit();
            let mut val_len = MaybeUninit::uninit();
            let next_exists = raw::oscore_msg_protected_optiter_next(self.msg.unwrap().get(), &mut self.iter, num.as_mut_ptr(), val.as_mut_ptr(), val_len.as_mut_ptr());
            if !next_exists {
                let msg = self.msg.take().unwrap();
                let err = raw::oscore_msg_protected_optiter_finish(msg.get(), &mut self.iter);
                if raw::oscore_msgerr_protected_is_error(err) {
                    return Some(MessageOption { num: OPTION_INVALID, val: &[] })
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
