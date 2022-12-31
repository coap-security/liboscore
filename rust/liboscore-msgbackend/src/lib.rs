//! Backend for liboscore's native message API
//!
//! This is (and, unless one wants to go through `Box<dyn ReadableMessage>`) necessarily a bit
//! opinionated, in that it binds to a concrete message type (or set thereof).
//!
//! It wraps different implementations of coap-message in an enum.
#![no_std]
#![allow(non_camel_case_types)]

#[cfg(feature = "alloc")]
extern crate alloc;

use core::mem::MaybeUninit;

use coap_message::{
    MessageOption as _, MinimalWritableMessage, MutableWritableMessage, ReadableMessage,
};

/// Void stand-in recognized by the cbindgen library by its name
#[allow(non_camel_case_types)]
pub enum c_void {}

struct Message<'a> {
    data: MessageVariant<'a>,
    /// We have to keep the payload length that is not kept in the message because libOSCORE does
    /// not differentiate between writable and readable messages. coap-message has writable
    /// messages whose payload you could map to whichever length you want (as long as it's within
    /// the available length), and readable whose payload you could map exactly as it is. But
    /// libOSCORE (at least its tests) expect to truncate a message, and then map it (in full
    /// written length) to read it back. coap-message doesn't support that, so we keep extra data
    /// to make it work.
    ///
    /// As a future optimization, one could consider removing it, but then tests (standalone-demo)
    /// would fail.
    payload_length: Option<usize>,
}

enum MessageVariant<'a> {
    #[cfg(feature = "alloc")]
    CmHmHm(coap_message::heapmessage::HeapMessage),
    CmuImwM(&'a mut coap_message_utils::inmemory_write::Message<'a>),
    // Note that there's little point in wrapping anything that's Readable but not MutableWritable:
    // All our decryption happens in-place.
}

impl<'a> Message<'a> {
    unsafe fn from_ptr(ptr: oscore_msg_native_t) -> &'a mut Self {
        unsafe { &mut *(ptr.0 as *mut Message<'a>) }
    }
}

impl<'a> ReadableMessage for Message<'a> {
    type Code = u8;
    type MessageOption<'b> = MessageOption<'b> where Self: 'b;
    type OptionsIter<'b> = OptionsIter<'b> where Self: 'b;
    fn code(&self) -> u8 {
        match &self.data {
            #[cfg(feature = "alloc")]
            MessageVariant::CmHmHm(m) => m.code(),
            MessageVariant::CmuImwM(m) => m.code(),
        }
    }
    fn payload(&self) -> &[u8] {
        // Panic rather than having a trivial yet still untested implementation
        panic!("This function is not used by the oscore_msg_native implementation");
    }
    fn options(&self) -> Self::OptionsIter<'_> {
        match &self.data {
            #[cfg(feature = "alloc")]
            MessageVariant::CmHmHm(m) => OptionsIter::CmHmHm(m.options()),
            MessageVariant::CmuImwM(m) => OptionsIter::CmuImwM(m.options()),
        }
    }
}

impl<'a> MinimalWritableMessage for Message<'a> {
    type Code = u8;
    type OptionNumber = u16;

    fn set_code(&mut self, code: u8) {
        match &mut self.data {
            #[cfg(feature = "alloc")]
            MessageVariant::CmHmHm(m) => m.set_code(code),
            MessageVariant::CmuImwM(m) => m.set_code(code),
        }
    }
    fn add_option(&mut self, option: u16, data: &[u8]) {
        match &mut self.data {
            #[cfg(feature = "alloc")]
            MessageVariant::CmHmHm(m) => m.add_option(option, data),
            MessageVariant::CmuImwM(m) => m.add_option(option, data),
        }
    }
    fn set_payload(&mut self, _: &[u8]) {
        // Panic rather than having a trivial yet still untested implementation
        panic!("This function is not used by the oscore_msg_native implementation");
    }
}

impl<'a> MutableWritableMessage for Message<'a> {
    fn available_space(&self) -> usize {
        match &self.data {
            #[cfg(feature = "alloc")]
            MessageVariant::CmHmHm(m) => m.available_space(),
            MessageVariant::CmuImwM(m) => m.available_space(),
        }
    }
    fn payload_mut(&mut self) -> &mut [u8] {
        // Panic rather than having a trivial yet still untested implementation
        panic!("This function is not used by the oscore_msg_native implementation");
    }
    fn payload_mut_with_len(&mut self, len: usize) -> &mut [u8] {
        match &mut self.data {
            #[cfg(feature = "alloc")]
            MessageVariant::CmHmHm(m) => m.payload_mut_with_len(len),
            MessageVariant::CmuImwM(m) => m.payload_mut_with_len(len),
        }
    }
    fn truncate(&mut self, len: usize) {
        self.payload_length = Some(len);

        match &mut self.data {
            #[cfg(feature = "alloc")]
            MessageVariant::CmHmHm(m) => m.truncate(len),
            MessageVariant::CmuImwM(m) => m.truncate(len),
        }
    }
    fn mutate_options<F: FnMut(u16, &mut [u8])>(&mut self, f: F) {
        match &mut self.data {
            #[cfg(feature = "alloc")]
            MessageVariant::CmHmHm(m) => m.mutate_options(f),
            MessageVariant::CmuImwM(m) => m.mutate_options(f),
        }
    }
}

enum OptionsIter<'a> {
    #[cfg(feature = "alloc")]
    CmHmHm(<coap_message::heapmessage::HeapMessage as ReadableMessage>::OptionsIter<'a>),
    CmuImwM(<coap_message_utils::inmemory_write::Message<'a> as ReadableMessage>::OptionsIter<'a>),
}

impl<'a> core::iter::Iterator for OptionsIter<'a> {
    type Item = MessageOption<'a>;

    fn next(&mut self) -> Option<MessageOption<'a>> {
        match self {
            #[cfg(feature = "alloc")]
            OptionsIter::CmHmHm(i) => i.next().map(MessageOption::CmHmHm),
            OptionsIter::CmuImwM(i) => i.next().map(MessageOption::CmuImwM),
        }
    }
}

enum MessageOption<'a> {
    #[cfg(feature = "alloc")]
    CmHmHm(<coap_message::heapmessage::HeapMessage as ReadableMessage>::MessageOption<'a>),
    CmuImwM(<coap_message_utils::inmemory_write::Message<'a> as ReadableMessage>::MessageOption<'a>),
}

impl<'a> coap_message::MessageOption for MessageOption<'a> {
    fn number(&self) -> u16 {
        match self {
            #[cfg(feature = "alloc")]
            MessageOption::CmHmHm(m) => m.number(),
            MessageOption::CmuImwM(m) => m.number(),
        }
    }

    fn value(&self) -> &[u8] {
        match self {
            #[cfg(feature = "alloc")]
            MessageOption::CmHmHm(m) => m.value(),
            MessageOption::CmuImwM(m) => m.value(),
        }
    }
}

/// The message type is conveniently already more pointer-like; given that we pass around pointers
/// to a concrete type (albeit possibly an enum), it's just that.
///
/// The current convention this crate adheres to is to go through a level of indirection (being a
/// pointer to the Message enum) rather than the full enum itself. The latter is well within the
/// design space of libOSCORE, but given that there is as of 2022 some confusion about WASM's ABI
/// (C and Rust-on-some-target-triples disagree on whether they are passed by value or by
/// reference on the ABI level when passed by value on the API level), a small struct is
/// preferable.
///
/// If `&dyn the-required-traits` were possible, we could also pass that (subject to the same
/// limitations as passing the full enum).
///
/// The void pointer hides a [Message] enum (because it can't be repr(C)) that always has
/// "sufficient" lifetime (we have to trust the C side on that).
#[repr(C)]
pub struct oscore_msg_native_t(*mut c_void);

#[repr(C)]
pub struct oscore_msg_native_optiter_t([u64; 12]);

/// Errors out of message operations
///
/// Note that due to coap-message's general infallible nature (it expect messages to be allocated
/// sufficiently large, and panics if that is not upheld), this only contains error values for
/// things where coap-message is markedly distinct from msg_native, and thus this crate actually
/// implements anything (that can fail) rather than passing on.
// All need unique names as they do get mapped out to the C side as well
#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum oscore_msgerr_native_t {
    ResultOk,
    UpdateOptionWrongLength,
    UpdateOptionNotFound,
}

#[no_mangle]
pub extern "C" fn oscore_msg_native_get_code(msg: oscore_msg_native_t) -> u8 {
    unsafe { Message::from_ptr(msg) }.code()
}

#[no_mangle]
pub extern "C" fn oscore_msg_native_set_code(msg: oscore_msg_native_t, code: u8) {
    unsafe { Message::from_ptr(msg) }.set_code(code)
}

#[no_mangle]
pub extern "C" fn oscore_msg_native_append_option(
    msg: oscore_msg_native_t,
    option_number: u16,
    value: *const u8,
    value_len: usize,
) -> oscore_msgerr_native_t {
    let value = unsafe { core::slice::from_raw_parts(value, value_len) };
    unsafe { Message::from_ptr(msg) }.add_option(option_number, value);
    oscore_msgerr_native_t::ResultOk
}

#[no_mangle]
pub extern "C" fn oscore_msg_native_update_option(
    msg: oscore_msg_native_t,
    option_number: u16,
    option_occurrence: usize,
    value: *const u8,
    value_len: usize,
) -> oscore_msgerr_native_t {
    let msg = unsafe { Message::from_ptr(msg) };
    let value = unsafe { core::slice::from_raw_parts(value, value_len) };

    let mut result = oscore_msgerr_native_t::ResultOk;
    let mut occurrence = Some(option_occurrence);
    msg.mutate_options(|onum, oval| {
        if onum == option_number {
            occurrence = match occurrence {
                Some(0) => {
                    if oval.len() == value.len() {
                        oval[..].copy_from_slice(value);
                    } else {
                        result = oscore_msgerr_native_t::UpdateOptionWrongLength;
                    }
                    None
                }
                Some(i) => Some(i - 1),
                None => None,
            }
        }
    });
    if occurrence.is_some() {
        result = oscore_msgerr_native_t::UpdateOptionNotFound;
    }
    result
}

#[no_mangle]
pub extern "C" fn oscore_msg_native_optiter_init(
    msg: oscore_msg_native_t,
    iter: &mut MaybeUninit<oscore_msg_native_optiter_t>,
) {
    let msg = unsafe { Message::from_ptr(msg) };
    assert!(
        core::mem::size_of::<oscore_msg_native_optiter_t>()
            >= core::mem::size_of::<OptionsIter<'static>>(),
        "OptionsIter doesn't fit in oscore_msg_native_optiter_t"
    );
    assert!(
        core::mem::align_of::<oscore_msg_native_optiter_t>()
            >= core::mem::align_of::<OptionsIter<'static>>(),
        "oscore_msg_native_optiter_t is insufficiently aligned for OptionsIter"
    );
    let iter: &mut MaybeUninit<OptionsIter> = unsafe { core::mem::transmute(iter) };
    iter.write(msg.options());
}

#[no_mangle]
pub extern "C" fn oscore_msg_native_map_payload(
    msg: oscore_msg_native_t,
    payload: &mut *mut u8,
    payload_len: &mut usize,
) -> oscore_msgerr_native_t {
    let msg = unsafe { Message::from_ptr(msg) };
    if let Some(len) = msg.payload_length {
        *payload_len = len;
    } else {
        let original_space = msg.available_space();
        // FIXME: Heap versions would report SIZE_MAX, which is technically correct but highly
        // impractical for the implementation that'd just map it all rater than bounding.
        let available_space = original_space.clamp(0, 4097);
        *payload_len = available_space.saturating_sub(1);
    }
    *payload = msg.payload_mut_with_len(*payload_len).as_mut_ptr();
    oscore_msgerr_native_t::ResultOk
}

#[no_mangle]
pub extern "C" fn oscore_msgerr_native_is_error(msgerr: oscore_msgerr_native_t) -> bool {
    msgerr != oscore_msgerr_native_t::ResultOk
}

#[no_mangle]
pub extern "C" fn oscore_msg_native_trim_payload(
    msg: oscore_msg_native_t,
    payload_len: usize,
) -> oscore_msgerr_native_t {
    unsafe { Message::from_ptr(msg) }.truncate(payload_len);
    oscore_msgerr_native_t::ResultOk
}

#[no_mangle]
pub extern "C" fn oscore_msg_native_optiter_next(
    _: oscore_msg_native_t,
    iter: &mut oscore_msg_native_optiter_t,
    option_number: &mut u16,
    value: &mut *const u8,
    value_len: &mut usize,
) -> bool {
    let iter: &mut OptionsIter = unsafe { core::mem::transmute(iter) };
    if let Some(o) = iter.next() {
        *option_number = o.number();
        let value_slice = o.value();
        *value = value_slice.as_ptr();
        *value_len = value_slice.len();
        true
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn oscore_msg_native_optiter_finish(
    _: oscore_msg_native_t,
    iter: &mut MaybeUninit<oscore_msg_native_optiter_t>,
) -> oscore_msgerr_native_t {
    let iter: &mut MaybeUninit<OptionsIter> = unsafe { core::mem::transmute(iter) };
    unsafe { iter.assume_init_drop() };
    // Here the error models differ: oscore_msg_native would report errors here, whereas
    // coap-message implementations are expected to produce garbage options to indicate somethign
    // went awry
    oscore_msgerr_native_t::ResultOk
}

#[cfg(feature = "alloc")]
#[no_mangle]
pub extern "C" fn oscore_test_msg_create() -> oscore_msg_native_t {
    let msg = alloc::boxed::Box::new(Message {
        data: MessageVariant::CmHmHm(coap_message::heapmessage::HeapMessage::new()),
        payload_length: None,
    });

    oscore_msg_native_t(alloc::boxed::Box::into_raw(msg) as *mut _)
}

#[cfg(feature = "alloc")]
#[no_mangle]
pub extern "C" fn oscore_test_msg_destroy(msg: oscore_msg_native_t) {
    let boxed = unsafe { alloc::boxed::Box::from_raw(msg.0) };
    drop(boxed);
}

// Functions for interacting with messages from the Rust side

/// Make a [coap_message::heapmessage::HeapMessage] usable as a [raw::oscore_msg_native_t]
///
/// This is a low-level function mainly used by tests.
#[cfg(feature = "alloc")]
// FIXME: This drops the heapmessage afterwards; that's OK for decoding (and for encoding we'll
// probably want to create it freshly anyway)
pub fn with_heapmessage_as_msg_native<F, R>(
    msg: coap_message::heapmessage::HeapMessage,
    f: F,
) -> R
where
    F: FnOnce(oscore_msg_native_t) -> R
{
    // This is just the kind of message that does need its payload length known and set
    let payload_len = msg.payload().len();
    let mut wrapped_message = Message {
        data: MessageVariant::CmHmHm(msg),
        payload_length: Some(payload_len),
    };
    f(oscore_msg_native_t(&mut wrapped_message as *mut _ as *mut _))
}

/// Make a [coap_message_utils::inmemory_write::Message] usable as a [raw::oscore_msg_native_t]
///
/// This is a low-level function used by the high-level wrappers in the liboscore crate.
pub fn with_inmemory_as_msg_native<'a, 'b: 'a, F, R>(
    msg: &'a mut coap_message_utils::inmemory_write::Message<'b>,
    f: F,
) -> R
where
    F: FnOnce(oscore_msg_native_t) -> R
{
    // FIXME: find a safe way to do this
    // Safety: Message is for some reason considered invariant over its lifetime argument, when
    // from how it's working it should be coercible into a shorter lifetime argument.
    let msg: &'a mut coap_message_utils::inmemory_write::Message<'a> = unsafe { core::mem::transmute(msg) };

    // We don't reliably know a payload length ... this is bound to get confusing
    let mut wrapped_message = Message {
        data: MessageVariant::CmuImwM(msg),
        payload_length: None,
    };
    f(oscore_msg_native_t(&mut wrapped_message as *mut _ as *mut _))
}
