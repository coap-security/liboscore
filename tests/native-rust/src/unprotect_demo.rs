//! Run the "unprotect-demo" case, but with the test code in Rust.
//!
//! Unlike the unprotect demo, this derives the key right away (depending on having an HKDF
//! algorithm, which generally is available given we have a Rust backend).

use core::mem::MaybeUninit;

use coap_message::{MessageOption, MinimalWritableMessage, ReadableMessage};

use liboscore::raw;

pub fn run() -> Result<(), &'static str> {
    // From OSCORE plug test, security context A
    let immutables = liboscore::PrimitiveImmutables::derive(
        liboscore::HkdfAlg::from_number(5).unwrap(),
        b"\x9e\x7c\xa9\x22\x23\x78\x63\x40",
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10",
        None,
        liboscore::AeadAlg::from_number(24).unwrap(),
        b"\x01",
        b"",
    )
    .unwrap();

    let mut primitive = liboscore::PrimitiveContext::new_from_fresh_material(immutables);

    let mut msg = coap_message_implementations::heap::HeapMessage::new();
    let oscopt = b"\x09\x00";
    msg.add_option(9, oscopt).unwrap();
    msg.set_payload(b"\x5c\x94\xc1\x29\x80\xfd\x93\x68\x4f\x37\x1e\xb2\xf5\x25\xa2\x69\x3b\x47\x4d\x5e\x37\x16\x45\x67\x63\x74\xe6\x8d\x4c\x20\x4a\xdb").unwrap();

    liboscore_msgbackend::with_heapmessage_as_msg_native(msg, |msg| {
        unsafe {
            let header = liboscore::OscoreOption::parse(oscopt).unwrap();

            let mut unprotected = MaybeUninit::uninit();
            let mut request_id = MaybeUninit::uninit();
            let ret = raw::oscore_unprotect_request(
                msg,
                unprotected.as_mut_ptr(),
                &header.into_inner(),
                primitive.as_mut(),
                request_id.as_mut_ptr(),
            );
            assert!(ret == raw::oscore_unprotect_request_result_OSCORE_UNPROTECT_REQUEST_OK);
            let unprotected = unprotected.assume_init();

            let unprotected = liboscore::ProtectedMessage::new(unprotected);
            assert!(unprotected.code() == 1);

            let mut message_options = unprotected.options().fuse();
            let mut ref_options = [(11, "oscore"), (11, "hello"), (11, "1")]
                .into_iter()
                .fuse();
            for (msg_o, ref_o) in (&mut message_options).zip(&mut ref_options) {
                assert!(msg_o.number() == ref_o.0);
                assert!(std::str::from_utf8(msg_o.value()) == Ok(ref_o.1));
            }
            assert!(
                message_options.next().is_none(),
                "Message contained extra options"
            );
            assert!(
                ref_options.next().is_none(),
                "Message didn't contain the reference options"
            );
            assert!(unprotected.payload() == b"");
        };
    });

    // We've taken a *mut of it, let's make sure it lives to the end
    drop(primitive);

    Ok(())
}
