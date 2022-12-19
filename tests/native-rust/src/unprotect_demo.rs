//! Run the "unprotect-demo" case, but with the test code in Rust.

use core::mem::MaybeUninit;

use coap_message::{ReadableMessage, MinimalWritableMessage, MessageOption};

use liboscore::raw;

pub fn run() -> Result<(), &'static str> {
    unsafe {
        let mut aeadalg = MaybeUninit::<u32>::uninit();
        let err = raw::oscore_crypto_aead_from_number(aeadalg.as_mut_ptr(), 24);
        assert!(!raw::oscore_cryptoerr_is_error(err));
        let aeadalg = aeadalg.assume_init();

        let key = raw::oscore_context_primitive_immutables {
            common_iv: *b"d\xf0\xbd1MK\xe0<'\x0c+\x1c\0",

            recipient_id: *b"_______",
            recipient_id_len: 0,
            recipient_key: *b"\xd50\x1e\xb1\x8d\x06xI\x95\x08\x93\xba*\xc8\x91A|\x89\xae\t\xdfJ8U\xaa\x00\n\xc9\xff\xf3\x87Q",

            aeadalg,

            // completely unused...
            sender_id: *b"_______",
            sender_id_len: 23,
            sender_key: *b"________________________________",
        };


        let mut primitive = raw::oscore_context_primitive {
            immutables: &key,
            // all zero as in C
            replay_window: 0,
            replay_window_left_edge: 0,
            // unused
            sender_sequence_number: 0,
        };

        let mut secctx = raw::oscore_context_t {
            type_: raw::oscore_context_type_OSCORE_CONTEXT_PRIMITIVE,
            data: &mut primitive as *mut _ as *mut _,
        };

        let mut msg = coap_message::heapmessage::HeapMessage::new();
        let oscopt = b"\x09\x00";
        msg.add_option(9, oscopt);
        msg.set_payload(b"\x5c\x94\xc1\x29\x80\xfd\x93\x68\x4f\x37\x1e\xb2\xf5\x25\xa2\x69\x3b\x47\x4d\x5e\x37\x16\x45\x67\x63\x74\xe6\x8d\x4c\x20\x4a\xdb");

        liboscore_msgbackend::with_heapmessage_as_msg_native(msg, |msg| {
            let mut header = MaybeUninit::uninit();
            let ret = raw::oscore_oscoreoption_parse(header.as_mut_ptr(), oscopt.as_ptr(), oscopt.len());
            assert!(ret);
            let header = header.assume_init();
            let mut unprotected = MaybeUninit::uninit();
            let mut request_id = MaybeUninit::uninit();
            let ret = raw::oscore_unprotect_request(msg, unprotected.as_mut_ptr(), header, &mut secctx, request_id.as_mut_ptr());
            assert!(ret == raw::oscore_unprotect_request_result_OSCORE_UNPROTECT_REQUEST_OK);
            let unprotected = unprotected.assume_init();

            let unprotected = liboscore::ProtectedMessage::new(unprotected);
            assert!(unprotected.code() == 1);

            let mut message_options = unprotected.options().fuse();
            let mut ref_options = [(11, "oscore"), (11, "hello"), (11, "1")].into_iter().fuse();
            for (msg_o, ref_o) in (&mut message_options).zip(&mut ref_options) {
                assert!(msg_o.number() == ref_o.0);
                assert!(std::str::from_utf8(msg_o.value()) == Ok(ref_o.1));
            }
            assert!(message_options.next().is_none(), "Message contained extra options");
            assert!(ref_options.next().is_none(), "Message didn't contain the reference options");
            assert!(unprotected.payload() == b"");
        });

        // We've taken a *mut of it, let's make sure it lives to the end
        drop(primitive);
    };

    Ok(())
}
