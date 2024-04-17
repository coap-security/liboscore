//! This example is not so much here to serve as a usage example (all usage of this crate comes via
//! liboscore), but to have something runnable that can be inspected statically or dynamically for
//! stack usage.

use core::mem::MaybeUninit;
use liboscore_cryptobackend::aead::*;
use liboscore_cryptobackend::*;

fn main() -> Result<(), ()> {
    let key = b"0123456789----------0123456789--";
    let nonce = b"0123456789--";
    let mut msgbuf = *b"Message.0123456789------"; // 8 byte plus 16 tag

    let mut alg = MaybeUninit::uninit();
    let err = oscore_crypto_aead_from_number(&mut alg, 24);
    if oscore_cryptoerr_is_error(err) {
        return Err(());
    };
    let alg = unsafe { alg.assume_init() };

    let mut state = MaybeUninit::uninit();
    let err = oscore_crypto_aead_encrypt_start(&mut state, alg, 0, 8, nonce.as_ptr(), key.as_ptr());
    if oscore_cryptoerr_is_error(err) {
        return Err(());
    };
    let mut state = unsafe { state.assume_init() };
    let msgbuflen = msgbuf.len();
    let err = oscore_crypto_aead_encrypt_inplace(&mut state, msgbuf.as_mut_ptr(), msgbuflen);
    if oscore_cryptoerr_is_error(err) {
        return Err(());
    };

    Ok(())
}
