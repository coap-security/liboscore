//! Backend for liboscore's crypto API that fans out to AEAD algorithms base on the aead Rust
//! crate.
//!
//! This takes a mixture of trait- and enum-based approaches; algorithms are handled as trait
//! objects (or constructors derived from them), but the oscore_crypto_aead_encryptstate_t would
//! eventually be an enum in order to be Sized and thus stack-allocatable.
#![no_std]

mod aead;
mod hkdf;

/// Void stand-in recognized by the cbindgen library by its name
#[allow(non_camel_case_types)]
pub enum c_void {
}

// Those types that are passed in and out as arguments need to be repr(C). The rest can be any repr
// as it is only stack-allocated and passed through pointers, but CryptoErr and Algorithm are
// passed around explicitly.

#[repr(C)]
pub enum CryptoErr {
    Ok,
    NoSuchAlgorithm,
    /// Data was put into the AAD, plaintext or buffer whose length was not as originally announced
    UnexpectedDataLength,
    /// The only possible encryption error
    BufferShorterThanTag,
    /// Decryption failed (ie. message corruption / tampering / disagreement on nonce or AAD)
    DecryptError,
    /// Returned when the AAD is longer than pre-allocated, and neither streaming AAD nor dynamic
    /// allocation are not implemented (which is unconditional so far)
    AadPreallocationExceeded,
    /// A kind of identifier was requested of an algorithm that is not specified
    NoIdentifier,
}

#[no_mangle]
pub extern "C"
fn oscore_cryptoerr_is_error(err: CryptoErr) -> bool {
    match err {

        CryptoErr::Ok => false,
        _ => true,
    }
}
