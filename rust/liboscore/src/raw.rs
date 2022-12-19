#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(non_upper_case_globals)]

// Types we block in the bindgen, but we have to make them available
use liboscore_msgbackend::{oscore_msgerr_native_t, oscore_msg_native_t};
use liboscore_cryptobackend::aead::{DecryptState as oscore_crypto_aead_decryptstate_t, EncryptState as oscore_crypto_aead_encryptstate_t};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
