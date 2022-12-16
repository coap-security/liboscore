use core::mem::MaybeUninit;

use sha2::Sha256;

use super::CryptoErr;

#[repr(C)]
pub enum Algorithm {
    /// HMAC w/ SHA-256
    Hmac256_256,
}

impl Algorithm {
    fn from_number(num: i32) -> Option<Self> {
        match num {
            5 => Some(Algorithm::Hmac256_256),
            _ => None
        }
    }
}

#[no_mangle]
pub extern "C"
fn oscore_crypto_hkdf_from_number(alg: &mut MaybeUninit<Algorithm>, num: i32) -> CryptoErr {
    if let Some(found) = Algorithm::from_number(num) {
        alg.write(found);
        CryptoErr::Ok
    } else {
        CryptoErr::NoSuchAlgorithm
    }
}

#[no_mangle]
fn oscore_crypto_hkdf_derive(
    alg: Algorithm,
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    info: *const u8,
    info_len: usize,
    out: *mut u8,
    out_len: usize,
) -> CryptoErr {
    let salt = unsafe { core::slice::from_raw_parts(salt, salt_len) };
    let ikm = unsafe { core::slice::from_raw_parts(ikm, ikm_len) };
    let info = unsafe { core::slice::from_raw_parts(info, info_len) };
    let out = unsafe { core::slice::from_raw_parts_mut(out, out_len) };

    let result = match alg {
        Algorithm::Hmac256_256 => hkdf::Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, out),
    };

    match result {
        Ok(()) => CryptoErr::Ok,
        // FIXME: is that an accurate error?
        Err(_) => CryptoErr::UnexpectedDataLength,
    }
}
