//! Dummy backend not supporting any HKDFs really
#![no_std]

use core::mem::MaybeUninit;

use liboscore_cryptobackend_aead::CryptoErr;

type Algorithm = i32; // but practically uninhabited; C just doesn't like zero-sized types

#[no_mangle]
pub extern "C"
fn oscore_crypto_hkdf_from_number(alg: &mut MaybeUninit<Algorithm>, num: i32) -> CryptoErr {
    CryptoErr::NoSuchAlgorithm
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
    unreachable!("Algorithm should be uninhabited")
}
