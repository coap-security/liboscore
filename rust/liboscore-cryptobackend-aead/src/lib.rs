//! Backend for liboscore's crypto API that fans out to AEAD algorithms base on the aead Rust
//! crate.
//!
//! This takes a mixture of trait- and enum-based approaches; algorithms are handled as trait
//! objects (or constructors derived from them), but the oscore_crypto_aead_encryptstate_t would
//! eventually be an enum in order to be Sized and thus stack-allocatable.
#![no_std]

use typenum::marker_traits::Unsigned;
use aead::generic_array::GenericArray;
use core::mem::MaybeUninit;

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

/// Expressed as an enum for lack of type variables and/or the unsuitability of the NewAead::new
/// method as a function pointer constructor due to its generic component.
///
/// (Possibly one could make a trait that only has an associated type, have it impl'd by the
/// algorithms as a ZST, have static single objects for each and pass them as `&'static dyn`, but
/// that makes them two pointers large. One could probably pick the vtable from trait object
/// pointers, but that's deep unsafe territory.)
#[derive(Copy, Clone)]
#[repr(C)]
pub enum Algorithm {
    #[cfg(feature="chacha20poly1305")]
    ChaCha20Poly1305,
    #[cfg(feature="aes-ccm")]
    AesCcm16_64_128,
    #[cfg(feature="aes-ccm")]
    AesCcm16_128_128,
    #[cfg(feature="aes-gcm")]
    A128GCM,
    #[cfg(feature="aes-gcm")]
    A256GCM,
}

#[cfg(feature="chacha20poly1305")]
type AlgtypeChaCha20Poly1305 = chacha20poly1305::ChaCha20Poly1305;
#[cfg(feature="aes-ccm")]
type AlgtypeAesCcm16_64_128 = aes_ccm::AesCcm<typenum::consts::U8>;
#[cfg(feature="aes-ccm")]
type AlgtypeAesCcm16_128_128 = aes_ccm::AesCcm<typenum::consts::U16>;
#[cfg(feature="aes-gcm")]
type AlgtypeA128GCM = aes_gcm::Aes128Gcm;
#[cfg(feature="aes-gcm")]
type AlgtypeA256GCM = aes_gcm::Aes256Gcm;

/// A fully deparametrized type for variables that might want to be type variables for a `dyn
/// AeadMutInPlace + KeyInit` but can't for lack of type variables and limitations in object safety
/// of traits.
impl Algorithm {
    fn from_number(num: i32) -> Option<Self> {
        match num {
            #[cfg(feature="chacha20poly1305")]
            24 => Some(Algorithm::ChaCha20Poly1305),
            #[cfg(feature="aes-ccm")]
            10 => Some(Algorithm::AesCcm16_64_128),
            #[cfg(feature="aes-ccm")]
            30 => Some(Algorithm::AesCcm16_128_128),
            #[cfg(feature="aes-gcm")]
            1 => Some(Algorithm::A128GCM),
            #[cfg(feature="aes-gcm")]
            3 => Some(Algorithm::A256GCM),
            _ => None
        }
    }

    fn to_number(&self) -> Option<i32> {
        Some(match self {
            #[cfg(feature="chacha20poly1305")]
            Algorithm::ChaCha20Poly1305 => 24,
            #[cfg(feature="aes-ccm")]
            Algorithm::AesCcm16_64_128 => 10,
            #[cfg(feature="aes-ccm")]
            Algorithm::AesCcm16_128_128 => 30,
            #[cfg(feature="aes-gcm")]
            Algorithm::A128GCM => 1,
            #[cfg(feature="aes-gcm")]
            Algorithm::A256GCM => 3,
        })
    }

    fn tag_length(&self) -> usize {
        match self {
            #[cfg(feature="chacha20poly1305")]
            Algorithm::ChaCha20Poly1305 => <AlgtypeChaCha20Poly1305 as aead::AeadCore>::TagSize::to_usize(),
            #[cfg(feature="aes-ccm")]
            Algorithm::AesCcm16_64_128 => <AlgtypeAesCcm16_64_128 as aead::AeadCore>::TagSize::to_usize(),
            #[cfg(feature="aes-ccm")]
            Algorithm::AesCcm16_128_128 => <AlgtypeAesCcm16_128_128 as aead::AeadCore>::TagSize::to_usize(),
            #[cfg(feature="aes-gcm")]
            Algorithm::A128GCM => <AlgtypeA128GCM as aead::AeadCore>::TagSize::to_usize(),
            #[cfg(feature="aes-gcm")]
            Algorithm::A256GCM => <AlgtypeA256GCM as aead::AeadCore>::TagSize::to_usize(),
        }
    }

    fn iv_length(&self) -> usize {
        match self {
            #[cfg(feature="chacha20poly1305")]
            Algorithm::ChaCha20Poly1305 => <AlgtypeChaCha20Poly1305 as aead::AeadCore>::NonceSize::to_usize(),
            #[cfg(feature="aes-ccm")]
            Algorithm::AesCcm16_64_128 => <AlgtypeAesCcm16_64_128 as aead::AeadCore>::NonceSize::to_usize(),
            #[cfg(feature="aes-ccm")]
            Algorithm::AesCcm16_128_128 => <AlgtypeAesCcm16_128_128 as aead::AeadCore>::NonceSize::to_usize(),
            #[cfg(feature="aes-gcm")]
            Algorithm::A128GCM => <AlgtypeA128GCM as aead::AeadCore>::NonceSize::to_usize(),
            #[cfg(feature="aes-gcm")]
            Algorithm::A256GCM => <AlgtypeA256GCM as aead::AeadCore>::NonceSize::to_usize(),
        }
    }

    fn key_length(&self) -> usize {
        match self {
            #[cfg(feature="chacha20poly1305")]
            Algorithm::ChaCha20Poly1305 => <AlgtypeChaCha20Poly1305 as aead::KeySizeUser>::key_size(),
            #[cfg(feature="aes-ccm")]
            Algorithm::AesCcm16_64_128 => <AlgtypeAesCcm16_64_128 as aead::KeySizeUser>::key_size(),
            #[cfg(feature="aes-ccm")]
            Algorithm::AesCcm16_128_128 => <AlgtypeAesCcm16_128_128 as aead::KeySizeUser>::key_size(),
            #[cfg(feature="aes-gcm")]
            Algorithm::A128GCM => <AlgtypeA128GCM as aead::KeySizeUser>::key_size(),
            #[cfg(feature="aes-gcm")]
            Algorithm::A256GCM => <AlgtypeA256GCM as aead::KeySizeUser>::key_size(),
        }
    }
}

const AAD_BUFFER_SIZE: usize = 32;

// Ideally with streaming AAD, those would be enums that union all the intermediate state types of
// the individual algorithms

pub struct EncryptState {
    alg: Algorithm,
    iv: *const u8,
    key: *const u8,
    buffered_aad: heapless::Vec<u8, AAD_BUFFER_SIZE>,
}

#[repr(transparent)]
pub struct DecryptState {
    actually_encrypt: EncryptState,
}

#[no_mangle]
pub extern "C"
fn oscore_crypto_aead_from_number(alg: &mut MaybeUninit<Algorithm>, num: i32) -> CryptoErr {
    if let Some(found) = Algorithm::from_number(num) {
        alg.write(found);
        CryptoErr::Ok
    } else {
        CryptoErr::NoSuchAlgorithm
    }
}

#[no_mangle]
pub extern "C"
fn oscore_crypto_aead_get_number(alg: Algorithm, num: &mut MaybeUninit<i32>) -> CryptoErr {
    if let Some(found) = alg.to_number() {
        num.write(found);
        CryptoErr::Ok
    } else {
        CryptoErr::NoIdentifier
    }
}

#[no_mangle]
pub extern "C"
fn oscore_crypto_aead_from_string(_alg: &mut MaybeUninit<Algorithm>, _string: *const u8, _string_len: usize) -> CryptoErr {
    CryptoErr::NoSuchAlgorithm
}

#[no_mangle]
pub extern "C"
fn oscore_crypto_aead_get_taglength(alg: Algorithm) -> usize {
    alg.tag_length()
}

#[no_mangle]
pub extern "C"
fn oscore_crypto_aead_get_ivlength(alg: Algorithm) -> usize {
    alg.iv_length()
}

#[no_mangle]
pub extern "C"
fn oscore_crypto_aead_get_keylength(alg: Algorithm) -> usize {
    alg.key_length()
}

#[no_mangle]
pub extern "C"
fn oscore_crypto_aead_encrypt_start(
    state: &mut MaybeUninit<EncryptState>,
    alg: Algorithm,
    aad_len: usize,
    _plaintext_len: usize,
    iv: *const u8,
    key: *const u8,
) -> CryptoErr {
    if aad_len > AAD_BUFFER_SIZE {
        return CryptoErr::AadPreallocationExceeded;
    }

    let created = EncryptState {
        alg,
        iv,
        key,
        buffered_aad: heapless::Vec::new(),
    };
    state.write(created);

    CryptoErr::Ok
}

#[no_mangle]
pub extern "C"
fn oscore_crypto_aead_encrypt_feed_aad(
    state: *mut c_void,
    aad_chunk: *const u8,
    aad_chunk_len: usize,
) -> CryptoErr
{
    let state: &mut EncryptState = unsafe { core::mem::transmute(state) };

    let aad_chunk = unsafe { core::slice::from_raw_parts(aad_chunk, aad_chunk_len) };
    match state.buffered_aad.extend_from_slice(aad_chunk) {
        Ok(()) => CryptoErr::Ok,
        Err(_) => CryptoErr::UnexpectedDataLength,
    }
}

/// Workhorse of oscore_crypto_aead_encrypt_inplace that is generic and thus can access all the
/// lengths
///
/// This does duplicate some code that during monomorphization that *could* be deduplciated (esp.
/// the (paincipher, tag) splitting, for which alg.tag_length could be used), but this way it's
/// easier and duplicate code should be minimal, given that A::TagSize can be used right away.
fn _encrypt_inplace<A>(
    state: &mut EncryptState,
    buffer: *mut u8,
    buffer_len: usize,
) -> CryptoErr
where
    A: aead::AeadMutInPlace + aead::KeyInit
{
    let taglen = A::TagSize::to_usize();

    let buffer = unsafe { core::slice::from_raw_parts_mut(buffer, buffer_len) };
    let plaintextlength = match buffer.len().checked_sub(taglen) {
        Some(x) => x,
        None => return CryptoErr::BufferShorterThanTag
    };
    let (plaincipher, tag) = buffer.split_at_mut(plaintextlength);

    // The checks in GenericArray initialization should make the intermediary constant go away
    let keylen = A::KeySize::to_usize();
    let key = unsafe { core::slice::from_raw_parts(state.key, keylen) };
    let key = GenericArray::clone_from_slice(key);

    // Same as above
    let noncelen = A::NonceSize::to_usize();
    let nonce = unsafe { core::slice::from_raw_parts(state.iv, noncelen) };
    let nonce = GenericArray::from_slice(nonce);

    let mut aead = A::new(&key);
    let tagdata = match aead.encrypt_in_place_detached(
            nonce, 
            state.buffered_aad.as_ref(),
            plaincipher
        )
    {
        Ok(tagdata) => tagdata,
        // There's no real documentation on what that error could be (given that
        // encrypt_in_place is documented to return an error (only, presumably) if the
        // buffer has insufficient capacity) which can't be happening here any more
        Err(_) => return CryptoErr::BufferShorterThanTag
    };
    tag.copy_from_slice(&tagdata);

    CryptoErr::Ok
}

#[no_mangle]
pub extern "C"
fn oscore_crypto_aead_encrypt_inplace(
    state: &mut EncryptState,
    buffer: *mut u8,
    buffer_len: usize,
) -> CryptoErr
{
    match state.alg {
        #[cfg(feature="chacha20poly1305")]
        Algorithm::ChaCha20Poly1305 => _encrypt_inplace::<AlgtypeChaCha20Poly1305>(state, buffer, buffer_len),
        #[cfg(feature="aes-ccm")]
        Algorithm::AesCcm16_64_128 => _encrypt_inplace::<AlgtypeAesCcm16_64_128>(state, buffer, buffer_len),
        #[cfg(feature="aes-ccm")]
        Algorithm::AesCcm16_128_128 => _encrypt_inplace::<AlgtypeAesCcm16_128_128>(state, buffer, buffer_len),
        #[cfg(feature="aes-gcm")]
        Algorithm::A128GCM => _encrypt_inplace::<AlgtypeA128GCM>(state, buffer, buffer_len),
        #[cfg(feature="aes-gcm")]
        Algorithm::A256GCM => _encrypt_inplace::<AlgtypeA256GCM>(state, buffer, buffer_len),
    }
}

#[no_mangle]
pub extern "C"
fn oscore_crypto_aead_decrypt_start(
    state: &mut MaybeUninit<DecryptState>,
    alg: Algorithm,
    aad_len: usize,
    plaintext_len: usize,
    iv: *const u8,
    key: *const u8,
) -> CryptoErr {
    // Hoping the compiler is smart enough to do that right in-place, as we can't initialize a
    // struct by its fields
    let mut tempstate = MaybeUninit::uninit();
    let ret = oscore_crypto_aead_encrypt_start(&mut tempstate, alg, aad_len, plaintext_len, iv, key);
    if let CryptoErr::Ok = ret {
        state.write(DecryptState { actually_encrypt: unsafe { tempstate.assume_init() } });
    }
    ret
}

#[no_mangle]
pub extern "C"
fn oscore_crypto_aead_decrypt_feed_aad(
    state: *mut c_void,
    aad_chunk: *const u8,
    aad_chunk_len: usize,
) -> CryptoErr
{
    let state: &mut DecryptState = unsafe { core::mem::transmute(state) };

    oscore_crypto_aead_encrypt_feed_aad(unsafe { core::mem::transmute(&mut state.actually_encrypt) }, aad_chunk, aad_chunk_len)
}

/// Workhorse of oscore_crypto_aead_decrypt_inplace that is generic and thus can access all the
/// lengths
///
/// This does duplicate some code that during monomorphization that *could* be deduplciated (esp.
/// the (paincipher, tag) splitting, for which alg.tag_length could be used), but this way it's
/// easier and duplicate code should be minimal, given that A::TagSize can be used right away.
fn _decrypt_inplace<A>(
    state: &mut DecryptState,
    buffer: *mut u8,
    buffer_len: usize,
) -> CryptoErr
where
    A: aead::AeadMutInPlace + aead::KeyInit
{
    let state = &mut state.actually_encrypt;

    let taglen = state.alg.tag_length();

    let buffer = unsafe { core::slice::from_raw_parts_mut(buffer, buffer_len) };
    let plaintextlength = match buffer.len().checked_sub(taglen) {
        Some(x) => x,
        None => return CryptoErr::BufferShorterThanTag
    };
    let (plaincipher, tag) = buffer.split_at_mut(plaintextlength);

    // Suitable const propagation should eliminate this; unfortunately, GenericArray has no
    // from_raw_part
    let keylen = state.alg.key_length();
    let key = unsafe { core::slice::from_raw_parts(state.key, keylen) };
    let key = GenericArray::clone_from_slice(key);

    // Same as above
    let noncelen = state.alg.iv_length();
    let nonce = unsafe { core::slice::from_raw_parts(state.iv, noncelen) };
    let nonce = GenericArray::from_slice(nonce);

    // and similar but not quite like
    let tag = GenericArray::from_slice(tag);

    let _aad: &[u8] = state.buffered_aad.as_ref();
    let _nonce: &[u8] = nonce.as_ref();
    let _key: &[u8] = key.as_ref();

    let mut aead = A::new(&key);
    match aead.decrypt_in_place_detached(
            nonce, 
            state.buffered_aad.as_ref(),
            plaincipher,
            tag
        )
    {
        Ok(()) => return CryptoErr::Ok,
        Err(_) => return CryptoErr::DecryptError
    };
}

#[no_mangle]
pub extern "C"
fn oscore_crypto_aead_decrypt_inplace(
    state: &mut DecryptState,
    buffer: *mut u8,
    buffer_len: usize,
) -> CryptoErr
{
    match state.actually_encrypt.alg {
        #[cfg(feature="chacha20poly1305")]
        Algorithm::ChaCha20Poly1305 => _decrypt_inplace::<AlgtypeChaCha20Poly1305>(state, buffer, buffer_len),
        #[cfg(feature="aes-ccm")]
        Algorithm::AesCcm16_64_128 => _decrypt_inplace::<AlgtypeAesCcm16_64_128>(state, buffer, buffer_len),
        #[cfg(feature="aes-ccm")]
        Algorithm::AesCcm16_128_128 => _decrypt_inplace::<AlgtypeAesCcm16_128_128>(state, buffer, buffer_len),
        #[cfg(feature="aes-gcm")]
        Algorithm::A128GCM => _decrypt_inplace::<AlgtypeA128GCM>(state, buffer, buffer_len),
        #[cfg(feature="aes-gcm")]
        Algorithm::A256GCM => _decrypt_inplace::<AlgtypeA256GCM>(state, buffer, buffer_len),
    }
}

#[no_mangle]
pub extern "C"
fn oscore_cryptoerr_is_error(err: CryptoErr) -> bool {
    match err {

        CryptoErr::Ok => false,
        _ => true,
    }
}
