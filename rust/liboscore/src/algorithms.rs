use core::mem::MaybeUninit;

use crate::raw;

/// Error type for algorithm constructors
///
/// Note that this error doesn't tell whether the algorithm is generally unsupported, support is
/// just not built in currently, or whether it's even an algorithm of a different type -- because
/// in general, we can't know.
#[derive(Debug, Copy, Clone)]
pub struct AlgorithmNotSupported;

/// An HKDF algorithm (usable for OSCORE context derivation)
#[derive(Copy, Clone)]
pub struct HkdfAlg(raw::oscore_crypto_hkdfalg_t);

impl HkdfAlg {
    pub fn from_number(number: i32) -> Result<Self, AlgorithmNotSupported> {
        let mut _0 = MaybeUninit::uninit();
        let result = unsafe { raw::oscore_crypto_hkdf_from_number(_0.as_mut_ptr(), number) };
        if unsafe { raw::oscore_cryptoerr_is_error(result) } {
            return Err(AlgorithmNotSupported);
        }
        Ok(HkdfAlg(unsafe { _0.assume_init() }))
    }

    pub fn into_inner(self) -> raw::oscore_crypto_hkdfalg_t {
        self.0
    }
}

/// An AEAD algorithm (usable for OSCORE message protection)
#[derive(Copy, Clone)]
pub struct AeadAlg(raw::oscore_crypto_aeadalg_t);

impl AeadAlg {
    pub fn from_number(number: i32) -> Result<Self, AlgorithmNotSupported> {
        let mut _0 = MaybeUninit::uninit();
        let result = unsafe { raw::oscore_crypto_aead_from_number(_0.as_mut_ptr(), number) };
        if unsafe { raw::oscore_cryptoerr_is_error(result) } {
            return Err(AlgorithmNotSupported);
        }
        Ok(AeadAlg(unsafe { _0.assume_init() }))
    }

    pub fn into_inner(self) -> raw::oscore_crypto_aeadalg_t {
        self.0
    }

    pub fn iv_len(&self) -> usize {
        unsafe { raw::oscore_crypto_aead_get_ivlength(self.clone().0) }
    }
}
