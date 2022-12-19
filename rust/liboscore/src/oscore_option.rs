use core::mem::MaybeUninit;
use core::marker::PhantomData;

use crate::raw;

/// Extracted data of (and indices into) the data inside the OSCORE option
pub struct OscoreOption<'a>(raw::oscore_oscoreoption_t, PhantomData<&'a [u8]>);

#[derive(Debug, Copy, Clone)]
pub struct UnsupportedFields;

impl<'a> OscoreOption<'a> {
    /// Parse an option value
    ///
    /// Lifetime is tied to the parsed data, because "The input provided needs to be valid for as long
    /// as the resulting out is used".
    pub fn parse(optval: &'a [u8]) -> Result<Self, UnsupportedFields> {
        let mut _0 = MaybeUninit::uninit();
        // Safety: preconditions of C function are satisfied, and lifetimes are OK
        let ret = unsafe {
            raw::oscore_oscoreoption_parse(_0.as_mut_ptr(), optval.as_ptr(), optval.len())
        };
        if !ret {
            return Err(UnsupportedFields);
        }
        // Safety: C function promises it has initialized it
        Ok(Self(unsafe { _0.assume_init() }, PhantomData))
    }

    pub fn into_inner(self) -> raw::oscore_oscoreoption_t {
        self.0
    }
}
