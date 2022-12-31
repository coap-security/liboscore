use core::mem::MaybeUninit;
use core::marker::PhantomData;

use crate::raw;

/// Extracted data of (and indices into) the data inside the OSCORE option
pub struct OscoreOption<'a>(raw::oscore_oscoreoption_t, PhantomData<&'a [u8]>);

/// Error type for parsing the OSCORE option
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

    pub fn kid_context(&self) -> Option<&'a [u8]> {
        if self.0.kid_context.is_null() {
            None
        } else {
            Some(unsafe { core::slice::from_raw_parts(self.0.kid_context, self.0.kid_context_len as _) })
        }
    }

    fn partial_iv(&self) -> Option<&'a [u8]> {
        if self.0.partial_iv.is_null() {
            None
        } else {
            Some(unsafe { core::slice::from_raw_parts(self.0.partial_iv, self.0.partial_iv_len as _) })
        }
    }

    pub fn kid(&self) -> Option<&'a [u8]> {
        if self.0.kid.is_null() {
            None
        } else {
            Some(unsafe { core::slice::from_raw_parts(self.0.kid, self.0.kid_len) })
        }
    }
}

impl<'a> core::fmt::Debug for OscoreOption<'a> {
    // Note that these are reaching into libOSCORE internals. The wrappers are developed as part
    // of and together with libOSCORE, so we can do that, but this does show details that are
    // generally inaccessible.
    fn fmt(&self, w: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(w, "OscoreOption {{ ")?;
        write!(w, "partial_iv: {:?}, ", self.partial_iv());
        write!(w, "kid: {:?}, ", self.kid());
        write!(w, "kid_context: {:?}, ", self.kid_context());
        write!(w, "}}")
    }
}
