//! Wrappers for crating primitive contexts
//!
//! As the security context data is split into a variable section and an immutable section
//! referenced there, a staggered setup is needed to ensure the immutables are not moved once used
//! by the mutables.

use core::mem::MaybeUninit;
use core::marker::PhantomData;

use crate::raw;

pub struct PrimitiveImmutables(raw::oscore_context_primitive_immutables);

impl PrimitiveImmutables {
    pub fn derive(
        hkdf_alg: crate::algorithms::HkdfAlg,
        ikm: &[u8],
        salt: &[u8],
        context: Option<&[u8]>,
        aead_alg: crate::algorithms::AeadAlg,
        sender_id: &[u8],
        recipient_id: &[u8],
        ) -> Self
    {
        let mut _0 = MaybeUninit::<raw::oscore_context_primitive_immutables>::uninit();
        unsafe {
            (*_0.as_mut_ptr()).recipient_id[..recipient_id.len()].copy_from_slice(recipient_id);
            (*_0.as_mut_ptr()).recipient_id_len = recipient_id.len();
            (*_0.as_mut_ptr()).sender_id[..sender_id.len()].copy_from_slice(sender_id);
            (*_0.as_mut_ptr()).sender_id_len = sender_id.len();
            (*_0.as_mut_ptr()).aeadalg = aead_alg.into_inner();
        }
        unsafe { raw::oscore_context_primitive_derive(
            _0.as_mut_ptr(), 
            hkdf_alg.into_inner(),
            ikm.as_ptr(),
            ikm.len(),
            salt.as_ptr(),
            salt.len(),
            context.map(|c| c.as_ptr()).unwrap_or_else(|| core::ptr::null()),
            context.map(|c| c.len()).unwrap_or(0),
        ) };
        Self(unsafe { _0.assume_init() })
    }
}

pub struct PrimitiveContext<'a>(raw::oscore_context_primitive, PhantomData<&'a PrimitiveImmutables>);

impl<'a> PrimitiveContext<'a> {
    /// Create a new security context
    ///
    /// ## Security
    ///
    /// The material in the `immutables` must never have been used before. For example, it may be
    /// material that has just been produced from an ACE OSCORE exchange to which this device
    /// contributed entropy.
    pub fn new_from_fresh_material(immutables: &'a PrimitiveImmutables) -> Self {
        Self(raw::oscore_context_primitive {
            immutables: &immutables.0,
            replay_window: 0,
            replay_window_left_edge: 0,
            sender_sequence_number: 0,
        }, PhantomData)
    }

    pub fn as_inner(&mut self) -> *mut raw::oscore_context_primitive {
        &mut self.0 as *mut _
    }
}
