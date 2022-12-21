//! Wrappers for crating primitive contexts
//!
//! As the security context data is split into a variable section and an immutable section
//! referenced there, a staggered setup is needed to ensure the immutables are not moved once used
//! by the mutables.

use core::mem::MaybeUninit;
use core::marker::PhantomData;

use crate::raw;

pub struct PrimitiveImmutables(raw::oscore_context_primitive_immutables);

#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum DeriveError {
    SenderIdTooLong,
    RecipientIdTooLong,
    ContextTooLong,
}

impl PrimitiveImmutables {
    pub fn derive(
        hkdf_alg: crate::algorithms::HkdfAlg,
        ikm: &[u8],
        salt: &[u8],
        context: Option<&[u8]>,
        aead_alg: crate::algorithms::AeadAlg,
        sender_id: &[u8],
        recipient_id: &[u8],
        ) -> Result<Self, DeriveError>
    {
        if recipient_id.len() > aead_alg.iv_len() - raw::IV_KEYID_UNUSABLE as usize {
            return Err(DeriveError::RecipientIdTooLong);
        }
        if sender_id.len() > aead_alg.iv_len() - raw::IV_KEYID_UNUSABLE as usize {
            return Err(DeriveError::SenderIdTooLong);
        }
        if context.map(|c| c.len() > raw::OSCORE_KEYIDCONTEXT_MAXLEN as _) == Some(true) {
            return Err(DeriveError::ContextTooLong);
        }

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
        Ok(Self(unsafe { _0.assume_init() }))
    }
}

/// A simplistic owned primitive context
///
/// This is very simplistic in two ways:
///
/// * While the context is self-referential in principle, it makes use of the known and simple
///   linking structure, and fixes itself every time it is used.
///
/// * It is only used through exclusive access, whereas actually a context might be used at the
///   same time in different ways (once exclusively, many times shared, and unlike references they
///   don't conflict)
pub struct PrimitiveContext {
    immutables: raw::oscore_context_primitive_immutables,
    primitive: raw::oscore_context_primitive,
    context: raw::oscore_context_t,
}

impl PrimitiveContext {
    /// Create a new security context
    ///
    /// ## Security
    ///
    /// The material in the `immutables` must never have been used before. For example, it may be
    /// material that has just been produced from an ACE OSCORE exchange to which this device
    /// contributed entropy.
    pub fn new_from_fresh_material(immutables: PrimitiveImmutables) -> Self {
        Self {
            immutables: immutables.0,
            primitive: raw::oscore_context_primitive {
                immutables: core::ptr::null(),
                replay_window: 0,
                replay_window_left_edge: 0,
                sender_sequence_number: 0,
            },
            context: raw::oscore_context_t {
                data: core::ptr::null_mut(),
                type_: raw::oscore_context_type_OSCORE_CONTEXT_PRIMITIVE,
            }
        }

    }

    fn fix(&mut self) {
        self.primitive.immutables = &self.immutables as *const _;
        self.context.data = &mut self.primitive as *mut _ as *mut _;
    }

    pub fn as_mut(&mut self) -> &mut raw::oscore_context_t {
        self.fix();
        &mut self.context
    }
}
