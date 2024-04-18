//! Wrappers for crating primitive contexts
//!
//! As the security context data is split into a variable section and an immutable section
//! referenced there, a staggered setup is needed to ensure the immutables are not moved once used
//! by the mutables.

use core::mem::MaybeUninit;

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
    ) -> Result<Self, DeriveError> {
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
        unsafe {
            raw::oscore_context_primitive_derive(
                _0.as_mut_ptr(),
                hkdf_alg.into_inner(),
                salt.as_ptr(),
                salt.len(),
                ikm.as_ptr(),
                ikm.len(),
                context
                    .map(|c| c.as_ptr())
                    .unwrap_or_else(|| core::ptr::null()),
                context.map(|c| c.len()).unwrap_or(0),
            )
        };
        Ok(Self(unsafe { _0.assume_init() }))
    }

    fn sender_id(&self) -> &[u8] {
        &self.0.sender_id[..self.0.sender_id_len]
    }

    pub fn recipient_id(&self) -> &[u8] {
        &self.0.recipient_id[..self.0.recipient_id_len]
    }
}

impl core::fmt::Debug for PrimitiveImmutables {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        // Displaying anything more, like the keys or IV, would be trickier -- we've already
        // converted the AeadAlg (where their lengths are in) into its C version.
        use pretty_hex::simple_hex_write;
        write!(f, "PrimitiveImmutables ")?;
        write!(f, "{{ sender_id: '")?;
        simple_hex_write(f, &self.sender_id())?;
        write!(f, "', recipient_id: '")?;
        simple_hex_write(f, &self.recipient_id())?;
        write!(f, "' }}")?;
        Ok(())
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
    immutables: PrimitiveImmutables,
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
            immutables,
            primitive: raw::oscore_context_primitive {
                immutables: core::ptr::null(),
                replay_window: 0,
                replay_window_left_edge: 0,
                sender_sequence_number: 0,
            },
            context: raw::oscore_context_t {
                data: core::ptr::null_mut(),
                type_: raw::oscore_context_type_OSCORE_CONTEXT_PRIMITIVE,
            },
        }
    }

    fn fix(&mut self) {
        self.primitive.immutables = &self.immutables.0 as *const _;
        self.context.data = &mut self.primitive as *mut _ as *mut _;
    }

    pub fn as_mut(&mut self) -> &mut raw::oscore_context_t {
        self.fix();
        &mut self.context
    }

    pub fn recipient_id(&self) -> &[u8] {
        self.immutables.recipient_id()
    }
}

impl core::fmt::Debug for PrimitiveContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "PrimitiveContext {{ sender_sequence_number: {}, replay_window_left_edge: {}, replay_window: {:b}, immutables: {:?} }}", self.primitive.sender_sequence_number, self.primitive.replay_window_left_edge, self.primitive.replay_window, self.immutables)
    }
}
