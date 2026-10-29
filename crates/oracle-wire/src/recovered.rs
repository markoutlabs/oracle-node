//! The half of verification that needs no registry: decode the payload and
//! recover its signer.

use crate::Address;

/// A decoded payload and the address that signed it, before the registry check.
///
/// Recovery needs no registry, so a consumer can run it on another thread. The
/// payload stays untrusted until `authorize` finds the signer in a [`crate::VerifiedRegistry`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovered<T> {
    pub(crate) value: T,
    pub(crate) signer: Address,
}

impl<T> Recovered<T> {
    pub(crate) const fn new(value: T, signer: Address) -> Self {
        Self { value, signer }
    }

    /// Returns the address that signed. Authorship, not trust.
    #[must_use]
    pub const fn signer(&self) -> Address {
        self.signer
    }

    /// Returns the payload **without** any trust check, like
    /// `decode_unverified`.
    #[must_use]
    pub const fn unverified(&self) -> &T {
        &self.value
    }
}
