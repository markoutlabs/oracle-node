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

    /// A value that a node in this process made and did not sign: `author` stands in for the
    /// recovered signer.
    ///
    /// Only an app that runs its node and the SDK in one process turns on `local-unsigned`.
    /// The registry check still decides whether `author` is trusted.
    #[cfg(feature = "local-unsigned")]
    #[must_use]
    pub const fn local(value: T, author: Address) -> Self {
        Self::new(value, author)
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
