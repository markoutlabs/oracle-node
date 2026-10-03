//! Signing-key certificates.
//!
//! A node has two keys. The **identity key** is long-lived, stays encrypted on
//! the operator's machine, and signs nothing but certificates. The **signing key** lives in process
//! memory, signs every price update, and is rotated on a schedule. A certificate
//! is the identity key's statement that a given signing address is authorised
//! for a given window.
//!
//! The point of the split is blast radius: a stolen signing key is bad for at
//! most its remaining validity window and is revoked by publishing a registry
//! that omits it. A stolen identity key requires governance action.

use oracle_types::NANOS_PER_SEC;

use crate::codec::Sink as _;
use crate::payload::{KIND_SIGNING_KEY_CERT, PAYLOAD_VERSION};
use crate::{Address, Signature, Signer, VerifyError, WireError, domain, signer};

/// Maximum length of a node identifier, in bytes.
pub const MAX_NODE_ID_LEN: usize = 64;

/// An identity key's authorisation of a signing key for a time window.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyCert {
    /// The node this signing key belongs to.
    pub node_id: String,
    /// The authorised signing address.
    pub address: Address,
    /// Start of validity, unix seconds, inclusive.
    pub not_before: u64,
    /// End of validity, unix seconds, exclusive.
    pub not_after: u64,
    /// The identity key's signature over the canonical certificate bytes.
    pub signature: Signature,
}

impl SigningKeyCert {
    /// Builds the canonical bytes an identity key signs.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::FieldTooLong`] if `node_id` exceeds [`MAX_NODE_ID_LEN`].
    pub fn signing_bytes(
        node_id: &str,
        address: Address,
        not_before: u64,
        not_after: u64,
    ) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::with_capacity(4 + node_id.len() + 36);
        out.put_u8(PAYLOAD_VERSION);
        out.put_u8(KIND_SIGNING_KEY_CERT);
        out.try_put_str("node_id", node_id, MAX_NODE_ID_LEN)?;
        out.put_bytes(address.as_bytes());
        out.put_u64(not_before);
        out.put_u64(not_after);
        Ok(out)
    }

    /// Issues a certificate.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::FieldTooLong`] if `node_id` is too long, or
    /// [`WireError::InvalidHex`] via the encoding path.
    pub fn issue(
        identity: &Signer,
        node_id: &str,
        address: Address,
        not_before: u64,
        not_after: u64,
    ) -> Result<Self, WireError> {
        let bytes = Self::signing_bytes(node_id, address, not_before, not_after)?;
        Ok(Self {
            node_id: node_id.to_owned(),
            address,
            not_before,
            not_after,
            signature: identity.sign_payload(&bytes),
        })
    }

    /// Returns this certificate's canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::FieldTooLong`] if `node_id` exceeds [`MAX_NODE_ID_LEN`].
    pub fn to_signing_bytes(&self) -> Result<Vec<u8>, WireError> {
        Self::signing_bytes(&self.node_id, self.address, self.not_before, self.not_after)
    }

    /// Returns the digest the identity key signed.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::FieldTooLong`] if `node_id` exceeds [`MAX_NODE_ID_LEN`].
    pub fn digest(&self) -> Result<[u8; 32], WireError> {
        Ok(domain::digest(&self.to_signing_bytes()?))
    }

    /// Recovers the identity address that issued this certificate.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::RecoveryFailed`] if recovery fails, or
    /// [`WireError::FieldTooLong`] if `node_id` is too long.
    pub fn recover_issuer(&self) -> Result<Address, WireError> {
        signer::recover_address(&self.digest()?, &self.signature)
    }

    /// Returns `true` if the window is well-formed.
    #[must_use]
    pub const fn has_valid_window(&self) -> bool {
        self.not_before < self.not_after
    }

    /// Returns `true` if the certificate covers `publish_time_ns`.
    #[must_use]
    pub const fn covers(&self, publish_time_ns: u64) -> bool {
        let start = self.not_before.saturating_mul(NANOS_PER_SEC);
        let end = self.not_after.saturating_mul(NANOS_PER_SEC);
        start <= publish_time_ns && publish_time_ns < end
    }

    /// Checks that the certificate covers an update's publish time.
    ///
    /// # Why publish time and not "now"
    ///
    /// Validity is evaluated at the instant the update claims to have been
    /// signed. Checking against the current clock instead would mean every key
    /// rotation retroactively invalidated everything signed under the previous
    /// key — historical updates would stop verifying the moment a certificate
    /// expired, which is precisely backwards.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::CertificateNotYetValid`] or
    /// [`VerifyError::CertificateExpired`].
    pub fn check_covers(&self, publish_time_ns: u64) -> Result<(), VerifyError> {
        let published = publish_time_ns / NANOS_PER_SEC;
        if publish_time_ns < self.not_before.saturating_mul(NANOS_PER_SEC) {
            return Err(VerifyError::CertificateNotYetValid {
                signer: self.address,
                not_before: self.not_before,
                published,
            });
        }
        if publish_time_ns >= self.not_after.saturating_mul(NANOS_PER_SEC) {
            return Err(VerifyError::CertificateExpired {
                signer: self.address,
                not_after: self.not_after,
                published,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 3_600;

    fn identity() -> Signer {
        Signer::from_secret_bytes([1_u8; 32]).expect("valid key")
    }

    fn hot() -> Signer {
        Signer::from_secret_bytes([2_u8; 32]).expect("valid key")
    }

    fn cert() -> SigningKeyCert {
        SigningKeyCert::issue(
            &identity(),
            "oracle-eu-1",
            hot().address(),
            1_000,
            1_000 + 24 * HOUR,
        )
        .expect("issues")
    }

    #[test]
    fn issued_certificates_recover_to_the_identity_key() {
        assert_eq!(
            cert().recover_issuer().expect("recovers"),
            identity().address()
        );
    }

    #[test]
    fn tampering_with_any_field_breaks_the_issuer() {
        let issuer = identity().address();
        let mutations: [fn(&mut SigningKeyCert); 4] = [
            |c| c.node_id = "oracle-eu-2".to_owned(),
            |c| c.address = Address::from_bytes([0xFF; 20]),
            |c| c.not_before = 0,
            |c| c.not_after = u64::MAX,
        ];
        for mutate in mutations {
            let mut tampered = cert();
            mutate(&mut tampered);
            assert_ne!(
                tampered.recover_issuer().expect("recovery still succeeds"),
                issuer,
                "a mutated certificate must not recover to the real identity key"
            );
        }
    }

    #[test]
    fn validity_window_is_half_open() {
        let cert = cert();
        assert!(!cert.covers(999 * NANOS_PER_SEC));
        assert!(cert.covers(1_000 * NANOS_PER_SEC));
        assert!(cert.covers((1_000 + 24 * HOUR - 1) * NANOS_PER_SEC));
        // not_after is exclusive.
        assert!(!cert.covers((1_000 + 24 * HOUR) * NANOS_PER_SEC));
    }

    #[test]
    fn check_covers_reports_which_side_failed() {
        let cert = cert();
        assert!(matches!(
            cert.check_covers(500 * NANOS_PER_SEC),
            Err(VerifyError::CertificateNotYetValid {
                not_before: 1_000,
                published: 500,
                ..
            })
        ));
        assert!(matches!(
            cert.check_covers((1_000 + 48 * HOUR) * NANOS_PER_SEC),
            Err(VerifyError::CertificateExpired { .. })
        ));
        assert!(cert.check_covers(2_000 * NANOS_PER_SEC).is_ok());
    }

    #[test]
    fn absurd_expiry_saturates_instead_of_overflowing() {
        let mut cert = cert();
        cert.not_after = u64::MAX;
        // u64::MAX seconds in nanoseconds overflows. Saturation must clamp the
        // window to u64::MAX rather than wrapping to a small number, which would
        // expire the certificate instantly.
        assert!(cert.covers(u64::MAX - 1));
        assert!(cert.covers(1_000 * NANOS_PER_SEC));
        // The interval stays half-open even when saturated.
        assert!(!cert.covers(u64::MAX));
    }

    #[test]
    fn rejects_over_long_node_ids() {
        assert!(matches!(
            SigningKeyCert::issue(&identity(), &"x".repeat(65), hot().address(), 0, 1),
            Err(WireError::FieldTooLong {
                limit: MAX_NODE_ID_LEN,
                actual: 65,
                ..
            })
        ));
    }

    #[test]
    fn window_wellformedness_is_checkable() {
        let mut cert = cert();
        assert!(cert.has_valid_window());
        cert.not_after = cert.not_before;
        assert!(!cert.has_valid_window());
    }

    #[test]
    fn json_round_trips() {
        let cert = cert();
        let json = serde_json::to_string(&cert).expect("serializes");
        assert_eq!(
            serde_json::from_str::<SigningKeyCert>(&json).expect("deserializes"),
            cert
        );
    }
}
