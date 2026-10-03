//! Signing keys and public-key recovery.

use core::fmt;
use std::sync::LazyLock;

use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey};

use crate::{Address, Signature, WireError, domain};

/// One shared curve context. Building a `Secp256k1` context costs milliseconds,
/// so it must not happen per signature.
static SECP: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);

/// A secp256k1 signing key.
///
/// # Handling
///
/// This is the hot signing key, not the node identity key. It is expected to
/// live in process memory, be rotated on a schedule, and be authorised by a
/// [`crate::SigningKeyCert`] issued by the identity key — which should live in a
/// KMS or HSM and never sign a price.
///
/// The [`fmt::Debug`] implementation redacts the secret, and [`Drop`] erases it.
/// Neither is a substitute for keeping the key out of logs, cores, and swap.
pub struct Signer {
    secret: SecretKey,
    public: PublicKey,
    address: Address,
}

impl Signer {
    /// Loads a signing key from 32 raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidSecretKey`] if the bytes are not a valid
    /// scalar for the curve (zero, or at or above the group order).
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self, WireError> {
        let secret = SecretKey::from_byte_array(bytes).map_err(|_| WireError::InvalidSecretKey)?;
        let public = secret.public_key(&SECP);
        let address = Address::from_public_key(&public);
        Ok(Self {
            secret,
            public,
            address,
        })
    }

    /// Generates a key from the operating system's CSPRNG.
    ///
    /// This is the only key-generation path in the codebase. The seeded keys in
    /// the examples and test helpers are derived from small integers and are
    /// guessable by construction — they exist so that fixtures are reproducible,
    /// and using one for anything real would hand over the node.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::EntropyUnavailable`] if the OS entropy source cannot
    /// be read. There is deliberately no fallback: a key drawn from a weaker
    /// source is indistinguishable from a good one everywhere downstream.
    pub fn generate() -> Result<Self, WireError> {
        // A uniformly random 32-byte string lands outside the curve order with
        // probability around 2^-128. Negligible is not impossible, and the
        // failure would be silent, so draw again rather than reason about it.
        for _ in 0..8 {
            let mut bytes = [0_u8; 32];
            getrandom::fill(&mut bytes)
                .map_err(|e| WireError::EntropyUnavailable(e.to_string()))?;
            let signer = Self::from_secret_bytes(bytes);
            bytes.fill(0);
            if let Ok(signer) = signer {
                return Ok(signer);
            }
        }
        Err(WireError::EntropyUnavailable(
            "the entropy source repeatedly produced invalid scalars".to_owned(),
        ))
    }

    /// Returns the secret key as hex, without a `0x` prefix.
    ///
    /// The one deliberate way to get the secret out of this type — [`fmt::Debug`]
    /// redacts it and [`Drop`] erases it, so anything that exports the key should
    /// be obvious at the call site rather than incidental.
    #[must_use]
    pub fn to_secret_hex(&self) -> String {
        hex::encode(self.secret.secret_bytes())
    }

    /// Loads a signing key from hex, with or without a `0x` prefix.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidHex`] if the string is not 32 bytes of hex,
    /// or [`WireError::InvalidSecretKey`] if it is not a valid scalar.
    pub fn from_hex(hex_str: &str) -> Result<Self, WireError> {
        let body = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(body, &mut bytes).map_err(|_| WireError::InvalidHex {
            field: "secret_key",
            expected: 32,
        })?;
        let signer = Self::from_secret_bytes(bytes);
        bytes.fill(0);
        signer
    }

    /// Returns the address this key signs under.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Returns the public key.
    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Signs a precomputed 32-byte digest.
    ///
    /// # Panics
    ///
    /// Panics if the curve backend returns a non-canonical signature. That
    /// cannot happen for any input — `libsecp256k1` always emits low-`s` — so it
    /// would mean the linked library is broken. Crashing is the correct response:
    /// a node that has lost confidence in its signing backend must stop signing,
    /// not emit signatures nobody can verify.
    #[must_use]
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Signature {
        let message = Message::from_digest(*digest);
        let recoverable = SECP.sign_ecdsa_recoverable(message, &self.secret);
        Signature::from_recoverable(&recoverable)
            .expect("libsecp256k1 always produces canonical low-s signatures")
    }

    /// Signs a canonical payload under the protocol domain.
    ///
    /// # Panics
    ///
    /// See [`Signer::sign_digest`].
    #[must_use]
    pub fn sign_payload(&self, payload: &[u8]) -> Signature {
        self.sign_digest(&domain::digest(payload))
    }
}

impl Drop for Signer {
    fn drop(&mut self) {
        self.secret.non_secure_erase();
    }
}

impl fmt::Debug for Signer {
    /// Prints the address only. The secret is never rendered, by any formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("address", &self.address)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Recovers the address that signed `digest`.
///
/// # Security
///
/// Recovery is **not** verification. For any well-formed signature this returns
/// *some* address; an attacker signing with a freshly generated key gets a
/// perfectly successful recovery. The result is meaningful only after it is
/// matched against a trusted registry — which is why the only path from a frame
/// to a [`oracle_types::PriceUpdate`] you can act on goes through
/// [`crate::UnverifiedFrame::verify`].
///
/// # Errors
///
/// Returns [`WireError::RecoveryFailed`] if no public key corresponds to the
/// signature and digest.
pub fn recover_address(digest: &[u8; 32], signature: &Signature) -> Result<Address, WireError> {
    let recoverable = signature.to_recoverable()?;
    let message = Message::from_digest(*digest);
    let public = SECP
        .recover_ecdsa(message, &recoverable)
        .map_err(|_| WireError::RecoveryFailed)?;
    Ok(Address::from_public_key(&public))
}

/// Recovers the address that signed a canonical payload under the protocol domain.
///
/// # Security
///
/// See [`recover_address`]: this establishes authorship, not trust.
///
/// # Errors
///
/// Returns [`WireError::RecoveryFailed`] if recovery fails.
pub fn recover_payload_signer(payload: &[u8], signature: &Signature) -> Result<Address, WireError> {
    recover_address(&domain::digest(payload), signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_recover_round_trip() {
        let signer = Signer::from_secret_bytes([42_u8; 32]).expect("valid key");
        let payload = b"canonical payload bytes";
        let signature = signer.sign_payload(payload);
        assert_eq!(
            recover_payload_signer(payload, &signature).expect("recovers"),
            signer.address()
        );
    }

    #[test]
    fn a_different_payload_recovers_a_different_address() {
        let signer = Signer::from_secret_bytes([42_u8; 32]).expect("valid key");
        let signature = signer.sign_payload(b"original");
        let recovered = recover_payload_signer(b"tampered", &signature).expect("recovers");
        // Recovery still succeeds — it just yields someone else. This is exactly
        // why recovery alone proves nothing.
        assert_ne!(recovered, signer.address());
    }

    #[test]
    fn signing_is_deterministic() {
        // RFC 6979 nonces: the same key and digest always give the same bytes.
        let signer = Signer::from_secret_bytes([7_u8; 32]).expect("valid key");
        assert_eq!(signer.sign_payload(b"x"), signer.sign_payload(b"x"));
    }

    #[test]
    fn rejects_invalid_secret_keys() {
        // Zero is not a valid scalar.
        assert_eq!(
            Signer::from_secret_bytes([0_u8; 32]).err(),
            Some(WireError::InvalidSecretKey)
        );
        // Neither is anything at or above the group order.
        assert_eq!(
            Signer::from_secret_bytes([0xFF_u8; 32]).err(),
            Some(WireError::InvalidSecretKey)
        );
        assert!(Signer::from_hex("not hex").is_err());
        assert!(Signer::from_hex("0x01").is_err());
    }

    #[test]
    fn hex_loading_matches_byte_loading() {
        let bytes = [9_u8; 32];
        let from_bytes = Signer::from_secret_bytes(bytes).expect("valid key");
        let from_hex = Signer::from_hex(&format!("0x{}", hex::encode(bytes))).expect("valid key");
        assert_eq!(from_bytes.address(), from_hex.address());
    }

    #[test]
    fn generated_keys_are_usable_and_distinct() {
        let first = Signer::generate().expect("entropy available");
        let second = Signer::generate().expect("entropy available");
        assert_ne!(
            first.address(),
            second.address(),
            "two generated keys must not collide"
        );

        // The generated key round-trips through the same path the node uses to
        // load it back from a file.
        let reloaded = Signer::from_hex(&first.to_secret_hex()).expect("valid key");
        assert_eq!(reloaded.address(), first.address());

        // And it actually signs.
        let signature = first.sign_payload(b"payload");
        assert_eq!(
            recover_payload_signer(b"payload", &signature).expect("recovers"),
            first.address()
        );
    }

    #[test]
    fn secret_hex_is_32_bytes_without_a_prefix() {
        let hex = Signer::generate()
            .expect("entropy available")
            .to_secret_hex();
        assert_eq!(hex.len(), 64);
        assert!(!hex.starts_with("0x"));
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn debug_output_never_contains_the_secret() {
        let secret = [0xAB_u8; 32];
        let signer = Signer::from_secret_bytes(secret).expect("valid key");
        let rendered = format!("{signer:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&hex::encode(secret)));
    }
}
