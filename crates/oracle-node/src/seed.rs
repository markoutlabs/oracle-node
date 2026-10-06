//! A node's secret seed and the two keys derived from it.
//!
//! The secp256k1 key signs price updates, and its address is the node's id in
//! the registry. The ed25519 key signs samples for venues that verify ed25519
//! in a canister, such as tapray-perps. Each key is HKDF-SHA256 of the seed
//! under its own label, so neither key reveals the seed or the other key, and
//! the operator backs up one secret.
//!
//! A key file holds the seed as `oracle-node-seed-v1:<hex>`. Bare hex is a
//! secp256k1 key from before seeds, and loads without an ed25519 key.

use std::fmt;

use hkdf::Hkdf;
use oracle_wire::{Signer, WireError};
use sha2::Sha256;
use zeroize::Zeroizing;

/// The prefix that marks a seed in a key file.
pub const SEED_PREFIX: &str = "oracle-node-seed-v1:";

const SECP256K1_LABEL: &[u8] = b"price-oracle/node/secp256k1/v1";
const ED25519_LABEL: &[u8] = b"price-oracle/node/ed25519/v1";

/// A seed or a key could not be made or read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SeedError {
    /// The OS entropy source failed.
    #[error("cannot read OS entropy: {0}")]
    Entropy(String),
    /// The text is not a seed or a key.
    #[error("not a seed or a key: {0}")]
    Malformed(String),
    /// The derived secp256k1 key is not valid.
    #[error(transparent)]
    Key(#[from] WireError),
}

/// A node's 32-byte secret seed. Wiped on drop.
pub struct Seed(Zeroizing<[u8; 32]>);

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(..)")
    }
}

impl Seed {
    /// Draws a new seed from the OS.
    ///
    /// # Errors
    ///
    /// Returns [`SeedError::Entropy`] if the OS entropy source cannot be read.
    pub fn generate() -> Result<Self, SeedError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|e| SeedError::Entropy(e.to_string()))?;
        Ok(Self(bytes))
    }

    /// The seed as a key file holds it.
    #[must_use]
    pub fn to_text(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("{SEED_PREFIX}{}", hex::encode(*self.0)))
    }

    /// Reads a seed written by [`Self::to_text`]. `None` if the text has no
    /// seed prefix.
    #[must_use]
    pub fn from_text(text: &str) -> Option<Result<Self, SeedError>> {
        let hex_text = text.trim().strip_prefix(SEED_PREFIX)?;
        let mut bytes = Zeroizing::new([0_u8; 32]);
        Some(
            hex::decode_to_slice(hex_text, bytes.as_mut())
                .map(|()| Self(bytes))
                .map_err(|e| SeedError::Malformed(format!("seed: {e}"))),
        )
    }

    /// The secp256k1 key: price updates, and the node's id.
    ///
    /// # Errors
    ///
    /// Returns [`SeedError::Key`] only if every derivation lands outside the
    /// curve order, which happens with probability far below 2^-128 each.
    pub fn signer(&self) -> Result<Signer, SeedError> {
        let mut error = None;
        for retry in 0_u8..8 {
            let mut label = SECP256K1_LABEL.to_vec();
            // The first attempt uses the bare label, so the common case is the
            // documented derivation.
            if retry > 0 {
                label.push(retry);
            }
            match Signer::from_secret_bytes(*self.derive(&label)) {
                Ok(signer) => return Ok(signer),
                Err(e) => error = Some(e),
            }
        }
        Err(error.map_or_else(
            || SeedError::Malformed("no secp256k1 key".to_owned()),
            SeedError::Key,
        ))
    }

    /// The ed25519 key: samples for venues that verify ed25519.
    #[must_use]
    pub fn publisher(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.derive(ED25519_LABEL))
    }

    fn derive(&self, label: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0_u8; 32]);
        Hkdf::<Sha256>::new(None, self.0.as_ref())
            .expand(label, out.as_mut())
            .expect("32 bytes is within HKDF-SHA256's output limit");
        out
    }
}

/// The keys a node signs with.
pub struct NodeKeys {
    /// Signs price updates. Its address is the node's id.
    pub signing: Signer,
    /// Signs samples for venues that verify ed25519. `None` for a key file
    /// from before seeds.
    pub publisher: Option<ed25519_dalek::SigningKey>,
}

impl NodeKeys {
    /// Both keys from a seed.
    ///
    /// # Errors
    ///
    /// Returns [`SeedError::Key`] if no valid secp256k1 key can be derived.
    pub fn from_seed(seed: &Seed) -> Result<Self, SeedError> {
        Ok(Self {
            signing: seed.signer()?,
            publisher: Some(seed.publisher()),
        })
    }

    /// Reads what a key file or `key_env` holds: a seed, or a bare secp256k1
    /// key in hex.
    ///
    /// # Errors
    ///
    /// Returns [`SeedError`] if the text is neither.
    pub fn from_text(text: &str) -> Result<Self, SeedError> {
        match Seed::from_text(text) {
            Some(seed) => Self::from_seed(&seed?),
            None => Ok(Self {
                signing: Signer::from_hex(text.trim())?,
                publisher: None,
            }),
        }
    }
}

/// An ed25519 public key in hex, as a publisher slot records it.
#[must_use]
pub fn publisher_hex(key: &ed25519_dalek::SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> Seed {
        Seed(Zeroizing::new([byte; 32]))
    }

    /// A change to the labels or the KDF moves every node's id and publisher
    /// key. The secrets were computed apart from this code, with Python's
    /// `hmac` and `hashlib`.
    #[test]
    fn the_derivation_is_pinned() {
        let keys = NodeKeys::from_seed(&seed(7)).expect("derives");
        let publisher = keys.publisher.as_ref().expect("a publisher key");
        assert_eq!(
            *keys.signing.to_secret_hex(),
            "bbb8490c43a6ec00a76429d3b8ddedb932cbe32da534ae009a082149ed76d828"
        );
        assert_eq!(
            hex::encode(Zeroizing::new(publisher.to_bytes())),
            "b8c4b522b867b5707335ec932864a56b0adbb3064e52282c4cf47e2ab4bd10fb"
        );
        assert_eq!(
            keys.signing.address().to_checksummed(),
            "0xE0D53D12bFDA19e192537920dCbAF1CCD0BDd442"
        );
        assert_eq!(
            publisher_hex(publisher),
            "5dc8f60e897f56902b2ce401928a317ae70333c1feb6b91b43738e320d5c9a7b"
        );
    }

    /// tapray-perps verifies with ed25519-zebra under ZIP-215. Signing is
    /// deterministic, so this crate's signatures must pass it.
    #[test]
    fn a_publisher_signature_passes_the_zip215_verifier() {
        use ed25519_dalek::Signer as _;
        let keys = NodeKeys::from_seed(&seed(7)).expect("derives");
        let publisher = keys.publisher.expect("a publisher key");
        let message = b"a price sample";
        let signature = publisher.sign(message);
        let verifier =
            ed25519_zebra::VerificationKey::try_from(publisher.verifying_key().to_bytes())
                .expect("a valid point");
        verifier
            .verify(
                &ed25519_zebra::Signature::from(signature.to_bytes()),
                message,
            )
            .expect("verifies under ZIP-215");
    }

    #[test]
    fn the_two_keys_are_independent_of_each_other_and_of_the_seed() {
        let keys = NodeKeys::from_seed(&seed(7)).expect("derives");
        let secp = keys.signing.to_secret_hex();
        let ed = hex::encode(Zeroizing::new(keys.publisher.expect("a key").to_bytes()));
        assert_ne!(*secp, ed);
        assert_ne!(*secp, hex::encode([7_u8; 32]));
        assert_ne!(ed, hex::encode([7_u8; 32]));
        let other = NodeKeys::from_seed(&seed(8)).expect("derives");
        assert_ne!(other.signing.address(), keys.signing.address());
    }

    #[test]
    fn a_seed_round_trips_and_bare_hex_is_a_legacy_key() {
        let text = seed(7).to_text();
        assert!(text.starts_with(SEED_PREFIX));
        let keys = NodeKeys::from_text(&format!("{}\n", &*text)).expect("a seed");
        assert!(keys.publisher.is_some());

        let legacy = Signer::from_secret_bytes([9; 32]).expect("valid");
        let keys = NodeKeys::from_text(&legacy.to_secret_hex()).expect("a key");
        assert_eq!(keys.signing.address(), legacy.address());
        assert!(keys.publisher.is_none());

        assert!(NodeKeys::from_text(&format!("{SEED_PREFIX}zz")).is_err());
        assert!(NodeKeys::from_text("not a key").is_err());
    }
}
