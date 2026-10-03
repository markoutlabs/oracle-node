//! `libsecp256k1` backend.

use std::sync::LazyLock;

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{All, Message, PublicKey, Secp256k1};

use crate::WireError;

/// One shared curve context. Building a `Secp256k1` context costs milliseconds,
/// so it must not happen per signature.
static SECP: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);

/// A secret scalar.
pub(crate) struct SecretKey(secp256k1::SecretKey);

impl SecretKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Result<Self, WireError> {
        secp256k1::SecretKey::from_byte_array(bytes)
            .map(Self)
            .map_err(|_| WireError::InvalidSecretKey)
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.0.secret_bytes()
    }

    pub(crate) fn public_compressed(&self) -> [u8; 33] {
        self.0.public_key(&SECP).serialize()
    }

    /// Signs a digest. Returns `r ‖ s` and the recovery id in `{0, 1}`.
    ///
    /// `libsecp256k1` always emits low-`s`.
    pub(crate) fn sign_digest(&self, digest: &[u8; 32]) -> ([u8; 64], u8) {
        let sig = SECP.sign_ecdsa_recoverable(Message::from_digest(*digest), &self.0);
        let (recovery_id, compact) = sig.serialize_compact();
        // `RecoveryId` is always 0..=3 and the backend never emits 2 or 3 here.
        let recovery = u8::try_from(i32::from(recovery_id)).unwrap_or(u8::MAX);
        (compact, recovery)
    }

    pub(crate) fn erase(&mut self) {
        self.0.non_secure_erase();
    }
}

/// Recovers the uncompressed public key that signed `digest`.
pub(crate) fn recover(
    digest: &[u8; 32],
    compact: &[u8; 64],
    recovery: u8,
) -> Result<[u8; 65], WireError> {
    let recovery_id =
        RecoveryId::try_from(i32::from(recovery)).map_err(|_| WireError::RecoveryFailed)?;
    let sig = RecoverableSignature::from_compact(compact, recovery_id)
        .map_err(|_| WireError::RecoveryFailed)?;
    SECP.recover_ecdsa(Message::from_digest(*digest), &sig)
        .map(|key| key.serialize_uncompressed())
        .map_err(|_| WireError::RecoveryFailed)
}

/// Folds `s` into the low half of the group, leaving low-`s` input unchanged.
pub(crate) fn normalize_s(compact: &[u8; 64]) -> Result<[u8; 64], WireError> {
    let mut sig = secp256k1::ecdsa::Signature::from_compact(compact)
        .map_err(|_| WireError::RecoveryFailed)?;
    sig.normalize_s();
    Ok(sig.serialize_compact())
}

/// Decompresses a 33-byte public key.
pub(crate) fn decompress(compressed: &[u8; 33]) -> Result<[u8; 65], WireError> {
    PublicKey::from_byte_array_compressed(*compressed)
        .map(|key| key.serialize_uncompressed())
        .map_err(|_| WireError::InvalidPublicKey)
}
