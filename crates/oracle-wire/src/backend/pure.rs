//! Pure-Rust `k256` backend.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

use crate::WireError;

/// A secret scalar.
pub(crate) struct SecretKey(SigningKey);

impl SecretKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Result<Self, WireError> {
        SigningKey::from_bytes((&bytes).into())
            .map(Self)
            .map_err(|_| WireError::InvalidSecretKey)
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }

    pub(crate) fn public_compressed(&self) -> [u8; 33] {
        let point = self.0.verifying_key().to_encoded_point(true);
        let mut out = [0_u8; 33];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Signs a digest. Returns `r ‖ s` and the recovery id in `{0, 1}`.
    ///
    /// # Panics
    ///
    /// Panics if the backend fails to sign, which cannot happen for a valid key
    /// and a 32-byte digest.
    pub(crate) fn sign_digest(&self, digest: &[u8; 32]) -> ([u8; 64], u8) {
        let (sig, recovery): (Signature, RecoveryId) = self
            .0
            .sign_prehash(digest)
            .expect("a valid key signs any 32-byte digest");
        // Low-s is canonical. Negating `s` flips the parity of the recovered
        // point, so the recovery id flips with it.
        let (sig, recovery) = match sig.normalize_s() {
            Some(low) => (low, recovery.to_byte() ^ 1),
            None => (sig, recovery.to_byte()),
        };
        (sig.to_bytes().into(), recovery)
    }

    pub(crate) fn erase(&mut self) {
        // `SigningKey` zeroizes on drop. Nothing to do before then.
    }
}

/// Recovers the uncompressed public key that signed `digest`.
pub(crate) fn recover(
    digest: &[u8; 32],
    compact: &[u8; 64],
    recovery: u8,
) -> Result<[u8; 65], WireError> {
    let recovery_id = RecoveryId::from_byte(recovery).ok_or(WireError::RecoveryFailed)?;
    let sig = Signature::from_slice(compact).map_err(|_| WireError::RecoveryFailed)?;
    let key = VerifyingKey::recover_from_prehash(digest, &sig, recovery_id)
        .map_err(|_| WireError::RecoveryFailed)?;
    Ok(uncompressed(&key))
}

/// Decompresses a 33-byte public key.
pub(crate) fn decompress(compressed: &[u8; 33]) -> Result<[u8; 65], WireError> {
    VerifyingKey::from_sec1_bytes(compressed)
        .map(|key| uncompressed(&key))
        .map_err(|_| WireError::InvalidPublicKey)
}

fn uncompressed(key: &VerifyingKey) -> [u8; 65] {
    let point = key.to_encoded_point(false);
    let mut out = [0_u8; 65];
    out.copy_from_slice(point.as_bytes());
    out
}
