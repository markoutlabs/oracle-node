//! 65-byte recoverable ECDSA signatures.

use core::fmt;
use core::str::FromStr;

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};

use crate::WireError;

/// Length of an encoded signature: `r ‖ s ‖ v`.
pub const SIGNATURE_LEN: usize = 65;

/// Half the secp256k1 group order, `n / 2`, big-endian.
///
/// Signatures with `s` above this are malleable — negating `s` yields a second
/// signature that verifies identically. Only the low form is canonical.
const HALF_CURVE_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// The Ethereum convention: recovery ids are offset by 27 on the wire.
const RECOVERY_OFFSET: u8 = 27;

/// A recoverable ECDSA signature, `r ‖ s ‖ v` with `v` in `{27, 28}`.
///
/// The `v` offset of 27 matches Ethereum's `ecrecover`, so a future on-chain
/// verifier consumes these bytes unchanged.
///
/// Every constructor enforces canonicality: `r` and `s` non-zero, `s` at or
/// below the curve half-order, and `v` in range. A [`Signature`] that exists is
/// structurally valid; whether it is *trusted* is a separate question answered
/// only by the registry.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Parses and validates 65 signature bytes.
    ///
    /// # Errors
    ///
    /// - [`WireError::InvalidRecoveryByte`] if `v` is not 27 or 28.
    /// - [`WireError::ZeroScalar`] if `r` or `s` is zero.
    /// - [`WireError::HighS`] if `s` is above the curve half-order.
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Result<Self, WireError> {
        let sig = Self(bytes);
        let recovery = sig.recovery_byte();
        if recovery != RECOVERY_OFFSET && recovery != RECOVERY_OFFSET + 1 {
            return Err(WireError::InvalidRecoveryByte(recovery));
        }
        let (r, s) = (sig.r(), sig.s());
        if r == [0_u8; 32] || s == [0_u8; 32] {
            return Err(WireError::ZeroScalar);
        }
        // Big-endian byte arrays compare lexicographically the same way the
        // integers they encode compare.
        if s > HALF_CURVE_ORDER {
            return Err(WireError::HighS);
        }
        Ok(sig)
    }

    /// Builds a signature from a `libsecp256k1` recoverable signature.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if the produced signature is not canonical, which
    /// would indicate a broken signing backend rather than bad input.
    pub fn from_recoverable(sig: &RecoverableSignature) -> Result<Self, WireError> {
        let (recovery_id, compact) = sig.serialize_compact();
        let recovery = i32::from(recovery_id);
        let recovery = u8::try_from(recovery).map_err(|_| WireError::RecoveryFailed)?;
        let mut bytes = [0_u8; SIGNATURE_LEN];
        let (head, tail) = bytes.split_at_mut(64);
        head.copy_from_slice(&compact);
        if let Some(slot) = tail.first_mut() {
            *slot = recovery
                .checked_add(RECOVERY_OFFSET)
                .ok_or(WireError::RecoveryFailed)?;
        }
        Self::from_bytes(bytes)
    }

    /// Converts to a `libsecp256k1` recoverable signature for key recovery.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::RecoveryFailed`] if the scalars do not form a
    /// signature the backend accepts.
    pub fn to_recoverable(self) -> Result<RecoverableSignature, WireError> {
        let recovery = self
            .recovery_byte()
            .checked_sub(RECOVERY_OFFSET)
            .ok_or(WireError::InvalidRecoveryByte(self.recovery_byte()))?;
        let recovery_id = RecoveryId::try_from(i32::from(recovery))
            .map_err(|_| WireError::InvalidRecoveryByte(self.recovery_byte()))?;
        let compact = self.0.get(..64).ok_or(WireError::RecoveryFailed)?;
        RecoverableSignature::from_compact(compact, recovery_id)
            .map_err(|_| WireError::RecoveryFailed)
    }

    /// Returns the raw 65 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }

    /// Returns the `r` scalar.
    #[must_use]
    pub fn r(&self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        if let Some(slice) = self.0.get(..32) {
            out.copy_from_slice(slice);
        }
        out
    }

    /// Returns the `s` scalar.
    #[must_use]
    pub fn s(&self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        if let Some(slice) = self.0.get(32..64) {
            out.copy_from_slice(slice);
        }
        out
    }

    /// Returns the raw recovery byte `v`, which is 27 or 28.
    #[must_use]
    pub fn recovery_byte(&self) -> u8 {
        self.0.get(64).copied().unwrap_or(0)
    }

    /// Returns the recovery id, 0 or 1.
    #[must_use]
    pub fn recovery_id(&self) -> u8 {
        self.recovery_byte().saturating_sub(RECOVERY_OFFSET)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({self})")
    }
}

impl FromStr for Signature {
    type Err = WireError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let body = s.strip_prefix("0x").unwrap_or(s);
        let mut bytes = [0_u8; SIGNATURE_LEN];
        hex::decode_to_slice(body, &mut bytes).map_err(|_| WireError::InvalidHex {
            field: "signature",
            expected: SIGNATURE_LEN,
        })?;
        Self::from_bytes(bytes)
    }
}

impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Signer;

    fn valid_signature() -> Signature {
        let signer = Signer::from_secret_bytes([3_u8; 32]).expect("valid key");
        signer.sign_digest(&[9_u8; 32])
    }

    #[test]
    fn signing_produces_canonical_signatures() {
        // libsecp256k1 always emits low-s; this asserts we never relax that.
        for seed in 1_u8..32 {
            let signer = Signer::from_secret_bytes([seed; 32]).expect("valid key");
            let sig = signer.sign_digest(&[seed; 32]);
            assert!(sig.s() <= HALF_CURVE_ORDER, "seed {seed} produced high-s");
            assert!(matches!(sig.recovery_byte(), 27 | 28));
        }
    }

    #[test]
    fn rejects_high_s_signatures() {
        let sig = valid_signature();
        let mut bytes = *sig.as_bytes();
        // Flipping the top bit of s pushes it above the half-order.
        if let Some(byte) = bytes.get_mut(32) {
            *byte |= 0x80;
        }
        assert_eq!(Signature::from_bytes(bytes), Err(WireError::HighS));
    }

    #[test]
    fn rejects_bad_recovery_bytes() {
        let sig = valid_signature();
        for bad in [0_u8, 1, 26, 29, 255] {
            let mut bytes = *sig.as_bytes();
            if let Some(byte) = bytes.get_mut(64) {
                *byte = bad;
            }
            assert_eq!(
                Signature::from_bytes(bytes),
                Err(WireError::InvalidRecoveryByte(bad))
            );
        }
    }

    #[test]
    fn rejects_zero_scalars() {
        let sig = valid_signature();
        let mut zero_r = *sig.as_bytes();
        if let Some(slice) = zero_r.get_mut(..32) {
            slice.fill(0);
        }
        assert_eq!(Signature::from_bytes(zero_r), Err(WireError::ZeroScalar));

        let mut zero_s = *sig.as_bytes();
        if let Some(slice) = zero_s.get_mut(32..64) {
            slice.fill(0);
        }
        assert_eq!(Signature::from_bytes(zero_s), Err(WireError::ZeroScalar));
    }

    #[test]
    fn recoverable_round_trip() {
        let sig = valid_signature();
        let recoverable = sig.to_recoverable().expect("canonical");
        assert_eq!(
            Signature::from_recoverable(&recoverable).expect("canonical"),
            sig
        );
    }

    #[test]
    fn hex_round_trips() {
        let sig = valid_signature();
        assert_eq!(sig.to_string().parse::<Signature>().expect("valid"), sig);
        assert!("0xdeadbeef".parse::<Signature>().is_err());
    }
}
