//! Signer addresses and compressed public keys.

use core::fmt;
use core::str::FromStr;

use secp256k1::PublicKey;

use crate::WireError;
use crate::keccak::keccak256;

/// A 20-byte signer identity: the last 20 bytes of the Keccak-256 hash of the
/// uncompressed public key, matching Ethereum's address derivation.
///
/// An address is never transmitted as an authenticated field. It is *recovered*
/// from a signature, which is why a forged update cannot claim to be from
/// another node — the recovered address simply will not match anything in the
/// registry.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct Address([u8; 20]);

impl Address {
    /// Length of an address in bytes.
    pub const LEN: usize = 20;

    /// Wraps 20 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Derives the address of a public key.
    ///
    /// `keccak256(uncompressed_pubkey_without_prefix)[12..32]`.
    #[must_use]
    pub fn from_public_key(key: &PublicKey) -> Self {
        let uncompressed = key.serialize_uncompressed();
        // Byte 0 is the 0x04 uncompressed marker and is not hashed.
        let body = uncompressed.get(1..).unwrap_or(&[]);
        let hash = keccak256(body);
        let mut out = [0_u8; 20];
        if let Some(tail) = hash.get(12..) {
            out.copy_from_slice(tail);
        }
        Self(out)
    }

    /// Renders the address with an EIP-55 mixed-case checksum.
    ///
    /// Useful in logs and config files: a typo in a pinned governance address is
    /// otherwise undetectable until signatures start failing in production.
    #[must_use]
    pub fn to_checksummed(&self) -> String {
        let lower = hex::encode(self.0);
        let hash = keccak256(lower.as_bytes());
        let mut out = String::with_capacity(2 + lower.len());
        out.push_str("0x");
        for (i, ch) in lower.chars().enumerate() {
            // Nibble i of the hash decides the case of character i.
            let byte = hash.get(i / 2).copied().unwrap_or(0);
            let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0F };
            if nibble >= 8 {
                out.extend(ch.to_uppercase());
            } else {
                out.push(ch);
            }
        }
        out
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

impl FromStr for Address {
    type Err = WireError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let body = s.strip_prefix("0x").unwrap_or(s);
        let mut bytes = [0_u8; 20];
        hex::decode_to_slice(body, &mut bytes).map_err(|_| WireError::InvalidHex {
            field: "address",
            expected: Self::LEN,
        })?;
        Ok(Self(bytes))
    }
}

impl From<&PublicKey> for Address {
    fn from(key: &PublicKey) -> Self {
        Self::from_public_key(key)
    }
}

impl serde::Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// A 33-byte compressed secp256k1 public key, as stored in the node registry.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompressedPublicKey([u8; 33]);

impl CompressedPublicKey {
    /// Length in bytes.
    pub const LEN: usize = 33;

    /// Wraps 33 raw bytes without checking that they form a curve point.
    ///
    /// Use [`CompressedPublicKey::decode`] before relying on the key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 33]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    /// Serializes a public key into compressed form.
    #[must_use]
    pub fn from_public_key(key: &PublicKey) -> Self {
        Self(key.serialize())
    }

    /// Decodes to a curve point.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidPublicKey`] if the bytes are not a valid
    /// compressed point.
    pub fn decode(&self) -> Result<PublicKey, WireError> {
        PublicKey::from_byte_array_compressed(self.0).map_err(|_| WireError::InvalidPublicKey)
    }

    /// Returns the address this key signs under.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidPublicKey`] if the bytes are not a valid
    /// compressed point.
    pub fn address(&self) -> Result<Address, WireError> {
        Ok(Address::from_public_key(&self.decode()?))
    }
}

impl fmt::Display for CompressedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for CompressedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CompressedPublicKey({self})")
    }
}

impl FromStr for CompressedPublicKey {
    type Err = WireError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let body = s.strip_prefix("0x").unwrap_or(s);
        let mut bytes = [0_u8; 33];
        hex::decode_to_slice(body, &mut bytes).map_err(|_| WireError::InvalidHex {
            field: "identity_pubkey",
            expected: Self::LEN,
        })?;
        Ok(Self(bytes))
    }
}

impl serde::Serialize for CompressedPublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for CompressedPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Signer;

    /// The canonical Ethereum test vector: secret key `1`.
    ///
    /// This is an *external* check on the whole derivation chain — curve
    /// arithmetic, uncompressed serialization, Keccak-256, and the 12-byte
    /// offset. Any one of those being subtly wrong changes the answer.
    #[test]
    fn derives_the_known_address_for_secret_key_one() {
        let mut secret = [0_u8; 32];
        if let Some(last) = secret.last_mut() {
            *last = 1;
        }
        let signer = Signer::from_secret_bytes(secret).expect("valid key");
        assert_eq!(
            signer.address().to_string(),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
        assert_eq!(
            signer.address().to_checksummed(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
    }

    #[test]
    fn address_hex_round_trips_with_and_without_prefix() {
        let address = Address::from_bytes([0xAB; 20]);
        assert_eq!(
            address.to_string().parse::<Address>().expect("valid"),
            address
        );
        assert_eq!(
            hex::encode([0xAB_u8; 20])
                .parse::<Address>()
                .expect("valid"),
            address
        );
        assert!("0x1234".parse::<Address>().is_err());
        assert!("not-hex".parse::<Address>().is_err());
    }

    #[test]
    fn compressed_key_round_trips_through_the_curve() {
        let signer = Signer::from_secret_bytes([7_u8; 32]).expect("valid key");
        let compressed = CompressedPublicKey::from_public_key(&signer.public_key());
        assert_eq!(
            compressed.decode().expect("valid point"),
            signer.public_key()
        );
        assert_eq!(compressed.address().expect("valid point"), signer.address());
        assert_eq!(
            compressed
                .to_string()
                .parse::<CompressedPublicKey>()
                .expect("valid"),
            compressed
        );
    }

    #[test]
    fn invalid_compressed_keys_are_rejected() {
        let bogus = CompressedPublicKey::from_bytes([0xFF; 33]);
        assert_eq!(bogus.decode(), Err(WireError::InvalidPublicKey));
    }
}
