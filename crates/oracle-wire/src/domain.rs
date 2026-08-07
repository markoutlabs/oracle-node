//! Domain separation for every signature this protocol produces.
//!
//! # Relationship to EIP-712
//!
//! The digest is EIP-712 *shaped* but not EIP-712 *compliant*, and the deviation
//! is deliberate.
//!
//! Strict EIP-712 replaces the message hash with a `structHash` built by hashing
//! a type string and then each field into a 32-byte word. Our payloads are
//! already a fixed, canonical byte layout, so we hash those bytes directly:
//!
//! ```text
//! digest = keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ keccak256(payload))
//! ```
//!
//! On-chain this is *cheaper* than the compliant form — one `keccak256` over a
//! calldata slice instead of a dozen word-packing operations — and the payload
//! is canonical by construction, so the field-tagging that `structHash` provides
//! buys nothing here.
//!
//! The practical consequence: these digests are **not** compatible with wallet
//! `eth_signTypedData`. They are meant to be produced by node software and
//! verified by `ecrecover`, and nothing else.
//!
//! Domain separation across payload types is carried by the `kind` byte, which
//! is the second byte of every payload. A price update can therefore never be
//! reinterpreted as a certificate or a registry, even though all three share one
//! digest function.

use std::sync::LazyLock;

use crate::keccak::{keccak256, keccak256_parts};

/// Domain name.
pub const DOMAIN_NAME: &str = "PriceOracle";

/// Domain version. Bumping this invalidates every existing signature.
pub const DOMAIN_VERSION: &str = "1";

/// Chain id. Zero means "off-chain, chain-agnostic".
///
/// A future on-chain deployment uses that chain's real id, which cleanly
/// prevents off-chain signatures from being replayed on-chain.
pub const DOMAIN_CHAIN_ID: u64 = 0;

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId)")`.
static DOMAIN_TYPEHASH: LazyLock<[u8; 32]> =
    LazyLock::new(|| keccak256(b"EIP712Domain(string name,string version,uint256 chainId)"));

/// The domain separator, computed once.
static DOMAIN_SEPARATOR: LazyLock<[u8; 32]> = LazyLock::new(|| {
    let mut chain_id = [0_u8; 32];
    // uint256, big-endian: the low 8 bytes carry the value.
    if let Some(tail) = chain_id.get_mut(24..) {
        tail.copy_from_slice(&DOMAIN_CHAIN_ID.to_be_bytes());
    }
    keccak256_parts(&[
        DOMAIN_TYPEHASH.as_slice(),
        keccak256(DOMAIN_NAME.as_bytes()).as_slice(),
        keccak256(DOMAIN_VERSION.as_bytes()).as_slice(),
        chain_id.as_slice(),
    ])
});

/// Returns the domain separator.
#[must_use]
pub fn domain_separator() -> [u8; 32] {
    *DOMAIN_SEPARATOR
}

/// Computes the digest that gets signed for a canonical payload.
///
/// The payload's `kind` byte separates payload types from one another, so this
/// single function serves price updates, certificates, and the registry.
#[must_use]
pub fn digest(payload: &[u8]) -> [u8; 32] {
    let payload_hash = keccak256(payload);
    keccak256_parts(&[
        &[0x19, 0x01],
        DOMAIN_SEPARATOR.as_slice(),
        payload_hash.as_slice(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frozen. A change here silently invalidates every signature ever issued,
    /// so it must be a deliberate edit accompanied by a `DOMAIN_VERSION` bump.
    ///
    /// Cross-checked against `foundry`, which computes the same value from the
    /// EIP-712 definition alone:
    ///
    /// ```text
    /// TH=$(cast keccak "EIP712Domain(string name,string version,uint256 chainId)")
    /// N=$(cast keccak "PriceOracle"); V=$(cast keccak "1")
    /// cast keccak 0x${TH#0x}${N#0x}${V#0x}$(printf '0%.0s' {1..64})
    /// ```
    #[test]
    fn domain_separator_is_stable() {
        assert_eq!(
            hex::encode(*DOMAIN_TYPEHASH),
            "c2f8787176b8ac6bf7215b4adcc1e069bf4ab82d9ab1df05a57a91d425935b6e"
        );
        assert_eq!(
            hex::encode(domain_separator()),
            "13bb3c3ca2fe9d51da4217029742cf381b8759cc6d9730e6b60d3d5fabe0f149"
        );
    }

    #[test]
    fn digest_depends_on_the_payload() {
        assert_ne!(digest(b"a"), digest(b"b"));
        assert_eq!(digest(b"a"), digest(b"a"));
    }

    #[test]
    fn digest_is_domain_bound() {
        // The digest must not be a bare hash of the payload: that would let a
        // signature produced for any other protocol be replayed here.
        assert_ne!(digest(b"payload"), keccak256(b"payload"));
    }
}
