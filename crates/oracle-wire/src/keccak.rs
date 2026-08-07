//! Keccak-256, the hash used throughout the protocol.
//!
//! Keccak-256 rather than SHA3-256 (they differ in padding) because it is what
//! the EVM's `KECCAK256` opcode computes. Choosing it costs nothing off-chain
//! and keeps an on-chain verifier a straightforward port.

use tiny_keccak::{Hasher as _, Keccak};

/// Hashes a byte string with Keccak-256.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0_u8; 32];
    hasher.finalize(&mut out);
    out
}

/// Hashes the concatenation of several byte strings without joining them first.
#[must_use]
pub fn keccak256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0_u8; 32];
    hasher.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Published Keccak-256 vectors. These are external checks: they confirm the
    /// hash really is Keccak-256 and not SHA3-256, which differ only in padding
    /// and would otherwise fail silently and identically on both sides.
    #[test]
    fn matches_published_keccak256_vectors() {
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex::encode(keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        assert_eq!(
            hex::encode(keccak256(b"hello")),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn streaming_matches_contiguous() {
        assert_eq!(keccak256_parts(&[b"abc"]), keccak256(b"abc"));
        assert_eq!(keccak256_parts(&[b"a", b"b", b"c"]), keccak256(b"abc"));
        assert_eq!(keccak256_parts(&[]), keccak256(b""));
    }
}
