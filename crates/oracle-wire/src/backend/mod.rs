//! The secp256k1 backend.
//!
//! Two implementations with one byte-level contract. The `libsecp` feature is
//! `libsecp256k1`, the fastest option and the reference everything else is
//! checked against; the node and the proxy use it. The `pure-rust` feature is
//! `k256`, which needs no C compiler; the SDK and wasm32 use it, and it wins
//! when a build has both. `make test` runs the golden vectors under each, which
//! is what proves the two backends agree.
//!
//! Nothing outside this module names a backend type. Keys cross the boundary
//! as fixed-size byte arrays, signatures as `(r ‖ s, recovery_id)`.

#[cfg(all(
    feature = "libsecp",
    not(any(target_arch = "wasm32", feature = "pure-rust"))
))]
mod libsecp;
#[cfg(all(
    feature = "libsecp",
    not(any(target_arch = "wasm32", feature = "pure-rust"))
))]
pub(crate) use libsecp::*;

#[cfg(any(target_arch = "wasm32", feature = "pure-rust"))]
mod pure;
#[cfg(any(target_arch = "wasm32", feature = "pure-rust"))]
pub(crate) use pure::*;

#[cfg(not(any(target_arch = "wasm32", feature = "pure-rust", feature = "libsecp")))]
compile_error!("oracle-wire needs a secp256k1 backend: the `pure-rust` or the `libsecp` feature");

/// Name of the active backend, for diagnostics.
#[must_use]
pub const fn name() -> &'static str {
    if cfg!(any(target_arch = "wasm32", feature = "pure-rust")) {
        "k256"
    } else {
        "libsecp256k1"
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_compact_sec1_key_is_refused_by_every_backend() {
        let mut key = [0_u8; 33];
        key[0] = 0x05;
        key[1..].copy_from_slice(
            &hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .expect("hex"),
        );
        assert!(super::decompress(&key).is_err());
        key[0] = 0x02;
        assert!(
            super::decompress(&key).is_ok(),
            "the generator itself is a key"
        );
    }
}
