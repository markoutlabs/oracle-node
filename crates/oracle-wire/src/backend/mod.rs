//! The secp256k1 backend.
//!
//! Two implementations with one byte-level contract. The `libsecp` feature is
//! `libsecp256k1`, the fastest option and the reference everything else is
//! checked against; the node and the proxy use it. The `pure-rust` feature is
//! `k256`, which needs no C compiler; the SDK and wasm32 use it, and it wins
//! when a build has both. CI runs the golden vectors under it, which is what
//! proves the two backends agree.
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
