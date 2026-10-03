//! The secp256k1 backend.
//!
//! Two implementations with one byte-level contract. Native builds use
//! `libsecp256k1`, which is the fastest option and the reference everything
//! else is checked against. wasm32 builds use the pure-Rust `k256`, because
//! the C backend needs a wasm-capable C compiler that most toolchains lack.
//!
//! The `pure-rust` feature selects `k256` on native targets too. CI runs the
//! golden vectors under it, which is what proves the two backends agree.
//!
//! Nothing outside this module names a backend type. Keys cross the boundary
//! as fixed-size byte arrays, signatures as `(r ‖ s, recovery_id)`.

#[cfg(not(any(target_arch = "wasm32", feature = "pure-rust")))]
mod libsecp;
#[cfg(not(any(target_arch = "wasm32", feature = "pure-rust")))]
pub(crate) use libsecp::*;

#[cfg(any(target_arch = "wasm32", feature = "pure-rust"))]
mod pure;
#[cfg(any(target_arch = "wasm32", feature = "pure-rust"))]
pub(crate) use pure::*;

/// Name of the active backend, for diagnostics.
#[must_use]
pub const fn name() -> &'static str {
    if cfg!(any(target_arch = "wasm32", feature = "pure-rust")) {
        "k256"
    } else {
        "libsecp256k1"
    }
}
