//! The registry canister as deployed on the Internet Computer mainnet.
//!
//! A change here moves the trust root of every node and consumer that uses the
//! defaults, so it is one reviewed commit that sets both.

/// The registry canister's id: where `/registry.json` and `/clients.json` are
/// served, and whose certificate proves them current.
pub const CANISTER_ID: Option<&str> = Some("xb5gv-diaaa-aaaaf-qg5qa-cai");

/// The address of the canister's threshold key, which signs every registry
/// and client list. Consumers and nodes pin it.
pub const GOVERNANCE_ADDRESS: Option<&str> = Some("0x7FB990Cc1111a00931B6396E5780C79574e36897");

/// The root key every mainnet certificate chains to.
pub use crate::source::IC_MAINNET_ROOT_KEY as ROOT_KEY;
