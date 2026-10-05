//! The registry canister as deployed on the Internet Computer mainnet.
//!
//! Both values are `None` until the canister is deployed. A change here moves
//! the trust root of every node and consumer that uses the defaults, so it is
//! one reviewed commit that sets both.

/// The registry canister's id: where `/registry.json` and `/clients.json` are
/// served, and whose certificate proves them current.
pub const CANISTER_ID: Option<&str> = None;

/// The address of the canister's threshold key, which signs every registry
/// and client list. Consumers and nodes pin it.
pub const GOVERNANCE_ADDRESS: Option<&str> = None;

/// The root key every mainnet certificate chains to.
pub use crate::source::IC_MAINNET_ROOT_KEY as ROOT_KEY;
