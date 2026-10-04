//! Canonical encoding, signing, and verification for oracle price updates.
//!
//! This crate owns the protocol's byte layouts and its cryptography. Everything
//! a node signs and everything a consumer verifies passes through here.
//!
//! # The one thing to understand
//!
//! **A signature proves authorship, not truth.** It says a particular node
//! asserted a particular price at a particular time. It says nothing about
//! whether that price is right, or even whether the node ever connected to an
//! exchange — `num_sources` is inside the signed payload, but nothing binds that
//! claim to reality. There is no verifiable computation here.
//!
//! The defence against a lying or malfunctioning node is not cryptographic. It
//! is the median across N independently-keyed nodes, plus divergence monitoring.
//! A consumer that verifies signatures from a single node has confirmed who is
//! talking and learned nothing about whether to believe them.
//!
//! # The verification path
//!
//! The types enforce the order of operations, so the dangerous shortcut — treat
//! successful key recovery as successful verification — cannot be taken by
//! accident:
//!
//! ```text
//!   bytes ──parse──▶ UnverifiedFrame ──verify(&VerifiedRegistry)──▶ VerifiedUpdate
//!                          │
//!                          └─ recover_signer() yields an address for ANY
//!                             well-formed signature, including a forged one
//! ```
//!
//! [`VerifiedRegistry`] is itself only obtainable by checking a [`Registry`]
//! against a governance address the caller pins, and against a version floor, so
//! a node cannot vouch for its own registry and an old registry cannot be
//! replayed to reinstate a revoked key.
//!
//! Verification here stops at "a registered node really signed this". Sequence
//! monotonicity, staleness, and cross-node quorum are consumer policy and belong
//! to the client SDK. A signed update is a bearer token that never expires on its
//! own: a relay that withholds new updates and rebroadcasts an old one passes
//! every check in this crate.
//!
//! # Example
//!
//! ```
//! use oracle_types::{FeedId, Flags, PriceUpdate, Venue};
//! use oracle_wire::{Signer, UnverifiedFrame};
//!
//! let signer = Signer::from_secret_bytes([7u8; 32])?;
//! let update = PriceUpdate {
//!     feed_id: FeedId::from_bytes([0x11; 32]),
//!     flags: Flags::NONE,
//!     price: 6_431_250_000_000,
//!     conf: 3_200_000,
//!     expo: -8,
//!     publish_time_ns: 1_754_582_400_000_000_000,
//!     observation_time_ns: 1_754_582_399_998_000_000,
//!     prev_publish_time_ns: 1_754_582_399_000_000_000,
//!     seq: 1,
//!     num_sources: 2,
//!     sources: [Venue::Binance, Venue::Coinbase].into_iter().collect(),
//! };
//!
//! let frame = signer.sign_update(&update).encode_frame();
//! let parsed = UnverifiedFrame::parse(&frame)?;
//!
//! // Authorship, yes. Trust, not yet — that needs a registry.
//! assert_eq!(parsed.recover_signer()?, signer.address());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod address;
mod auth;
mod backend;
mod cert;
mod clients;
mod codec;
pub mod domain;
mod error;
mod frame;
mod keccak;
mod payload;
mod registry;
mod signature;
mod signer;

pub use address::{Address, CompressedPublicKey};
pub use auth::{
    AUTH_PAYLOAD_SIZE, TRANSPORT_PROTOCOL, auth_ok_payload, auth_ok_transcript,
    client_auth_payload, client_auth_transcript,
};
pub use backend::name as backend_name;
pub use cert::{MAX_NODE_ID_LEN, NO_EXPIRY, SigningKeyCert};
pub use clients::{ClientEntry, ClientList, MAX_CLIENT_ID_LEN, MAX_CLIENTS, VerifiedClientList};
pub use error::{VerifyError, WireError};
pub use frame::{
    FRAME_SIZE, FRAME_TYPE_PRICE_UPDATE, SignedUpdate, UnverifiedFrame, VerifiedUpdate,
};
pub use keccak::{keccak256, keccak256_parts};
pub use payload::{
    KIND_CLIENT_AUTH, KIND_CLIENT_LIST, KIND_NODE_AUTH_OK, KIND_PRICE_UPDATE, KIND_REGISTRY,
    KIND_SIGNING_KEY_CERT, PAYLOAD_VERSION, PRICE_UPDATE_SIZE, decode_price_update,
    encode_price_update, feed_id,
};
pub use registry::{
    KeyHistoryEntry, MAX_CERTS_PER_NODE, MAX_ENDPOINT_LEN, MAX_ENDPOINTS, MAX_NODES,
    MAX_OPERATOR_LEN, NodeEntry, Quorum, Registry, VerifiedRegistry,
};
pub use signature::{SIGNATURE_LEN, Signature};
pub use signer::{Signer, recover_address, recover_payload_signer};
