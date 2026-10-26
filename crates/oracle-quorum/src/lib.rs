//! Verify signed oracle frames and resolve one price from many nodes.
//!
//! [`verify`] checks each frame: the registry, replay, freshness and
//! coherence. [`quorum`] takes the latest accepted frame of each node and
//! resolves one price. Both are pure: time comes in as an argument and there
//! is no I/O, so the SDK and the registry canister run the same code.

pub mod quorum;
pub mod testing;
pub mod verify;

pub use quorum::{Concern, FeedView, NodeFeedState, QuorumConfig, Resolved, Status};
pub use verify::{
    Accepted, AcceptedBatch, AcceptedBook, AcceptedFunding, AcceptedVenues, RejectReason, Verifier,
    VerifyConfig, verify_historical,
};
