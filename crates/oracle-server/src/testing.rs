//! Fixtures for exercising a server without a signing node behind it.
//!
//! Public rather than `#[cfg(test)]` so integration tests and downstream
//! consumers can stand up a fake node. **The keys are derived from small
//! integers — never use them in production.**

use oracle_types::{FeedId, Flags, PriceUpdate, Venue, VenueSet};
use oracle_wire::{CompressedPublicKey, NodeEntry, Quorum, Registry, Signer, SigningKeyCert};

/// The node id used by [`test_registry`].
pub const NODE_ID: &str = "oracle-test-1";

/// Returns the fixture node's hot signing key.
///
/// # Panics
///
/// Cannot panic: the seed is a valid curve scalar.
#[must_use]
pub fn signing_key() -> Signer {
    Signer::from_secret_bytes([0x41; 32]).expect("valid test key")
}

/// Returns the fixture node's identity key.
///
/// # Panics
///
/// Cannot panic: the seed is a valid curve scalar.
#[must_use]
pub fn identity_key() -> Signer {
    Signer::from_secret_bytes([0x01; 32]).expect("valid test key")
}

/// Returns the governance key that signs the fixture registry.
///
/// # Panics
///
/// Cannot panic: the seed is a valid curve scalar.
#[must_use]
pub fn governance_key() -> Signer {
    Signer::from_secret_bytes([0xC0; 32]).expect("valid test key")
}

/// Builds a signed single-node registry.
///
/// # Panics
///
/// Panics if the fixture cannot be encoded, which would be a bug here.
#[must_use]
pub fn test_registry() -> Registry {
    let identity = identity_key();
    let cert = SigningKeyCert::issue(
        &identity,
        NODE_ID,
        signing_key().address(),
        0,
        4_102_444_800,
    )
    .expect("fixture node id is short enough");
    let node = NodeEntry {
        node_id: NODE_ID.to_owned(),
        operator: "test".to_owned(),
        identity_pubkey: CompressedPublicKey::from_public_key(&identity.public_key()),
        endpoints: vec!["ws://127.0.0.1:0/v1/ws".to_owned()],
        signing_keys: vec![cert],
        weight: 1,
    };
    Registry::sign(
        &governance_key(),
        1,
        0,
        vec![node],
        Quorum {
            min_nodes: 1,
            recommended: 3,
        },
    )
    .expect("fixture registry encodes")
}

/// Builds a healthy update for a feed.
#[must_use]
pub fn sample_update(feed_id: FeedId) -> PriceUpdate {
    PriceUpdate {
        feed_id,
        flags: Flags::NONE,
        price: 6_400_000_000_000,
        conf: 50_000_000,
        expo: -8,
        publish_time_ns: 1_754_582_400_000_000_000,
        observation_time_ns: 1_754_582_399_999_000_000,
        prev_publish_time_ns: 1_754_582_399_000_000_000,
        seq: 1,
        num_sources: 5,
        sources: Venue::ALL.into_iter().collect::<VenueSet>(),
    }
}
