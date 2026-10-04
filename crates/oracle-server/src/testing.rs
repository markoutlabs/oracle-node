//! Fixtures for exercising a server without a signing node behind it.
//!
//! Public rather than `#[cfg(test)]` so integration tests and downstream
//! consumers can stand up a fake node. **The keys are derived from small
//! integers — never use them in production.**

use std::sync::Arc;

use oracle_types::{FeedId, Flags, PriceUpdate, Venue, VenueSet};
use oracle_wire::{ClientEntry, ClientList, NodeEntry, Quorum, Registry, Signer, SigningKeyCert};

use crate::transport::{NodeTransport, TransportConfig, unix_now};

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
        identity_pubkey: identity.public_key(),
        endpoints: vec!["ws://127.0.0.1:0/v2/ws".to_owned()],
        signing_keys: vec![cert],
        weight: 1,
    };
    // Issued now, not at the epoch: a client treats a registry older than its
    // `max_registry_age` as stale and degrades every feed.
    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Registry::sign(
        &governance_key(),
        1,
        issued_at,
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

/// The client id of [`client_key`] in [`test_client_list`].
pub const CLIENT_ID: &str = "c-1";

/// The test client's API key.
///
/// # Panics
///
/// Cannot panic: the seed is a valid curve scalar.
#[must_use]
pub fn client_key() -> Signer {
    Signer::from_secret_bytes([0x51; 32]).expect("valid test key")
}

/// A client list naming [`client_key`] for a day, signed by [`governance_key`].
///
/// # Panics
///
/// Cannot panic: the fixture encodes.
#[must_use]
pub fn test_client_list() -> ClientList {
    ClientList::sign(
        &governance_key(),
        1,
        unix_now(),
        60,
        vec![ClientEntry {
            client_id: CLIENT_ID.to_owned(),
            pubkey: client_key().public_key(),
            expires_at: unix_now() + 86_400,
        }],
    )
    .expect("fixture client list encodes")
}

/// A transport that admits [`client_key`] and signs with [`signing_key`].
///
/// # Panics
///
/// Cannot panic: the fixture list is signed by the fixture governance key.
#[must_use]
pub fn test_transport() -> Arc<NodeTransport> {
    let clients = test_client_list()
        .verify(governance_key().address(), 0)
        .expect("fixture client list verifies");
    NodeTransport::new(
        NODE_ID,
        Arc::new(signing_key()),
        clients,
        TransportConfig::default(),
        64,
        unix_now(),
    )
}
