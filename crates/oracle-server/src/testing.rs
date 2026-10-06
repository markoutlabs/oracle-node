//! Fixtures for exercising a server without a signing node behind it.
//!
//! Public rather than `#[cfg(test)]` so integration tests and downstream
//! consumers can stand up a fake node. **The keys are derived from small
//! integers — never use them in production.**

use std::sync::Arc;

use oracle_types::{FeedId, Flags, PriceUpdate, Venue, VenueSet};
use oracle_wire::{ClientEntry, ClientList, NodeEntry, Quorum, Registry, Signer};

use crate::transport::{NodeTransport, TransportConfig, unix_now};

/// Returns the fixture node's key. Its address is the node's id.
///
/// # Panics
///
/// Cannot panic: the seed is a valid curve scalar.
#[must_use]
pub fn signing_key() -> Signer {
    Signer::from_secret_bytes([0x41; 32]).expect("valid test key")
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
    let node = NodeEntry {
        address: signing_key().address(),
        endpoints: vec!["ws://127.0.0.1:0/v2/ws".to_owned()],
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
            address: client_key().address(),
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
        Arc::new(signing_key()),
        clients,
        TransportConfig::default(),
        64,
        unix_now(),
    )
}
