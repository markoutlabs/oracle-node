//! Fake nodes and registries, for testing consumers of this SDK.
//!
//! Deliberately public rather than `#[cfg(test)]`: anyone building on this crate
//! needs a way to exercise their halt and degrade handling without standing up
//! five signing nodes, and a hand-rolled fake will get the frame layout subtly
//! wrong.
//!
//! Every key here is derived from a small integer. **Never use these in
//! production** — the secrets are guessable by construction.

use oracle_types::{
    BookLevel, BookUpdate, FeedId, Flags, FundingBasis, FundingUpdate, MarketKind, NANOS_PER_SEC,
    PriceUpdate, SourceStatus, Venue, VenueEntry, VenueReport, VenueSet,
};
use oracle_wire::{Address, NodeEntry, Quorum, Registry, Signer, VerifiedRegistry};

/// Issue time of test registries, unix seconds. Tests use it as their clock.
pub const REGISTRY_ISSUED_AT: u64 = 1_754_582_400;

/// Seed for the governance key that signs test registries.
const GOVERNANCE_SEED: u8 = 0xC0;

/// Returns the governance key test registries are signed with.
///
/// # Panics
///
/// Cannot panic: the seed is a valid curve scalar.
#[must_use]
pub fn governance() -> Signer {
    Signer::from_secret_bytes([GOVERNANCE_SEED; 32]).expect("valid test key")
}

/// A fake oracle node. Its signing key's address is its id.
pub struct TestNode {
    signing: Signer,
    outgoing: Option<Signer>,
    seed: u8,
}

impl TestNode {
    /// Builds a node from a seed. Distinct seeds give distinct keys.
    ///
    /// # Panics
    ///
    /// Panics if `seed` is zero.
    #[must_use]
    pub fn new(seed: u8) -> Self {
        assert!(seed != 0, "seed 0 is not a valid secret key");
        Self {
            signing: Signer::from_secret_bytes([seed.wrapping_add(0x40).max(1); 32])
                .expect("valid test key"),
            outgoing: None,
            seed,
        }
    }

    /// Returns the address this node's updates recover to.
    #[must_use]
    pub fn signing_address(&self) -> Address {
        self.signing.address()
    }

    /// Rotates to a fresh key, as governance's `replace_node` does. The old
    /// key is kept for [`TestNode::sign_outgoing`]; [`TestNode::entry`] lists
    /// only the new one.
    ///
    /// # Panics
    ///
    /// Panics if called twice on one node, which would need a third key this
    /// helper does not derive.
    pub fn rotate(&mut self) {
        assert!(
            self.outgoing.is_none(),
            "this helper models a single rotation"
        );
        // Derived from the node's own seed, so rotating one node can never
        // collide with another node's key and quietly turn a two-node test into
        // a one-node one.
        let next = Signer::from_secret_bytes([self.seed.wrapping_add(0x80).max(1); 32])
            .expect("valid test key");
        assert_ne!(
            next.address(),
            self.signing.address(),
            "the rotated key must differ from the outgoing one"
        );
        self.outgoing = Some(std::mem::replace(&mut self.signing, next));
    }

    /// Signs an update with the current key and returns the wire frame.
    #[must_use]
    pub fn sign(&self, update: &PriceUpdate) -> Vec<u8> {
        self.signing.sign_update(update).encode_frame().to_vec()
    }

    /// Signs a venue report with the current key and returns the wire frame.
    ///
    /// # Panics
    ///
    /// Panics if the report cannot be encoded.
    #[must_use]
    pub fn sign_venues(&self, report: &VenueReport) -> Vec<u8> {
        self.signing
            .sign_venue_report(report)
            .expect("an encodable report")
            .encode_frame()
    }

    /// Signs a book update with the current key and returns the wire frame.
    ///
    /// # Panics
    ///
    /// Panics if the update cannot be encoded.
    #[must_use]
    pub fn sign_book(&self, update: &BookUpdate) -> Vec<u8> {
        self.signing
            .sign_book_update(update)
            .expect("an encodable update")
            .encode_frame()
    }

    /// Signs a funding update with the current key and returns the wire frame.
    ///
    /// # Panics
    ///
    /// Panics if the update cannot be encoded.
    #[must_use]
    pub fn sign_funding(&self, update: &FundingUpdate) -> Vec<u8> {
        self.signing
            .sign_funding_update(update)
            .expect("an encodable update")
            .encode_frame()
    }

    /// Signs an update with the pre-rotation key.
    ///
    /// # Panics
    ///
    /// Panics if the node has not rotated.
    #[must_use]
    pub fn sign_outgoing(&self, update: &PriceUpdate) -> Vec<u8> {
        self.outgoing
            .as_ref()
            .expect("node has not rotated")
            .sign_update(update)
            .encode_frame()
            .to_vec()
    }

    /// Builds this node's registry entry. The endpoint comes from the seed, so
    /// a rotation keeps it.
    #[must_use]
    pub fn entry(&self) -> NodeEntry {
        NodeEntry {
            address: self.signing.address(),
            endpoints: vec![format!("wss://node-{}.test/v2/ws", self.seed)],
            weight: 1,
        }
    }
}

/// Builds a verified registry containing the given nodes.
///
/// # Panics
///
/// Panics if the nodes cannot form a valid registry, which would be a bug in
/// this module rather than in the caller.
#[must_use]
pub fn registry_with(nodes: &[&TestNode]) -> VerifiedRegistry {
    let entries: Vec<NodeEntry> = nodes.iter().map(|node| node.entry()).collect();
    signed_registry(1, entries)
        .verify(governance().address(), 0)
        .expect("test registry verifies")
}

/// Builds a signed but unverified registry at an explicit version.
///
/// The refresh path takes a [`Registry`] rather than a [`VerifiedRegistry`] —
/// verifying it is the client's job — so exercising that path needs a way to
/// produce one at a chosen version.
///
/// # Panics
///
/// Panics if the entries cannot form a valid registry.
#[must_use]
pub fn signed_registry(version: u64, entries: Vec<NodeEntry>) -> Registry {
    let quorum = Quorum {
        min_nodes: u16::try_from(entries.len()).unwrap_or(u16::MAX),
        recommended: u16::try_from(entries.len()).unwrap_or(u16::MAX),
    };
    Registry::sign(&governance(), version, REGISTRY_ISSUED_AT, entries, quorum)
        .expect("test registry encodes")
}

/// Signs a registry with a key that is not the pinned governance key.
///
/// # Panics
///
/// Panics if the entries cannot form a valid registry.
#[must_use]
pub fn forged_registry(version: u64, entries: Vec<NodeEntry>) -> Registry {
    let impostor = Signer::from_secret_bytes([0xF0; 32]).expect("valid test key");
    let quorum = Quorum {
        min_nodes: u16::try_from(entries.len()).unwrap_or(u16::MAX),
        recommended: u16::try_from(entries.len()).unwrap_or(u16::MAX),
    };
    Registry::sign(&impostor, version, REGISTRY_ISSUED_AT, entries, quorum)
        .expect("test registry encodes")
}

/// Builds a venue report with one used Binance entry.
#[must_use]
pub fn venues_at(publish_time_ns: u64, seq: u64) -> VenueReport {
    VenueReport {
        feed_id: FeedId::from_bytes([7; 32]),
        publish_time_ns,
        seq,
        expo: -8,
        entries: vec![VenueEntry {
            venue: Venue::Binance,
            market: MarketKind::Spot,
            symbol: "BTCUSDT".to_owned(),
            status: SourceStatus::Used,
            weight_bps: 10_000,
            bid: Some(6_399_990_000_000),
            ask: Some(6_400_010_000_000),
            bid_qty: Some(100_000_000),
            ask_qty: Some(100_000_000),
            impact_bid: None,
            impact_ask: None,
            mark: None,
            index: None,
            funding: None,
            exchange_time_ns: None,
            local_recv_ns: publish_time_ns.saturating_sub(1_000_000),
        }],
    }
}

/// A funding update for Bybit's `BTCUSDT` perpetual at `publish_time_ns`.
#[must_use]
pub fn funding_at(publish_time_ns: u64, seq: u64, rate: i64) -> FundingUpdate {
    FundingUpdate {
        venue: Venue::Bybit,
        market: MarketKind::LinearPerp,
        symbol: "BTCUSDT".to_owned(),
        publish_time_ns,
        seq,
        basis: FundingBasis::Interval,
        rate,
        predicted_rate: None,
        interval_ns: Some(8 * 3_600 * NANOS_PER_SEC),
        next_funding_time_ns: None,
        settled: None,
        open_interest: None,
        exchange_time_ns: None,
        local_recv_ns: publish_time_ns.saturating_sub(1_000_000),
    }
}

/// Builds a Binance `BTCUSDT` book frame with one level on each side.
#[must_use]
pub fn book_at(publish_time_ns: u64, seq: u64, snapshot: bool, bid_qty: u64) -> BookUpdate {
    BookUpdate {
        venue: Venue::Binance,
        market: MarketKind::Spot,
        symbol: "BTCUSDT".to_owned(),
        publish_time_ns,
        seq,
        snapshot,
        exchange_time_ns: None,
        local_recv_ns: publish_time_ns.saturating_sub(1_000_000),
        venue_seq: Some(seq),
        bids: vec![BookLevel {
            price: 6_399_990_000_000,
            qty: bid_qty,
        }],
        asks: vec![BookLevel {
            price: 6_400_010_000_000,
            qty: 100_000_000,
        }],
    }
}

/// Builds a plain healthy price update.
#[must_use]
pub fn update_at(publish_time_ns: u64, seq: u64) -> PriceUpdate {
    PriceUpdate {
        feed_id: FeedId::from_bytes([7; 32]),
        flags: Flags::NONE,
        price: 6_400_000_000_000,
        conf: 50_000_000,
        expo: -8,
        publish_time_ns,
        observation_time_ns: publish_time_ns.saturating_sub(1_000_000),
        prev_publish_time_ns: publish_time_ns.saturating_sub(NANOS_PER_SEC),
        seq,
        num_sources: 5,
        sources: Venue::ALL.into_iter().collect::<VenueSet>(),
    }
}
