//! Prices: nodes push signed frames, and each listed feed resolves to the
//! median of the nodes.
//!
//! The checks and the median are the SDK's own code from `oracle-quorum`, so
//! the canister's price for a set of frames is the SDK's price for them. No
//! Internet Computer dependency here: time comes in as an argument.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use candid::CandidType;
use oracle_quorum::{QuorumConfig, RejectReason, Resolved, Status, Verifier, VerifyConfig};
use oracle_types::{FeedId, Symbol};
use oracle_wire::{Address, FRAME_SIZE, UnverifiedFrame, VerifiedRegistry, VerifyError, feed_id};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// The most frames that one push can carry.
pub const MAX_FRAMES_PER_PUSH: usize = 32;

/// How old a pushed frame can be. A node pushes its latest frame, which is
/// at most one node heartbeat old, and ingress takes some seconds.
pub const ACCEPT_MAX_AGE: Duration = Duration::from_secs(30);

/// How far ahead of the canister's clock a frame can be. IC time can lag
/// wall time.
pub const ACCEPT_MAX_SKEW: Duration = Duration::from_secs(10);

/// How long a node's last frame counts toward the quorum: two push
/// heartbeats of 30 s and a margin for ingress.
pub const RESOLVE_MAX_AGE: Duration = Duration::from_secs(75);

/// What `push` did with one frame.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Stored as the node's latest frame for its feed.
    Accepted,
    /// The feed is not on the canister's list.
    UnknownFeed,
    /// No registry is published yet.
    NoRegistry,
    /// Malformed, or a signature that is not valid.
    Invalid,
    /// The signer is not a listed node.
    UnknownSigner,
    /// The signer is a key that the registry retired.
    RetiredKey,
    /// The sequence does not advance: the frame or a newer one is stored.
    Replayed,
    /// Published more than 30 s ago.
    TooOld,
    /// More than 10 s ahead of the canister's clock.
    FromTheFuture,
    /// Observed after it was published.
    Incoherent,
}

impl Verdict {
    fn of(reason: &RejectReason) -> Self {
        match reason {
            RejectReason::Untrusted(VerifyError::UnknownSigner { .. }) => Self::UnknownSigner,
            RejectReason::RetiredKey { .. } => Self::RetiredKey,
            RejectReason::Replayed { .. } => Self::Replayed,
            RejectReason::TooOld { .. } => Self::TooOld,
            RejectReason::FromTheFuture { .. } => Self::FromTheFuture,
            RejectReason::IncoherentTimestamps { .. } => Self::Incoherent,
            _ => Self::Invalid,
        }
    }
}

/// How much to trust a price, in Candid.
#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PriceStatus {
    /// Enough nodes agree.
    Ok,
    /// Usable, but act on `conf`.
    Degraded,
    /// Not usable.
    Halted,
}

/// One feed's price for another canister: integers at the feed's exponent.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PriceRecord {
    /// The 32-byte feed id: keccak256 of the symbol.
    pub feed_id: ByteBuf,
    /// The canonical symbol, such as `CRYPTO.BTC/USD`.
    pub symbol: String,
    /// How much to trust the price.
    pub status: PriceStatus,
    /// The median of the nodes, as a mantissa: price × 10^-expo.
    pub price: Option<i64>,
    /// The confidence half-width, as a mantissa.
    pub conf: Option<u64>,
    /// The decimal exponent of `price` and `conf`.
    pub expo: i32,
    /// The freshest contributing publish time, unix nanoseconds.
    pub publish_time_ns: u64,
    /// Nodes that contributed.
    pub nodes: u32,
    /// Nodes that reported the feed halted.
    pub halted_nodes: u32,
    /// Why the price is not `Ok`, such as `insufficient_nodes`.
    pub concerns: Vec<String>,
    /// The spread between the nodes, in basis points of the price.
    pub spread_bps: Option<String>,
    /// When the canister resolved the price, unix nanoseconds.
    pub resolved_at_ns: u64,
}

impl PriceRecord {
    fn of(symbol: Symbol, resolved: &Resolved, resolved_at_ns: u64) -> Self {
        let expo = symbol.expo();
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        Self {
            feed_id: ByteBuf::from(resolved.feed_id.as_bytes().to_vec()),
            symbol: symbol.to_string(),
            status: match resolved.status {
                Status::Ok => PriceStatus::Ok,
                Status::Degraded => PriceStatus::Degraded,
                Status::Halted => PriceStatus::Halted,
            },
            price: resolved.price.and_then(|price| price.to_scaled(expo).ok()),
            conf: resolved
                .conf
                .and_then(|conf| conf.to_scaled_unsigned(expo).ok()),
            expo,
            publish_time_ns: resolved.publish_time_ns,
            nodes: count(resolved.nodes),
            halted_nodes: count(resolved.halted_nodes),
            concerns: resolved
                .concerns
                .iter()
                .map(|concern| concern.as_str().to_owned())
                .collect(),
            spread_bps: resolved.spread_bps.map(|spread| spread.to_string()),
            resolved_at_ns,
        }
    }
}

/// The prices in stable memory across an upgrade.
#[derive(CandidType, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredPrices {
    /// The listed feeds, as canonical symbols.
    pub feeds: Vec<String>,
    /// Each node's latest accepted frame of each feed.
    pub frames: Vec<ByteBuf>,
}

/// The listed feeds and each node's latest frame of each.
#[derive(Default)]
pub struct Prices {
    verifier: Option<Verifier>,
    quorum: usize,
    feeds: BTreeMap<FeedId, Feed>,
}

struct Feed {
    symbol: Symbol,
    view: oracle_quorum::FeedView,
    frames: BTreeMap<Address, [u8; FRAME_SIZE]>,
}

impl Feed {
    fn new(symbol: Symbol, id: FeedId) -> Self {
        Self {
            symbol,
            view: oracle_quorum::FeedView::with_kind(id, symbol.kind()),
            frames: BTreeMap::new(),
        }
    }

    fn resolve(&self, config: &QuorumConfig, now_ns: u64) -> Resolved {
        let mut resolved = self.view.resolve(config, now_ns);
        resolved.symbol = Some(self.symbol);
        resolved
    }
}

impl Prices {
    /// Sets the listed feeds. A feed that stays keeps its frames.
    pub fn set_feeds(&mut self, symbols: &[Symbol]) {
        let mut feeds = BTreeMap::new();
        for symbol in symbols {
            let id = feed_id(symbol);
            let feed = self
                .feeds
                .remove(&id)
                .unwrap_or_else(|| Feed::new(*symbol, id));
            feeds.insert(id, feed);
        }
        self.feeds = feeds;
        self.mark_slow();
    }

    /// The listed feeds: the id and the symbol of each.
    pub fn feeds(&self) -> impl Iterator<Item = (FeedId, Symbol)> + '_ {
        self.feeds.iter().map(|(id, feed)| (*id, feed.symbol))
    }

    /// Adopts a newly published registry. A de-listed node loses its seat at once.
    pub fn set_registry(&mut self, registry: VerifiedRegistry) {
        self.quorum = usize::from(registry.quorum().recommended);
        let listed: BTreeSet<Address> = registry.nodes().iter().map(|node| node.address).collect();
        for feed in self.feeds.values_mut() {
            feed.view.retain_nodes(&|node| listed.contains(node));
            feed.frames.retain(|node, _| listed.contains(node));
        }
        match &mut self.verifier {
            Some(verifier) => verifier.set_registry(registry),
            None => {
                self.verifier = Some(Verifier::new(
                    registry,
                    VerifyConfig {
                        max_age: ACCEPT_MAX_AGE,
                        slow_max_age: ACCEPT_MAX_AGE,
                        max_skew: ACCEPT_MAX_SKEW,
                    },
                ));
            }
        }
        self.mark_slow();
    }

    fn mark_slow(&mut self) {
        if let Some(verifier) = &mut self.verifier {
            for (id, feed) in &self.feeds {
                if feed.symbol.kind().is_slow() {
                    verifier.mark_slow(*id);
                }
            }
        }
    }

    /// Checks and stores each frame. Returns one verdict for each, in order.
    pub fn push(&mut self, frames: &[impl AsRef<[u8]>], now_ns: u64) -> Vec<Verdict> {
        frames
            .iter()
            .map(|frame| self.apply(frame.as_ref(), now_ns))
            .collect()
    }

    /// Returns `true` at the first frame that `push` accepts, so an honest
    /// push costs one signature recovery. It stores that frame, like `push`.
    pub fn accepts_any(&mut self, frames: &[impl AsRef<[u8]>], now_ns: u64) -> bool {
        frames
            .iter()
            .any(|frame| self.apply(frame.as_ref(), now_ns) == Verdict::Accepted)
    }

    fn apply(&mut self, bytes: &[u8], now_ns: u64) -> Verdict {
        let Ok(parsed) = UnverifiedFrame::parse(bytes) else {
            return Verdict::Invalid;
        };
        let Ok(update) = parsed.decode_unverified() else {
            return Verdict::Invalid;
        };
        let Some(feed) = self.feeds.get_mut(&update.feed_id) else {
            return Verdict::UnknownFeed;
        };
        // The checks without a signature recovery come first, because the
        // recovery costs the most. The verifier repeats them.
        if feed
            .frames
            .values()
            .any(|stored| stored.as_slice() == bytes)
        {
            return Verdict::Replayed;
        }
        if let Some(verdict) = clock(update.publish_time_ns, now_ns) {
            return verdict;
        }
        let Some(verifier) = self.verifier.as_mut() else {
            return Verdict::NoRegistry;
        };
        match verifier.accept(bytes, now_ns) {
            Ok(accepted) => {
                let Ok(frame) = <[u8; FRAME_SIZE]>::try_from(bytes) else {
                    return Verdict::Invalid;
                };
                feed.view.record(accepted.signer, accepted.update);
                feed.frames.insert(accepted.signer, frame);
                Verdict::Accepted
            }
            Err(reason) => Verdict::of(&reason),
        }
    }

    fn quorum_config(&self) -> QuorumConfig {
        QuorumConfig {
            quorum: self.quorum.max(1),
            max_age: RESOLVE_MAX_AGE,
            slow_max_age: RESOLVE_MAX_AGE,
            ..QuorumConfig::default()
        }
    }

    /// Resolves every listed feed at `now_ns`.
    #[must_use]
    pub fn resolve_all(&self, now_ns: u64) -> Vec<Resolved> {
        let config = self.quorum_config();
        self.feeds
            .values()
            .map(|feed| feed.resolve(&config, now_ns))
            .collect()
    }

    /// One feed's price at `now_ns`, or `None` for a feed that is not listed.
    #[must_use]
    pub fn price(&self, id: &FeedId, now_ns: u64) -> Option<PriceRecord> {
        let feed = self.feeds.get(id)?;
        let resolved = feed.resolve(&self.quorum_config(), now_ns);
        Some(PriceRecord::of(feed.symbol, &resolved, now_ns))
    }

    /// Every listed feed's price at `now_ns`.
    #[must_use]
    pub fn prices(&self, now_ns: u64) -> Vec<PriceRecord> {
        let config = self.quorum_config();
        self.feeds
            .values()
            .map(|feed| PriceRecord::of(feed.symbol, &feed.resolve(&config, now_ns), now_ns))
            .collect()
    }

    /// Each node's latest frame of each feed: the symbol, the node and the bytes.
    pub fn frames(&self) -> impl Iterator<Item = (Symbol, Address, &[u8; FRAME_SIZE])> + '_ {
        self.feeds.values().flat_map(|feed| {
            feed.frames
                .iter()
                .map(move |(node, frame)| (feed.symbol, *node, frame))
        })
    }

    /// The feeds and the frames, for stable memory.
    #[must_use]
    pub fn to_stored(&self) -> StoredPrices {
        StoredPrices {
            feeds: self
                .feeds
                .values()
                .map(|feed| feed.symbol.to_string())
                .collect(),
            frames: self
                .frames()
                .map(|(_, _, frame)| ByteBuf::from(frame.to_vec()))
                .collect(),
        }
    }

    /// Rebuilds the prices after an upgrade, with the published registry.
    #[must_use]
    pub fn restore(stored: &StoredPrices, registry: Option<VerifiedRegistry>) -> Self {
        let symbols: Vec<Symbol> = stored
            .feeds
            .iter()
            .filter_map(|symbol| symbol.parse().ok())
            .collect();
        let mut prices = Self::default();
        prices.set_feeds(&symbols);
        if let Some(registry) = registry {
            prices.set_registry(registry);
        }
        for frame in &stored.frames {
            // Each frame passed the clock when it was pushed. At its own publish
            // time it gets its replay mark back, and the quorum's age limit
            // still drops it when it is too old.
            let published = UnverifiedFrame::parse(frame)
                .and_then(|parsed| parsed.decode_unverified())
                .map(|update| update.publish_time_ns);
            if let Ok(published) = published {
                prices.apply(frame, published);
            }
        }
        prices
    }
}

fn clock(publish_time_ns: u64, now_ns: u64) -> Option<Verdict> {
    let nanos = |limit: Duration| u64::try_from(limit.as_nanos()).unwrap_or(u64::MAX);
    if publish_time_ns > now_ns {
        (publish_time_ns - now_ns > nanos(ACCEPT_MAX_SKEW)).then_some(Verdict::FromTheFuture)
    } else {
        (now_ns - publish_time_ns > nanos(ACCEPT_MAX_AGE)).then_some(Verdict::TooOld)
    }
}

#[cfg(test)]
mod tests {
    use oracle_quorum::testing::{REGISTRY_ISSUED_AT, TestNode, registry_with, update_at};
    use oracle_types::{Flags, NANOS_PER_SEC};

    use super::*;

    const NOW: u64 = (REGISTRY_ISSUED_AT + 600) * NANOS_PER_SEC;

    fn nanos(limit: Duration) -> u64 {
        u64::try_from(limit.as_nanos()).expect("fits in u64")
    }

    fn btc() -> Symbol {
        "CRYPTO.BTC/USD".parse().expect("a valid symbol")
    }

    fn frame(node: &TestNode, published: u64, seq: u64, price: i64) -> Vec<u8> {
        let mut update = update_at(published, seq);
        update.feed_id = feed_id(&btc());
        update.price = price;
        node.sign(&update)
    }

    fn listed(nodes: &[&TestNode]) -> Prices {
        let mut prices = Prices::default();
        prices.set_feeds(&[btc()]);
        prices.set_registry(registry_with(nodes));
        prices
    }

    fn btc_price(prices: &Prices, now: u64) -> PriceRecord {
        prices.price(&feed_id(&btc()), now).expect("BTC is listed")
    }

    #[test]
    fn three_nodes_resolve_to_their_median() {
        let nodes = [TestNode::new(1), TestNode::new(2), TestNode::new(3)];
        let mut prices = listed(&[&nodes[0], &nodes[1], &nodes[2]]);
        let frames: Vec<Vec<u8>> = nodes
            .iter()
            .zip([6_400_000_000_000, 6_401_000_000_000, 6_402_000_000_000])
            .map(|(node, price)| frame(node, NOW, 1, price))
            .collect();
        assert_eq!(prices.push(&frames, NOW), [Verdict::Accepted; 3]);
        let record = btc_price(&prices, NOW);
        assert_eq!(record.status, PriceStatus::Ok);
        assert_eq!(record.price, Some(6_401_000_000_000));
        assert_eq!((record.expo, record.nodes), (-8, 3));
        assert_eq!(record.symbol, "CRYPTO.BTC/USD");
        assert_eq!(record.feed_id.as_slice(), feed_id(&btc()).as_bytes());
    }

    #[test]
    fn a_replay_and_an_older_sequence_are_refused() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        let newer = frame(&node, NOW, 2, 1);
        let older = frame(&node, NOW, 1, 1);
        assert_eq!(prices.push(&[&newer], NOW), [Verdict::Accepted]);
        assert_eq!(
            prices.push(&[&newer, &older], NOW),
            [Verdict::Replayed, Verdict::Replayed]
        );
        assert!(!prices.accepts_any(&[&newer, &older], NOW));
    }

    #[test]
    fn the_cheap_checks_come_before_the_signature() {
        let node = TestNode::new(1);
        let stranger = TestNode::new(9);
        let mut prices = listed(&[&node]);
        let mut eth = update_at(NOW, 1);
        eth.feed_id = feed_id(&"CRYPTO.ETH/USD".parse().expect("a valid symbol"));
        let old = NOW - nanos(ACCEPT_MAX_AGE) - 1;
        let ahead = NOW + nanos(ACCEPT_MAX_SKEW) + 1;
        let verdicts = prices.push(
            &[
                node.sign(&eth),
                frame(&node, old, 1, 1),
                frame(&node, ahead, 1, 1),
                frame(&stranger, NOW, 1, 1),
                vec![0; 10],
            ],
            NOW,
        );
        assert_eq!(
            verdicts,
            [
                Verdict::UnknownFeed,
                Verdict::TooOld,
                Verdict::FromTheFuture,
                Verdict::UnknownSigner,
                Verdict::Invalid,
            ]
        );
    }

    #[test]
    fn no_registry_accepts_nothing() {
        let mut prices = Prices::default();
        prices.set_feeds(&[btc()]);
        let frames = [frame(&TestNode::new(1), NOW, 1, 1)];
        assert_eq!(prices.push(&frames, NOW), [Verdict::NoRegistry]);
    }

    #[test]
    fn below_the_quorum_and_after_the_age_limit_the_feed_halts() {
        let nodes = [TestNode::new(1), TestNode::new(2), TestNode::new(3)];
        let mut prices = listed(&[&nodes[0], &nodes[1], &nodes[2]]);
        let frames = [frame(&nodes[0], NOW, 1, 1), frame(&nodes[1], NOW, 1, 1)];
        prices.push(&frames, NOW);
        let record = btc_price(&prices, NOW);
        assert_eq!(record.status, PriceStatus::Halted);
        assert_eq!(record.concerns, ["insufficient_nodes"]);

        prices.push(&[frame(&nodes[2], NOW, 1, 1)], NOW);
        assert_eq!(btc_price(&prices, NOW).status, PriceStatus::Ok);
        let later = NOW + nanos(RESOLVE_MAX_AGE) + 1;
        assert_eq!(btc_price(&prices, later).status, PriceStatus::Halted);
    }

    #[test]
    fn a_halted_node_does_not_count() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        let mut update = update_at(NOW, 1);
        update.feed_id = feed_id(&btc());
        update.flags = Flags::HALTED;
        prices.push(&[node.sign(&update)], NOW);
        let record = btc_price(&prices, NOW);
        assert_eq!(
            (record.status, record.halted_nodes),
            (PriceStatus::Halted, 1)
        );
    }

    #[test]
    fn a_removed_node_loses_its_seat_and_its_key_is_retired() {
        let (kept, removed) = (TestNode::new(1), TestNode::new(2));
        let mut prices = listed(&[&kept, &removed]);
        let frames = [frame(&kept, NOW, 1, 1), frame(&removed, NOW, 1, 1)];
        prices.push(&frames, NOW);
        prices.set_registry(registry_with(&[&kept]));
        assert_eq!(prices.frames().count(), 1);
        assert_eq!(btc_price(&prices, NOW).nodes, 1);
        assert_eq!(
            prices.push(&[frame(&removed, NOW, 2, 1)], NOW),
            [Verdict::RetiredKey]
        );
    }

    #[test]
    fn a_feed_that_stays_listed_keeps_its_frames() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        prices.push(&[frame(&node, NOW, 1, 1)], NOW);
        let eth: Symbol = "CRYPTO.ETH/USD".parse().expect("a valid symbol");
        prices.set_feeds(&[eth, btc()]);
        assert_eq!(prices.frames().count(), 1);
        prices.set_feeds(&[eth]);
        assert_eq!(prices.frames().count(), 0);
        assert!(prices.price(&feed_id(&btc()), NOW).is_none());
    }

    #[test]
    fn a_restore_keeps_the_prices_and_the_replay_marks() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        let stored_frame = frame(&node, NOW, 5, 6_400_000_000_000);
        prices.push(&[&stored_frame], NOW);
        let stored = prices.to_stored();

        let later = NOW + 40 * NANOS_PER_SEC;
        let mut restored = Prices::restore(&stored, Some(registry_with(&[&node])));
        assert_eq!(btc_price(&restored, later).price, Some(6_400_000_000_000));
        assert_eq!(
            restored.push(&[frame(&node, later, 4, 1)], later),
            [Verdict::Replayed]
        );
        assert_eq!(restored.to_stored(), stored);
    }

    /// The current mainnet canister saved one value. The new one reads a
    /// second, optional value, which is `None` in the old blob.
    #[test]
    fn an_old_stable_blob_restores_without_prices() {
        let old = candid::encode_args((b"{}".to_vec(),)).expect("encodes");
        let mut decoder = candid::de::IDLDeserialize::new(&old).expect("decodes");
        let (state, prices): (Vec<u8>, Option<StoredPrices>) =
            candid::utils::ArgumentDecoder::decode(&mut decoder).expect("decodes");
        assert_eq!((state.as_slice(), prices), (b"{}".as_slice(), None));
    }
}
