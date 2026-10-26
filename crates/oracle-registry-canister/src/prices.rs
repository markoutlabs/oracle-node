//! Prices: nodes push signed batches or frames, and each listed feed resolves
//! to the median of the nodes. A batch costs one signature recovery for all
//! its updates.
//!
//! The checks and the median are the SDK's own code from `oracle-quorum`, so
//! the canister's price for a set of frames is the SDK's price for them. No
//! Internet Computer dependency here: time comes in as an argument.

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::Duration;

use candid::CandidType;
use oracle_quorum::{QuorumConfig, RejectReason, Resolved, Status, Verifier, VerifyConfig};
use oracle_types::{FeedId, PriceUpdate, Symbol};
use oracle_wire::{
    Address, FRAME_TYPE_PRICE_BATCH, UnverifiedFrame, UnverifiedPriceBatch, VerifiedRegistry,
    VerifyError, feed_id,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// The most frames or batches that one push can carry.
pub const MAX_FRAMES_PER_PUSH: usize = 32;

/// How old a pushed frame can be. A node pushes its latest frame, which is
/// at most one node heartbeat old, and ingress takes some seconds.
pub const ACCEPT_MAX_AGE: Duration = Duration::from_secs(30);

/// How far ahead of the canister's clock a frame can be. IC time can lag
/// wall time.
pub const ACCEPT_MAX_SKEW: Duration = Duration::from_secs(10);

/// How long a node's latest update counts toward the quorum, until governance
/// sets it: two push heartbeats of 30 s and a margin for ingress.
pub const DEFAULT_PRICE_WINDOW: Duration = Duration::from_secs(75);

/// The shortest price window: ingress alone takes some seconds.
pub const MIN_PRICE_WINDOW: Duration = Duration::from_secs(10);

/// The longest price window.
pub const MAX_PRICE_WINDOW: Duration = Duration::from_secs(600);

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
    /// Each frame or batch that holds a node's latest update of a feed.
    pub frames: Vec<ByteBuf>,
    /// The price window in seconds, when governance set one.
    pub window_secs: Option<u64>,
}

/// A frame or a batch that holds a node's latest update of some feeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source<'a> {
    /// The node that signed it.
    pub node: Address,
    /// The frame or batch, as the node pushed it.
    pub bytes: &'a [u8],
    /// The feeds whose latest update from this node it holds.
    pub symbols: Vec<Symbol>,
}

/// The listed feeds and each node's latest update of each.
#[derive(Default)]
pub struct Prices {
    verifier: Option<Verifier>,
    quorum: usize,
    window: Option<Duration>,
    feeds: BTreeMap<FeedId, Feed>,
}

struct Feed {
    symbol: Symbol,
    view: oracle_quorum::FeedView,
    // A batch is shared by every feed whose latest update it holds.
    sources: BTreeMap<Address, Rc<[u8]>>,
}

impl Feed {
    fn new(symbol: Symbol, id: FeedId) -> Self {
        Self {
            symbol,
            view: oracle_quorum::FeedView::with_kind(id, symbol.kind()),
            sources: BTreeMap::new(),
        }
    }

    fn resolve(&self, config: &QuorumConfig, now_ns: u64) -> Resolved {
        let mut resolved = self.view.resolve(config, now_ns);
        resolved.symbol = Some(self.symbol);
        resolved
    }

    fn holds(&self, bytes: &[u8]) -> bool {
        self.sources.values().any(|stored| **stored == *bytes)
    }
}

impl Prices {
    /// Sets the listed feeds. A feed that stays keeps its updates.
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
            feed.sources.retain(|node, _| listed.contains(node));
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

    /// Checks and stores each frame or batch. Returns one verdict for each
    /// update, in order; a blob that does not parse gets one `Invalid`.
    pub fn push(&mut self, blobs: &[impl AsRef<[u8]>], now_ns: u64) -> Vec<Verdict> {
        blobs
            .iter()
            .flat_map(|blob| self.apply(blob.as_ref(), now_ns))
            .collect()
    }

    /// Returns `true` at the first frame or batch that `push` accepts, so an
    /// honest push costs one signature recovery. It stores what it accepts,
    /// like `push`.
    pub fn accepts_any(&mut self, blobs: &[impl AsRef<[u8]>], now_ns: u64) -> bool {
        blobs.iter().any(|blob| {
            self.apply(blob.as_ref(), now_ns)
                .contains(&Verdict::Accepted)
        })
    }

    fn apply(&mut self, bytes: &[u8], now_ns: u64) -> Vec<Verdict> {
        if bytes.first() == Some(&FRAME_TYPE_PRICE_BATCH) {
            self.apply_batch(bytes, now_ns)
        } else {
            vec![self.apply_frame(bytes, now_ns)]
        }
    }

    /// The checks without a signature recovery, which costs the most. The
    /// verifier repeats them.
    fn precheck(&self, update: &PriceUpdate, now_ns: u64) -> Option<Verdict> {
        if !self.feeds.contains_key(&update.feed_id) {
            return Some(Verdict::UnknownFeed);
        }
        clock(update.publish_time_ns, now_ns)
    }

    fn apply_frame(&mut self, bytes: &[u8], now_ns: u64) -> Verdict {
        let Ok(update) = UnverifiedFrame::parse(bytes).and_then(|frame| frame.decode_unverified())
        else {
            return Verdict::Invalid;
        };
        if let Some(verdict) = self.precheck(&update, now_ns) {
            return verdict;
        }
        if self
            .feeds
            .get(&update.feed_id)
            .is_some_and(|feed| feed.holds(bytes))
        {
            return Verdict::Replayed;
        }
        let Some(verifier) = self.verifier.as_mut() else {
            return Verdict::NoRegistry;
        };
        match verifier.accept(bytes, now_ns) {
            Ok(accepted) => {
                self.record(accepted.signer, accepted.update, &Rc::from(bytes));
                Verdict::Accepted
            }
            Err(reason) => Verdict::of(&reason),
        }
    }

    fn apply_batch(&mut self, bytes: &[u8], now_ns: u64) -> Vec<Verdict> {
        let Ok(updates) =
            UnverifiedPriceBatch::parse(bytes).and_then(|batch| batch.decode_unverified())
        else {
            return vec![Verdict::Invalid];
        };
        if updates.iter().any(|update| {
            self.feeds
                .get(&update.feed_id)
                .is_some_and(|feed| feed.holds(bytes))
        }) {
            return vec![Verdict::Replayed; updates.len()];
        }
        let prechecks: Vec<Option<Verdict>> = updates
            .iter()
            .map(|update| self.precheck(update, now_ns))
            .collect();
        if prechecks.iter().all(Option::is_some) {
            return prechecks.into_iter().flatten().collect();
        }
        let Some(verifier) = self.verifier.as_mut() else {
            return vec![Verdict::NoRegistry; updates.len()];
        };
        let accepted = match verifier.accept_batch(bytes, now_ns) {
            Ok(accepted) => accepted,
            Err(reason) => return vec![Verdict::of(&reason); updates.len()],
        };
        let source: Rc<[u8]> = Rc::from(bytes);
        prechecks
            .into_iter()
            .zip(accepted.updates)
            .map(|(precheck, outcome)| match (precheck, outcome) {
                (Some(verdict), _) => verdict,
                (None, Ok(update)) => {
                    self.record(accepted.signer, update, &source);
                    Verdict::Accepted
                }
                (None, Err(reason)) => Verdict::of(&reason),
            })
            .collect()
    }

    fn record(&mut self, node: Address, update: PriceUpdate, source: &Rc<[u8]>) {
        if let Some(feed) = self.feeds.get_mut(&update.feed_id) {
            feed.view.record(node, update);
            feed.sources.insert(node, Rc::clone(source));
        }
    }

    /// Sets how long a node's latest update counts toward the quorum. About
    /// three push intervals keeps a feed live through one lost push.
    ///
    /// # Errors
    ///
    /// Returns the reason for a window outside [`MIN_PRICE_WINDOW`] to
    /// [`MAX_PRICE_WINDOW`].
    pub fn set_window(&mut self, window: Duration) -> Result<(), String> {
        if !(MIN_PRICE_WINDOW..=MAX_PRICE_WINDOW).contains(&window) {
            return Err(format!(
                "the price window must be {} to {} s",
                MIN_PRICE_WINDOW.as_secs(),
                MAX_PRICE_WINDOW.as_secs()
            ));
        }
        self.window = Some(window);
        Ok(())
    }

    /// How long a node's latest update counts toward the quorum.
    #[must_use]
    pub fn window(&self) -> Duration {
        self.window.unwrap_or(DEFAULT_PRICE_WINDOW)
    }

    fn quorum_config(&self) -> QuorumConfig {
        QuorumConfig {
            quorum: self.quorum.max(1),
            max_age: self.window(),
            slow_max_age: self.window(),
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

    /// Each frame or batch that holds a node's latest update of some feed, once.
    #[must_use]
    pub fn sources(&self) -> Vec<Source<'_>> {
        let mut sources: Vec<(&Rc<[u8]>, Source<'_>)> = Vec::new();
        for feed in self.feeds.values() {
            for (node, bytes) in &feed.sources {
                match sources.iter_mut().find(|(seen, _)| Rc::ptr_eq(seen, bytes)) {
                    Some((_, source)) => source.symbols.push(feed.symbol),
                    None => sources.push((
                        bytes,
                        Source {
                            node: *node,
                            bytes,
                            symbols: vec![feed.symbol],
                        },
                    )),
                }
            }
        }
        sources.into_iter().map(|(_, source)| source).collect()
    }

    /// The feeds and the frames and batches, for stable memory.
    #[must_use]
    pub fn to_stored(&self) -> StoredPrices {
        StoredPrices {
            feeds: self
                .feeds
                .values()
                .map(|feed| feed.symbol.to_string())
                .collect(),
            frames: self
                .sources()
                .into_iter()
                .map(|source| ByteBuf::from(source.bytes.to_vec()))
                .collect(),
            window_secs: self.window.map(|window| window.as_secs()),
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
        if let Some(secs) = stored.window_secs {
            let _ = prices.set_window(Duration::from_secs(secs));
        }
        if let Some(registry) = registry {
            prices.set_registry(registry);
        }
        for blob in &stored.frames {
            // Each update passed the clock when it was pushed. At the newest
            // publish time of its frame or batch it gets its replay mark back,
            // and the quorum's age limit still drops it when it is too old.
            if let Some(published) = newest_publish_time(blob) {
                prices.apply(blob, published);
            }
        }
        prices
    }
}

fn newest_publish_time(bytes: &[u8]) -> Option<u64> {
    let updates = if bytes.first() == Some(&FRAME_TYPE_PRICE_BATCH) {
        UnverifiedPriceBatch::parse(bytes)
            .and_then(|batch| batch.decode_unverified())
            .ok()?
    } else {
        vec![
            UnverifiedFrame::parse(bytes)
                .and_then(|frame| frame.decode_unverified())
                .ok()?,
        ]
    };
    updates.iter().map(|update| update.publish_time_ns).max()
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
        let later = NOW + nanos(DEFAULT_PRICE_WINDOW) + 1;
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
        assert_eq!(prices.sources().len(), 1);
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
        assert_eq!(prices.sources().len(), 1);
        prices.set_feeds(&[eth]);
        assert_eq!(prices.sources().len(), 0);
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

    fn update(symbol: &str, published: u64, seq: u64, price: i64) -> PriceUpdate {
        let mut update = update_at(published, seq);
        update.feed_id = feed_id(&symbol.parse().expect("a valid symbol"));
        update.price = price;
        update
    }

    #[test]
    fn a_batch_gives_a_verdict_for_each_update() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        let eth: Symbol = "CRYPTO.ETH/USD".parse().expect("a valid symbol");
        prices.set_feeds(&[btc(), eth]);
        let old = NOW - nanos(ACCEPT_MAX_AGE) - 1;
        let batch = node.sign_batch(&[
            update("CRYPTO.BTC/USD", NOW, 1, 6_400_000_000_000),
            update("CRYPTO.SOL/USD", NOW, 1, 1),
            update("CRYPTO.ETH/USD", old, 1, 1),
        ]);
        assert_eq!(
            prices.push(&[&batch], NOW),
            [Verdict::Accepted, Verdict::UnknownFeed, Verdict::TooOld]
        );
        assert_eq!(btc_price(&prices, NOW).price, Some(6_400_000_000_000));
        let [source] = prices.sources().try_into().expect("one source");
        assert_eq!(
            (source.node, source.symbols),
            (node.signing_address(), vec![btc()])
        );
        assert_eq!(source.bytes, batch.as_slice());
    }

    #[test]
    fn a_batch_replay_is_refused_without_a_recovery() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        let batch = node.sign_batch(&[update("CRYPTO.BTC/USD", NOW, 2, 1)]);
        assert_eq!(prices.push(&[&batch], NOW), [Verdict::Accepted]);
        assert_eq!(prices.push(&[&batch], NOW), [Verdict::Replayed]);
        assert!(!prices.accepts_any(&[&batch], NOW));
        let single = frame(&node, NOW, 2, 1);
        assert_eq!(
            prices.push(&[&single], NOW),
            [Verdict::Replayed],
            "one sequence for both"
        );
    }

    #[test]
    fn a_batch_from_a_stranger_or_junk_is_refused_whole() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        let stranger = TestNode::new(9).sign_batch(&[update("CRYPTO.BTC/USD", NOW, 1, 1)]);
        assert_eq!(prices.push(&[&stranger], NOW), [Verdict::UnknownSigner]);
        let mut junk = node.sign_batch(&[update("CRYPTO.BTC/USD", NOW, 1, 1)]);
        junk.truncate(100);
        assert_eq!(prices.push(&[&junk], NOW), [Verdict::Invalid]);
    }

    #[test]
    fn a_restore_keeps_the_prices_and_marks_of_a_batch() {
        let nodes = [TestNode::new(1), TestNode::new(2)];
        let mut prices = listed(&[&nodes[0], &nodes[1]]);
        let eth: Symbol = "CRYPTO.ETH/USD".parse().expect("a valid symbol");
        prices.set_feeds(&[btc(), eth]);
        let batch = nodes[0].sign_batch(&[
            update("CRYPTO.BTC/USD", NOW, 5, 6_400_000_000_000),
            update("CRYPTO.ETH/USD", NOW, 5, 2_300_000_000_000),
        ]);
        let single = frame(&nodes[1], NOW, 5, 6_402_000_000_000);
        prices.push(&[&batch, &single], NOW);
        let stored = prices.to_stored();
        assert_eq!(stored.frames.len(), 2, "the batch is stored once");

        let later = NOW + 40 * NANOS_PER_SEC;
        let mut restored = Prices::restore(&stored, Some(registry_with(&[&nodes[0], &nodes[1]])));
        assert_eq!(btc_price(&restored, later).nodes, 2);
        let older = nodes[0].sign_batch(&[update("CRYPTO.ETH/USD", later, 4, 1)]);
        assert_eq!(restored.push(&[&older], later), [Verdict::Replayed]);
        assert_eq!(restored.to_stored(), stored);
    }

    #[test]
    fn governance_sets_the_price_window() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        prices.push(&[frame(&node, NOW, 1, 1)], NOW);
        let at = |secs: u64| NOW + secs * NANOS_PER_SEC;
        assert_eq!(
            btc_price(&prices, at(60)).status,
            PriceStatus::Ok,
            "75 s by default"
        );

        prices
            .set_window(Duration::from_secs(25))
            .expect("in range");
        assert_eq!(btc_price(&prices, at(25)).status, PriceStatus::Ok);
        assert_eq!(btc_price(&prices, at(26)).status, PriceStatus::Halted);
        for out_of_range in [9, 601] {
            assert!(
                prices
                    .set_window(Duration::from_secs(out_of_range))
                    .is_err()
            );
        }
        assert_eq!(prices.window(), Duration::from_secs(25));

        let restored = Prices::restore(&prices.to_stored(), Some(registry_with(&[&node])));
        assert_eq!(
            restored.window(),
            Duration::from_secs(25),
            "an upgrade keeps it"
        );
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
