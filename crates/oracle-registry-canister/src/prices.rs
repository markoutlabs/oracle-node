//! Prices: nodes push signed batches, and each listed feed resolves to the
//! median of the nodes. A batch costs one signature recovery for all its
//! updates.
//!
//! The checks and the median are the SDK's own code from `oracle-quorum`, so
//! the canister's price for a set of frames is the SDK's price for them. No
//! Internet Computer dependency here: time comes in as an argument.

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::Duration;

use candid::CandidType;
use oracle_quorum::{
    Concern, QuorumConfig, RejectReason, Resolved, Status, Verifier, VerifyConfig,
};
use oracle_types::{FeedId, Fixed, PriceUpdate, Symbol};
use oracle_wire::{
    Address, PushPolicy, UnverifiedPriceBatch, VerifiedRegistry, VerifyError, feed_id,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

pub use oracle_registry_api::{
    ACCEPT_MAX_AGE, ACCEPT_MAX_SKEW, DEFAULT_PRICE_WINDOW, MAX_FRAMES_PER_PUSH, MAX_PRICE_WINDOW,
    MAX_PUSH_BYTES, MIN_PRICE_WINDOW, PriceRecord, PriceStatus, Verdict,
};

use crate::admission::{Admission, Refusal, SIGNED_START};

fn verdict_of(reason: &RejectReason) -> Verdict {
    match reason {
        RejectReason::Untrusted(VerifyError::UnknownSigner { .. }) => Verdict::UnknownSigner,
        RejectReason::RetiredKey { .. } => Verdict::RetiredKey,
        RejectReason::Replayed { .. } => Verdict::Replayed,
        RejectReason::TooOld { .. } => Verdict::TooOld,
        RejectReason::FromTheFuture { .. } => Verdict::FromTheFuture,
        RejectReason::IncoherentTimestamps { .. } => Verdict::Incoherent,
        _ => Verdict::Invalid,
    }
}

/// One feed resolved at one time. `get_price` and `/prices.json` both come
/// from it, so the two public shapes of a price cannot drift apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedPrice {
    /// The feed's canonical symbol.
    pub symbol: Symbol,
    /// The SDK's resolution of the nodes' latest updates.
    pub resolved: Resolved,
    /// When the canister resolved it, unix nanoseconds.
    pub resolved_at_ns: u64,
}

/// One entry of `/prices.json`. A golden test freezes this shape: proxies and
/// the JS SDK read it, so a field change is a breaking change.
#[derive(Serialize, Debug)]
pub struct PriceEntry<'a> {
    /// The 32-byte feed id, as `0x` hex.
    pub feed_id: FeedId,
    /// The canonical symbol.
    pub symbol: Symbol,
    /// `ok`, `degraded` or `halted`.
    pub status: Status,
    /// The median of the nodes, as a decimal string.
    pub price: Option<Fixed>,
    /// The confidence half-width, as a decimal string.
    pub conf: Option<Fixed>,
    /// Nodes that contributed.
    pub nodes: usize,
    /// Nodes that reported the feed halted.
    pub halted_nodes: usize,
    /// Why the price is not `ok`.
    pub concerns: &'a [Concern],
    /// The freshest contributing publish time, unix nanoseconds, as a string.
    #[serde(with = "oracle_types::num_str")]
    pub publish_time_ns: u64,
    /// The spread between the nodes, in basis points of the price.
    pub spread_bps: Option<Fixed>,
}

impl FeedPrice {
    /// The Candid record of `get_price`: integers at the feed's exponent.
    #[must_use]
    pub fn record(&self) -> PriceRecord {
        let resolved = &self.resolved;
        let expo = self.symbol.expo();
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        PriceRecord {
            feed_id: ByteBuf::from(resolved.feed_id.as_bytes().to_vec()),
            symbol: self.symbol.to_string(),
            status: match resolved.status {
                Status::Ok => PriceStatus::Ok,
                Status::Degraded => PriceStatus::Degraded,
                Status::Halted => PriceStatus::Halted,
            },
            price: resolved.price.and_then(|price| price.to_scaled(expo).ok()),
            conf: resolved
                .conf
                // Rounded up: a band rounded down claims more precision than the nodes have.
                .and_then(|conf| conf.to_scaled_unsigned_up(expo).ok()),
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
            resolved_at_ns: self.resolved_at_ns,
        }
    }

    /// The entry of `/prices.json`: decimal strings at full precision.
    #[must_use]
    pub fn entry(&self) -> PriceEntry<'_> {
        let resolved = &self.resolved;
        PriceEntry {
            feed_id: resolved.feed_id,
            symbol: self.symbol,
            status: resolved.status,
            price: resolved.price,
            conf: resolved.conf,
            nodes: resolved.nodes,
            halted_nodes: resolved.halted_nodes,
            concerns: &resolved.concerns,
            publish_time_ns: resolved.publish_time_ns,
            spread_bps: resolved.spread_bps,
        }
    }
}

/// The prices in stable memory across an upgrade.
#[derive(CandidType, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredPrices {
    /// The listed feeds, as canonical symbols.
    pub feeds: Vec<String>,
    /// Each batch that holds a node's latest update of a feed.
    pub frames: Vec<ByteBuf>,
    /// The price window in seconds, when governance set one.
    pub window_secs: Option<u64>,
}

/// A batch that holds a node's latest update of some feeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source<'a> {
    /// The node that signed it.
    pub node: Address,
    /// The batch, as the node pushed it.
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
    admission: Admission,
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

    fn resolve(&self, config: &QuorumConfig, now_ns: u64) -> FeedPrice {
        let mut resolved = self.view.resolve(config, now_ns);
        resolved.symbol = Some(self.symbol);
        FeedPrice {
            symbol: self.symbol,
            resolved,
            resolved_at_ns: now_ns,
        }
    }

    /// SPEC §3.7 P6: the signer hint is not signed, so a copy with another
    /// hint is the same batch.
    fn holds(&self, bytes: &[u8]) -> bool {
        let signed = bytes.get(SIGNED_START..);
        self.sources
            .values()
            .any(|stored| stored.get(SIGNED_START..) == signed)
    }
}

impl Prices {
    /// Sets the listed feeds. A feed that stays keeps its updates.
    pub fn set_feeds(&mut self, symbols: &[Symbol]) {
        let mut feeds = BTreeMap::new();
        for symbol in symbols {
            let id = feed_id(symbol);
            // A symbol given twice would replace the feed it kept with an empty one.
            if feeds.contains_key(&id) {
                continue;
            }
            let feed = self
                .feeds
                .remove(&id)
                .unwrap_or_else(|| Feed::new(*symbol, id));
            feeds.insert(id, feed);
        }
        self.feeds = feeds;
        self.set_feed_kinds();
    }

    /// The listed feeds: the id and the symbol of each.
    pub fn feeds(&self) -> impl Iterator<Item = (FeedId, Symbol)> + '_ {
        self.feeds.iter().map(|(id, feed)| (*id, feed.symbol))
    }

    /// The number of listed feeds.
    #[must_use]
    pub fn feed_count(&self) -> usize {
        self.feeds.len()
    }

    /// Adopts a newly published registry. A de-listed node loses its seat at once.
    pub fn set_registry(&mut self, registry: VerifiedRegistry) {
        self.quorum = usize::from(registry.quorum().recommended);
        let listed: BTreeSet<Address> = registry.nodes().iter().map(|node| node.address).collect();
        for feed in self.feeds.values_mut() {
            feed.view.retain_nodes(&|node| listed.contains(node));
            feed.sources.retain(|node, _| listed.contains(node));
        }
        self.admission.retain_nodes(|node| listed.contains(node));
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
        self.set_feed_kinds();
    }

    /// Adopts the push pace of a newly published feed set (SPEC §3.7 P5).
    pub fn set_pace(&mut self, pace: Option<PushPolicy>) {
        self.admission.set_pace(pace);
    }

    /// The shortest time between two batches of one node.
    #[must_use]
    pub fn min_push_interval(&self) -> Duration {
        self.admission.min_interval()
    }

    /// The kind sets each feed's age limit in the verifier.
    fn set_feed_kinds(&mut self) {
        if let Some(verifier) = &mut self.verifier {
            for (id, feed) in &self.feeds {
                verifier.set_feed_kind(*id, feed.symbol.kind());
            }
        }
    }

    /// Checks and stores each batch. Returns one verdict for each update, in
    /// order; a batch that does not parse gets one `Invalid`.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] of a push that breaks a rule for the whole push,
    /// before any batch changes the state.
    pub fn push(
        &mut self,
        blobs: &[impl AsRef<[u8]>],
        now_ns: u64,
    ) -> Result<Vec<Verdict>, Refusal> {
        self.admission.check_frames(blobs, now_ns)?;
        Ok(blobs
            .iter()
            .flat_map(|blob| self.apply_batch(blob.as_ref(), now_ns))
            .collect())
    }

    /// `inspect_message`'s check: every batch must hold an update that `push`
    /// accepts. It stores them, like `push`; the IC drops what it stores.
    ///
    /// # Errors
    ///
    /// Returns why the push must not reach the canister.
    pub fn inspect(&mut self, blobs: &[impl AsRef<[u8]>], now_ns: u64) -> Result<(), Refusal> {
        self.admission.check_frames(blobs, now_ns)?;
        // SPEC §3.7 P10: one fresh batch must not carry replays or junk in with
        // it, because each of those costs a signature recovery under consensus.
        for blob in blobs {
            if !self
                .apply_batch(blob.as_ref(), now_ns)
                .contains(&Verdict::Accepted)
            {
                return Err(Refusal::NothingNew);
            }
        }
        Ok(())
    }

    /// SPEC §3.7 P7: the checks without a signature recovery, which costs the
    /// most. The verifier repeats them.
    fn precheck(&self, update: &PriceUpdate, now_ns: u64) -> Option<Verdict> {
        if !self.feeds.contains_key(&update.feed_id) {
            return Some(Verdict::UnknownFeed);
        }
        Admission::clock(update.publish_time_ns, now_ns)
    }

    fn apply_batch(&mut self, bytes: &[u8], now_ns: u64) -> Vec<Verdict> {
        let Ok(batch) = UnverifiedPriceBatch::parse(bytes) else {
            return vec![Verdict::Invalid];
        };
        let Ok(updates) = batch.decode_unverified() else {
            return vec![Verdict::Invalid];
        };
        let count = updates.len();
        let all = |verdict: Verdict| vec![verdict; count];
        if updates.iter().any(|update| {
            self.feeds
                .get(&update.feed_id)
                .is_some_and(|feed| feed.holds(bytes))
        }) {
            return all(Verdict::Replayed);
        }
        let prechecks: Vec<Option<Verdict>> = updates
            .iter()
            .map(|update| self.precheck(update, now_ns))
            .collect();
        if prechecks.iter().all(Option::is_some) {
            return prechecks.into_iter().flatten().collect();
        }
        let Some(verifier) = self.verifier.as_mut() else {
            return all(Verdict::NoRegistry);
        };
        // SPEC §3.7 P8: a batch from a node signs with that node's address as
        // its hint, so another hint needs no recovery to refuse.
        let hint = batch.signer_hint();
        if verifier.registry().authorize(hint).is_err() {
            return all(if verifier.is_retired(hint) {
                Verdict::RetiredKey
            } else {
                Verdict::UnknownSigner
            });
        }
        // One parse and one decode serve the cheap checks and the recovery.
        let recovered = match batch.recover_decoded(updates) {
            Ok(recovered) => recovered,
            Err(error) => return all(verdict_of(&RejectReason::from(error))),
        };
        // SPEC §3.7 P9: the hint check comes before the verifier moves the
        // sequence, so a relabeled copy cannot spend the node's genuine batch.
        if recovered.signer() != hint {
            return all(Verdict::Invalid);
        }
        let accepted = match verifier.accept_recovered_batch(recovered, now_ns) {
            Ok(accepted) => accepted,
            Err(reason) => return all(verdict_of(&reason)),
        };
        self.admission.record_push(accepted.signer, now_ns);
        if prechecks.contains(&Some(Verdict::UnknownFeed)) {
            // The verifier marks every update of a batch, and a node must not
            // fill the heap with marks of feeds that the canister does not price.
            let feeds = &self.feeds;
            verifier.retain_feeds(|feed| feeds.contains_key(feed));
        }
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
                (None, Err(reason)) => verdict_of(&reason),
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
    pub fn resolve_all(&self, now_ns: u64) -> Vec<FeedPrice> {
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
        Some(feed.resolve(&self.quorum_config(), now_ns).record())
    }

    /// Every listed feed's price at `now_ns`.
    #[must_use]
    pub fn prices(&self, now_ns: u64) -> Vec<PriceRecord> {
        self.resolve_all(now_ns)
            .iter()
            .map(FeedPrice::record)
            .collect()
    }

    /// Each batch that holds a node's latest update of some feed, once, in
    /// the order of the feeds that first hold it.
    #[must_use]
    pub fn sources(&self) -> Vec<Source<'_>> {
        let mut sources: Vec<Source<'_>> = Vec::new();
        // Keyed by the shared allocation: one batch is one `Rc` for all its feeds.
        let mut seen: BTreeMap<*const u8, usize> = BTreeMap::new();
        for feed in self.feeds.values() {
            for (node, bytes) in &feed.sources {
                let key = Rc::as_ptr(bytes).cast::<u8>();
                match seen.get(&key).and_then(|&at| sources.get_mut(at)) {
                    Some(source) => source.symbols.push(feed.symbol),
                    None => {
                        seen.insert(key, sources.len());
                        sources.push(Source {
                            node: *node,
                            bytes,
                            symbols: vec![feed.symbol],
                        });
                    }
                }
            }
        }
        sources
    }

    /// The feeds and the batches, for stable memory.
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

    /// Rebuilds the prices after an upgrade, with the published registry and
    /// the feed set's pace. A single frame that an older canister stored is dropped.
    #[must_use]
    pub fn restore(
        stored: &StoredPrices,
        registry: Option<VerifiedRegistry>,
        pace: Option<PushPolicy>,
    ) -> Self {
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
        prices.set_pace(pace);
        for blob in &stored.frames {
            // Each update passed the clock when it was pushed. At the newest
            // publish time of its batch it gets its replay mark back, and the
            // quorum's age limit still drops it when it is too old.
            if let Some(published) = newest_publish_time(blob) {
                prices.apply_batch(blob, published);
            }
        }
        // The restore times are not push times, so no node waits for them.
        prices.admission.forget_pushes();
        prices
    }
}

fn newest_publish_time(bytes: &[u8]) -> Option<u64> {
    UnverifiedPriceBatch::parse(bytes)
        .and_then(|batch| batch.decode_unverified())
        .ok()?
        .iter()
        .map(|update| update.publish_time_ns)
        .max()
}

#[cfg(test)]
mod tests {
    use oracle_quorum::testing::{NEXT_EPOCH_NS, TestNode, registry_with};
    use oracle_types::{Flags, NANOS_PER_SEC};

    use super::*;
    use crate::admission::nanos;
    use crate::testing::usd;

    /// Ten steps of [`TestNode::next`] after its first publish time: its first
    /// updates are a few seconds old, inside the clock windows.
    const NOW: u64 = NEXT_EPOCH_NS + 10 * NANOS_PER_SEC;
    const BTC: &str = "CRYPTO.BTC/USD";
    const ETH: &str = "CRYPTO.ETH/USD";
    const SOL: &str = "CRYPTO.SOL/USD";
    /// Past the shortest interval between two batches of one node, with no feed set pace.
    const NEXT_PUSH: u64 = 2 * NANOS_PER_SEC;

    fn symbol(text: &str) -> Symbol {
        text.parse().expect("a valid symbol")
    }

    fn id(feed: &str) -> FeedId {
        feed_id(&symbol(feed))
    }

    /// The node's next batch: one next update of each feed, all at `price`.
    fn batch(node: &TestNode, feeds: &[&str], price: i64) -> Vec<u8> {
        let updates: Vec<PriceUpdate> = feeds
            .iter()
            .map(|feed| node.next(id(feed), price))
            .collect();
        node.sign_batch(&updates)
    }

    fn btc_batch(node: &TestNode, price: i64) -> Vec<u8> {
        batch(node, &[BTC], price)
    }

    fn listed(nodes: &[&TestNode]) -> Prices {
        let mut prices = Prices::default();
        prices.set_feeds(&[symbol(BTC)]);
        prices.set_registry(registry_with(nodes));
        prices
    }

    fn btc_price(prices: &Prices, now: u64) -> PriceRecord {
        prices.price(&id(BTC), now).expect("BTC is listed")
    }

    fn push(prices: &mut Prices, blobs: &[&Vec<u8>], now: u64) -> Vec<Verdict> {
        prices
            .push(blobs, now)
            .expect("the push passes the push rules")
    }

    /// The push time of the `step`-th push of one node in a test.
    fn later(step: u64) -> u64 {
        NOW + step * NEXT_PUSH
    }

    #[test]
    fn three_nodes_resolve_to_their_median() {
        let nodes = [TestNode::new(1), TestNode::new(2), TestNode::new(3)];
        let mut prices = listed(&[&nodes[0], &nodes[1], &nodes[2]]);
        let batches: Vec<Vec<u8>> = nodes
            .iter()
            .zip([usd(64_000), usd(64_010), usd(64_020)])
            .map(|(node, price)| btc_batch(node, price))
            .collect();
        assert_eq!(prices.push(&batches, NOW), Ok(vec![Verdict::Accepted; 3]));
        let record = btc_price(&prices, NOW);
        assert_eq!(record.status, PriceStatus::Ok);
        assert_eq!(record.price, Some(usd(64_010)));
        assert_eq!((record.expo, record.nodes), (-8, 3));
        assert_eq!(record.symbol, BTC);
        assert_eq!(record.feed_id.as_slice(), id(BTC).as_bytes());
    }

    #[test]
    fn a_replay_and_an_older_sequence_are_refused() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        let older = btc_batch(&node, 1);
        let newer = btc_batch(&node, 1);
        assert_eq!(push(&mut prices, &[&newer], NOW), [Verdict::Accepted]);
        assert_eq!(push(&mut prices, &[&newer], later(1)), [Verdict::Replayed]);
        assert_eq!(push(&mut prices, &[&older], later(2)), [Verdict::Replayed]);
        assert_eq!(
            prices.inspect(&[&older], later(3)),
            Err(Refusal::NothingNew)
        );
    }

    /// SPEC §3.7 P6: the hint is outside the signature, so a copy with another
    /// hint is a replay, found without a recovery.
    #[test]
    fn a_copy_with_another_hint_is_a_replay() {
        let (node, other) = (TestNode::new(1), TestNode::new(2));
        let mut prices = listed(&[&node, &other]);
        let first = btc_batch(&node, 1);
        assert_eq!(push(&mut prices, &[&first], NOW), [Verdict::Accepted]);
        let mut copy = first.clone();
        copy.splice(
            1..SIGNED_START,
            other.signing_address().as_bytes().iter().copied(),
        );
        assert_eq!(push(&mut prices, &[&copy], later(1)), [Verdict::Replayed]);
    }

    /// SPEC §3.7 P8, P9: the hint names the node, so another hint is refused,
    /// before the recovery when it names no listed node.
    #[test]
    fn a_batch_whose_hint_is_not_its_signer_is_invalid() {
        let (node, other, stranger) = (TestNode::new(1), TestNode::new(2), TestNode::new(9));
        let mut prices = listed(&[&node, &other]);
        let relabel = |hint: Address| {
            let mut relabeled = btc_batch(&node, 1);
            relabeled.splice(1..SIGNED_START, hint.as_bytes().iter().copied());
            relabeled
        };
        assert_eq!(
            push(&mut prices, &[&relabel(other.signing_address())], NOW),
            [Verdict::Invalid]
        );
        assert_eq!(
            push(&mut prices, &[&relabel(stranger.signing_address())], NOW),
            [Verdict::UnknownSigner]
        );
        assert!(prices.sources().is_empty(), "no false hint is stored");
    }

    /// SPEC §3.7 P9: the hint check comes before the sequence moves, so a
    /// relabeled copy cannot spend the node's genuine batch.
    #[test]
    fn a_relabeled_copy_leaves_the_genuine_batch_accepted() {
        let (node, other) = (TestNode::new(1), TestNode::new(2));
        let mut prices = listed(&[&node, &other]);
        let genuine = btc_batch(&node, 1);
        let mut copy = genuine.clone();
        copy.splice(
            1..SIGNED_START,
            other.signing_address().as_bytes().iter().copied(),
        );
        assert_eq!(push(&mut prices, &[&copy], NOW), [Verdict::Invalid]);
        assert_eq!(push(&mut prices, &[&genuine], NOW), [Verdict::Accepted]);
    }

    #[test]
    fn a_fresh_batch_cannot_carry_junk_or_a_replay_past_inspection() {
        let (node, other) = (TestNode::new(1), TestNode::new(2));
        let mut prices = listed(&[&node, &other]);
        let first = btc_batch(&other, 1);
        assert_eq!(push(&mut prices, &[&first], NOW), [Verdict::Accepted]);
        let mut forged = btc_batch(&other, 1);
        // A flipped bit in the signature's `r` recovers another key, or none.
        let at = forged.len().saturating_sub(oracle_wire::SIGNATURE_LEN) + 5;
        if let Some(byte) = forged.get_mut(at) {
            *byte ^= 1;
        }
        // The IC drops what an inspection stores; here it stays, so each check comes later.
        assert_eq!(
            prices.inspect(&[btc_batch(&node, 1), forged], later(1)),
            Err(Refusal::NothingNew),
            "junk after a fresh batch"
        );
        assert_eq!(
            prices.inspect(&[btc_batch(&node, 1), first], later(2)),
            Err(Refusal::NothingNew),
            "a replay after a fresh batch"
        );
        assert_eq!(prices.inspect(&[btc_batch(&node, 1)], later(3)), Ok(()));
        assert_eq!(
            prices.inspect(&Vec::<Vec<u8>>::new(), later(4)),
            Err(Refusal::FrameCount { count: 0 }),
            "an empty push"
        );
    }

    #[test]
    fn a_batch_leaves_no_marks_for_feeds_the_canister_does_not_price() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        // Taken first, so its `seq` is below that of the SOL update in the batch.
        let earlier = node.next(id(SOL), 1);
        let both = batch(&node, &[BTC, SOL], 1);
        assert_eq!(
            push(&mut prices, &[&both], NOW),
            [Verdict::Accepted, Verdict::UnknownFeed]
        );
        prices.set_feeds(&[symbol(BTC), symbol(SOL)]);
        assert_eq!(
            push(&mut prices, &[&node.sign_batch(&[earlier])], later(1)),
            [Verdict::Accepted],
            "the canister kept no SOL mark"
        );
    }

    #[test]
    fn a_symbol_given_twice_keeps_its_feed() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        assert_eq!(
            push(&mut prices, &[&btc_batch(&node, 7)], NOW),
            [Verdict::Accepted]
        );
        prices.set_feeds(&[symbol(BTC), symbol(BTC)]);
        assert_eq!(btc_price(&prices, NOW).nodes, 1);
    }

    #[test]
    fn the_cheap_checks_come_before_the_signature() {
        let node = TestNode::new(1);
        let stranger = TestNode::new(9);
        let mut prices = listed(&[&node]);
        let at = |publish_time_ns: u64| {
            node.sign_batch(&[PriceUpdate {
                publish_time_ns,
                ..node.next(id(BTC), 1)
            }])
        };
        let mut junk = btc_batch(&node, 1);
        junk.truncate(100);
        for (label, batch, verdict) in [
            (
                "an unlisted feed",
                batch(&node, &[ETH], 1),
                Verdict::UnknownFeed,
            ),
            (
                "too old",
                at(NOW - nanos(ACCEPT_MAX_AGE) - 1),
                Verdict::TooOld,
            ),
            (
                "ahead of the clock",
                at(NOW + nanos(ACCEPT_MAX_SKEW) + 1),
                Verdict::FromTheFuture,
            ),
            (
                "a stranger",
                btc_batch(&stranger, 1),
                Verdict::UnknownSigner,
            ),
            ("junk", junk, Verdict::Invalid),
        ] {
            assert_eq!(push(&mut prices, &[&batch], NOW), [verdict], "{label}");
        }
    }

    /// SPEC §3.7 P3: a node streams single frames to its clients and never a
    /// batch, so a client can relay only single frames.
    #[test]
    fn a_single_price_frame_is_refused_whole() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        let single = node.sign(&node.next(id(BTC), 1));
        assert_eq!(prices.push(&[&single], NOW), Err(Refusal::NotABatch));
        assert_eq!(prices.inspect(&[&single], NOW), Err(Refusal::NotABatch));
        assert!(prices.sources().is_empty());
    }

    #[test]
    fn no_registry_accepts_nothing() {
        let mut prices = Prices::default();
        prices.set_feeds(&[symbol(BTC)]);
        let node = TestNode::new(1);
        assert_eq!(
            push(&mut prices, &[&btc_batch(&node, 1)], NOW),
            [Verdict::NoRegistry]
        );
    }

    #[test]
    fn below_the_quorum_and_after_the_age_limit_the_feed_halts() {
        let nodes = [TestNode::new(1), TestNode::new(2), TestNode::new(3)];
        let mut prices = listed(&[&nodes[0], &nodes[1], &nodes[2]]);
        let two = [btc_batch(&nodes[0], 1), btc_batch(&nodes[1], 1)];
        prices.push(&two, NOW).expect("passes the push rules");
        let record = btc_price(&prices, NOW);
        assert_eq!(record.status, PriceStatus::Halted);
        assert_eq!(record.concerns, ["insufficient_nodes"]);

        let third = btc_batch(&nodes[2], 1);
        push(&mut prices, &[&third], NOW);
        assert_eq!(btc_price(&prices, NOW).status, PriceStatus::Ok);
        // Every update is at most the first step old, so the window runs from there.
        let stale = NEXT_EPOCH_NS + NANOS_PER_SEC + nanos(DEFAULT_PRICE_WINDOW) + 1;
        assert_eq!(btc_price(&prices, stale).status, PriceStatus::Halted);
    }

    #[test]
    fn a_halted_node_does_not_count() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        let halted = PriceUpdate {
            flags: Flags::HALTED,
            ..node.next(id(BTC), 1)
        };
        push(&mut prices, &[&node.sign_batch(&[halted])], NOW);
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
        let batches = [btc_batch(&kept, 1), btc_batch(&removed, 1)];
        prices.push(&batches, NOW).expect("passes the push rules");
        prices.set_registry(registry_with(&[&kept]));
        assert_eq!(prices.sources().len(), 1);
        assert_eq!(btc_price(&prices, NOW).nodes, 1);
        assert_eq!(
            push(&mut prices, &[&btc_batch(&removed, 1)], NOW),
            [Verdict::RetiredKey]
        );
    }

    #[test]
    fn a_feed_that_stays_listed_keeps_its_frames() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        push(&mut prices, &[&btc_batch(&node, 1)], NOW);
        prices.set_feeds(&[symbol(ETH), symbol(BTC)]);
        assert_eq!(prices.sources().len(), 1);
        prices.set_feeds(&[symbol(ETH)]);
        assert_eq!(prices.sources().len(), 0);
        assert!(prices.price(&id(BTC), NOW).is_none());
    }

    #[test]
    fn a_batch_gives_a_verdict_for_each_update() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        prices.set_feeds(&[symbol(BTC), symbol(ETH)]);
        let old = PriceUpdate {
            publish_time_ns: NOW - nanos(ACCEPT_MAX_AGE) - 1,
            ..node.next(id(ETH), 1)
        };
        let mixed = node.sign_batch(&[node.next(id(BTC), usd(64_000)), node.next(id(SOL), 1), old]);
        assert_eq!(
            push(&mut prices, &[&mixed], NOW),
            [Verdict::Accepted, Verdict::UnknownFeed, Verdict::TooOld]
        );
        assert_eq!(btc_price(&prices, NOW).price, Some(usd(64_000)));
        let [source] = prices.sources().try_into().expect("one source");
        assert_eq!(
            (source.node, source.symbols),
            (node.signing_address(), vec![symbol(BTC)])
        );
        assert_eq!(source.bytes, mixed.as_slice());
    }

    #[test]
    fn a_batch_replay_is_refused_without_a_recovery() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        let once = btc_batch(&node, 1);
        assert_eq!(push(&mut prices, &[&once], NOW), [Verdict::Accepted]);
        assert_eq!(push(&mut prices, &[&once], later(1)), [Verdict::Replayed]);
        assert_eq!(prices.inspect(&[&once], later(2)), Err(Refusal::NothingNew));
    }

    #[test]
    fn a_batch_from_a_stranger_or_junk_is_refused_whole() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        let stranger = btc_batch(&TestNode::new(9), 1);
        assert_eq!(
            push(&mut prices, &[&stranger], NOW),
            [Verdict::UnknownSigner]
        );
        let mut junk = btc_batch(&node, 1);
        junk.truncate(100);
        assert_eq!(push(&mut prices, &[&junk], NOW), [Verdict::Invalid]);
    }

    #[test]
    fn a_restore_keeps_the_prices_and_marks_of_a_batch() {
        let nodes = [TestNode::new(1), TestNode::new(2)];
        let mut prices = listed(&[&nodes[0], &nodes[1]]);
        prices.set_feeds(&[symbol(BTC), symbol(ETH)]);
        // Taken first, so its `seq` is below that of the ETH update in the batch.
        let older = nodes[0].next(id(ETH), 1);
        let both = nodes[0].sign_batch(&[
            nodes[0].next(id(BTC), usd(64_000)),
            nodes[0].next(id(ETH), usd(23_000)),
        ]);
        let other = btc_batch(&nodes[1], usd(64_020));
        prices
            .push(&[&both, &other], NOW)
            .expect("passes the push rules");
        let stored = prices.to_stored();
        assert_eq!(stored.frames.len(), 2, "the batch is stored once");

        let restore_at = NOW + 20 * NANOS_PER_SEC;
        let registry = registry_with(&[&nodes[0], &nodes[1]]);
        let mut restored = Prices::restore(&stored, Some(registry), None);
        assert_eq!(btc_price(&restored, restore_at).nodes, 2);
        assert_eq!(btc_price(&restored, restore_at).price, Some(usd(64_010)));
        assert_eq!(
            push(&mut restored, &[&nodes[0].sign_batch(&[older])], restore_at),
            [Verdict::Replayed]
        );
        assert_eq!(restored.to_stored(), stored);
    }

    #[test]
    fn governance_sets_the_price_window() {
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        let update = node.next(id(BTC), 1);
        let published = update.publish_time_ns;
        push(&mut prices, &[&node.sign_batch(&[update])], NOW);
        let at = |secs: u64| published + secs * NANOS_PER_SEC;
        let default = DEFAULT_PRICE_WINDOW.as_secs();
        assert_eq!(btc_price(&prices, at(default)).status, PriceStatus::Ok);
        assert_eq!(
            btc_price(&prices, at(default + 1)).status,
            PriceStatus::Halted
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

        let restored = Prices::restore(&prices.to_stored(), Some(registry_with(&[&node])), None);
        assert_eq!(
            restored.window(),
            Duration::from_secs(25),
            "an upgrade keeps it"
        );
    }

    /// A band rounded down to zero would claim an exact price.
    #[test]
    fn a_confidence_band_below_one_unit_publishes_as_one() {
        /// Two digits finer than the feed's exponent, so one unit of the update is 0.01 of the feed's.
        const FINER_EXPO: i32 = -10;
        let node = TestNode::new(1);
        let mut prices = listed(&[&node]);
        let tight = PriceUpdate {
            expo: FINER_EXPO,
            conf: 1,
            ..node.next(id(BTC), usd(64_000) * 100)
        };
        prices
            .push(&[node.sign_batch(&[tight])], NOW)
            .expect("passes the push rules");
        let [btc] = prices.resolve_all(NOW).try_into().expect("one feed");
        let band = btc.resolved.conf.expect("a band");
        assert_eq!(
            band.to_scaled_unsigned(btc.symbol.expo()),
            Ok(0),
            "under one unit"
        );
        assert_eq!(btc.record().conf, Some(1));
        assert_eq!(btc.record().price, Some(usd(64_000)));
    }

    /// The dedupe is keyed by the shared batch, not O(S²), and each batch is
    /// one source with all its feeds, in feed order.
    #[test]
    fn each_batch_is_one_source_with_all_its_feeds() {
        let nodes = [TestNode::new(1), TestNode::new(2)];
        let mut prices = listed(&[&nodes[0], &nodes[1]]);
        prices.set_feeds(&[symbol(BTC), symbol(ETH), symbol(SOL)]);
        let all = batch(&nodes[0], &[BTC, ETH, SOL], 1);
        let eth = batch(&nodes[1], &[ETH], 1);
        prices
            .push(&[&all, &eth], NOW)
            .expect("passes the push rules");
        let sources: Vec<(Address, usize)> = prices
            .sources()
            .iter()
            .map(|source| (source.node, source.symbols.len()))
            .collect();
        assert_eq!(
            sources,
            [
                (nodes[0].signing_address(), 3),
                (nodes[1].signing_address(), 1)
            ]
        );
    }
}
