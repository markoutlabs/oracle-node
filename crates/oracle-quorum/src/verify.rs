//! Per-update verification: everything `oracle-wire` deliberately does not do.
//!
//! `oracle-wire` stops at "a registered node really signed this". That leaves
//! three checks, and all three are the consumer's job because all three are
//! policy:
//!
//! - **Replay.** A signed update is a bearer token that never expires on its own.
//!   A relay that stops forwarding and rebroadcasts an old frame passes every
//!   cryptographic check flawlessly. Sequence monotonicity is what stops it.
//! - **Staleness.** The same attack, seen from the other side: signatures say
//!   nothing about freshness. Only the local clock does.
//! - **Coherence.** An update claiming to observe the market after it was signed
//!   is nonsense, and nonsense is worth rejecting rather than reasoning about.
//!
//! Skip these and the signatures buy you nothing.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::time::Duration;

use oracle_types::{
    BookUpdate, FeedId, FeedKind, FundingUpdate, InstrumentId, NANOS_PER_SEC, PriceUpdate,
    VenueReport,
};
use oracle_wire::{
    Address, MAX_FEEDS, NodeListing, Recovered, UnverifiedBookFrame, UnverifiedFrame,
    UnverifiedFundingFrame, UnverifiedPriceBatch, UnverifiedVenueFrame, VerifiedRegistry,
    VerifyError,
};

use crate::age::{AgeLimits, Frame};
pub use crate::age::{FUNDING_MAX_AGE, SLOW_MAX_AGE};

/// The most feeds that one node holds a price or a venue report mark for: a feed set's limit.
pub const MAX_FEEDS_PER_NODE: usize = MAX_FEEDS;

/// The most books, and the most perpetuals, that one node holds a mark for.
// About seven times the 1,163 sources of the network feed set on 2026-11-06.
pub const MAX_INSTRUMENTS_PER_NODE: usize = 8_192;

/// Freshness policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyConfig {
    /// Reject updates published longer ago than this.
    ///
    /// This is the **only** defence against a relay that withholds new updates
    /// and rebroadcasts an old, perfectly-signed one. There is no cryptographic
    /// substitute.
    pub max_age: Duration,

    /// The same limit for a slow feed (funding, open interest), which nodes
    /// publish on a 10 s heartbeat. See [`Verifier::set_feed_kind`].
    pub slow_max_age: Duration,

    /// Tolerance for a node's clock running ahead of ours.
    ///
    /// Some slack is necessary — nodes and consumers do not share a clock — but
    /// unbounded slack would let a node mint updates far in the future that stay
    /// "fresh" forever.
    pub max_skew: Duration,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        let ages = AgeLimits::default();
        Self {
            max_age: ages.max_age,
            slow_max_age: ages.slow_max_age,
            max_skew: Duration::from_millis(500),
        }
    }
}

impl VerifyConfig {
    /// The age limits of this policy.
    #[must_use]
    pub const fn ages(&self) -> AgeLimits {
        AgeLimits {
            max_age: self.max_age,
            slow_max_age: self.slow_max_age,
        }
    }
}

/// Why an update was refused.
///
/// Every variant is worth a counter. A sudden rise in [`RejectReason::Replayed`]
/// or [`RejectReason::TooOld`] means something is sitting between you and the
/// node, and no signature check will tell you that.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RejectReason {
    /// The frame was malformed, or not signed by a node in the registry.
    ///
    /// For [`VerifyError::UnknownSigner`] the client refreshes the registry
    /// once and retries: the signer may be a node that just rotated.
    #[error(transparent)]
    Untrusted(#[from] VerifyError),

    /// Signed by a key the registry has since retired.
    ///
    /// Not a reason to refresh: the registry already knows this key, and the
    /// node that held it has moved on. A few of these right after a rotation are
    /// frames that were in flight. A steady stream is a stolen key in use.
    #[error("update from {signer} is signed by a retired key")]
    RetiredKey {
        /// The retired signing key.
        signer: Address,
    },

    /// The sequence number did not advance for this `(node, feed)` pair.
    ///
    /// Either a replay or a node that reset its counter. Both are refusals.
    #[error("replayed update from {signer}: seq {seq} does not advance past {last_seq}")]
    Replayed {
        /// The signing node.
        signer: Address,
        /// Sequence carried by the update.
        seq: u64,
        /// Highest sequence already accepted.
        last_seq: u64,
    },

    /// The update was published too long ago.
    #[error("stale update from {signer}: published {age_ms}ms ago, limit is {limit_ms}ms")]
    TooOld {
        /// The signing node.
        signer: Address,
        /// How old, in milliseconds.
        age_ms: u64,
        /// The configured limit.
        limit_ms: u64,
    },

    /// The update claims to have been published in the future.
    #[error("update from {signer} is {skew_ms}ms in the future, tolerance is {limit_ms}ms")]
    FromTheFuture {
        /// The signing node.
        signer: Address,
        /// How far ahead, in milliseconds.
        skew_ms: u64,
        /// The configured tolerance.
        limit_ms: u64,
    },

    /// The update's own timestamps contradict each other.
    #[error("update from {signer} claims to observe the market after it was signed")]
    IncoherentTimestamps {
        /// The signing node.
        signer: Address,
    },

    /// A book or funding frame for an instrument that the signed feed set does not list.
    #[error("update from {signer} is for {instrument}, which the feed set does not list")]
    Unlisted {
        /// The signing node.
        signer: Address,
        /// The instrument of the frame.
        instrument: InstrumentId,
    },

    /// The node holds marks for `limit` feeds or instruments, and the frame names one more.
    #[error("update from {signer} names a new feed or book past the limit of {limit}")]
    OverLimit {
        /// The signing node.
        signer: Address,
        /// The limit of that kind of frame.
        limit: usize,
    },
}

/// A book update that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedBook {
    /// The update.
    pub update: BookUpdate,
    /// The venue instrument of the update.
    pub instrument: InstrumentId,
    /// The node that signed it.
    pub signer: Address,
    /// That node's index in the registry it was verified against.
    pub node_index: usize,
}

/// A funding update that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedFunding {
    /// The update.
    pub update: FundingUpdate,
    /// The node that signed it.
    pub signer: Address,
    /// That node's index in the registry it was verified against.
    pub node_index: usize,
}

/// A venue report that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedVenues {
    /// The report.
    pub report: VenueReport,
    /// The node that signed it.
    pub signer: Address,
    /// That node's index in the registry it was verified against.
    pub node_index: usize,
}

/// An update that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The update.
    pub update: PriceUpdate,
    /// The node that signed it: the address its key recovered to.
    pub signer: Address,
    /// That node's index in the registry it was verified against.
    ///
    /// Positional, and therefore only meaningful against that exact registry
    /// version. Use [`Accepted::signer`] for anything that outlives a refresh.
    pub node_index: usize,
}

/// A price batch whose signature passed, with the checks of each update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedBatch {
    /// The node that signed it: the address its key recovered to.
    pub signer: Address,
    /// That node's index in the registry it was verified against.
    pub node_index: usize,
    /// Each update, or why it was refused, in the batch's order.
    pub updates: Vec<Result<PriceUpdate, RejectReason>>,
}

/// The sequence marks of one kind of frame, per node, with a limit on the keys of each node.
struct Marks<K> {
    per_node: HashMap<Address, HashMap<K, u64>>,
    limit: usize,
}

impl<K: Clone + Eq + Hash> Marks<K> {
    fn new(limit: usize) -> Self {
        Self {
            per_node: HashMap::new(),
            limit,
        }
    }

    // The limit: a listed node could otherwise name a new feed or book in each
    // frame, and every mark would stay in memory.
    fn advance(&mut self, signer: Address, key: &K, seq: u64) -> Result<(), RejectReason> {
        let marks = self.per_node.entry(signer).or_default();
        if let Some(last_seq) = marks.get_mut(key) {
            if seq <= *last_seq {
                return Err(RejectReason::Replayed {
                    signer,
                    seq,
                    last_seq: *last_seq,
                });
            }
            *last_seq = seq;
            return Ok(());
        }
        if marks.len() >= self.limit {
            return Err(RejectReason::OverLimit {
                signer,
                limit: self.limit,
            });
        }
        marks.insert(key.clone(), seq);
        Ok(())
    }

    fn retain_nodes(&mut self, keep: impl Fn(&Address) -> bool) {
        self.per_node.retain(|node, _| keep(node));
    }

    fn retain_keys(&mut self, keep: impl Fn(&K) -> bool) {
        for marks in self.per_node.values_mut() {
            marks.retain(|key, _| keep(key));
        }
    }
}

/// Verifies frames against a pinned registry and a freshness policy.
///
/// Holds the per-`(node, feed)` sequence high-water marks, so it must persist
/// across updates — a verifier rebuilt per message provides no replay protection
/// at all.
///
/// The marks are keyed by node address, because registry indices shift on
/// every refresh. A rotation gives the new address a fresh floor. That is safe:
/// the new key has never signed, and the old key's frames are
/// [`RejectReason::RetiredKey`].
pub struct Verifier {
    registry: VerifiedRegistry,
    config: VerifyConfig,
    high_water: Marks<FeedId>,
    /// Venue reports count their own sequence, apart from prices.
    venue_high_water: Marks<FeedId>,
    book_high_water: Marks<InstrumentId>,
    funding_high_water: Marks<InstrumentId>,
    /// Addresses that a registry this verifier once trusted listed, and the
    /// current one does not. Reported as [`RejectReason::RetiredKey`] rather than
    /// unknown, so the client does not go looking for a registry it already has.
    retired: HashSet<Address>,
    /// A feed id does not show its kind, and the kind sets the age limit.
    kinds: HashMap<FeedId, FeedKind>,
    /// `None` until the caller has a signed feed set.
    instruments: Option<HashSet<InstrumentId>>,
}

impl Verifier {
    /// Builds a verifier.
    #[must_use]
    pub fn new(registry: VerifiedRegistry, config: VerifyConfig) -> Self {
        Self {
            registry,
            config,
            high_water: Marks::new(MAX_FEEDS_PER_NODE),
            venue_high_water: Marks::new(MAX_FEEDS_PER_NODE),
            book_high_water: Marks::new(MAX_INSTRUMENTS_PER_NODE),
            funding_high_water: Marks::new(MAX_INSTRUMENTS_PER_NODE),
            retired: HashSet::new(),
            kinds: HashMap::new(),
            instruments: None,
        }
    }

    /// Holds this feed's prices and venue reports to the age limit of `kind`.
    pub fn set_feed_kind(&mut self, feed_id: FeedId, kind: FeedKind) {
        self.kinds.insert(feed_id, kind);
    }

    /// Holds this feed's prices and venue reports to `slow_max_age`, like [`Self::set_feed_kind`].
    pub fn mark_slow(&mut self, feed_id: FeedId) {
        // Funding stands for every slow kind: the age rule reads only `is_slow`.
        if !self.feed_kind(feed_id).is_slow() {
            self.kinds.insert(feed_id, FeedKind::Funding8h);
        }
    }

    /// Accepts book and funding frames only for `instruments`, the sources of a signed feed set.
    /// `None` accepts any, up to [`MAX_INSTRUMENTS_PER_NODE`] for each node.
    pub fn set_instruments(&mut self, instruments: Option<HashSet<InstrumentId>>) {
        // The marks of an instrument that leaves stay, within the limit, so a
        // frame accepted before cannot pass again when the instrument comes back.
        self.instruments = instruments;
    }

    /// The kind of a feed from [`Self::set_feed_kind`], or a price feed when unknown.
    #[must_use]
    pub fn feed_kind(&self, feed_id: FeedId) -> FeedKind {
        self.kinds.get(&feed_id).copied().unwrap_or_default()
    }

    fn max_age(&self, frame: Frame) -> Duration {
        self.config.ages().max_age(frame)
    }

    /// Returns the registry in use.
    #[must_use]
    pub const fn registry(&self) -> &VerifiedRegistry {
        &self.registry
    }

    /// Replaces the registry, keeping the sequence high-water marks of the
    /// nodes that stay listed, so a refresh does not reopen their replay window.
    pub fn set_registry(&mut self, registry: VerifiedRegistry) {
        let still_listed: HashSet<Address> = addresses(&registry).collect();
        for address in addresses(&self.registry) {
            if !still_listed.contains(&address) {
                self.retired.insert(address);
            }
        }
        // A retired address never verifies again, so its marks are dead weight.
        let listed = |node: &Address| still_listed.contains(node);
        self.high_water.retain_nodes(listed);
        self.venue_high_water.retain_nodes(listed);
        self.book_high_water.retain_nodes(listed);
        self.funding_high_water.retain_nodes(listed);
        self.registry = registry;
    }

    /// Drops the price and venue report marks of every feed that `keep` refuses.
    ///
    /// A frame of a dropped feed that is still younger than its age limit can then pass once more.
    pub fn retain_feeds(&mut self, keep: impl Fn(&FeedId) -> bool) {
        self.high_water.retain_keys(&keep);
        self.venue_high_water.retain_keys(&keep);
    }

    /// Returns `true` if a registry this verifier once trusted listed `signer`
    /// and the current one does not.
    #[must_use]
    pub fn is_retired(&self, signer: Address) -> bool {
        self.retired.contains(&signer)
    }

    /// Verifies one wire frame.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`]. Signature and registry failures come first, so a
    /// forged frame is never measured against the clock.
    pub fn accept(&mut self, frame: &[u8], now_ns: u64) -> Result<Accepted, RejectReason> {
        let recovered = UnverifiedFrame::parse(frame)
            .map_err(VerifyError::from)?
            .recover()?;
        self.accept_recovered(recovered, now_ns)
    }

    /// [`Self::accept`] for a frame recovered elsewhere, such as in a node's own task.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`], in the same order as [`Self::accept`].
    pub fn accept_recovered(
        &mut self,
        recovered: Recovered<PriceUpdate>,
        now_ns: u64,
    ) -> Result<Accepted, RejectReason> {
        let verified = self.trusted(recovered.authorize(&self.registry))?;
        let update = *verified.update();
        let signer = verified.signer();
        let node_index = verified.node_index();
        let update = self.check_update(signer, update, now_ns)?;
        Ok(Accepted {
            update,
            signer,
            node_index,
        })
    }

    /// Verifies a price batch: one signature for every update, then the
    /// checks of [`Self::accept`] on each update alone. Each update shares the
    /// sequence marks of the node's single price frames.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`] for the whole batch when it is malformed or its
    /// signer is not a listed node.
    pub fn accept_batch(
        &mut self,
        frame: &[u8],
        now_ns: u64,
    ) -> Result<AcceptedBatch, RejectReason> {
        let parsed = UnverifiedPriceBatch::parse(frame).map_err(VerifyError::from)?;
        let updates = parsed.decode_unverified().map_err(VerifyError::from)?;
        self.accept_parsed_batch(&parsed, updates, now_ns)
    }

    /// [`Self::accept_batch`] for a batch that the caller parsed and decoded already.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::accept_batch`], and [`RejectReason::Untrusted`] if
    /// `updates` are not the decode of `batch`.
    pub fn accept_parsed_batch(
        &mut self,
        batch: &UnverifiedPriceBatch,
        updates: Vec<PriceUpdate>,
        now_ns: u64,
    ) -> Result<AcceptedBatch, RejectReason> {
        self.accept_recovered_batch(batch.recover_decoded(updates)?, now_ns)
    }

    /// [`Self::accept_batch`] for a batch recovered elsewhere, so a caller can
    /// compare the signer with the frame's hint before any sequence moves.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::accept_batch`] after the recovery.
    pub fn accept_recovered_batch(
        &mut self,
        recovered: Recovered<Vec<PriceUpdate>>,
        now_ns: u64,
    ) -> Result<AcceptedBatch, RejectReason> {
        let verified = self.trusted(recovered.authorize(&self.registry))?;
        let signer = verified.signer();
        let node_index = verified.node_index();
        let updates = verified
            .into_updates()
            .into_iter()
            .map(|update| self.check_update(signer, update, now_ns))
            .collect();
        Ok(AcceptedBatch {
            signer,
            node_index,
            updates,
        })
    }

    fn check_update(
        &mut self,
        signer: Address,
        update: PriceUpdate,
        now_ns: u64,
    ) -> Result<PriceUpdate, RejectReason> {
        // SPEC §7 step 5, and a previous publish after this one.
        if !update.timestamps_coherent() {
            return Err(RejectReason::IncoherentTimestamps { signer });
        }
        // Clock checks before the sequence update, so a rejected frame cannot
        // advance the high-water mark and lock out the legitimate one behind it.
        let max_age = self.max_age(Frame::Price(self.feed_kind(update.feed_id)));
        self.check_clock(signer, update.publish_time_ns, now_ns, max_age)?;
        self.high_water
            .advance(signer, &update.feed_id, update.seq)?;
        Ok(update)
    }

    /// Verifies one venue report frame, with the same checks as a price frame.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`], in the same order as [`Self::accept`].
    pub fn accept_venues(
        &mut self,
        frame: &[u8],
        now_ns: u64,
    ) -> Result<AcceptedVenues, RejectReason> {
        let recovered = UnverifiedVenueFrame::parse(frame)
            .map_err(VerifyError::from)?
            .recover()?;
        self.accept_venues_recovered(recovered, now_ns)
    }

    /// [`Self::accept_venues`] for a frame whose signer is already recovered, like
    /// [`Self::accept_recovered`].
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`], in the same order as [`Self::accept`].
    pub fn accept_venues_recovered(
        &mut self,
        recovered: Recovered<VenueReport>,
        now_ns: u64,
    ) -> Result<AcceptedVenues, RejectReason> {
        let verified = self.trusted(recovered.authorize(&self.registry))?;
        let (signer, node_index) = (verified.signer(), verified.node_index());
        let report = verified.into_report();
        if !report.timestamps_coherent() {
            return Err(RejectReason::IncoherentTimestamps { signer });
        }
        let max_age = self.max_age(Frame::VenueReport(self.feed_kind(report.feed_id)));
        self.check_clock(signer, report.publish_time_ns, now_ns, max_age)?;
        self.venue_high_water
            .advance(signer, &report.feed_id, report.seq)?;
        Ok(AcceptedVenues {
            report,
            signer,
            node_index,
        })
    }

    /// Verifies one book frame, with the same checks as a price frame. A gap
    /// in `seq` passes here: the book, not the verifier, decides what a gap
    /// means.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`], in the same order as [`Self::accept`].
    pub fn accept_book(&mut self, frame: &[u8], now_ns: u64) -> Result<AcceptedBook, RejectReason> {
        let recovered = UnverifiedBookFrame::parse(frame)
            .map_err(VerifyError::from)?
            .recover()?;
        self.accept_book_recovered(recovered, now_ns)
    }

    /// [`Self::accept_book`] for a frame whose signer is already recovered, like
    /// [`Self::accept_recovered`].
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`], in the same order as [`Self::accept`].
    pub fn accept_book_recovered(
        &mut self,
        recovered: Recovered<BookUpdate>,
        now_ns: u64,
    ) -> Result<AcceptedBook, RejectReason> {
        let verified = self.trusted(recovered.authorize(&self.registry))?;
        let (signer, node_index) = (verified.signer(), verified.node_index());
        let update = verified.into_update();
        let instrument = InstrumentId::new(update.venue, update.market, update.symbol.as_str());
        self.listed(signer, &instrument)?;
        if !update.timestamps_coherent() {
            return Err(RejectReason::IncoherentTimestamps { signer });
        }
        self.check_clock(
            signer,
            update.publish_time_ns,
            now_ns,
            self.max_age(Frame::Book),
        )?;
        self.book_high_water
            .advance(signer, &instrument, update.seq)?;
        Ok(AcceptedBook {
            update,
            instrument,
            signer,
            node_index,
        })
    }

    /// Verifies one funding frame, with the same checks as a book frame. The
    /// age limit is two funding heartbeats.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`], in the same order as [`Self::accept`].
    pub fn accept_funding(
        &mut self,
        frame: &[u8],
        now_ns: u64,
    ) -> Result<AcceptedFunding, RejectReason> {
        let recovered = UnverifiedFundingFrame::parse(frame)
            .map_err(VerifyError::from)?
            .recover()?;
        self.accept_funding_recovered(recovered, now_ns)
    }

    /// [`Self::accept_funding`] for a frame whose signer is already recovered, like
    /// [`Self::accept_recovered`].
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`], in the same order as [`Self::accept`].
    pub fn accept_funding_recovered(
        &mut self,
        recovered: Recovered<FundingUpdate>,
        now_ns: u64,
    ) -> Result<AcceptedFunding, RejectReason> {
        let verified = self.trusted(recovered.authorize(&self.registry))?;
        let (signer, node_index) = (verified.signer(), verified.node_index());
        let update = verified.into_update();
        let perpetual = InstrumentId::new(update.venue, update.market, update.symbol.as_str());
        self.listed(signer, &perpetual)?;
        if !update.timestamps_coherent() {
            return Err(RejectReason::IncoherentTimestamps { signer });
        }
        self.check_clock(
            signer,
            update.publish_time_ns,
            now_ns,
            self.max_age(Frame::Funding),
        )?;
        self.funding_high_water
            .advance(signer, &perpetual, update.seq)?;
        Ok(AcceptedFunding {
            update,
            signer,
            node_index,
        })
    }

    /// Reports a key that a past registry listed as retired, not unknown, so
    /// the client does not fetch a registry that it already has.
    fn trusted<T>(&self, verified: Result<T, VerifyError>) -> Result<T, RejectReason> {
        verified.map_err(|error| match error {
            VerifyError::UnknownSigner { signer } if self.retired.contains(&signer) => {
                RejectReason::RetiredKey { signer }
            }
            error => error.into(),
        })
    }

    fn listed(&self, signer: Address, instrument: &InstrumentId) -> Result<(), RejectReason> {
        match &self.instruments {
            Some(listed) if !listed.contains(instrument) => Err(RejectReason::Unlisted {
                signer,
                instrument: instrument.clone(),
            }),
            _ => Ok(()),
        }
    }

    fn check_clock(
        &self,
        signer: Address,
        publish_time_ns: u64,
        now_ns: u64,
        max_age: Duration,
    ) -> Result<(), RejectReason> {
        if publish_time_ns > now_ns {
            let skew = publish_time_ns - now_ns;
            let limit = nanos(self.config.max_skew);
            if skew > limit {
                return Err(RejectReason::FromTheFuture {
                    signer,
                    skew_ms: skew / 1_000_000,
                    limit_ms: limit / 1_000_000,
                });
            }
        } else {
            let age = now_ns - publish_time_ns;
            let limit = nanos(max_age);
            if age > limit {
                return Err(RejectReason::TooOld {
                    signer,
                    age_ms: age / 1_000_000,
                    limit_ms: limit / 1_000_000,
                });
            }
        }
        Ok(())
    }
}

/// Verifies a stored frame against the node that was listed when it was
/// published.
///
/// The live path never calls this. It serves audit and dispute: a frame signed
/// last month by a node since rotated out must still verify, and one signed
/// after it was removed must not (SPEC §3.5). `listing` is what the registry
/// canister serves for the frame's signer. Its times are the canister's word.
///
/// # Errors
///
/// Returns [`VerifyError::UnknownSigner`] if the frame is not signed by
/// `listing.address`, and [`VerifyError::NotListedAt`] if the publish time
/// falls outside the listing.
pub fn verify_historical(frame: &[u8], listing: &NodeListing) -> Result<PriceUpdate, VerifyError> {
    let parsed = UnverifiedFrame::parse(frame)?;
    let signer = parsed.recover_signer()?;
    if signer != listing.address {
        return Err(VerifyError::UnknownSigner { signer });
    }
    let update = parsed.decode_unverified()?;
    let published = update.publish_time_ns;
    let after_added = published >= listing.added_at.saturating_mul(NANOS_PER_SEC);
    let before_removed = listing
        .removed_at
        .is_none_or(|removed_at| published < removed_at.saturating_mul(NANOS_PER_SEC));
    if !(after_added && before_removed) {
        return Err(VerifyError::NotListedAt {
            signer,
            published: published / NANOS_PER_SEC,
            added_at: listing.added_at,
            removed_at: listing.removed_at,
        });
    }
    Ok(update)
}

/// Every address a registry lists.
fn addresses(registry: &VerifiedRegistry) -> impl Iterator<Item = Address> + '_ {
    registry.nodes().iter().map(|node| node.address)
}

/// Converts a duration to nanoseconds, saturating.
fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{TestNode, book_at, funding_at, registry_with, update_at, venues_at};
    use oracle_types::{MarketKind, NANOS_PER_SEC, Venue};

    const NOW: u64 = 1_754_582_400 * NANOS_PER_SEC;

    fn verifier(node: &TestNode) -> Verifier {
        Verifier::new(registry_with(&[node]), VerifyConfig::default())
    }

    fn on_feed(update: PriceUpdate, feed: u8) -> PriceUpdate {
        PriceUpdate {
            feed_id: FeedId::from_bytes([feed; 32]),
            ..update
        }
    }

    #[test]
    fn a_batch_checks_one_signature_and_each_update_alone() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let stale = on_feed(update_at(NOW - 3 * NANOS_PER_SEC, 5), 2);
        let batch = node.sign_batch(&[update_at(NOW, 5), stale]);
        let accepted = verifier
            .accept_batch(&batch, NOW)
            .expect("the signature passes");
        assert_eq!(accepted.signer, node.signing_address());
        let [fresh, old] = accepted.updates.as_slice() else {
            panic!("two verdicts: {:?}", accepted.updates);
        };
        assert_eq!(fresh.as_ref().map(|update| update.seq), Ok(5));
        assert!(matches!(old, Err(RejectReason::TooOld { .. })), "{old:?}");
    }

    #[test]
    fn a_parsed_batch_takes_the_same_checks_without_a_second_decode() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let batch = node.sign_batch(&[update_at(NOW, 5), on_feed(update_at(NOW, 6), 2)]);
        let parsed = UnverifiedPriceBatch::parse(&batch).expect("parses");
        let updates = parsed.decode_unverified().expect("decodes");
        let accepted = verifier
            .accept_parsed_batch(&parsed, updates.clone(), NOW)
            .expect("the signature passes");
        assert!(accepted.updates.iter().all(Result::is_ok));
        let mut forged = updates;
        if let Some(first) = forged.first_mut() {
            first.price = 1;
        }
        assert!(matches!(
            verifier.accept_parsed_batch(&parsed, forged, NOW),
            Err(RejectReason::Untrusted(VerifyError::Wire(_)))
        ));
    }

    #[test]
    fn a_recovered_batch_moves_no_sequence_before_the_caller_accepts_it() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let batch = node.sign_batch(&[update_at(NOW, 5)]);
        let recovered = UnverifiedPriceBatch::parse(&batch)
            .expect("parses")
            .recover()
            .expect("recovers");
        assert_eq!(recovered.signer(), node.signing_address());
        assert!(verifier.accept(&node.sign(&update_at(NOW, 5)), NOW).is_ok());
        let accepted = verifier
            .accept_recovered_batch(recovered, NOW)
            .expect("the signer is listed");
        assert!(matches!(
            accepted.updates.as_slice(),
            [Err(RejectReason::Replayed { .. })]
        ));
    }

    #[test]
    fn retain_feeds_drops_the_price_and_venue_marks_of_a_dropped_feed() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        assert!(verifier.accept(&node.sign(&update_at(NOW, 5)), NOW).is_ok());
        assert!(
            verifier
                .accept_venues(&node.sign_venues(&venues_at(NOW, 5)), NOW)
                .is_ok()
        );
        verifier.retain_feeds(|_| false);
        assert!(verifier.high_water.per_node.values().all(HashMap::is_empty));
        assert!(
            verifier
                .venue_high_water
                .per_node
                .values()
                .all(HashMap::is_empty)
        );
    }

    #[test]
    fn a_batch_shares_the_sequence_of_single_frames() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let batch = node.sign_batch(&[update_at(NOW, 5)]);
        assert!(verifier.accept_batch(&batch, NOW).is_ok());
        assert!(matches!(
            verifier.accept(&node.sign(&update_at(NOW, 5)), NOW),
            Err(RejectReason::Replayed { .. })
        ));
        let again = verifier
            .accept_batch(&batch, NOW)
            .expect("the signature passes");
        assert!(matches!(
            again.updates.as_slice(),
            [Err(RejectReason::Replayed { .. })]
        ));
    }

    #[test]
    fn a_batch_from_a_stranger_is_refused_whole() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let batch = TestNode::new(9).sign_batch(&[update_at(NOW, 1)]);
        assert!(matches!(
            verifier.accept_batch(&batch, NOW),
            Err(RejectReason::Untrusted(VerifyError::UnknownSigner { .. }))
        ));
    }

    #[test]
    fn a_well_formed_update_from_a_registered_node_is_accepted() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let frame = node.sign(&update_at(NOW, 1));
        let accepted = verifier.accept(&frame, NOW).expect("accepted");
        assert_eq!(accepted.signer, node.signing_address());
        assert_eq!(accepted.update.seq, 1);
    }

    #[test]
    fn a_slow_feed_is_held_to_its_own_limit() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let between_heartbeats = update_at(NOW - 9 * NANOS_PER_SEC, 1);
        let frame = node.sign(&between_heartbeats);
        assert!(
            matches!(
                verifier.accept(&frame, NOW),
                Err(RejectReason::TooOld { .. })
            ),
            "a price feed allows 2 s"
        );
        verifier.mark_slow(between_heartbeats.feed_id);
        verifier
            .accept(&frame, NOW)
            .expect("a slow feed allows 25 s");
        let too_old = node.sign(&update_at(NOW - 30 * NANOS_PER_SEC, 2));
        assert!(matches!(
            verifier.accept(&too_old, NOW),
            Err(RejectReason::TooOld { .. })
        ));
    }

    #[test]
    fn a_feed_kind_sets_the_age_of_its_prices_and_reports() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let open_interest = on_feed(update_at(NOW - 9 * NANOS_PER_SEC, 1), 3);
        verifier.set_feed_kind(open_interest.feed_id, FeedKind::OpenInterest);
        assert!(verifier.accept(&node.sign(&open_interest), NOW).is_ok());
        let mark = on_feed(update_at(NOW - 9 * NANOS_PER_SEC, 1), 4);
        verifier.set_feed_kind(mark.feed_id, FeedKind::PerpMark);
        assert!(matches!(
            verifier.accept(&node.sign(&mark), NOW),
            Err(RejectReason::TooOld {
                limit_ms: 2_000,
                ..
            })
        ));
    }

    #[test]
    fn a_previous_publish_after_the_publish_is_incoherent() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let mut update = update_at(NOW, 1);
        update.prev_publish_time_ns = NOW + 1;
        assert!(matches!(
            verifier.accept(&node.sign(&update), NOW),
            Err(RejectReason::IncoherentTimestamps { .. })
        ));
        update.prev_publish_time_ns = NOW;
        assert!(verifier.accept(&node.sign(&update), NOW).is_ok());
    }

    /// The live view, the tap and an archive must hold the same signed value.
    #[test]
    fn a_venue_time_after_the_signature_stays_as_signed() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let ahead = Some(NOW + 3_600 * NANOS_PER_SEC);
        let book = BookUpdate {
            exchange_time_ns: ahead,
            ..book_at(NOW, 1, true, 100)
        };
        let accepted = verifier
            .accept_book(&node.sign_book(&book), NOW)
            .expect("accepted");
        assert_eq!(accepted.update.exchange_time_ns, ahead);
        assert_eq!(
            accepted.instrument,
            InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT")
        );
        let funding = FundingUpdate {
            exchange_time_ns: ahead,
            ..funding_at(NOW, 1, 100)
        };
        let accepted = verifier
            .accept_funding(&node.sign_funding(&funding), NOW)
            .expect("accepted");
        assert_eq!(accepted.update.exchange_time_ns, ahead);
    }

    /// An instrument that leaves the feed set and comes back keeps its mark,
    /// so a frame accepted before cannot pass a second time.
    #[test]
    fn an_instrument_that_leaves_the_feed_set_and_comes_back_keeps_its_mark() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let listed = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");
        let other = InstrumentId::new(Venue::Okx, MarketKind::Spot, "BTC-USDT");
        verifier.set_instruments(Some(HashSet::from([listed.clone()])));
        let frame = node.sign_book(&book_at(NOW, 5, true, 100));
        assert!(verifier.accept_book(&frame, NOW).is_ok());
        verifier.set_instruments(Some(HashSet::from([other])));
        verifier.set_instruments(Some(HashSet::from([listed])));
        assert!(matches!(
            verifier.accept_book(&frame, NOW),
            Err(RejectReason::Replayed { .. })
        ));
    }

    /// The refusal comes before the mark, so a node that invents instruments
    /// leaves nothing behind.
    #[test]
    fn a_book_or_perpetual_outside_the_feed_set_is_refused() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let other = InstrumentId::new(Venue::Okx, MarketKind::Spot, "BTC-USDT");
        verifier.set_instruments(Some(HashSet::from([other])));
        assert!(matches!(
            verifier.accept_book(&node.sign_book(&book_at(NOW, 1, true, 100)), NOW),
            Err(RejectReason::Unlisted { .. })
        ));
        assert!(matches!(
            verifier.accept_funding(&node.sign_funding(&funding_at(NOW, 1, 100)), NOW),
            Err(RejectReason::Unlisted { .. })
        ));
        assert!(verifier.book_high_water.per_node.is_empty());
        let listed = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");
        verifier.set_instruments(Some(HashSet::from([listed])));
        assert!(
            verifier
                .accept_book(&node.sign_book(&book_at(NOW, 1, true, 100)), NOW)
                .is_ok()
        );
    }

    #[test]
    fn a_new_key_past_the_limit_is_refused_and_known_keys_still_advance() {
        let node = Address::from_bytes([1; 20]);
        let mut marks: Marks<u8> = Marks::new(2);
        assert!(marks.advance(node, &1, 1).is_ok());
        assert!(marks.advance(node, &2, 1).is_ok());
        assert_eq!(
            marks.advance(node, &3, 1),
            Err(RejectReason::OverLimit {
                signer: node,
                limit: 2
            })
        );
        assert!(marks.advance(node, &1, 2).is_ok());
        assert!(
            marks.advance(Address::from_bytes([2; 20]), &3, 1).is_ok(),
            "the limit is for each node"
        );
        marks.retain_keys(|key| *key != 1);
        assert!(marks.advance(node, &3, 1).is_ok());
    }

    #[test]
    fn a_venue_report_has_its_own_sequence() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let price = node.sign(&update_at(NOW, 5));
        assert!(verifier.accept(&price, NOW).is_ok());
        let report = node.sign_venues(&venues_at(NOW, 1));
        let accepted = verifier
            .accept_venues(&report, NOW)
            .expect("a price seq of 5 does not block venue seq 1");
        assert_eq!(accepted.signer, node.signing_address());
        assert!(matches!(
            verifier.accept_venues(&report, NOW),
            Err(RejectReason::Replayed { .. })
        ));
    }

    #[test]
    fn a_stale_or_incoherent_venue_report_is_refused() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let old = node.sign_venues(&venues_at(NOW - 5 * NANOS_PER_SEC, 1));
        assert!(matches!(
            verifier.accept_venues(&old, NOW),
            Err(RejectReason::TooOld { .. })
        ));
        let mut report = venues_at(NOW, 2);
        if let Some(entry) = report.entries.first_mut() {
            entry.local_recv_ns = NOW + 1;
        }
        assert!(matches!(
            verifier.accept_venues(&node.sign_venues(&report), NOW),
            Err(RejectReason::IncoherentTimestamps { .. })
        ));
        assert!(
            verifier
                .accept(&node.sign_venues(&venues_at(NOW, 3)), NOW)
                .is_err(),
            "a venue frame is not a price frame"
        );
    }

    #[test]
    fn an_update_from_an_unregistered_node_is_refused() {
        let node = TestNode::new(1);
        let impostor = TestNode::new(9);
        let mut verifier = verifier(&node);
        let frame = impostor.sign(&update_at(NOW, 1));
        assert!(matches!(
            verifier.accept(&frame, NOW),
            Err(RejectReason::Untrusted(VerifyError::UnknownSigner { .. }))
        ));
    }

    /// The core replay defence. The frame is genuine and perfectly signed; only
    /// the sequence number reveals that it has been seen before.
    #[test]
    fn a_replayed_frame_is_refused_even_though_its_signature_is_valid() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let frame = node.sign(&update_at(NOW, 5));

        assert!(verifier.accept(&frame, NOW).is_ok());
        assert!(matches!(
            verifier.accept(&frame, NOW),
            Err(RejectReason::Replayed {
                seq: 5,
                last_seq: 5,
                ..
            })
        ));
    }

    #[test]
    fn a_lower_sequence_number_is_refused() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        assert!(
            verifier
                .accept(&node.sign(&update_at(NOW, 10)), NOW)
                .is_ok()
        );
        assert!(matches!(
            verifier.accept(&node.sign(&update_at(NOW, 9)), NOW),
            Err(RejectReason::Replayed {
                seq: 9,
                last_seq: 10,
                ..
            })
        ));
    }

    /// Sequence numbers are tracked per feed, not globally, so two feeds
    /// advancing independently must not lock each other out.
    #[test]
    fn sequence_tracking_is_per_feed_and_per_node() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);

        let mut first = update_at(NOW, 10);
        first.feed_id = FeedId::from_bytes([1; 32]);
        let mut second = update_at(NOW, 3);
        second.feed_id = FeedId::from_bytes([2; 32]);

        assert!(verifier.accept(&node.sign(&first), NOW).is_ok());
        assert!(verifier.accept(&node.sign(&second), NOW).is_ok());
    }

    /// The withhold-and-replay attack: every signature still verifies, and only
    /// the local clock notices.
    #[test]
    fn a_withheld_update_goes_stale() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let frame = node.sign(&update_at(NOW, 1));

        // Five seconds later, a relay finally forwards it.
        let later = NOW + 5 * NANOS_PER_SEC;
        assert!(matches!(
            verifier.accept(&frame, later),
            Err(RejectReason::TooOld {
                limit_ms: 2_000,
                ..
            })
        ));
    }

    #[test]
    fn an_update_from_the_future_is_refused() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let ahead = node.sign(&update_at(NOW + 5 * NANOS_PER_SEC, 1));
        assert!(matches!(
            verifier.accept(&ahead, NOW),
            Err(RejectReason::FromTheFuture { limit_ms: 500, .. })
        ));
    }

    #[test]
    fn small_clock_skew_is_tolerated() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        // 100ms ahead, inside the 500ms tolerance.
        let ahead = node.sign(&update_at(NOW + 100_000_000, 1));
        assert!(verifier.accept(&ahead, NOW).is_ok());
    }

    #[test]
    fn incoherent_timestamps_are_refused() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let mut update = update_at(NOW, 1);
        update.observation_time_ns = update.publish_time_ns + 1;
        assert!(matches!(
            verifier.accept(&node.sign(&update), NOW),
            Err(RejectReason::IncoherentTimestamps { .. })
        ));
    }

    /// A rejected frame must not consume the sequence number, or an attacker
    /// could lock out the legitimate update simply by replaying it early.
    #[test]
    fn a_clock_rejected_frame_does_not_advance_the_high_water_mark() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);

        let future = node.sign(&update_at(NOW + 5 * NANOS_PER_SEC, 7));
        assert!(verifier.accept(&future, NOW).is_err());

        // The same sequence number, legitimately published now, must still pass.
        let genuine = node.sign(&update_at(NOW, 7));
        assert!(verifier.accept(&genuine, NOW).is_ok());
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let mut frame = node.sign(&update_at(NOW, 1));
        // Flip a bit inside the signed region.
        if let Some(byte) = frame.get_mut(21 + 36) {
            *byte ^= 0x01;
        }
        assert!(verifier.accept(&frame, NOW).is_err());
    }

    /// A rotation lists a new address. Its replay floor starts fresh, and the
    /// old key's frames, replays included, stop at the retired check.
    #[test]
    fn a_rotation_moves_the_replay_floor_to_the_new_address() {
        let mut node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let update = update_at(NOW, 5);
        let old_frame = node.sign(&update);
        assert!(verifier.accept(&old_frame, NOW).is_ok());

        node.rotate();
        verifier.set_registry(registry_with(&[&node]));

        assert!(matches!(
            verifier.accept(&old_frame, NOW),
            Err(RejectReason::RetiredKey { .. })
        ));
        let accepted = verifier
            .accept(&node.sign(&update), NOW)
            .expect("the new key has its own floor");
        assert_eq!(accepted.signer, node.signing_address());
        assert!(matches!(
            verifier.accept(&node.sign(&update), NOW),
            Err(RejectReason::Replayed { .. })
        ));
    }

    /// One live key per node. The old key is retired on adoption, and it is
    /// reported as retired rather than unknown, so the client does not go looking
    /// for a newer registry it already has.
    #[test]
    fn a_rotated_out_key_is_retired_not_unknown() {
        let mut node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let old_address = node.signing_address();

        node.rotate();
        verifier.set_registry(registry_with(&[&node]));

        assert!(matches!(
            verifier.accept(&node.sign_outgoing(&update_at(NOW, 1)), NOW),
            Err(RejectReason::RetiredKey { signer }) if signer == old_address
        ));
        assert!(verifier.is_retired(old_address));
        let accepted = verifier
            .accept(&node.sign(&update_at(NOW, 2)), NOW)
            .expect("the live key verifies");
        assert_eq!(accepted.signer, node.signing_address());
    }

    /// Recovery may run long before the verifier sees the frame. The registry
    /// check runs at acceptance, so a key removed in between is refused.
    #[test]
    fn a_key_removed_after_recovery_is_refused() {
        let mut node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let old_address = node.signing_address();
        let recovered = UnverifiedFrame::parse(&node.sign(&update_at(NOW, 1)))
            .expect("parses")
            .recover()
            .expect("recovers");

        node.rotate();
        verifier.set_registry(registry_with(&[&node]));

        assert!(matches!(
            verifier.accept_recovered(recovered, NOW),
            Err(RejectReason::RetiredKey { signer }) if signer == old_address
        ));
    }

    /// Both paths share the sequence marks, so a frame is accepted once.
    #[test]
    fn a_recovered_frame_is_a_replay_after_the_same_frame() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let frame = node.sign_venues(&venues_at(NOW, 1));
        assert!(verifier.accept_venues(&frame, NOW).is_ok());
        let recovered = UnverifiedVenueFrame::parse(&frame)
            .expect("parses")
            .recover()
            .expect("recovers");
        assert!(matches!(
            verifier.accept_venues_recovered(recovered, NOW),
            Err(RejectReason::Replayed { .. })
        ));
    }

    /// Stored frames verify while their signer was listed, and not after.
    #[test]
    fn historical_verification_follows_the_listing() {
        let node = TestNode::new(1);
        let added_at = NOW / NANOS_PER_SEC - 60;
        let removed_at = NOW / NANOS_PER_SEC + 5;
        let listing = NodeListing {
            address: node.signing_address(),
            added_at,
            removed_at: Some(removed_at),
        };
        let at = |secs: u64, seq| node.sign(&update_at(secs * NANOS_PER_SEC, seq));

        assert!(verify_historical(&at(added_at, 1), &listing).is_ok());
        assert!(verify_historical(&at(removed_at - 1, 2), &listing).is_ok());
        for outside in [added_at - 1, removed_at] {
            assert!(matches!(
                verify_historical(&at(outside, 3), &listing),
                Err(VerifyError::NotListedAt { published, .. }) if published == outside
            ));
        }
        let still_listed = NodeListing {
            removed_at: None,
            ..listing.clone()
        };
        assert!(
            verify_historical(&at(removed_at + 3_600, 4), &still_listed).is_ok(),
            "a listed node has no end"
        );
        let impostor = TestNode::new(9);
        assert!(matches!(
            verify_historical(&impostor.sign(&update_at(NOW, 1)), &listing),
            Err(VerifyError::UnknownSigner { .. })
        ));
    }

    #[test]
    fn rotating_the_registry_keeps_replay_protection() {
        let node = TestNode::new(1);
        let mut verifier = verifier(&node);
        let frame = node.sign(&update_at(NOW, 4));
        assert!(verifier.accept(&frame, NOW).is_ok());

        verifier.set_registry(registry_with(&[&node]));
        assert!(
            matches!(
                verifier.accept(&frame, NOW),
                Err(RejectReason::Replayed { .. })
            ),
            "a registry swap must not reopen the replay window"
        );
    }
}
