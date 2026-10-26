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
use std::time::Duration;

use oracle_types::{
    BookUpdate, FUNDING_HEARTBEAT, FeedId, FundingUpdate, InstrumentId, NANOS_PER_SEC, PriceUpdate,
    SLOW_HEARTBEAT, VenueReport,
};
use oracle_wire::{
    Address, NodeListing, UnverifiedBookFrame, UnverifiedFrame, UnverifiedFundingFrame,
    UnverifiedVenueFrame, VerifiedRegistry, VerifyError,
};

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
    /// publish on a 10 s heartbeat. See [`Verifier::mark_slow`].
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
        Self {
            max_age: Duration::from_secs(2),
            slow_max_age: SLOW_MAX_AGE,
            max_skew: Duration::from_millis(500),
        }
    }
}

/// Two slow heartbeats and a margin, so one lost heartbeat does not make a slow
/// feed stale.
pub const SLOW_MAX_AGE: Duration = Duration::from_secs(25);
const _: () = assert!(SLOW_MAX_AGE.as_secs() > 2 * SLOW_HEARTBEAT.as_secs());

/// How old a funding frame may be. A new subscriber gets the node's latest
/// frame, which can be a whole heartbeat old.
pub const FUNDING_MAX_AGE: Duration = FUNDING_HEARTBEAT.saturating_mul(2);

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
}

/// A book update that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedBook {
    /// The update.
    pub update: BookUpdate,
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
    high_water: HashMap<(Address, FeedId), u64>,
    /// Venue reports count their own sequence, apart from prices.
    venue_high_water: HashMap<(Address, FeedId), u64>,
    book_high_water: HashMap<(Address, InstrumentId), u64>,
    funding_high_water: HashMap<(Address, InstrumentId), u64>,
    /// Addresses that a registry this verifier once trusted listed, and the
    /// current one does not. Reported as [`RejectReason::RetiredKey`] rather than
    /// unknown, so the client does not go looking for a registry it already has.
    retired: HashSet<Address>,
    /// Feeds held to `slow_max_age`. A feed id does not show its kind.
    slow: HashSet<FeedId>,
}

impl Verifier {
    /// Builds a verifier.
    #[must_use]
    pub fn new(registry: VerifiedRegistry, config: VerifyConfig) -> Self {
        Self {
            registry,
            config,
            high_water: HashMap::new(),
            venue_high_water: HashMap::new(),
            book_high_water: HashMap::new(),
            funding_high_water: HashMap::new(),
            retired: HashSet::new(),
            slow: HashSet::new(),
        }
    }

    /// Holds this feed's prices and venue reports to `slow_max_age`. The client
    /// calls it for each funding or open interest feed that it subscribes to.
    pub fn mark_slow(&mut self, feed_id: FeedId) {
        self.slow.insert(feed_id);
    }

    fn max_age(&self, feed_id: FeedId) -> Duration {
        if self.slow.contains(&feed_id) {
            self.config.slow_max_age
        } else {
            self.config.max_age
        }
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
        self.high_water
            .retain(|(node, _), _| still_listed.contains(node));
        self.venue_high_water
            .retain(|(node, _), _| still_listed.contains(node));
        self.book_high_water
            .retain(|(node, _), _| still_listed.contains(node));
        self.funding_high_water
            .retain(|(node, _), _| still_listed.contains(node));
        self.registry = registry;
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
        let parsed = UnverifiedFrame::parse(frame).map_err(VerifyError::from)?;
        let verified = match parsed.verify(&self.registry) {
            Ok(verified) => verified,
            Err(VerifyError::UnknownSigner { signer }) if self.retired.contains(&signer) => {
                return Err(RejectReason::RetiredKey { signer });
            }
            Err(error) => return Err(error.into()),
        };
        let update = *verified.update();
        let signer = verified.signer();
        let node_index = verified.node_index();

        if update.observation_time_ns > update.publish_time_ns {
            return Err(RejectReason::IncoherentTimestamps { signer });
        }
        // Clock checks before the sequence update, so a rejected frame cannot
        // advance the high-water mark and lock out the legitimate one behind it.
        self.check_clock(
            signer,
            update.publish_time_ns,
            now_ns,
            self.max_age(update.feed_id),
        )?;
        advance(
            &mut self.high_water,
            (signer, update.feed_id),
            update.seq,
            signer,
        )?;
        Ok(Accepted {
            update,
            signer,
            node_index,
        })
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
        let parsed = UnverifiedVenueFrame::parse(frame).map_err(VerifyError::from)?;
        let verified = match parsed.verify(&self.registry) {
            Ok(verified) => verified,
            Err(VerifyError::UnknownSigner { signer }) if self.retired.contains(&signer) => {
                return Err(RejectReason::RetiredKey { signer });
            }
            Err(error) => return Err(error.into()),
        };
        let (signer, node_index) = (verified.signer(), verified.node_index());
        let report = verified.into_report();
        if !report.timestamps_coherent() {
            return Err(RejectReason::IncoherentTimestamps { signer });
        }
        self.check_clock(
            signer,
            report.publish_time_ns,
            now_ns,
            self.max_age(report.feed_id),
        )?;
        advance(
            &mut self.venue_high_water,
            (signer, report.feed_id),
            report.seq,
            signer,
        )?;
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
        let parsed = UnverifiedBookFrame::parse(frame).map_err(VerifyError::from)?;
        let verified = match parsed.verify(&self.registry) {
            Ok(verified) => verified,
            Err(VerifyError::UnknownSigner { signer }) if self.retired.contains(&signer) => {
                return Err(RejectReason::RetiredKey { signer });
            }
            Err(error) => return Err(error.into()),
        };
        let (signer, node_index) = (verified.signer(), verified.node_index());
        let update = verified.into_update();
        if !update.timestamps_coherent() {
            return Err(RejectReason::IncoherentTimestamps { signer });
        }
        self.check_clock(signer, update.publish_time_ns, now_ns, self.config.max_age)?;
        let book = InstrumentId::new(update.venue, update.market, update.symbol.as_str());
        let key = (signer, book);
        if let Some(last_seq) = self.book_high_water.get(&key).copied()
            && update.seq <= last_seq
        {
            return Err(RejectReason::Replayed {
                signer,
                seq: update.seq,
                last_seq,
            });
        }
        self.book_high_water.insert(key, update.seq);
        Ok(AcceptedBook {
            update,
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
        let parsed = UnverifiedFundingFrame::parse(frame).map_err(VerifyError::from)?;
        let verified = match parsed.verify(&self.registry) {
            Ok(verified) => verified,
            Err(VerifyError::UnknownSigner { signer }) if self.retired.contains(&signer) => {
                return Err(RejectReason::RetiredKey { signer });
            }
            Err(error) => return Err(error.into()),
        };
        let (signer, node_index) = (verified.signer(), verified.node_index());
        let update = verified.into_update();
        if !update.timestamps_coherent() {
            return Err(RejectReason::IncoherentTimestamps { signer });
        }
        self.check_clock(signer, update.publish_time_ns, now_ns, FUNDING_MAX_AGE)?;
        let perpetual = InstrumentId::new(update.venue, update.market, update.symbol.as_str());
        let key = (signer, perpetual);
        if let Some(last_seq) = self.funding_high_water.get(&key).copied()
            && update.seq <= last_seq
        {
            return Err(RejectReason::Replayed {
                signer,
                seq: update.seq,
                last_seq,
            });
        }
        self.funding_high_water.insert(key, update.seq);
        Ok(AcceptedFunding {
            update,
            signer,
            node_index,
        })
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

/// Raises the high-water mark for `key`, or refuses a sequence that does not
/// advance.
fn advance(
    marks: &mut HashMap<(Address, FeedId), u64>,
    key: (Address, FeedId),
    seq: u64,
    signer: Address,
) -> Result<(), RejectReason> {
    if let Some(last_seq) = marks.get(&key).copied()
        && seq <= last_seq
    {
        return Err(RejectReason::Replayed {
            signer,
            seq,
            last_seq,
        });
    }
    marks.insert(key, seq);
    Ok(())
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
    use crate::testing::{TestNode, registry_with, update_at, venues_at};
    use oracle_types::NANOS_PER_SEC;

    const NOW: u64 = 1_754_582_400 * NANOS_PER_SEC;

    fn verifier(node: &TestNode) -> Verifier {
        Verifier::new(registry_with(&[node]), VerifyConfig::default())
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
