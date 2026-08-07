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

use std::collections::HashMap;
use std::time::Duration;

use oracle_types::{FeedId, PriceUpdate};
use oracle_wire::{Address, UnverifiedFrame, VerifiedRegistry, VerifyError};

/// Freshness policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyConfig {
    /// Reject updates published longer ago than this.
    ///
    /// This is the **only** defence against a relay that withholds new updates
    /// and rebroadcasts an old, perfectly-signed one. There is no cryptographic
    /// substitute.
    pub max_age: Duration,

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
            max_skew: Duration::from_millis(500),
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
    #[error(transparent)]
    Untrusted(#[from] VerifyError),

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

/// An update that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The update.
    pub update: PriceUpdate,
    /// Which node signed it.
    pub signer: Address,
    /// That node's index in the registry it was verified against.
    pub node_index: usize,
}

/// Verifies frames against a pinned registry and a freshness policy.
///
/// Holds the per-`(node, feed)` sequence high-water marks, so it must persist
/// across updates — a verifier rebuilt per message provides no replay protection
/// at all.
pub struct Verifier {
    registry: VerifiedRegistry,
    config: VerifyConfig,
    high_water: HashMap<(Address, FeedId), u64>,
}

impl Verifier {
    /// Builds a verifier.
    #[must_use]
    pub fn new(registry: VerifiedRegistry, config: VerifyConfig) -> Self {
        Self {
            registry,
            config,
            high_water: HashMap::new(),
        }
    }

    /// Returns the registry in use.
    #[must_use]
    pub const fn registry(&self) -> &VerifiedRegistry {
        &self.registry
    }

    /// Replaces the registry, keeping the sequence high-water marks.
    ///
    /// Marks are retained deliberately: a registry rotation must not reopen the
    /// replay window for keys that remain listed.
    pub fn set_registry(&mut self, registry: VerifiedRegistry) {
        self.registry = registry;
    }

    /// Verifies one wire frame.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`]. Signature and registry failures come first, so a
    /// forged frame is never measured against the clock.
    pub fn accept(&mut self, frame: &[u8], now_ns: u64) -> Result<Accepted, RejectReason> {
        let parsed = UnverifiedFrame::parse(frame).map_err(VerifyError::from)?;
        let verified = parsed.verify(&self.registry)?;
        let update = *verified.update();
        let signer = verified.signer();

        if update.observation_time_ns > update.publish_time_ns {
            return Err(RejectReason::IncoherentTimestamps { signer });
        }

        // Clock checks before the sequence update, so a rejected frame cannot
        // advance the high-water mark and lock out the legitimate one behind it.
        if update.publish_time_ns > now_ns {
            let skew = update.publish_time_ns - now_ns;
            let limit = nanos(self.config.max_skew);
            if skew > limit {
                return Err(RejectReason::FromTheFuture {
                    signer,
                    skew_ms: skew / 1_000_000,
                    limit_ms: limit / 1_000_000,
                });
            }
        } else {
            let age = now_ns - update.publish_time_ns;
            let limit = nanos(self.config.max_age);
            if age > limit {
                return Err(RejectReason::TooOld {
                    signer,
                    age_ms: age / 1_000_000,
                    limit_ms: limit / 1_000_000,
                });
            }
        }

        let key = (signer, update.feed_id);
        if let Some(last_seq) = self.high_water.get(&key).copied()
            && update.seq <= last_seq
        {
            return Err(RejectReason::Replayed {
                signer,
                seq: update.seq,
                last_seq,
            });
        }
        self.high_water.insert(key, update.seq);

        Ok(Accepted {
            update,
            signer,
            node_index: verified.node_index(),
        })
    }
}

/// Converts a duration to nanoseconds, saturating.
fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{NODE_ID, TestNode, registry_with, update_at};
    use oracle_types::NANOS_PER_SEC;

    const NOW: u64 = 1_754_582_400 * NANOS_PER_SEC;

    fn verifier(node: &TestNode) -> Verifier {
        Verifier::new(registry_with(&[node]), VerifyConfig::default())
    }

    #[test]
    fn a_well_formed_update_from_a_registered_node_is_accepted() {
        let node = TestNode::new(1, NODE_ID);
        let mut verifier = verifier(&node);
        let frame = node.sign(&update_at(NOW, 1));
        let accepted = verifier.accept(&frame, NOW).expect("accepted");
        assert_eq!(accepted.signer, node.signing_address());
        assert_eq!(accepted.update.seq, 1);
    }

    #[test]
    fn an_update_from_an_unregistered_node_is_refused() {
        let node = TestNode::new(1, NODE_ID);
        let impostor = TestNode::new(9, "impostor");
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
        let node = TestNode::new(1, NODE_ID);
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
        let node = TestNode::new(1, NODE_ID);
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
        let node = TestNode::new(1, NODE_ID);
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
        let node = TestNode::new(1, NODE_ID);
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
        let node = TestNode::new(1, NODE_ID);
        let mut verifier = verifier(&node);
        let ahead = node.sign(&update_at(NOW + 5 * NANOS_PER_SEC, 1));
        assert!(matches!(
            verifier.accept(&ahead, NOW),
            Err(RejectReason::FromTheFuture { limit_ms: 500, .. })
        ));
    }

    #[test]
    fn small_clock_skew_is_tolerated() {
        let node = TestNode::new(1, NODE_ID);
        let mut verifier = verifier(&node);
        // 100ms ahead, inside the 500ms tolerance.
        let ahead = node.sign(&update_at(NOW + 100_000_000, 1));
        assert!(verifier.accept(&ahead, NOW).is_ok());
    }

    #[test]
    fn incoherent_timestamps_are_refused() {
        let node = TestNode::new(1, NODE_ID);
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
        let node = TestNode::new(1, NODE_ID);
        let mut verifier = verifier(&node);

        let future = node.sign(&update_at(NOW + 5 * NANOS_PER_SEC, 7));
        assert!(verifier.accept(&future, NOW).is_err());

        // The same sequence number, legitimately published now, must still pass.
        let genuine = node.sign(&update_at(NOW, 7));
        assert!(verifier.accept(&genuine, NOW).is_ok());
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let node = TestNode::new(1, NODE_ID);
        let mut verifier = verifier(&node);
        let mut frame = node.sign(&update_at(NOW, 1));
        // Flip a bit inside the signed region.
        if let Some(byte) = frame.get_mut(21 + 36) {
            *byte ^= 0x01;
        }
        assert!(verifier.accept(&frame, NOW).is_err());
    }

    #[test]
    fn rotating_the_registry_keeps_replay_protection() {
        let node = TestNode::new(1, NODE_ID);
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
