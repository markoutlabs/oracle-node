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
use std::sync::Arc;
use std::time::Duration;

use oracle_types::{FeedId, NANOS_PER_SEC, PriceUpdate};
use oracle_wire::{
    Address, CompressedPublicKey, KeyHistoryEntry, UnverifiedFrame, VerifiedRegistry, VerifyError,
};

/// A node's stable identity across registry versions.
///
/// Registry indices are positional and signing addresses are rotated, so neither
/// survives the events this type exists to be correct across. Reference-counted
/// because it is cloned once per accepted frame on the hot path.
pub type NodeId = Arc<str>;

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

/// An update that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The update.
    pub update: PriceUpdate,
    /// The signing key it recovered to.
    ///
    /// Identifies the *key*, not the node. Keys rotate; anything that outlives a
    /// rotation must use [`Accepted::node`].
    pub signer: Address,
    /// Which node signed it.
    pub node: NodeId,
    /// That node's index in the registry it was verified against.
    ///
    /// Positional, and therefore only meaningful against that exact registry
    /// version. Use [`Accepted::node`] for anything that outlives a refresh.
    pub node_index: usize,
}

/// Verifies frames against a pinned registry and a freshness policy.
///
/// Holds the per-`(node, feed)` sequence high-water marks, so it must persist
/// across updates — a verifier rebuilt per message provides no replay protection
/// at all.
///
/// The marks are keyed by **node**, not by signing key. Keying them by key would
/// hand every rotation a fresh replay floor, and registry indices shift on every
/// refresh. The node id is the one key that survives both.
pub struct Verifier {
    registry: VerifiedRegistry,
    config: VerifyConfig,
    high_water: HashMap<(NodeId, FeedId), u64>,
    /// Registry index → node id, so the hot path clones an `Arc` rather than a
    /// `String` for every accepted frame.
    node_ids: Vec<NodeId>,
    /// Signing keys that a registry this verifier once trusted listed, and the
    /// current one does not. Reported as [`RejectReason::RetiredKey`] rather than
    /// unknown, so the client does not go looking for a registry it already has.
    retired: HashSet<Address>,
}

impl Verifier {
    /// Builds a verifier.
    #[must_use]
    pub fn new(registry: VerifiedRegistry, config: VerifyConfig) -> Self {
        Self {
            node_ids: intern_node_ids(&registry),
            registry,
            config,
            high_water: HashMap::new(),
            retired: HashSet::new(),
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
    /// replay window for nodes that remain listed. They survive the swap because
    /// they are keyed by node id, which is stable across versions, rather than by
    /// registry index, which is not.
    pub fn set_registry(&mut self, registry: VerifiedRegistry) {
        let still_listed: HashSet<Address> = signing_addresses(&registry).collect();
        for address in signing_addresses(&self.registry) {
            if !still_listed.contains(&address) {
                self.retired.insert(address);
            }
        }
        self.node_ids = intern_node_ids(&registry);
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
        let node = self
            .node_ids
            .get(node_index)
            .cloned()
            .ok_or(VerifyError::UnknownSigner { signer })?;

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

        let key = (Arc::clone(&node), update.feed_id);
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
            node,
            node_index,
        })
    }
}

/// Verifies a stored frame against the key that was live when it was published.
///
/// The live path never calls this. It serves audit and dispute: a frame signed
/// last month under a key since rotated must still verify, and one signed under
/// that key *after* it was retired must not (SPEC §3.5).
///
/// `identity` is the node's identity key, from any registry version that
/// listed the node. `history` is the node's key history as the registry
/// canister serves it. The certificate in each entry is checked against
/// `identity`; the retirement time is the canister's word.
///
/// # Errors
///
/// Returns [`VerifyError::UnknownSigner`] if no entry carries the signing key,
/// [`VerifyError::CertificateIssuerMismatch`] if its certificate was not issued
/// by `identity`, and [`VerifyError::CertificateNotYetValid`] or
/// [`VerifyError::CertificateExpired`] if the publish time falls outside the
/// key's live window.
pub fn verify_historical(
    frame: &[u8],
    identity: &CompressedPublicKey,
    history: &[KeyHistoryEntry],
) -> Result<PriceUpdate, VerifyError> {
    let parsed = UnverifiedFrame::parse(frame)?;
    let signer = parsed.recover_signer()?;
    let entry = history
        .iter()
        .find(|entry| entry.cert.address == signer)
        .ok_or(VerifyError::UnknownSigner { signer })?;

    let expected = identity.address()?;
    let issuer = entry.cert.recover_issuer()?;
    if issuer != expected {
        return Err(VerifyError::CertificateIssuerMismatch {
            node_id: entry.cert.node_id.clone(),
            address: signer,
            issuer,
            expected,
        });
    }

    let update = parsed.decode_unverified()?;
    entry.cert.check_covers(update.publish_time_ns)?;
    if let Some(retired_at) = entry.retired_at
        && update.publish_time_ns >= retired_at.saturating_mul(NANOS_PER_SEC)
    {
        return Err(VerifyError::CertificateExpired {
            signer,
            not_after: retired_at,
            published: update.publish_time_ns / NANOS_PER_SEC,
        });
    }
    Ok(update)
}

/// Every signing address a registry lists.
fn signing_addresses(registry: &VerifiedRegistry) -> impl Iterator<Item = Address> + '_ {
    registry
        .nodes()
        .iter()
        .flat_map(|node| node.signing_keys.iter().map(|cert| cert.address))
}

/// Interns the registry's node ids, positionally.
fn intern_node_ids(registry: &VerifiedRegistry) -> Vec<NodeId> {
    registry
        .nodes()
        .iter()
        .map(|node| NodeId::from(node.node_id.as_str()))
        .collect()
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

    /// Replay state follows the node, not the key. After a rotation the new key
    /// inherits the node's sequence floor rather than starting from nothing.
    #[test]
    fn rotating_a_signing_key_does_not_reopen_the_replay_window() {
        let mut node = TestNode::new(1, NODE_ID);
        let mut verifier = verifier(&node);
        let update = update_at(NOW, 5);
        assert!(verifier.accept(&node.sign(&update), NOW).is_ok());

        node.rotate();
        verifier.set_registry(registry_with(&[&node]));

        // The same sequence number, re-signed under the new key, is still a replay.
        assert!(
            matches!(
                verifier.accept(&node.sign(&update), NOW),
                Err(RejectReason::Replayed {
                    seq: 5,
                    last_seq: 5,
                    ..
                })
            ),
            "the new key must inherit the node's sequence floor"
        );
    }

    /// One live key per node. The old key is retired on adoption, and it is
    /// reported as retired rather than unknown, so the client does not go looking
    /// for a newer registry it already has.
    #[test]
    fn a_rotated_out_key_is_retired_not_unknown() {
        let mut node = TestNode::new(1, NODE_ID);
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
        assert_eq!(&*accepted.node, NODE_ID);
    }

    /// Stored frames verify against the key that was live when they were
    /// published, and not after that key was retired.
    #[test]
    fn historical_verification_follows_the_key_that_was_live() {
        let mut node = TestNode::new(1, NODE_ID);
        let before = node.sign(&update_at(NOW, 1));
        let later = NOW + 10 * NANOS_PER_SEC;
        let after_retirement = node.sign(&update_at(later, 2));

        node.rotate();
        let rotated_at = NOW / NANOS_PER_SEC + 5;
        let history = node.history(rotated_at);
        let identity = node.identity_key();

        assert!(verify_historical(&before, &identity, &history).is_ok());
        assert!(matches!(
            verify_historical(&after_retirement, &identity, &history),
            Err(VerifyError::CertificateExpired { not_after, .. }) if not_after == rotated_at
        ));
        assert!(
            verify_historical(&node.sign(&update_at(later, 3)), &identity, &history).is_ok(),
            "the live generation has no retirement bound"
        );

        let impostor = TestNode::new(9, "impostor");
        assert!(matches!(
            verify_historical(&before, &impostor.identity_key(), &history),
            Err(VerifyError::CertificateIssuerMismatch { .. })
        ));
        assert!(matches!(
            verify_historical(&impostor.sign(&update_at(NOW, 1)), &identity, &history),
            Err(VerifyError::UnknownSigner { .. })
        ));
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
