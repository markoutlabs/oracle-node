//! Cross-node resolution: M-of-N signed updates into one price.
//!
//! This is where multi-node actually happens, and it is the piece a consumer left
//! to their own devices is most likely to get wrong — which is why it ships as a
//! library rather than as documentation.
//!
//! # The crux
//!
//! Inter-node disagreement feeds directly into the published confidence. A single
//! compromised or malfunctioning node cannot move the median, and its
//! disagreement automatically widens the band — so a consumer that keys off
//! `conf` reacts correctly with no extra logic and no extra vigilance.
//!
//! # What this cannot defend against
//!
//! Nodes running identical software. The median defends against key compromise,
//! operator compromise, and machine failure — all independent faults. A bug in
//! the shared aggregation code is perfectly correlated: every node signs the same
//! wrong price, with valid signatures, and every check here passes. See
//! SPEC.md §12.3.

use std::collections::HashMap;
use std::time::Duration;

use oracle_agg::stats;
use oracle_types::{FeedId, Fixed, PriceUpdate};

use crate::verify::NodeId;

/// Quorum and divergence policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuorumConfig {
    /// Distinct nodes required before a price is usable.
    pub quorum: usize,

    /// Inter-node spread above which the feed is reported degraded, in basis points.
    pub max_divergence_bps: Fixed,

    /// Drop a node's update once it is older than this.
    ///
    /// Applied again here, not only in the verifier, because a node can go quiet
    /// after its last update was accepted. Without this the quorum would be met
    /// by nodes that stopped talking minutes ago.
    pub max_age: Duration,
}

impl Default for QuorumConfig {
    fn default() -> Self {
        Self {
            quorum: 3,
            max_divergence_bps: Fixed::from_raw(50 * 1_000_000_000_000),
            max_age: Duration::from_secs(2),
        }
    }
}

/// How much to trust a resolved price.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Enough nodes agree.
    Ok,
    /// Usable, but the confidence interval is doing real work. Act on `conf`.
    Degraded,
    /// Not usable for settlement or liquidation.
    Halted,
}

/// Why a feed is not `Ok`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Concern {
    /// Fewer live nodes than the quorum requires.
    InsufficientNodes,
    /// The nodes disagree by more than the configured band.
    NodeDivergence,
    /// At least one node reported its own feed degraded.
    NodeReportedDegraded,
    /// At least one node reported its own feed halted, and was excluded.
    NodeReportedHalted,
    /// The registry document is older than the configured maximum.
    ///
    /// The canister re-signs on a heartbeat even with no change (SPEC §3.6), so
    /// an old document means the fetch path is broken or something is
    /// withholding newer versions. Membership changes may be missing.
    RegistryStale,
}

/// A resolved price for one feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// The feed.
    pub feed_id: FeedId,
    /// How much to trust it.
    pub status: Status,
    /// The cross-node median, or `None` when halted with nothing to report.
    pub price: Option<Fixed>,
    /// Confidence half-width, never narrower than half the inter-node spread.
    pub conf: Option<Fixed>,
    /// Nodes that contributed.
    pub nodes: usize,
    /// Nodes excluded for reporting their own feed halted.
    pub halted_nodes: usize,
    /// Why it is not `Ok`.
    pub concerns: Vec<Concern>,
    /// The freshest contributing publish time.
    pub publish_time_ns: u64,
}

impl Resolved {
    /// Returns `true` if this price may be used for settlement.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        matches!(self.status, Status::Ok | Status::Degraded)
    }
}

/// The latest accepted update from each node, for one feed.
///
/// Keyed by node rather than by signing key. Keys rotate and registry indices
/// shift on every refresh; the node id is the one key that survives both, so a
/// node's seat and its last update follow it through a rotation.
#[derive(Clone, Debug, Default)]
pub struct FeedView {
    feed_id: FeedId,
    per_node: HashMap<NodeId, PriceUpdate>,
}

impl FeedView {
    /// Builds an empty view.
    #[must_use]
    pub fn new(feed_id: FeedId) -> Self {
        Self {
            feed_id,
            per_node: HashMap::new(),
        }
    }

    /// Records a node's latest update, keeping the newer of the two.
    ///
    /// Out-of-order arrival across nodes is normal; the verifier guarantees
    /// monotonicity per node, so a lower sequence here is a duplicate.
    pub fn record(&mut self, node: NodeId, update: PriceUpdate) {
        match self.per_node.get(&node) {
            Some(existing) if existing.seq >= update.seq => {}
            _ => {
                self.per_node.insert(node, update);
            }
        }
    }

    /// Drops every node not in `keep`.
    ///
    /// Called when a new registry version de-lists a node. Revocation has to take
    /// effect on the spot: a node left in place would keep counting toward the
    /// quorum on the strength of updates it sent while still trusted, for as long
    /// as those updates stayed inside the staleness window.
    pub fn retain_nodes(&mut self, keep: &dyn Fn(&str) -> bool) {
        self.per_node.retain(|node, _| keep(node));
    }

    /// Returns how many nodes have reported.
    #[must_use]
    pub fn len(&self) -> usize {
        self.per_node.len()
    }

    /// Returns `true` if no node has reported.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.per_node.is_empty()
    }

    /// Resolves the feed.
    #[must_use]
    pub fn resolve(&self, config: &QuorumConfig, now_ns: u64) -> Resolved {
        let max_age = u64::try_from(config.max_age.as_nanos()).unwrap_or(u64::MAX);
        let mut concerns = Vec::new();
        let mut halted_nodes = 0;

        let mut live: Vec<&PriceUpdate> = Vec::with_capacity(self.per_node.len());
        for update in self.per_node.values() {
            if update.flags.is_halted() {
                halted_nodes += 1;
                continue;
            }
            // A node that stopped talking must stop counting toward the quorum.
            if now_ns.saturating_sub(update.publish_time_ns) > max_age {
                continue;
            }
            live.push(update);
        }
        if halted_nodes > 0 {
            concerns.push(Concern::NodeReportedHalted);
        }
        if live.iter().any(|update| update.flags.is_degraded()) {
            concerns.push(Concern::NodeReportedDegraded);
        }

        if live.len() < config.quorum {
            concerns.push(Concern::InsufficientNodes);
            return Resolved {
                feed_id: self.feed_id,
                status: Status::Halted,
                price: None,
                conf: None,
                nodes: live.len(),
                halted_nodes,
                concerns,
                publish_time_ns: 0,
            };
        }

        let mut prices: Vec<Fixed> = live.iter().filter_map(|u| u.price_fixed().ok()).collect();
        let mut confs: Vec<Fixed> = live.iter().filter_map(|u| u.conf_fixed().ok()).collect();

        let price = stats::median(&mut prices);
        let conf = stats::median(&mut confs).unwrap_or(Fixed::ZERO);

        // Half the inter-node spread is a floor on the published confidence.
        // This is what makes a disagreeing node visible to a consumer that only
        // ever looks at `conf`.
        let spread_half = match (prices.first(), prices.last()) {
            (Some(low), Some(high)) => high
                .checked_sub(*low)
                .and_then(|spread| spread.checked_div(Fixed::from_int(2).ok()?))
                .unwrap_or(Fixed::ZERO),
            _ => Fixed::ZERO,
        };
        let conf = conf.max(spread_half);

        if let (Some(price), Some(low), Some(high)) = (price, prices.first(), prices.last())
            && price.is_positive()
            && let Some(spread) = high.checked_sub(*low)
            && let Some(spread_bps) = spread.to_bps_of(price)
            && spread_bps > config.max_divergence_bps
        {
            concerns.push(Concern::NodeDivergence);
        }

        let status = if concerns.is_empty() {
            Status::Ok
        } else {
            Status::Degraded
        };
        let publish_time_ns = live.iter().map(|u| u.publish_time_ns).max().unwrap_or(0);

        Resolved {
            feed_id: self.feed_id,
            status,
            price,
            conf: Some(conf),
            nodes: live.len(),
            halted_nodes,
            concerns,
            publish_time_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_types::{Flags, NANOS_PER_SEC, Venue, VenueSet};

    const NOW: u64 = 1_754_582_400 * NANOS_PER_SEC;

    fn node(index: u8) -> NodeId {
        NodeId::from(format!("oracle-{index}").as_str())
    }

    fn update(price: &str, conf: &str, seq: u64, flags: Flags) -> PriceUpdate {
        let price: Fixed = price.parse().expect("valid decimal");
        let conf: Fixed = conf.parse().expect("valid decimal");
        PriceUpdate {
            feed_id: FeedId::from_bytes([7; 32]),
            flags,
            price: price.to_scaled(-8).expect("in range"),
            conf: conf.to_scaled_unsigned(-8).expect("in range"),
            expo: -8,
            publish_time_ns: NOW,
            observation_time_ns: NOW - 1_000_000,
            prev_publish_time_ns: NOW - NANOS_PER_SEC,
            seq,
            num_sources: 5,
            sources: Venue::ALL.into_iter().collect::<VenueSet>(),
        }
    }

    fn view(nodes: &[(u8, &str, &str, Flags)]) -> FeedView {
        let mut view = FeedView::new(FeedId::from_bytes([7; 32]));
        for (index, (id, price, conf, flags)) in nodes.iter().enumerate() {
            view.record(
                node(*id),
                update(price, conf, u64::try_from(index).unwrap_or(0) + 1, *flags),
            );
        }
        view
    }

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("valid decimal")
    }

    #[test]
    fn agreeing_nodes_resolve_cleanly() {
        let view = view(&[
            (1, "64000", "0.5", Flags::NONE),
            (2, "64000.1", "0.5", Flags::NONE),
            (3, "63999.9", "0.5", Flags::NONE),
        ]);
        let resolved = view.resolve(&QuorumConfig::default(), NOW);
        assert_eq!(resolved.status, Status::Ok);
        assert_eq!(resolved.price, Some(fixed("64000")));
        assert_eq!(resolved.nodes, 3);
        assert!(resolved.concerns.is_empty());
    }

    #[test]
    fn below_quorum_halts_and_reports_no_price() {
        let view = view(&[
            (1, "64000", "0.5", Flags::NONE),
            (2, "64000", "0.5", Flags::NONE),
        ]);
        let resolved = view.resolve(&QuorumConfig::default(), NOW);
        assert_eq!(resolved.status, Status::Halted);
        assert_eq!(
            resolved.price, None,
            "a halted feed must not offer a price to misuse"
        );
        assert!(!resolved.is_usable());
        assert!(resolved.concerns.contains(&Concern::InsufficientNodes));
    }

    /// The property the whole multi-node design rests on.
    #[test]
    fn one_compromised_node_cannot_move_the_median() {
        let honest = view(&[
            (1, "64000", "0.5", Flags::NONE),
            (2, "64000", "0.5", Flags::NONE),
            (3, "64000", "0.5", Flags::NONE),
        ]);
        let baseline = honest.resolve(&QuorumConfig::default(), NOW);

        let poisoned = view(&[
            (1, "64000", "0.5", Flags::NONE),
            (2, "64000", "0.5", Flags::NONE),
            (3, "64000", "0.5", Flags::NONE),
            (4, "1", "0.5", Flags::NONE),
            (5, "999999", "0.5", Flags::NONE),
        ]);
        let resolved = poisoned.resolve(&QuorumConfig::default(), NOW);
        assert_eq!(resolved.price, baseline.price, "the median must not move");
    }

    /// And the corollary: a disagreeing node widens the band automatically, so a
    /// consumer keying off `conf` reacts without any extra logic.
    #[test]
    fn node_disagreement_widens_the_confidence_and_degrades() {
        let view = view(&[
            (1, "64000", "0.5", Flags::NONE),
            (2, "64000", "0.5", Flags::NONE),
            (3, "65000", "0.5", Flags::NONE),
        ]);
        let resolved = view.resolve(&QuorumConfig::default(), NOW);
        assert_eq!(resolved.status, Status::Degraded);
        assert!(resolved.concerns.contains(&Concern::NodeDivergence));
        assert_eq!(
            resolved.conf,
            Some(fixed("500")),
            "half the inter-node spread"
        );
        assert!(
            resolved.is_usable(),
            "degraded is still usable — that is the point"
        );
    }

    #[test]
    fn confidence_is_never_narrower_than_the_node_spread() {
        // Every node claims great precision while disagreeing by 100.
        let view = view(&[
            (1, "64000", "0.01", Flags::NONE),
            (2, "64050", "0.01", Flags::NONE),
            (3, "64100", "0.01", Flags::NONE),
        ]);
        let resolved = view.resolve(&QuorumConfig::default(), NOW);
        assert_eq!(resolved.conf, Some(fixed("50")));
    }

    #[test]
    fn a_node_reporting_halted_is_excluded_and_rechecked_against_quorum() {
        let view = view(&[
            (1, "64000", "0.5", Flags::NONE),
            (2, "64000", "0.5", Flags::NONE),
            (3, "64000", "0.5", Flags::HALTED),
        ]);
        let resolved = view.resolve(&QuorumConfig::default(), NOW);
        assert_eq!(resolved.halted_nodes, 1);
        assert_eq!(
            resolved.status,
            Status::Halted,
            "excluding it drops us below quorum"
        );
        assert!(resolved.concerns.contains(&Concern::InsufficientNodes));
    }

    #[test]
    fn a_node_reporting_degraded_degrades_the_result() {
        let view = view(&[
            (1, "64000", "0.5", Flags::NONE),
            (2, "64000", "0.5", Flags::NONE),
            (3, "64000", "0.5", Flags::DEGRADED),
        ]);
        let resolved = view.resolve(&QuorumConfig::default(), NOW);
        assert_eq!(resolved.status, Status::Degraded);
        assert!(resolved.concerns.contains(&Concern::NodeReportedDegraded));
    }

    /// A node that goes quiet must stop counting, or the quorum becomes a count
    /// of nodes that once existed.
    #[test]
    fn nodes_that_stop_publishing_age_out_of_the_quorum() {
        let view = view(&[
            (1, "64000", "0.5", Flags::NONE),
            (2, "64000", "0.5", Flags::NONE),
            (3, "64000", "0.5", Flags::NONE),
        ]);
        let later = NOW + 10 * NANOS_PER_SEC;
        let resolved = view.resolve(&QuorumConfig::default(), later);
        assert_eq!(resolved.nodes, 0);
        assert_eq!(resolved.status, Status::Halted);
    }

    #[test]
    fn a_later_update_from_the_same_node_replaces_the_earlier_one() {
        let mut view = FeedView::new(FeedId::from_bytes([7; 32]));
        view.record(node(1), update("64000", "0.5", 1, Flags::NONE));
        view.record(node(1), update("64500", "0.5", 2, Flags::NONE));
        assert_eq!(view.len(), 1);

        // An out-of-order duplicate must not overwrite the newer value.
        view.record(node(1), update("1", "0.5", 1, Flags::NONE));
        view.record(node(2), update("64500", "0.5", 1, Flags::NONE));
        view.record(node(3), update("64500", "0.5", 1, Flags::NONE));

        let resolved = view.resolve(&QuorumConfig::default(), NOW);
        assert_eq!(resolved.price, Some(fixed("64500")));
    }

    #[test]
    fn an_even_number_of_nodes_averages_the_middle_two() {
        let view = view(&[
            (1, "64000", "0.5", Flags::NONE),
            (2, "64010", "0.5", Flags::NONE),
            (3, "64020", "0.5", Flags::NONE),
            (4, "64030", "0.5", Flags::NONE),
        ]);
        let resolved = view.resolve(&QuorumConfig::default(), NOW);
        assert_eq!(resolved.price, Some(fixed("64015")));
    }
}
