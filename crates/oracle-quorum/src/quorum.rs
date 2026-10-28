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
use oracle_types::{FeedId, FeedKind, Fixed, PriceUpdate, Symbol};
use oracle_wire::Address;
use serde::{Deserialize, Serialize};

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

    /// The same limit for a slow feed (funding, open interest), which nodes
    /// publish on a 10 s heartbeat.
    pub slow_max_age: Duration,
}

impl Default for QuorumConfig {
    fn default() -> Self {
        Self {
            quorum: 3,
            max_divergence_bps: Fixed::from_raw(50 * 1_000_000_000_000),
            max_age: Duration::from_secs(2),
            slow_max_age: crate::verify::SLOW_MAX_AGE,
        }
    }
}

impl QuorumConfig {
    /// Returns the staleness limit for a feed of this kind.
    #[must_use]
    pub const fn max_age_for(&self, kind: FeedKind) -> Duration {
        if kind.is_slow() {
            self.slow_max_age
        } else {
            self.max_age
        }
    }
}

/// How much to trust a resolved price.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Enough nodes agree.
    Ok,
    /// Usable, but the confidence interval is doing real work. Act on `conf`.
    Degraded,
    /// Not usable for settlement or liquidation.
    Halted,
}

impl Status {
    /// Returns the canonical name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Degraded => "degraded",
            Self::Halted => "halted",
        }
    }
}

/// Why a feed is not `Ok`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    /// No certified fetch has confirmed the registry within the configured maximum.
    ///
    /// The fetch path is broken or something is withholding newer versions
    /// (SPEC §3.6). Membership changes may be missing.
    RegistryStale,
}

impl Concern {
    /// Returns the canonical name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InsufficientNodes => "insufficient_nodes",
            Self::NodeDivergence => "node_divergence",
            Self::NodeReportedDegraded => "node_reported_degraded",
            Self::NodeReportedHalted => "node_reported_halted",
            Self::RegistryStale => "registry_stale",
        }
    }
}

/// What one node's latest update for a feed counts as, by the rules of
/// [`FeedView::resolve`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeFeedState {
    /// Fresh, and counted toward the quorum.
    Live,
    /// Fresh and counted, but the node flags its own sources as degraded.
    Degraded,
    /// The node reports the feed halted. It does not count.
    Halted,
    /// Older than the feed's staleness limit. It does not count.
    Stale,
}

impl NodeFeedState {
    /// Classifies one node's latest update against the feed's staleness limit,
    /// [`QuorumConfig::max_age_for`].
    #[must_use]
    pub fn of(update: &PriceUpdate, max_age: Duration, now_ns: u64) -> Self {
        // A node that stopped talking must stop counting toward the quorum, and a
        // halt it reported before it went silent must stop counting too.
        let max_age = u64::try_from(max_age.as_nanos()).unwrap_or(u64::MAX);
        if now_ns.saturating_sub(update.publish_time_ns) > max_age {
            return Self::Stale;
        }
        if update.flags.is_halted() {
            return Self::Halted;
        }
        if update.flags.is_degraded() {
            Self::Degraded
        } else {
            Self::Live
        }
    }

    /// Returns `true` if the update counts toward the quorum.
    #[must_use]
    pub const fn counts(self) -> bool {
        matches!(self, Self::Live | Self::Degraded)
    }
}

/// A resolved price for one feed.
///
/// As JSON, decimals and the publish time are strings: a JavaScript number
/// loses precision on a nanosecond timestamp.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolved {
    /// The feed.
    pub feed_id: FeedId,
    /// The feed's symbol. The client sets it for every subscribed feed; a
    /// [`FeedView`] on its own cannot know it.
    pub symbol: Option<Symbol>,
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
    #[serde(with = "oracle_types::num_str")]
    pub publish_time_ns: u64,
    /// Inter-node spread as basis points of the median's size, when there is a price.
    ///
    /// The number [`Concern::NodeDivergence`] is judged on, reported whether or
    /// not it crossed the line. A monitor watches it move; an alert fires on it.
    pub spread_bps: Option<Fixed>,
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
/// Keyed by node address, because registry indices shift on every refresh. A
/// rotation lists a new address, so the seat moves to it.
#[derive(Clone, Debug, Default)]
pub struct FeedView {
    feed_id: FeedId,
    kind: FeedKind,
    per_node: HashMap<Address, PriceUpdate>,
}

impl FeedView {
    /// Builds an empty view of a price feed.
    #[must_use]
    pub fn new(feed_id: FeedId) -> Self {
        Self::with_kind(feed_id, FeedKind::Price)
    }

    /// Builds an empty view of a feed of this kind. A slow kind gets the slow
    /// staleness limit.
    #[must_use]
    pub fn with_kind(feed_id: FeedId, kind: FeedKind) -> Self {
        Self {
            feed_id,
            kind,
            per_node: HashMap::new(),
        }
    }

    /// Returns the feed's kind.
    #[must_use]
    pub const fn kind(&self) -> FeedKind {
        self.kind
    }

    /// Records a node's latest update, keeping the newer of the two.
    ///
    /// Out-of-order arrival across nodes is normal; the verifier guarantees
    /// monotonicity per node, so a lower sequence here is a duplicate.
    pub fn record(&mut self, node: Address, update: PriceUpdate) {
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
    pub fn retain_nodes(&mut self, keep: &dyn Fn(&Address) -> bool) {
        self.per_node.retain(|node, _| keep(node));
    }

    /// Returns how many nodes have reported.
    #[must_use]
    pub fn len(&self) -> usize {
        self.per_node.len()
    }

    /// Every node's latest accepted update, in no particular order.
    pub fn latest(&self) -> impl Iterator<Item = (&Address, &PriceUpdate)> {
        self.per_node.iter()
    }

    /// One node's latest accepted update.
    #[must_use]
    pub fn get(&self, node: &Address) -> Option<&PriceUpdate> {
        self.per_node.get(node)
    }

    /// Returns `true` if no node has reported.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.per_node.is_empty()
    }

    /// Resolves the feed.
    #[must_use]
    pub fn resolve(&self, config: &QuorumConfig, now_ns: u64) -> Resolved {
        let mut concerns = Vec::new();
        let mut halted_nodes = 0;
        let max_age = config.max_age_for(self.kind);

        let mut live: Vec<(&PriceUpdate, Fixed, Fixed)> = Vec::with_capacity(self.per_node.len());
        for update in self.per_node.values() {
            match NodeFeedState::of(update, max_age, now_ns) {
                NodeFeedState::Halted => halted_nodes += 1,
                NodeFeedState::Stale => {}
                NodeFeedState::Live | NodeFeedState::Degraded => {
                    // A price that does not convert cannot enter the median, so it
                    // must not count toward the quorum either.
                    if let (Ok(price), Ok(conf)) = (update.price_fixed(), update.conf_fixed()) {
                        live.push((update, price, conf));
                    }
                }
            }
        }
        if halted_nodes > 0 {
            concerns.push(Concern::NodeReportedHalted);
        }
        if live.iter().any(|(update, ..)| update.flags.is_degraded()) {
            concerns.push(Concern::NodeReportedDegraded);
        }

        if live.len() < config.quorum {
            concerns.push(Concern::InsufficientNodes);
            return Resolved {
                feed_id: self.feed_id,
                symbol: None,
                status: Status::Halted,
                price: None,
                conf: None,
                nodes: live.len(),
                halted_nodes,
                concerns,
                publish_time_ns: 0,
                spread_bps: None,
            };
        }

        let mut prices: Vec<Fixed> = live.iter().map(|(_, price, _)| *price).collect();
        let mut confs: Vec<Fixed> = live.iter().map(|(_, _, conf)| *conf).collect();

        let price = stats::median(&mut prices);
        let conf = stats::median(&mut confs).unwrap_or(Fixed::ZERO);

        // A spread too wide to compute is the widest disagreement there is.
        let spread = match (prices.first(), prices.last()) {
            (Some(low), Some(high)) => high.checked_sub(*low).unwrap_or(Fixed::MAX),
            _ => Fixed::ZERO,
        };
        // Half the inter-node spread is a floor on the published confidence, so a
        // consumer that reads only `conf` sees a disagreeing node. Halving the raw
        // value, rounded up, cannot overflow.
        let conf = conf.max(Fixed::from_raw(spread.raw() / 2 + spread.raw() % 2));

        // Against the size of the median, so that a funding rate at or below zero
        // is checked too. A spread with no size in basis points fails the check.
        let spread_bps = price
            .and_then(Fixed::checked_abs)
            .filter(|median| !median.is_zero())
            .and_then(|median| spread.to_bps_of(median));
        if spread_bps.map_or(!spread.is_zero(), |bps| bps > config.max_divergence_bps) {
            concerns.push(Concern::NodeDivergence);
        }

        let status = if concerns.is_empty() {
            Status::Ok
        } else {
            Status::Degraded
        };
        let publish_time_ns = live
            .iter()
            .map(|(update, ..)| update.publish_time_ns)
            .max()
            .unwrap_or(0);

        Resolved {
            feed_id: self.feed_id,
            symbol: None,
            status,
            price,
            conf: Some(conf),
            nodes: live.len(),
            halted_nodes,
            concerns,
            publish_time_ns,
            spread_bps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_types::{Flags, NANOS_PER_SEC, Venue, VenueSet};

    const NOW: u64 = 1_754_582_400 * NANOS_PER_SEC;

    fn node(index: u8) -> Address {
        Address::from_bytes([index; 20])
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

    #[test]
    fn a_slow_feed_stays_live_between_its_heartbeats() {
        let config = QuorumConfig {
            quorum: 1,
            ..QuorumConfig::default()
        };
        let next_heartbeat = NOW + 9 * NANOS_PER_SEC;
        let mut price = FeedView::new(FeedId::from_bytes([7; 32]));
        price.record(node(1), update("64000", "0.5", 1, Flags::NONE));
        assert_eq!(price.resolve(&config, next_heartbeat).nodes, 0);

        let mut funding = FeedView::with_kind(FeedId::from_bytes([7; 32]), FeedKind::Funding8h);
        funding.record(node(1), update("0.0001", "0.00001", 1, Flags::NONE));
        let resolved = funding.resolve(&config, next_heartbeat);
        assert_eq!(resolved.nodes, 1);
        assert_eq!(resolved.status, Status::Ok);
        let after_two_lost = funding.resolve(&config, NOW + 26 * NANOS_PER_SEC);
        assert_eq!(after_two_lost.status, Status::Halted);
    }

    #[test]
    fn a_resolved_price_is_json_with_strings_and_names() {
        let resolved = Resolved {
            feed_id: FeedId::from_bytes([7; 32]),
            symbol: Some("CRYPTO.BTC/USD".parse().expect("valid")),
            status: Status::Degraded,
            price: Some("86599.95".parse().expect("decimal")),
            conf: Some("19.71".parse().expect("decimal")),
            nodes: 3,
            halted_nodes: 1,
            concerns: vec![Concern::NodeReportedHalted],
            publish_time_ns: 1_754_582_400_123_456_789,
            spread_bps: None,
        };
        let json = serde_json::to_value(&resolved).expect("serializes");
        let field = |pointer: &str| json.pointer(pointer).cloned();
        assert_eq!(field("/status"), Some("degraded".into()));
        assert_eq!(field("/concerns/0"), Some("node_reported_halted".into()));
        assert_eq!(field("/price"), Some("86599.95".into()));
        assert_eq!(
            field("/publish_time_ns"),
            Some("1754582400123456789".into()),
            "a string"
        );
        assert_eq!(field("/symbol"), Some("CRYPTO.BTC/USD".into()));
        assert_eq!(field("/spread_bps"), Some(serde_json::Value::Null));
        let back: Resolved = serde_json::from_value(json).expect("parses");
        assert_eq!(back, resolved);
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

    fn two_of(view: &FeedView) -> Resolved {
        let config = QuorumConfig {
            quorum: 2,
            ..QuorumConfig::default()
        };
        view.resolve(&config, NOW)
    }

    #[test]
    fn a_node_too_far_off_to_measure_still_degrades_the_feed() {
        let mut view = view(&[(1, "64000", "0.5", Flags::NONE)]);
        let mut huge = update("1", "0", 1, Flags::NONE);
        huge.price = 200_000_000_000_000;
        huge.expo = 0;
        view.record(node(2), huge);
        let resolved = two_of(&view);
        assert!(resolved.concerns.contains(&Concern::NodeDivergence));
        assert_eq!(resolved.status, Status::Degraded);
        assert!(resolved.conf > Some(fixed("1000000000000")), "{resolved:?}");
    }

    #[test]
    fn a_median_at_or_below_zero_is_still_checked_for_divergence() {
        let split = view(&[
            (1, "-64000", "0.5", Flags::NONE),
            (2, "64000", "0.5", Flags::NONE),
        ]);
        assert!(two_of(&split).concerns.contains(&Concern::NodeDivergence));
        let agreeing = view(&[
            (1, "-0.0001", "0", Flags::NONE),
            (2, "-0.0001", "0", Flags::NONE),
        ]);
        assert_eq!(two_of(&agreeing).status, Status::Ok);
    }

    #[test]
    fn a_price_that_does_not_convert_does_not_count_toward_the_quorum() {
        let mut view = view(&[(1, "64000", "0.5", Flags::NONE)]);
        let mut broken = update("1", "0.5", 1, Flags::NONE);
        broken.expo = 30;
        view.record(node(2), broken);
        let resolved = two_of(&view);
        assert_eq!((resolved.status, resolved.nodes), (Status::Halted, 1));
    }

    #[test]
    fn a_halt_from_a_node_that_went_silent_ages_out() {
        let mut view = view(&[
            (1, "64000", "0.5", Flags::NONE),
            (2, "64000", "0.5", Flags::NONE),
        ]);
        let mut halted = update("64000", "0.5", 1, Flags::HALTED);
        halted.publish_time_ns = NOW - 10 * NANOS_PER_SEC;
        view.record(node(3), halted);
        let resolved = two_of(&view);
        assert_eq!((resolved.status, resolved.halted_nodes), (Status::Ok, 0));
    }
}
