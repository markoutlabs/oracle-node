//! Which updates the node pushes to the registry canister, and when.
//!
//! The canister resolves each listed feed to the median of the nodes. A node
//! pushes a feed when its price moved, when its flags changed, or when a
//! heartbeat passed, and pushes at most once per interval: each push costs
//! the canister cycles. The due updates go out as one signed batch.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use ic_agent::export::Principal;
use ic_agent::export::reqwest::Url;
use oracle_types::{FeedId, Flags, PriceUpdate};

use crate::config::{ConfigError, NodeConfig};

/// The most updates in one push: one batch holds this many.
pub const MAX_UPDATES_PER_PUSH: usize = oracle_wire::MAX_BATCH_UPDATES;

/// The canister refuses an update older than 30 s. An older latest update
/// means the feed stopped, and a push of it would only be refused.
pub const MAX_FRAME_AGE: Duration = Duration::from_secs(25);

/// The longest heartbeat. The canister's price window must hold two of them;
/// the node warns when it does not.
const MAX_HEARTBEAT_SECS: u64 = 60;

/// When to push a feed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushPolicy {
    /// Push each feed at least this often.
    pub heartbeat: Duration,
    /// Push a feed at once when its price moved this much, in basis points.
    pub deviation_bps: u32,
    /// Push at most this often.
    pub min_interval: Duration,
}

/// Where the pushes go, from the `[publish]` and `[registry]` sections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushTarget {
    /// The Internet Computer API.
    pub gateway: String,
    /// The registry canister.
    pub canister: Principal,
    /// The root key of the canister's network, DER. `None` on mainnet.
    pub root_key: Option<Vec<u8>>,
    /// When to push.
    pub policy: PushPolicy,
}

impl PushTarget {
    /// The target of a config with a `[publish]` section, or `None` without one.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] for a gateway that is not a URL, a
    /// missing or invalid `registry.canister_id` or `registry.root_key`, or
    /// an interval out of range.
    pub fn from_config(config: &NodeConfig) -> Result<Option<Self>, ConfigError> {
        let Some(publish) = &config.publish else {
            return Ok(None);
        };
        let invalid = |text: String| ConfigError::Invalid(format!("publish: {text}"));
        Url::parse(&publish.gateway)
            .map_err(|error| invalid(format!("gateway `{}`: {error}", publish.gateway)))?;
        let canister = config
            .registry
            .canister_id
            .as_deref()
            .ok_or_else(|| invalid("the pushes need registry.canister_id".to_owned()))?;
        let canister = Principal::from_text(canister)
            .map_err(|error| invalid(format!("registry.canister_id `{canister}`: {error}")))?;
        let root_key = config
            .registry
            .root_key
            .as_deref()
            .map(hex::decode)
            .transpose()
            .map_err(|error| invalid(format!("registry.root_key: {error}")))?;
        if !(1..=MAX_HEARTBEAT_SECS).contains(&publish.heartbeat_secs) {
            return Err(invalid(format!(
                "heartbeat_secs must be 1 to {MAX_HEARTBEAT_SECS}"
            )));
        }
        if !(1..=publish.heartbeat_secs).contains(&publish.min_interval_secs) {
            return Err(invalid(
                "min_interval_secs must be 1 to heartbeat_secs".to_owned(),
            ));
        }
        if publish.deviation_bps == 0 {
            return Err(invalid("deviation_bps must be at least 1".to_owned()));
        }
        Ok(Some(Self {
            gateway: publish.gateway.clone(),
            canister,
            root_key,
            policy: PushPolicy {
                heartbeat: Duration::from_secs(publish.heartbeat_secs),
                deviation_bps: publish.deviation_bps,
                min_interval: Duration::from_secs(publish.min_interval_secs),
            },
        }))
    }
}

#[derive(Clone, Copy, Debug)]
struct Pushed {
    price: i64,
    flags: Flags,
    seq: u64,
    at_ns: u64,
}

/// Decides which of the node's latest updates to push.
#[derive(Debug)]
pub struct PushPlanner {
    policy: PushPolicy,
    feeds: HashSet<FeedId>,
    pushed: HashMap<FeedId, Pushed>,
    last_attempt_ns: Option<u64>,
}

impl PushPlanner {
    /// A planner with no feeds yet.
    #[must_use]
    pub fn new(policy: PushPolicy) -> Self {
        Self {
            policy,
            feeds: HashSet::new(),
            pushed: HashMap::new(),
            last_attempt_ns: None,
        }
    }

    /// Sets the feeds that the canister prices.
    pub fn set_feeds(&mut self, feeds: impl IntoIterator<Item = FeedId>) {
        self.feeds = feeds.into_iter().collect();
        self.pushed.retain(|feed, _| self.feeds.contains(feed));
    }

    /// The number of feeds that the canister prices.
    #[must_use]
    pub fn feed_count(&self) -> usize {
        self.feeds.len()
    }

    /// The updates to push at `now_ns`, at most [`MAX_UPDATES_PER_PUSH`].
    /// Empty within `min_interval` of the last attempt.
    pub fn due<'a>(
        &self,
        latest: impl IntoIterator<Item = &'a PriceUpdate>,
        now_ns: u64,
    ) -> Vec<PriceUpdate> {
        let since = |at_ns: u64| Duration::from_nanos(now_ns.saturating_sub(at_ns));
        if self
            .last_attempt_ns
            .is_some_and(|at| since(at) < self.policy.min_interval)
        {
            return Vec::new();
        }
        latest
            .into_iter()
            .filter(|update| self.feeds.contains(&update.feed_id))
            .filter(|update| since(update.publish_time_ns) <= MAX_FRAME_AGE)
            .filter(|update| match self.pushed.get(&update.feed_id) {
                None => true,
                Some(last) => {
                    update.seq > last.seq
                        && (update.flags != last.flags
                            || self.moved(last.price, update.price)
                            || since(last.at_ns) >= self.policy.heartbeat)
                }
            })
            .take(MAX_UPDATES_PER_PUSH)
            .copied()
            .collect()
    }

    fn moved(&self, from: i64, to: i64) -> bool {
        let change = (i128::from(to) - i128::from(from)).abs() * 10_000;
        change >= i128::from(self.policy.deviation_bps) * i128::from(from).abs() && to != from
    }

    /// Records a push attempt, so the next one waits `min_interval`.
    pub const fn attempted(&mut self, now_ns: u64) {
        self.last_attempt_ns = Some(now_ns);
    }

    /// Records an update that the canister now holds, or holds a newer one of.
    pub fn landed(&mut self, update: &PriceUpdate, now_ns: u64) {
        self.pushed.insert(
            update.feed_id,
            Pushed {
                price: update.price,
                flags: update.flags,
                seq: update.seq,
                at_ns: now_ns,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use oracle_client::testing::update_at;

    use super::*;

    const SEC: u64 = 1_000_000_000;
    const T0: u64 = 1_800_000_000 * SEC;

    fn planner() -> PushPlanner {
        let mut planner = PushPlanner::new(PushPolicy {
            heartbeat: Duration::from_secs(30),
            deviation_bps: 10,
            min_interval: Duration::from_secs(5),
        });
        planner.set_feeds([FeedId::from_bytes([7; 32])]);
        planner
    }

    fn at(published: u64, seq: u64, price: i64) -> PriceUpdate {
        let mut update = update_at(published, seq);
        update.price = price;
        update
    }

    fn due(planner: &PushPlanner, latest: &PriceUpdate, now: u64) -> usize {
        planner.due([latest], now).len()
    }

    fn push(planner: &mut PushPlanner, latest: &PriceUpdate, now: u64) {
        let due = planner.due([latest], now);
        planner.attempted(now);
        for update in &due {
            planner.landed(update, now);
        }
    }

    #[test]
    fn a_new_feed_is_due_and_then_waits_for_a_move_or_the_heartbeat() {
        let mut planner = planner();
        let first = at(T0, 1, 1_000_000);
        assert_eq!(due(&planner, &first, T0), 1);
        push(&mut planner, &first, T0);

        let small = at(T0 + 10 * SEC, 2, 1_000_500);
        assert_eq!(
            due(&planner, &small, T0 + 10 * SEC),
            0,
            "5 bp is below 10 bp"
        );
        let large = at(T0 + 10 * SEC, 3, 1_001_000);
        assert_eq!(due(&planner, &large, T0 + 10 * SEC), 1, "10 bp moves it");
        let quiet = at(T0 + 30 * SEC, 4, 1_000_000);
        assert_eq!(due(&planner, &quiet, T0 + 30 * SEC), 1, "the heartbeat");
    }

    #[test]
    fn a_flag_change_is_due_at_once() {
        let mut planner = planner();
        let first = at(T0, 1, 1_000_000);
        push(&mut planner, &first, T0);
        let mut halted = at(T0 + 6 * SEC, 2, 1_000_000);
        halted.flags = Flags::HALTED;
        assert_eq!(due(&planner, &halted, T0 + 6 * SEC), 1);
    }

    #[test]
    fn pushes_keep_the_minimum_interval_even_after_a_failure() {
        let mut planner = planner();
        let first = at(T0, 1, 1_000_000);
        planner.attempted(T0);
        assert_eq!(due(&planner, &first, T0 + 4 * SEC), 0);
        assert_eq!(
            due(&planner, &first, T0 + 5 * SEC),
            1,
            "a failed push retries"
        );
    }

    #[test]
    fn an_old_frame_or_an_unlisted_feed_is_never_due() {
        let planner = planner();
        let old = at(T0, 1, 1_000_000);
        assert_eq!(due(&planner, &old, T0 + 26 * SEC), 0);
        let mut other = at(T0, 1, 1_000_000);
        other.feed_id = FeedId::from_bytes([8; 32]);
        assert_eq!(due(&planner, &other, T0), 0);
    }

    #[test]
    fn a_push_carries_at_most_one_batch() {
        let mut planner = planner();
        let ids: Vec<FeedId> = (0..40).map(|n| FeedId::from_bytes([n; 32])).collect();
        planner.set_feeds(ids.iter().copied());
        let latest: Vec<PriceUpdate> = ids
            .iter()
            .map(|id| PriceUpdate {
                feed_id: *id,
                ..at(T0, 1, 1)
            })
            .collect();
        assert_eq!(planner.due(&latest, T0).len(), MAX_UPDATES_PER_PUSH);
    }
}
