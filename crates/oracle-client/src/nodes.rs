//! What the client knows about each node: its connection, its frames, and what
//! it says for each feed. [`OracleClient::nodes`](crate::OracleClient::nodes)
//! reports it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use oracle_types::{Fixed, PriceUpdate, Symbol};
use oracle_wire::Address;
use serde::Serialize;

use crate::latency::{LatencyHistogram, Percentiles};
use crate::quorum::NodeFeedState;
use crate::verify::RejectReason;

/// The client's connection to one node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConnectionState {
    /// No connection: the client has not subscribed, or the node lists no endpoint.
    #[default]
    Idle,
    /// Dialling, or in the handshake.
    Connecting,
    /// The handshake passed.
    Connected {
        /// When the handshake passed.
        #[serde(with = "oracle_types::num_str")]
        since_ns: u64,
    },
    /// The last attempt failed or the session ended.
    Backoff {
        /// When the next attempt starts.
        #[serde(with = "oracle_types::num_str")]
        retry_at_ns: u64,
    },
}

/// One node's connection history, written by its connection task.
#[derive(Clone, Debug, Default)]
pub(crate) struct Link {
    pub(crate) state: ConnectionState,
    pub(crate) connects: u64,
    pub(crate) failures: u64,
    pub(crate) last_error: Option<String>,
}

/// The links of every node, shared between the client and its connection tasks.
#[derive(Clone, Debug, Default)]
pub(crate) struct Links(Arc<Mutex<HashMap<Address, Link>>>);

impl Links {
    pub(crate) fn update(&self, node: Address, change: impl FnOnce(&mut Link)) {
        let mut links = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        change(links.entry(node).or_default());
    }

    pub(crate) fn get(&self, node: &Address) -> Link {
        let links = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        links.get(node).cloned().unwrap_or_default()
    }
}

/// Frames from one node since the client started.
///
/// A frame from an unknown or retired key is not a node's frame, so only the
/// client-wide [`ClientStats`](crate::ClientStats) counts it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct NodeFrames {
    /// Price frames accepted.
    pub accepted: u64,
    /// Venue report frames accepted.
    pub venue_reports: u64,
    /// Book frames accepted.
    pub book_updates: u64,
    /// Funding frames accepted.
    pub funding_updates: u64,
    /// Frames refused as replays.
    pub replayed: u64,
    /// Frames refused as stale or future-dated.
    pub out_of_time: u64,
    /// Frames refused for incoherent timestamps.
    pub incoherent: u64,
}

/// The time between a node's signature and its receipt here.
///
/// Microseconds, over the last full minute. It compares the node clock with
/// this one, so it is exact only with clocks in sync.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DeliveryWindow {
    /// Price frames in the window.
    pub count: u64,
    /// The median.
    pub p50_us: u64,
    /// The 90th percentile.
    pub p90_us: u64,
    /// The 99th percentile.
    pub p99_us: u64,
    /// The largest value.
    pub max_us: u64,
}

impl From<Percentiles> for DeliveryWindow {
    fn from(percentiles: Percentiles) -> Self {
        let us = |value: Duration| u64::try_from(value.as_micros()).unwrap_or(u64::MAX);
        Self {
            count: percentiles.count,
            p50_us: us(percentiles.p50),
            p90_us: us(percentiles.p90),
            p99_us: us(percentiles.p99),
            max_us: us(percentiles.max),
        }
    }
}

/// The length of one delivery window.
const WINDOW: Duration = Duration::from_secs(60);

/// Delivery latency in whole minutes, so the report follows the present and
/// not the whole run.
#[derive(Clone, Debug, Default)]
struct Window {
    current: LatencyHistogram,
    started_ns: u64,
    last: Option<Percentiles>,
}

impl Window {
    fn record(&mut self, publish_ns: u64, received_ns: u64) {
        let window = u64::try_from(WINDOW.as_nanos()).unwrap_or(u64::MAX);
        if self.started_ns == 0 {
            self.started_ns = received_ns;
        } else if received_ns.saturating_sub(self.started_ns) >= window {
            self.last = Some(self.current.percentiles());
            self.current.reset();
            self.started_ns = received_ns;
        }
        self.current.record_between(publish_ns, received_ns);
    }

    /// The last full window, or the first one while it fills. Nothing once the
    /// node has been silent for two windows.
    fn report(&self, now_ns: u64) -> Option<DeliveryWindow> {
        let window = u64::try_from(WINDOW.as_nanos()).unwrap_or(u64::MAX);
        if self.started_ns == 0 || now_ns.saturating_sub(self.started_ns) > window.saturating_mul(2)
        {
            return None;
        }
        let current = self.current.percentiles();
        self.last
            .or_else(|| (current.count > 0).then_some(current))
            .map(DeliveryWindow::from)
    }
}

/// What the client counted for one node, on its own task.
#[derive(Clone, Debug, Default)]
pub(crate) struct Tally {
    pub(crate) frames: NodeFrames,
    pub(crate) last_frame_ns: Option<u64>,
    delivery: Window,
}

impl Tally {
    pub(crate) fn seen(&mut self, received_ns: u64) {
        self.last_frame_ns = Some(
            self.last_frame_ns
                .map_or(received_ns, |last| last.max(received_ns)),
        );
    }

    pub(crate) fn price(&mut self, update: &PriceUpdate, received_ns: u64) {
        self.frames.accepted = self.frames.accepted.saturating_add(1);
        self.delivery.record(update.publish_time_ns, received_ns);
        self.seen(received_ns);
    }

    pub(crate) fn delivery(&self, now_ns: u64) -> Option<DeliveryWindow> {
        self.delivery.report(now_ns)
    }
}

/// The node a rejection belongs to: a listed node's frame that failed a check.
pub(crate) const fn rejected_node(reason: &RejectReason) -> Option<Address> {
    match reason {
        RejectReason::Replayed { signer, .. }
        | RejectReason::TooOld { signer, .. }
        | RejectReason::FromTheFuture { signer, .. }
        | RejectReason::IncoherentTimestamps { signer } => Some(*signer),
        RejectReason::Untrusted(_) | RejectReason::RetiredKey { .. } => None,
        // Non-exhaustive outside oracle-quorum.
        _ => None,
    }
}

impl NodeFrames {
    pub(crate) const fn record(&mut self, reason: &RejectReason) {
        match reason {
            RejectReason::Replayed { .. } => self.replayed = self.replayed.saturating_add(1),
            RejectReason::TooOld { .. } | RejectReason::FromTheFuture { .. } => {
                self.out_of_time = self.out_of_time.saturating_add(1);
            }
            RejectReason::IncoherentTimestamps { .. } => {
                self.incoherent = self.incoherent.saturating_add(1);
            }
            RejectReason::Untrusted(_) | RejectReason::RetiredKey { .. } => {}
            _ => {}
        }
    }
}

/// What one node says for one feed now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NodeFeed {
    /// The feed.
    pub symbol: Symbol,
    /// What the node's latest update counts as. `None` until the node sends one.
    pub state: Option<NodeFeedState>,
    /// The node's price.
    pub price: Option<Fixed>,
    /// The node's confidence half-width.
    pub conf: Option<Fixed>,
    /// The node's price against the resolved median, in signed basis points.
    /// `None` without a median.
    pub deviation_bps: Option<Fixed>,
    /// When the node signed its latest update.
    #[serde(with = "oracle_types::opt_num_str")]
    pub publish_time_ns: Option<u64>,
    /// The sequence number of its latest update.
    #[serde(with = "oracle_types::opt_num_str")]
    pub seq: Option<u64>,
}

impl NodeFeed {
    pub(crate) fn new(
        symbol: Symbol,
        update: Option<&PriceUpdate>,
        state: Option<NodeFeedState>,
        median: Option<Fixed>,
    ) -> Self {
        let price = update.and_then(|update| update.price_fixed().ok());
        let deviation_bps = price
            .zip(median)
            .and_then(|(price, median)| price.checked_sub(median)?.to_bps_of(median));
        Self {
            symbol,
            state,
            price,
            conf: update.and_then(|update| update.conf_fixed().ok()),
            deviation_bps,
            publish_time_ns: update.map(|update| update.publish_time_ns),
            seq: update.map(|update| update.seq),
        }
    }
}

/// What the client knows about one node in its registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NodeReport {
    /// The node's signing address, its id in the registry.
    pub address: Address,
    /// The registry's weight hint.
    pub weight: u16,
    /// The registry's endpoints for the node.
    pub endpoints: Vec<String>,
    /// The connection now.
    pub connection: ConnectionState,
    /// Handshakes that passed.
    pub connects: u64,
    /// Connection attempts and sessions that ended with an error.
    pub failures: u64,
    /// The last such error.
    pub last_error: Option<String>,
    /// When the last accepted frame from the node arrived.
    #[serde(with = "oracle_types::opt_num_str")]
    pub last_frame_ns: Option<u64>,
    /// The node's frames since the client started.
    pub frames: NodeFrames,
    /// Delivery latency over the last minute.
    pub delivery: Option<DeliveryWindow>,
    /// The node's latest update for each subscribed price feed.
    pub feeds: Vec<NodeFeed>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_types::NANOS_PER_SEC;

    const MS: u64 = 1_000_000;
    const NOW: u64 = 1_754_582_400 * NANOS_PER_SEC;

    #[test]
    fn the_delivery_window_reports_the_last_full_minute() {
        let mut window = Window::default();
        window.record(NOW, NOW + 2 * MS);
        assert_eq!(
            window.report(NOW).map(|w| w.count),
            Some(1),
            "the first window, while it fills"
        );

        let minute = 60 * NANOS_PER_SEC;
        window.record(NOW + minute, NOW + minute + 9 * MS);
        let report = window.report(NOW + minute).expect("a full window");
        assert_eq!(report.count, 1);
        assert_eq!(report.p50_us, 2_000, "the full window, not the new one");

        assert_eq!(
            window.report(NOW + 4 * minute),
            None,
            "silent for two windows"
        );
    }

    #[test]
    fn deviation_is_signed_basis_points_of_the_median() {
        let symbol: Symbol = "CRYPTO.BTC/USD".parse().expect("valid");
        let mut update = crate::testing::update_at(NOW, 1);
        update.price = 10_010_000_000;
        update.expo = -8;
        let median = Some("100".parse().expect("decimal"));
        let feed = NodeFeed::new(symbol, Some(&update), Some(NodeFeedState::Live), median);
        assert_eq!(feed.price, Some("100.1".parse().expect("decimal")));
        assert_eq!(feed.deviation_bps, Some("10".parse().expect("decimal")));

        let missing = NodeFeed::new(symbol, None, None, median);
        assert_eq!(
            (missing.price, missing.deviation_bps, missing.seq),
            (None, None, None)
        );
    }

    #[test]
    fn a_connection_serializes_with_its_state_as_a_tag() {
        let json =
            serde_json::to_value(ConnectionState::Connected { since_ns: NOW }).expect("json");
        assert_eq!(
            json,
            serde_json::json!({"state": "connected", "since_ns": NOW.to_string()})
        );
        let idle = serde_json::to_value(ConnectionState::Idle).expect("json");
        assert_eq!(idle, serde_json::json!({"state": "idle"}));
    }
}
