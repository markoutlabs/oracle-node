//! What the node reports about itself: once when it starts serving, then every
//! minute.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use console::style;
use oracle_client::{LatencyHistogram, Percentiles};
use oracle_types::{Observation, Venue};
use oracle_wire::Address;
use tracing::info;

/// How often the status line is written.
pub(crate) const STATUS_EVERY: Duration = Duration::from_secs(60);

/// The node as it starts serving.
pub(crate) struct Summary {
    pub(crate) listen: SocketAddr,
    pub(crate) address: Address,
    pub(crate) governance: Address,
    pub(crate) registry_version: u64,
    pub(crate) client_list_version: u64,
    pub(crate) clients: usize,
    pub(crate) feeds: usize,
    pub(crate) connections: usize,
}

impl Summary {
    pub(crate) fn log(&self) {
        info!(
            listen = %self.listen,
            address = %self.address,
            registry = self.registry_version,
            client_list = self.client_list_version,
            clients = self.clients,
            feeds = self.feeds,
            connections = self.connections,
            "serving subscribers"
        );
    }

    /// A block for a person at a terminal, written to stderr like the logs.
    pub(crate) fn banner(&self) -> String {
        let label = |text: &str| style(format!("{text:<12}")).for_stderr().dim();
        let lines = [
            (
                "node",
                style(self.address.to_checksummed())
                    .for_stderr()
                    .bold()
                    .to_string(),
            ),
            ("governance", self.governance.to_checksummed()),
            ("registry", format!("v{}", self.registry_version)),
            (
                "clients",
                format!(
                    "{} listed, client list v{}",
                    self.clients, self.client_list_version
                ),
            ),
            (
                "feeds",
                format!("{} over {} venue connections", self.feeds, self.connections),
            ),
        ];
        let mut out = format!(
            "\n  {} {}  serving on {}\n\n",
            style("oracle-node").for_stderr().bold().green(),
            env!("CARGO_PKG_VERSION"),
            style(self.listen).for_stderr().bold(),
        );
        for (name, value) in lines {
            out.push_str(&format!("  {} {value}\n", label(name)));
        }
        out
    }
}

/// The node over the last status interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NodeStatus {
    pub(crate) feeds_published: usize,
    pub(crate) feeds: usize,
    pub(crate) clients: usize,
    pub(crate) connections_up: u64,
    pub(crate) connections: usize,
    pub(crate) updates: u64,
    pub(crate) client_list_version: u64,
    /// From the venue data that moved a price to the signed update.
    pub(crate) signed: Percentiles,
}

impl NodeStatus {
    pub(crate) fn log(&self) {
        info!(
            feeds = %format_args!("{}/{}", self.feeds_published, self.feeds),
            clients = self.clients,
            connections = %format_args!("{}/{}", self.connections_up, self.connections),
            updates = self.updates,
            client_list = self.client_list_version,
            signed_p50_ms = millis(self.signed.p50),
            signed_p99_ms = millis(self.signed.p99),
            "status"
        );
    }
}

fn millis(value: Duration) -> f64 {
    value.as_secs_f64() * 1_000.0
}

/// The node's own share of the latency, over one status interval.
#[derive(Default)]
pub(crate) struct NodeLatency {
    signed: LatencyHistogram,
    venues: BTreeMap<Venue, LatencyHistogram>,
}

impl NodeLatency {
    /// The venue timestamp is the venue's claim. Thus the lag also holds the
    /// offset between the venue clock and ours.
    pub(crate) fn observed(&mut self, observation: &Observation) {
        if let Some(sent_ns) = observation.exchange_time_ns {
            self.venues
                .entry(observation.venue())
                .or_default()
                .record_between(sent_ns, observation.local_recv_ns);
        }
    }

    pub(crate) fn signed(&mut self, observed_ns: u64, now_ns: u64) {
        self.signed.record_between(observed_ns, now_ns);
    }

    /// Returns the figures for the interval, and starts the next one.
    pub(crate) fn take(&mut self) -> (Percentiles, Vec<(Venue, Percentiles)>) {
        let signed = self.signed.percentiles();
        self.signed.reset();
        let venues = self
            .venues
            .iter_mut()
            .map(|(venue, histogram)| {
                let percentiles = histogram.percentiles();
                histogram.reset();
                (*venue, percentiles)
            })
            .filter(|(_, percentiles)| percentiles.count > 0)
            .collect();
        (signed, venues)
    }
}

/// Logs the venue lag: p50 and p99 for each venue, in one line.
pub(crate) fn log_venue_lag(venues: &[(Venue, Percentiles)]) {
    if venues.is_empty() {
        return;
    }
    let text = venues
        .iter()
        .map(|(venue, lag)| {
            format!(
                "{} {:.1}/{:.1} ms",
                venue.as_str(),
                millis(lag.p50),
                millis(lag.p99)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    info!(p50_p99 = %text, "venue lag");
}

/// One line, because systemd shows `STATUS=` as one line.
impl fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{} feeds published, {} clients, {}/{} venue connections up, \
             {} updates in the last minute, client list v{}, \
             venue data to signed p50 {:.2} ms p99 {:.2} ms",
            self.feeds_published,
            self.feeds,
            self.clients,
            self.connections_up,
            self.connections,
            self.updates,
            self.client_list_version,
            millis(self.signed.p50),
            millis(self.signed.p99),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_is_one_line() {
        let status = NodeStatus {
            feeds_published: 11,
            feeds: 12,
            clients: 3,
            connections_up: 7,
            connections: 8,
            updates: 2_400,
            client_list_version: 4,
            signed: Percentiles::default(),
        };
        let text = status.to_string();
        assert!(!text.contains('\n'), "{text}");
        assert!(text.starts_with("11/12 feeds published"), "{text}");
        assert!(text.contains("7/8 venue connections up"), "{text}");
    }
}
