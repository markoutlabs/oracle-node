//! What the node reports about itself: once when it starts serving, then every
//! minute.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use console::style;
use oracle_client::{LatencyHistogram, Percentiles};
use oracle_ingest::VenueHealth;
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
    /// The network feed set version; zero for the config's own feeds.
    pub(crate) feed_set: u64,
    /// From the venue data that moved a price to the signed update.
    pub(crate) signed: Percentiles,
}

impl NodeStatus {
    /// `connections` are the venue connections, with their counters (SPEC §9.3).
    pub(crate) fn log(&self, connections: &[VenueHealth]) {
        info!(
            feeds = %format_args!("{}/{}", self.feeds_published, self.feeds),
            clients = self.clients,
            connections = %format_args!("{}/{}", self.connections_up, self.connections),
            updates = self.updates,
            client_list = self.client_list_version,
            feed_set = self.feed_set,
            signed_p50_ms = %format_args!("{:.2}", millis(self.signed.p50)),
            signed_p99_ms = %format_args!("{:.2}", millis(self.signed.p99)),
            venue_health = %venue_health(connections),
            "status"
        );
    }
}

/// Each connection with its counters since it was built, numbered within its
/// venue and market. The URL drops its query, which only lists the streams.
fn venue_health(connections: &[VenueHealth]) -> String {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    connections
        .iter()
        .map(|connection| {
            let stream = connection.stream().to_string();
            let place = seen.entry(stream.clone()).or_default();
            let number = *place;
            *place = place.saturating_add(1);
            let url = connection.url().split('?').next().unwrap_or_default();
            let counts = connection.counts();
            format!(
                "{stream}#{number} {url} connects {} decode_errors {} resyncs {} \
                 resubscribes {} idle_timeouts {}",
                counts.connects,
                counts.decode_errors,
                counts.resyncs,
                counts.resubscribes,
                counts.idle_timeouts,
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn millis(value: Duration) -> f64 {
    value.as_secs_f64() * 1_000.0
}

/// The node's own share of the latency, over one status interval.
#[derive(Default)]
pub(crate) struct NodeLatency {
    signed: LatencyHistogram,
    venues: BTreeMap<Venue, (LatencyHistogram, u64)>,
}

/// One venue's lag over one status interval.
pub(crate) struct VenueLag {
    pub(crate) venue: Venue,
    pub(crate) lag: Percentiles,
    /// Timestamps after our receipt time. Many mean that our clock is behind.
    pub(crate) ahead: u64,
}

impl NodeLatency {
    /// The venue timestamp is the venue's claim. Thus the lag also holds the
    /// offset between the venue clock and ours.
    pub(crate) fn observed(&mut self, observation: &Observation) {
        if let Some(lag_ns) = observation.venue_lag_ns() {
            let (lag, ahead) = self.venues.entry(observation.venue()).or_default();
            if let Ok(lag_ns) = u64::try_from(lag_ns) {
                lag.record(Duration::from_nanos(lag_ns));
            } else {
                lag.record(Duration::ZERO);
                *ahead = ahead.saturating_add(1);
            }
        }
    }

    pub(crate) fn signed(&mut self, observed_ns: u64, now_ns: u64) {
        self.signed.record_between(observed_ns, now_ns);
    }

    /// Returns the figures for the interval, and starts the next one.
    pub(crate) fn take(&mut self) -> (Percentiles, Vec<VenueLag>) {
        let signed = self.signed.percentiles();
        self.signed.reset();
        let venues = self
            .venues
            .iter_mut()
            .map(|(venue, (histogram, ahead))| {
                let lag = VenueLag {
                    venue: *venue,
                    lag: histogram.percentiles(),
                    ahead: std::mem::take(ahead),
                };
                histogram.reset();
                lag
            })
            .filter(|venue| venue.lag.count > 0)
            .collect();
        (signed, venues)
    }
}

/// Logs the venue lag in one line: p50 and p99 for each venue, and the share of
/// venue timestamps ahead of our clock. A lag below zero reads as zero.
pub(crate) fn log_venue_lag(venues: &[VenueLag]) {
    if venues.is_empty() {
        return;
    }
    let text = venues
        .iter()
        .map(|venue| {
            let mut text = format!(
                "{} {:.1}/{:.1} ms",
                venue.venue.as_str(),
                millis(venue.lag.p50),
                millis(venue.lag.p99)
            );
            if venue.ahead > 0 {
                let share = venue.ahead.saturating_mul(100) / venue.lag.count.max(1);
                text.push_str(&format!(" ({share}% ahead)"));
            }
            text
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
    use oracle_types::{Fixed, InstrumentId, MarketKind, ObsKind};

    fn observation(sent_ns: u64, received_ns: u64) -> Observation {
        Observation {
            instrument: InstrumentId::new(Venue::Kraken, MarketKind::Spot, "BTC/USD"),
            kind: ObsKind::Trade,
            price: Fixed::ONE,
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            depth_notional_1bp: None,
            exchange_time_ns: Some(sent_ns),
            local_recv_ns: received_ns,
            seq: None,
            book: None,
            funding: None,
        }
    }

    #[test]
    fn a_venue_clock_ahead_of_ours_is_counted() {
        let mut latency = NodeLatency::default();
        latency.observed(&observation(105_000_000, 100_000_000));
        latency.observed(&observation(90_000_000, 100_000_000));
        let (_, venues) = latency.take();
        let [kraken] = venues.as_slice() else {
            panic!("one venue: {}", venues.len());
        };
        assert_eq!((kraken.lag.count, kraken.ahead), (2, 1));
        assert_eq!(kraken.lag.max.as_millis(), 10);
        assert!(
            latency.take().1.is_empty(),
            "each take starts a new interval"
        );
    }

    #[test]
    fn each_venue_connection_shows_its_counters_and_its_place_in_its_market() {
        let stream = oracle_ingest::StreamId::new(Venue::Bitfinex, MarketKind::Spot);
        let url = "wss://api-pub.bitfinex.com/ws/2";
        let connections = [
            VenueHealth::new(stream, url),
            VenueHealth::new(stream, format!("{url}?streams=a/b")),
        ];
        let text = venue_health(&connections);
        let counters = "connects 0 decode_errors 0 resyncs 0 resubscribes 0 idle_timeouts 0";
        assert_eq!(
            text,
            format!("bitfinex:spot#0 {url} {counters}; bitfinex:spot#1 {url} {counters}")
        );
        assert!(venue_health(&[]).is_empty());
    }

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
            feed_set: 0,
            signed: Percentiles::default(),
        };
        let text = status.to_string();
        assert!(!text.contains('\n'), "{text}");
        assert!(text.starts_with("11/12 feeds published"), "{text}");
        assert!(text.contains("7/8 venue connections up"), "{text}");
    }
}
