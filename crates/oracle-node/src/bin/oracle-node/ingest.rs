//! The venue adapters while the node runs: one task each, so that a new feed
//! set replaces one venue while the others run.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use oracle_ingest::IngestEvent;
use oracle_ingest::binance::BinanceConfig;
use oracle_ingest::binance::snapshot::SnapshotConnector;
use oracle_ingest::clock::MonotonicClock;
use oracle_ingest::transport::WebSocketConnector;
use oracle_ingest::venues::kucoin_connect::KucoinConnector;
use oracle_ingest::venues::mexc_connect::MexcConnector;
use oracle_node::config::VenueConnection;
use oracle_node::{Adapter, build_venue_adapters};
use oracle_types::Venue;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// How long a venue adapter gets to close its sockets.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
/// The pause between two venues' swaps, so that one venue reconnects before
/// the next one goes.
const VENUE_PAUSE: Duration = Duration::from_secs(5);

/// The connectors under the venue adapters.
pub(crate) type Connectors = MexcConnector<KucoinConnector<SnapshotConnector<WebSocketConnector>>>;

/// Builds the connectors for the Binance instruments of `binance`.
pub(crate) fn connectors(binance: &BinanceConfig) -> anyhow::Result<Connectors> {
    let snapshots = SnapshotConnector::new(WebSocketConnector, binance.snapshot_routes())?
        .with_funding_info(binance.funding_info_routes())
        .with_open_interest(binance.open_interest_routes());
    Ok(MexcConnector::new(KucoinConnector::new(snapshots)?)?)
}

struct Running {
    stop: CancellationToken,
    task: JoinHandle<()>,
    connections: usize,
}

/// The venue adapters, one task each.
pub(crate) struct Ingest {
    events: mpsc::Sender<IngestEvent>,
    running: BTreeMap<Venue, Running>,
    /// The connections of every adapter, for the status line.
    connections: Arc<AtomicUsize>,
    clock: MonotonicClock,
    shutdown: CancellationToken,
}

impl Ingest {
    pub(crate) fn new(
        events: mpsc::Sender<IngestEvent>,
        clock: MonotonicClock,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            events,
            running: BTreeMap::new(),
            connections: Arc::new(AtomicUsize::new(0)),
            clock,
            shutdown,
        }
    }

    /// The connection count, shared with the status line.
    pub(crate) fn connections(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.connections)
    }

    fn count(&self) {
        let total = self.running.values().fold(0_usize, |sum, running| {
            sum.saturating_add(running.connections)
        });
        self.connections.store(total, Ordering::Relaxed);
    }

    /// Starts each adapter as its own task.
    pub(crate) fn start(&mut self, adapters: Vec<Adapter>) {
        for Adapter {
            venue,
            adapter,
            connections,
        } in adapters
        {
            let stop = self.shutdown.child_token();
            let token = stop.clone();
            let events = self.events.clone();
            let task = tokio::spawn(async move {
                let result = adapter.run(events, token.clone()).await;
                // After shutdown the pipeline is gone, so a failed send is expected.
                if let Err(error) = result
                    && !token.is_cancelled()
                {
                    error!(%venue, %error, "ingest stopped");
                }
            });
            self.running.insert(
                venue,
                Running {
                    stop,
                    task,
                    connections,
                },
            );
        }
        self.count();
    }

    /// Waits for the venue's sockets: each session sends its `Disconnected`
    /// first, so the pipeline clears the venue before the new data arrives.
    async fn stop(&mut self, venue: Venue) {
        let Some(running) = self.running.remove(&venue) else {
            return;
        };
        running.stop.cancel();
        if tokio::time::timeout(STOP_TIMEOUT, running.task)
            .await
            .is_err()
        {
            warn!(
                %venue,
                "the venue adapter did not stop in time; replacing it anyway"
            );
        }
        self.count();
    }

    /// Replaces the `changed` venues one at a time, so the other venues keep each quorum.
    pub(crate) async fn swap(
        &mut self,
        changed: &[Venue],
        mut binance: BinanceConfig,
        venues: Vec<(Venue, Vec<VenueConnection>)>,
    ) -> anyhow::Result<()> {
        let connector = connectors(&binance)?;
        let mut venues: BTreeMap<Venue, Vec<VenueConnection>> = venues.into_iter().collect();
        for (place, &venue) in changed.iter().enumerate() {
            if place > 0 {
                tokio::select! {
                    () = self.shutdown.cancelled() => return Ok(()),
                    () = tokio::time::sleep(VENUE_PAUSE) => {}
                }
            }
            self.stop(venue).await;
            // A venue that the new set does not read builds no adapter.
            let (binance, others) = if venue == Venue::Binance {
                (std::mem::take(&mut binance), Vec::new())
            } else {
                let others = venues
                    .remove(&venue)
                    .map(|connections| (venue, connections));
                (BinanceConfig::default(), others.into_iter().collect())
            };
            let adapters =
                build_venue_adapters(binance, others, connector.clone(), self.clock.clone())?;
            for adapter in &adapters {
                info!(
                    venue = %adapter.venue,
                    connections = adapter.connections,
                    "venue reconnects for the new feed set"
                );
            }
            self.start(adapters);
        }
        Ok(())
    }
}
