//! Replays a recording through the real pipeline (SPEC §10).
//!
//! A recording is what `oracle-node start --record` wrote: every raw venue
//! frame with the time it arrived. Replay feeds those frames to the same
//! adapters, decoders, session loop and aggregator the node runs, with two
//! substitutions: the transport reads the recording instead of a socket, and
//! the clock reads the recording instead of the wall.
//!
//! # Determinism
//!
//! Frames are released in recorded order across all connections, one at a
//! time, through a shared cursor. The clock is stored just before each frame is
//! handed over; on a single-threaded runtime nothing can run between a transport
//! returning a frame and the session stamping it, so every observation carries
//! its recorded receipt time. The driver then takes time from the observations
//! it receives, not from the clock, and ticks the pipeline at recorded-time
//! boundaries before applying the observation that crossed them. That is
//! independent of how far ahead the sessions have run, so two replays of one
//! recording produce the same updates and the same digest. The equality is the
//! cross-node conformance test in §10, and the digest is what it compares.
//!
//! Connection events carry no time of their own and are applied at the time of
//! the observation before them. A live node would have invalidated the venue at
//! the close itself; the difference is bounded by one inter-frame gap.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

pub mod adversarial;

use oracle_agg::{AggError, Aggregator, FeedStats};
use oracle_ingest::clock::MonotonicClock;
use oracle_ingest::{Connector, Frame, IngestEvent, Record, Transport, TransportError};
use oracle_node::{Pipeline, PipelineStats, ResolvedConfig, build_adapters};
use oracle_types::{FeedId, PriceUpdate};
use oracle_wire::{Signer, encode_price_update, keccak256};
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::warn;

/// Replay failed before or while running.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReplayError {
    /// The recording holds nothing to play.
    #[error("the recording is empty")]
    Empty,
    /// The feeds did not form a valid aggregator.
    #[error(transparent)]
    Config(#[from] oracle_agg::ConfigError),
    /// An adapter refused its configuration.
    #[error(transparent)]
    Ingest(#[from] oracle_ingest::IngestError),
}

/// What a replay produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Every update the pipeline published, in order.
    pub updates: Vec<PriceUpdate>,
    /// Pipeline counters.
    pub stats: PipelineStats,
    /// Per-feed aggregation counters: outliers rejected, halts, degradations.
    pub feeds: Vec<(FeedId, FeedStats)>,
    /// Keccak-256 over the canonical bytes of every update, in order.
    ///
    /// Two nodes fed the same recording must produce the same digest.
    pub digest: [u8; 32],
    /// Errors the aggregator reported while ticking.
    pub errors: Vec<String>,
}

/// The shared cursor over a recording.
struct Script {
    records: Vec<Record>,
    next: AtomicUsize,
    released: Notify,
    /// What every session's clock reads.
    now_ns: Arc<AtomicU64>,
    /// Sleep the recorded gaps instead of releasing frames back to back.
    realtime: bool,
}

impl Script {
    fn is_exhausted(&self) -> bool {
        self.next.load(Ordering::Acquire) >= self.records.len()
    }

    /// Waits until the head record satisfies `wanted`, then takes it.
    ///
    /// Returns `None` once the recording is exhausted. Only the head is ever
    /// released, so frames leave in recorded order whatever the task schedule.
    async fn take(&self, wanted: impl Fn(&Record) -> bool) -> Option<Record> {
        loop {
            let notified = self.released.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let index = self.next.load(Ordering::Acquire);
            let record = self.records.get(index)?;
            if wanted(record) {
                if self.realtime
                    && let Some(previous) = index.checked_sub(1).and_then(|i| self.records.get(i))
                {
                    let gap = record.time_ns().saturating_sub(previous.time_ns());
                    tokio::time::sleep(Duration::from_nanos(gap)).await;
                }
                // Stored before the frame is handed over, read by the session
                // right after. Single-threaded runtime: nothing runs in between.
                self.now_ns.store(record.time_ns(), Ordering::Release);
                self.next.store(index.saturating_add(1), Ordering::Release);
                self.released.notify_waiters();
                return Some(record.clone());
            }
            notified.await;
        }
    }
}

/// A connector that opens connections the recording says were opened.
#[derive(Clone)]
pub struct ReplayConnector {
    script: Arc<Script>,
}

impl Connector for ReplayConnector {
    type Conn = ReplayConn;

    async fn connect(&self, url: &str) -> Result<Self::Conn, TransportError> {
        match self
            .script
            .take(|record| matches!(record, Record::Connect { url: u, .. } if u == url))
            .await
        {
            Some(_) => Ok(ReplayConn {
                script: Arc::clone(&self.script),
                url: url.to_owned(),
            }),
            // Exhausted. Park until the driver cancels, rather than fail and
            // have the session reconnect in a loop.
            None => std::future::pending().await,
        }
    }
}

/// A connection that yields the recording's frames for one endpoint.
pub struct ReplayConn {
    script: Arc<Script>,
    url: String,
}

impl Transport for ReplayConn {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        let record = self
            .script
            .take(|record| record.url() == self.url && !matches!(record, Record::Connect { .. }))
            .await;
        Ok(match record {
            Some(Record::Text { text, .. }) => Some(Frame::Text(text)),
            Some(Record::Binary { bytes, .. }) => Some(Frame::Binary(bytes)),
            Some(Record::Close { .. } | Record::Connect { .. }) | None => None,
        })
    }

    async fn send_text(&mut self, _text: String) -> Result<(), TransportError> {
        Ok(())
    }
}

/// How long to wait for in-flight events once the recording is exhausted.
const DRAIN: Duration = Duration::from_millis(200);

/// Replays `records` through the pipeline `resolved` describes.
///
/// `signer` signs the published updates; a seeded key is fine, the signatures
/// are not part of the outcome. `realtime` sleeps the recorded gaps between
/// frames; otherwise the replay runs as fast as the pipeline allows.
///
/// Run this on a single-threaded runtime. See the module documentation.
///
/// # Errors
///
/// Returns [`ReplayError`] for an empty recording or a configuration the
/// aggregator or an adapter refuses.
pub async fn run(
    resolved: ResolvedConfig,
    records: Vec<Record>,
    signer: Signer,
    realtime: bool,
) -> Result<Outcome, ReplayError> {
    let first = records.first().ok_or(ReplayError::Empty)?.time_ns();
    let now_ns = Arc::new(AtomicU64::new(first));
    let script = Arc::new(Script {
        records,
        next: AtomicUsize::new(0),
        released: Notify::new(),
        now_ns: Arc::clone(&now_ns),
        realtime,
    });
    let connector = ReplayConnector {
        script: Arc::clone(&script),
    };
    let clock = MonotonicClock::driven(Arc::clone(&now_ns));

    let aggregator = Aggregator::new(resolved.feeds)?;
    let mut pipeline = Pipeline::new(aggregator, std::sync::Arc::new(signer));
    let adapters = build_adapters(resolved.binance, resolved.venues, connector, clock)?.adapters;

    let shutdown = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel::<IngestEvent>(1_024);
    let mut tasks = Vec::with_capacity(adapters.len());
    for adapter in adapters {
        let tx = tx.clone();
        let shutdown = shutdown.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(error) = adapter.run(tx, shutdown).await {
                warn!(%error, "adapter stopped");
            }
        }));
    }
    drop(tx);

    let interval = u64::try_from(resolved.tick_interval.as_nanos()).unwrap_or(u64::MAX);
    let last = script.records.last().map_or(first, Record::time_ns);
    let mut next_tick = first.saturating_add(interval);
    let mut now = first;
    let mut outcome = Outcome {
        updates: Vec::new(),
        stats: PipelineStats::default(),
        feeds: Vec::new(),
        digest: [0; 32],
        errors: Vec::new(),
    };

    loop {
        let event = if script.is_exhausted() {
            // Everything has been released; give in-flight observations time
            // to reach the channel, then stop.
            match tokio::time::timeout(DRAIN, rx.recv()).await {
                Ok(Some(event)) => event,
                Ok(None) | Err(_) => break,
            }
        } else {
            match rx.recv().await {
                Some(event) => event,
                None => break,
            }
        };
        // Time comes from the event, never from the shared clock: the sessions
        // may have released frames far beyond the one being applied here.
        // Ticks fire at recorded-time boundaries, before the event that crossed
        // them, which is how the live node orders them.
        if let IngestEvent::Observation(observation) = &event {
            now = now.max(observation.local_recv_ns);
        }
        while next_tick <= now {
            tick(&mut pipeline, next_tick, &mut outcome);
            next_tick = next_tick.saturating_add(interval);
        }
        pipeline.observe(&event);
    }
    // One final evaluation at the end of the recording.
    tick(&mut pipeline, now.max(last), &mut outcome);

    shutdown.cancel();
    for task in tasks {
        let _ = task.await;
    }

    outcome.stats = pipeline.stats();
    outcome.feeds = pipeline.feed_stats();
    let mut bytes = Vec::with_capacity(outcome.updates.len() * 128);
    for update in &outcome.updates {
        bytes.extend_from_slice(&encode_price_update(update));
    }
    outcome.digest = keccak256(&bytes);
    Ok(outcome)
}

fn tick(pipeline: &mut Pipeline, now_ns: u64, outcome: &mut Outcome) {
    let (signed, errors) = pipeline.tick(now_ns);
    outcome
        .updates
        .extend(signed.iter().map(|update| *update.update()));
    outcome
        .errors
        .extend(errors.iter().map(AggError::to_string));
}
