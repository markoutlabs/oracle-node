//! The task that owns the pipeline: it applies the ingest events in arrival
//! order, signs, and hands each frame to an [`Outlet`]. The node binary and
//! [`crate::embed`] run this one loop, each with its own outlet.

use std::future::Future;
use std::time::Duration;

use oracle_agg::AggError;
use oracle_ingest::IngestEvent;
use oracle_ingest::clock::{MonotonicClock, Resync};
use oracle_wire::SignedUpdate;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::Pipeline;

/// Bound on the ingest queue.
///
/// Bounded so a stalled pipeline applies backpressure to ingest rather than
/// growing without limit. Dropping the socket is recoverable; running out of
/// memory is not.
pub const INGEST_CAPACITY: usize = 8_192;
/// How often the node clock re-anchors to wall time.
const CLOCK_SYNC_EVERY: Duration = Duration::from_secs(1);
/// Normal drift is microseconds a second. A correction this large means the host
/// clock stepped.
const CLOCK_STEP_WARNING: u64 = 100_000_000;

/// Events applied before the changed feeds are evaluated. A burst then costs one
/// pass over the feeds it touched, not one per event, and stays bounded.
const BATCH_MAX: usize = 256;

/// Where the signed frames go, and what else the loop waits on.
pub trait Outlet: Send {
    /// What [`Self::extra`] yields.
    type Extra: Send;

    /// One more input, after the tick and before the ingest queue. It must be cancel-safe.
    fn extra(&mut self) -> impl Future<Output = Self::Extra> + Send;

    /// Takes what [`Self::extra`] yielded.
    fn on_extra(&mut self, extra: Self::Extra, pipeline: &mut Pipeline);

    /// Sees each ingest event just before the pipeline applies it.
    fn observed(&mut self, event: &IngestEvent);

    /// Takes the prices of one evaluation; `timed` is `Some` after new input.
    fn publish(
        &mut self,
        pipeline: &Pipeline,
        polled: (Vec<SignedUpdate>, Vec<AggError>),
        timed: Option<&MonotonicClock>,
    );

    /// Signs and takes the venue reports, books and funding that are due, after each evaluation.
    fn publish_venues(&mut self, pipeline: &mut Pipeline, now_ns: u64);

    /// Runs at the end of each pass of the loop.
    fn stepped(&mut self);
}

/// One task owns the pipeline. Events are applied in arrival order, which is
/// what preserves the disconnect-before-reconnect guarantee.
pub struct PipelineLoop<O> {
    /// The pipeline.
    pub pipeline: Pipeline,
    /// The venue adapters' events.
    pub ingest: mpsc::Receiver<IngestEvent>,
    /// How often every feed is evaluated with no new input.
    pub tick: Duration,
    /// The clock of the receipt times, which also stamps the publish times.
    pub clock: MonotonicClock,
    /// Where the frames go.
    pub outlet: O,
    /// Stops the loop.
    pub shutdown: CancellationToken,
}

impl<O: Outlet> PipelineLoop<O> {
    /// Runs until `shutdown`, or until every sender of the ingest queue is gone.
    pub async fn run(self) {
        let Self {
            pipeline,
            ingest,
            tick,
            clock,
            outlet,
            shutdown,
        } = self;
        drive(pipeline, ingest, tick, clock, Signing(outlet), shutdown).await;
    }
}

/// What [`drive`] hands each evaluation to. The node binary and the signed embedded node use
/// [`Signing`]; the unsigned embedded node has its own sink, so both modes share one loop.
pub(crate) trait Sink: Send {
    type Extra: Send;

    fn extra(&mut self) -> impl Future<Output = Self::Extra> + Send;

    fn on_extra(&mut self, extra: Self::Extra, pipeline: &mut Pipeline);

    fn observed(&mut self, event: &IngestEvent);

    /// Evaluates the feeds and takes what is due. `timed` is true after new input.
    fn evaluate(&mut self, pipeline: &mut Pipeline, clock: &MonotonicClock, timed: bool);

    fn stepped(&mut self);
}

/// Signs each evaluation and gives it to an [`Outlet`].
pub(crate) struct Signing<O>(pub(crate) O);

impl<O: Outlet> Sink for Signing<O> {
    type Extra = O::Extra;

    fn extra(&mut self) -> impl Future<Output = Self::Extra> + Send {
        self.0.extra()
    }

    fn on_extra(&mut self, extra: Self::Extra, pipeline: &mut Pipeline) {
        self.0.on_extra(extra, pipeline);
    }

    fn observed(&mut self, event: &IngestEvent) {
        self.0.observed(event);
    }

    fn evaluate(&mut self, pipeline: &mut Pipeline, clock: &MonotonicClock, timed: bool) {
        let polled = if timed {
            pipeline.flush(clock.now_ns())
        } else {
            pipeline.tick(clock.now_ns())
        };
        self.0.publish(pipeline, polled, timed.then_some(clock));
        self.0.publish_venues(pipeline, clock.now_ns());
    }

    fn stepped(&mut self) {
        self.0.stepped();
    }
}

/// The loop of [`PipelineLoop::run`], for any [`Sink`].
pub(crate) async fn drive<S: Sink>(
    mut pipeline: Pipeline,
    mut ingest: mpsc::Receiver<IngestEvent>,
    tick: Duration,
    clock: MonotonicClock,
    mut sink: S,
    shutdown: CancellationToken,
) {
    let mut ticker = tokio::time::interval(tick);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let retry = pipeline
            .next_retry_ns()
            .map(|at| Duration::from_nanos(at.saturating_sub(clock.now_ns())));
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            // The timers first: an ingest queue that is never empty would
            // otherwise starve the heartbeats and the outlet's own input.
            _ = ticker.tick() => sink.evaluate(&mut pipeline, &clock, false),
            extra = sink.extra() => sink.on_extra(extra, &mut pipeline),
            event = ingest.recv() => {
                let Some(event) = event else { break };
                sink.observed(&event);
                pipeline.observe(&event);
                for _ in 1..BATCH_MAX {
                    let Ok(event) = ingest.try_recv() else { break };
                    sink.observed(&event);
                    pipeline.observe(&event);
                }
                sink.evaluate(&mut pipeline, &clock, true);
            }
            () = tokio::time::sleep(retry.unwrap_or_default()), if retry.is_some() => {
                sink.evaluate(&mut pipeline, &clock, true);
            }
        }
        sink.stepped();
    }
    let stats = pipeline.stats();
    info!(
        observations = stats.observations,
        published = stats.published,
        connects = stats.connects,
        disconnects = stats.disconnects,
        unencodable = stats.encode_errors,
        "pipeline stopped"
    );
}

/// Keeps the node clock on wall time until `shutdown`. A consumer compares
/// publish times with its own clock.
pub async fn sync_clock(clock: MonotonicClock, shutdown: CancellationToken) {
    let mut ticker = tokio::time::interval(CLOCK_SYNC_EVERY);
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            _ = ticker.tick() => match clock.resync() {
                Resync::Stepped(step) if step > CLOCK_STEP_WARNING => {
                    warn!(step_ms = step / 1_000_000, "the wall clock stepped forward; the node clock followed");
                }
                Resync::Slewing(lead) if lead > CLOCK_STEP_WARNING => {
                    warn!(lead_ms = lead / 1_000_000, "the wall clock stepped back; the node clock runs slow until it matches");
                }
                Resync::Stepped(_) | Resync::Slewing(_) => {}
            },
        }
    }
}
