//! The task that owns the pipeline: it applies the ingest events in arrival
//! order, signs, and hands each frame to the server.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use oracle_agg::{AggError, Cause};
use oracle_ingest::IngestEvent;
use oracle_ingest::clock::{MonotonicClock, wall_clock_unix_nanos};
use oracle_node::Pipeline;
use oracle_node::ingest::Health;
use oracle_node::run::{Outlet, PipelineLoop};
use oracle_server::{Channel, ServerState};
use oracle_types::{FeedId, Symbol};
use oracle_wire::SignedUpdate;
use tokio::sync::mpsc;
use tokio::time::Interval;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::live_feeds::{Reconfigure, names};
use crate::notify;
use crate::status::{NodeLatency, NodeStatus, STATUS_EVERY, log_venue_lag};
use crate::tail::{log_observation, log_update};

/// One task owns the pipeline. Events are applied in arrival order, which is
/// what preserves the disconnect-before-reconnect guarantee.
pub(crate) struct PipelineTask {
    pub(crate) pipeline: Pipeline,
    pub(crate) ingest: mpsc::Receiver<IngestEvent>,
    /// A new network feed set, from the feed set task.
    pub(crate) reconfigure: mpsc::Receiver<Reconfigure>,
    pub(crate) state: Arc<ServerState>,
    pub(crate) tick: Duration,
    pub(crate) tail: bool,
    /// Names each feed id in the tail.
    pub(crate) symbols: HashMap<FeedId, Symbol>,
    /// Shared with the venue adapters, which a feed set change replaces.
    pub(crate) connections: Arc<std::sync::atomic::AtomicUsize>,
    /// The counters of each venue connection, shared with the venue adapters.
    pub(crate) health: Health,
    pub(crate) latency: NodeLatency,
    pub(crate) clock: MonotonicClock,
    pub(crate) watchdog: notify::Watchdog,
    pub(crate) shutdown: CancellationToken,
}

impl PipelineTask {
    pub(crate) async fn run(self) {
        let Self {
            pipeline,
            ingest,
            reconfigure,
            state,
            tick,
            tail,
            symbols,
            connections,
            health,
            latency,
            clock,
            watchdog,
            shutdown,
        } = self;
        // `interval` fires at once; the first status is due after a full interval.
        let status_ticker =
            tokio::time::interval_at(tokio::time::Instant::now() + STATUS_EVERY, STATUS_EVERY);
        let outlet = NodeOutlet {
            reconfigure,
            state,
            tail,
            symbols,
            connections,
            health,
            latency,
            watchdog,
            status_ticker,
            published: HashSet::new(),
            updates_before: 0,
        };
        PipelineLoop {
            pipeline,
            ingest,
            tick,
            clock,
            outlet,
            shutdown,
        }
        .run()
        .await;
    }
}

enum Extra {
    Reconfigure(Reconfigure),
    Status,
}

struct NodeOutlet {
    reconfigure: mpsc::Receiver<Reconfigure>,
    state: Arc<ServerState>,
    tail: bool,
    symbols: HashMap<FeedId, Symbol>,
    connections: Arc<std::sync::atomic::AtomicUsize>,
    health: Health,
    latency: NodeLatency,
    watchdog: notify::Watchdog,
    status_ticker: Interval,
    published: HashSet<FeedId>,
    updates_before: u64,
}

impl Outlet for NodeOutlet {
    type Extra = Extra;

    async fn extra(&mut self) -> Extra {
        tokio::select! {
            biased;
            Some(change) = self.reconfigure.recv() => Extra::Reconfigure(change),
            _ = self.status_ticker.tick() => Extra::Status,
        }
    }

    fn on_extra(&mut self, extra: Extra, pipeline: &mut Pipeline) {
        match extra {
            Extra::Reconfigure(change) => {
                // Above the floor of this run, and above every sequence the
                // old set used: `Aggregator::reconfigure` takes the larger.
                let floor = wall_clock_unix_nanos() / 1_000_000;
                let symbols = names(&change.feeds);
                let result = pipeline
                    .reconfigure(change.feeds, floor)
                    .map_err(|error| error.to_string());
                if result.is_ok() {
                    self.symbols = symbols;
                    self.published.clear();
                }
                let _ = change.reply.send(result);
            }
            Extra::Status => {
                let stats = pipeline.stats();
                let (signed, venues) = self.latency.take();
                let status = NodeStatus {
                    feeds_published: self.published.len(),
                    feeds: self.symbols.len(),
                    clients: self.state.transport().session_count(),
                    connections_up: stats.connections_up(),
                    connections: self.connections.load(Ordering::Relaxed),
                    updates: stats.published.saturating_sub(self.updates_before),
                    client_list_version: self.state.transport().clients_version(),
                    feed_set: self.state.feed_set_version(),
                    signed,
                };
                let health = self
                    .health
                    .lock()
                    .map(|health| health.clone())
                    .unwrap_or_default();
                status.log(&health);
                log_venue_lag(&venues);
                notify::status(&status.to_string());
                self.published.clear();
                self.updates_before = stats.published;
            }
        }
    }

    fn observed(&mut self, event: &IngestEvent) {
        if self.tail {
            log_observation(event);
        }
        if let IngestEvent::Observation(observation) = event {
            self.latency.observed(observation);
        }
    }

    /// `timed` is `Some` after new input. Only a move or a flag change counts
    /// as latency: a heartbeat repeats old data, and a halt carries none.
    fn publish(
        &mut self,
        pipeline: &Pipeline,
        (signed, errors): (Vec<SignedUpdate>, Vec<AggError>),
        timed: Option<&MonotonicClock>,
    ) {
        for error in errors {
            warn!(%error, "feed could not be encoded");
        }
        for update in signed {
            if self.tail {
                log_update(&update, self.symbols.get(&update.update().feed_id));
            }
            let feed_id = update.update().feed_id;
            let reaction = pipeline
                .last_trigger(feed_id)
                .filter(|trigger| matches!(trigger.cause, Cause::Moved | Cause::Flags))
                .filter(|_| !update.update().flags.is_halted());
            self.published.insert(feed_id);
            let _ = self.state.publish(update);
            if let (Some(clock), Some(trigger)) = (timed, reaction) {
                self.latency.signed(trigger.observed_ns, clock.now_ns());
            }
        }
    }

    /// Venue reports, book frames and funding frames go out after each
    /// evaluation.
    fn publish_venues(&mut self, pipeline: &mut Pipeline, now_ns: u64) {
        let hub = Arc::clone(self.state.hub());
        let (reports, errors) =
            pipeline.venue_reports(now_ns, |feed| hub.has_subscriber(Channel::Venues, feed));
        for error in errors {
            warn!(%error, "venue report could not be encoded");
        }
        for report in reports {
            let _ = self.state.publish_venues(report);
        }
        let (books, errors) = pipeline.book_updates(now_ns, |book| hub.has_book_subscriber(book));
        for error in errors {
            warn!(%error, "book update could not be encoded");
        }
        for update in books {
            let _ = self.state.publish_book(update);
        }
        let (funding, errors) = pipeline.funding_updates(now_ns);
        for error in errors {
            warn!(%error, "funding update could not be encoded");
        }
        for update in funding {
            let _ = self.state.publish_funding(update);
        }
    }

    // After each batch and each tick: the ticker fires every few
    // milliseconds, so only a stuck loop misses the interval.
    fn stepped(&mut self) {
        self.watchdog.beat(std::time::Instant::now());
    }
}
