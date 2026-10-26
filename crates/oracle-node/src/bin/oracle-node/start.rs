//! `oracle-node start`: ingest, aggregate, sign, serve.
//!
//! Startup proves everything that would make the node useless before it binds
//! the port: the key opens, the registry lists this node, the client list
//! verifies. A node that the registry does not list yet waits for governance.
//! Then it serves until SIGTERM or SIGINT.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::Args;
use oracle_agg::{AggError, Cause};
use oracle_ingest::IngestEvent;
use oracle_ingest::binance::snapshot::SnapshotConnector;
use oracle_ingest::clock::{MonotonicClock, Resync, wall_clock_unix_nanos};
use oracle_ingest::transport::WebSocketConnector;
use oracle_ingest::venues::kucoin_connect::KucoinConnector;
use oracle_ingest::venues::mexc_connect::MexcConnector;
use oracle_ingest::{Recorder, RecordingConnector};
use oracle_node::publish::PushTarget;
use oracle_node::{LogFormat, NodeConfig, Pipeline, ResolvedConfig, build_adapters, logging};
use oracle_server::{Channel, NodeTransport, ServerState, TransportConfig, router, unix_now};
use oracle_types::{FeedId, InstrumentId, Symbol};
use oracle_wire::{Address, Registry, SignedUpdate, Signer, VerifiedClientList};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::notify;
use crate::status::{NodeLatency, NodeStatus, STATUS_EVERY, Summary, log_venue_lag};
use crate::tail::{log_observation, log_update};

/// Bound on the ingest queue.
///
/// Bounded so a stalled pipeline applies backpressure to ingest rather than
/// growing without limit. Dropping the socket is recoverable; running out of
/// memory is not.
const INGEST_CAPACITY: usize = 8_192;
/// Open files beyond the client sockets and the venue connections: logs,
/// recordings, the runtime.
const SPARE_FILES: usize = 256;
/// Events applied before the changed feeds are evaluated. A burst then costs one
/// pass over the feeds it touched, not one per event, and stays bounded.
const BATCH_MAX: usize = 256;
/// How often the node clock re-anchors to wall time.
const CLOCK_SYNC_EVERY: Duration = Duration::from_secs(1);
/// Normal drift is microseconds a second. A correction this large means the host
/// clock stepped.
const CLOCK_STEP_WARNING: u64 = 100_000_000;
/// How often a node that the registry does not list fetches it again.
const LISTING_POLL: Duration = Duration::from_secs(30);

#[derive(Args)]
pub(crate) struct StartArgs {
    /// The node config file.
    config: PathBuf,
    /// Log every decoded observation going into the aggregator and every
    /// signed update coming out. The fastest way to see what a venue sends.
    #[arg(long)]
    tail: bool,
    /// Record every raw venue frame, with its receipt time, to this file as
    /// JSON lines. `oracle-replay` plays it back through the same pipeline.
    #[arg(long, value_name = "FILE")]
    record: Option<PathBuf>,
    /// How log lines look. `auto` picks journald under systemd, pretty at a
    /// terminal, and plain otherwise. `RUST_LOG` filters them.
    #[arg(long, value_enum, default_value_t)]
    log_format: LogFormat,
}

pub(crate) fn run(args: StartArgs) -> anyhow::Result<()> {
    // Before the runtime, which starts threads: see `logging::init`.
    let format = logging::init(args.log_format, "info")?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?
        .block_on(serve(args, format))
}

/// What startup proved.
struct Node {
    config: NodeConfig,
    resolved: ResolvedConfig,
    signer: Arc<Signer>,
    governance: Address,
    registry: Registry,
    clients: VerifiedClientList,
}

async fn serve(args: StartArgs, format: LogFormat) -> anyhow::Result<()> {
    let mut signals = Signals::new()?;
    let Some(Node {
        config,
        resolved,
        signer,
        governance,
        registry,
        clients,
    }) = load(&args.config, &mut signals).await?
    else {
        return Ok(());
    };
    let push = PushTarget::from_config(&config)?;
    let address = signer.address();
    let registry_version = registry.version;
    let feeds = resolved.symbols.len();
    let symbols: HashMap<FeedId, Symbol> = resolved
        .symbols
        .iter()
        .map(|symbol| (oracle_wire::feed_id(symbol), *symbol))
        .collect();

    // Sequence numbers must never go backwards for this node, including across
    // restarts. Milliseconds since the epoch outrun any publish counter.
    let books: HashMap<FeedId, Vec<InstrumentId>> = resolved
        .feeds
        .iter()
        .map(|feed| {
            let sources = feed.sources.iter().map(|source| source.instrument.clone());
            (feed.feed_id, sources.collect())
        })
        .collect();
    let seq_floor = wall_clock_unix_nanos() / 1_000_000;
    let aggregator = oracle_agg::Aggregator::new(resolved.feeds)?.with_sequence_floor(seq_floor);
    let pipeline =
        Pipeline::new(aggregator, Arc::clone(&signer)).with_stream_sequence_floor(seq_floor);

    // Freshness limits catch a withheld canister update. An operator's own file
    // cannot be withheld, and is never refreshed, so it is exempt.
    let limits = if config.clients.as_ref().is_some_and(|c| c.path.is_some()) {
        TransportConfig {
            admit_within: u64::MAX,
            serve_within: u64::MAX,
        }
    } else {
        TransportConfig::default()
    };
    let push_signer = Arc::clone(&signer);
    let transport = NodeTransport::new(
        signer,
        clients,
        limits,
        config.server.max_pending_feeds,
        unix_now(),
    );
    let state = ServerState::with_books(&resolved.symbols, books, registry, transport);
    let shutdown = CancellationToken::new();
    spawn_transport_tasks(
        Arc::clone(state.transport()),
        config.clone(),
        shutdown.clone(),
    );
    if let Some(target) = push {
        info!(canister = %target.canister, gateway = %target.gateway, "pushing frames to the registry canister");
        crate::publish::spawn(Arc::clone(&state), push_signer, target, shutdown.clone());
    }

    // One clock for receipt times and publish times, so a resync moves both.
    let clock = MonotonicClock::new();
    spawn_clock_sync(clock.clone(), shutdown.clone());
    let (ingest, connections) = spawn_ingest(
        resolved.binance,
        resolved.venues,
        args.record.as_deref(),
        &clock,
        &shutdown,
    )?;
    let pipeline_task = tokio::spawn(
        PipelineTask {
            pipeline,
            ingest,
            state: Arc::clone(&state),
            tick: resolved.tick_interval,
            tail: args.tail,
            feeds,
            symbols,
            connections,
            latency: NodeLatency::default(),
            clock,
            shutdown: shutdown.clone(),
        }
        .run(),
    );

    #[cfg(unix)]
    raise_open_files(
        config
            .server
            .limits
            .max_sockets
            .get()
            .saturating_add(connections)
            .saturating_add(SPARE_FILES),
    );
    let listener = tokio::net::TcpListener::bind(&config.server.listen).await?;
    let summary = Summary {
        listen: listener.local_addr()?,
        address,
        governance,
        registry_version,
        client_list_version: state.transport().clients_version(),
        clients: state.transport().client_count(),
        feeds,
        connections,
    };
    if format == LogFormat::Pretty {
        eprint!("{}", summary.banner());
    }
    summary.log();
    notify::ready(&format!("serving on {}", summary.listen));

    let limits = config.server.limits.clone();
    let server = oracle_server::serve(listener, router(state, &limits), limits, shutdown.clone());
    tokio::select! {
        () = server => {},
        signal = signals.recv() => {
            info!(signal = signal?, "shutting down");
        }
    }

    notify::stopping();
    shutdown.cancel();
    let _ = pipeline_task.await;
    Ok(())
}

/// Raises the open-file limit to its ceiling, and warns when it is still below
/// `needed`: past it, the node cannot accept clients or reach venues.
#[cfg(unix)]
fn raise_open_files(needed: usize) {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};
    let Ok((soft, hard)) = getrlimit(Resource::RLIMIT_NOFILE) else {
        return;
    };
    let needed = nix::libc::rlim_t::try_from(needed).unwrap_or(nix::libc::rlim_t::MAX);
    // macOS refuses an unlimited soft limit, so the second try asks only for `needed`.
    let limit = [hard, needed]
        .into_iter()
        .find(|&target| {
            target > soft
                && target <= hard
                && setrlimit(Resource::RLIMIT_NOFILE, target, hard).is_ok()
        })
        .unwrap_or(soft);
    if limit < needed {
        warn!(
            limit,
            needed,
            "the open-file limit is below what server.limits.max_sockets and the venues need; \
             raise LimitNOFILE or lower max_sockets"
        );
    }
}

/// Loads the config and the key, and waits until the registry lists this
/// node. Returns `None` if a signal stops the wait.
async fn load(path: &Path, signals: &mut Signals) -> anyhow::Result<Option<Node>> {
    notify::status("loading the config and the key");
    let config = NodeConfig::load(path)?;
    let resolved = config.resolve()?;
    // Both fail loudly at startup rather than at the first publish.
    let signer = Arc::new(config.load_signing_key()?);
    let governance = config.governance()?;

    info!(
        address = %signer.address(),
        feeds = resolved.feeds.len(),
        "starting"
    );
    let Some(registry) = listed_registry(&config, governance, signer.address(), signals).await?
    else {
        return Ok(None);
    };

    // Prices go only to listed clients (SPEC §6.1), so the node fails closed:
    // no client list, no start.
    notify::status("fetching the client list");
    let clients = config
        .fetch_client_list()
        .await?
        .context("the config needs a [clients] section: nodes serve only listed clients")?
        .verify(governance, 0)?;
    info!(
        version = clients.version(),
        clients = clients.clients().len(),
        "client list verified"
    );
    Ok(Some(Node {
        config,
        resolved,
        signer,
        governance,
        registry,
        clients,
    }))
}

/// Fetches the registry until it lists `address`. Returns `None` if a signal
/// stops the wait.
///
/// An unlisted node does not ingest or serve. Every subscriber would discard
/// what it signs, while each node-local metric reads healthy. `init` starts the
/// node before governance lists it, so the node waits rather than exits.
async fn listed_registry(
    config: &NodeConfig,
    governance: Address,
    address: Address,
    signals: &mut Signals,
) -> anyhow::Result<Option<Registry>> {
    notify::status("fetching the registry");
    let mut waiting = false;
    loop {
        let registry = tokio::select! {
            registry = config.fetch_registry() => registry?,
            signal = signals.recv() => {
                info!(signal = signal?, "shutting down before the registry lists this node");
                return Ok(None);
            }
        };
        let verified = registry.verify(governance, 0)?;
        match verified.authorize(address) {
            Ok(_) => {
                if waiting {
                    info!(version = verified.version(), "the registry lists this node");
                }
                return Ok(Some(registry));
            }
            Err(error) if !waiting => {
                warn!(
                    %address,
                    version = verified.version(),
                    %error,
                    every_secs = LISTING_POLL.as_secs(),
                    "the registry does not list this node; waiting for governance to add it"
                );
                waiting = true;
            }
            Err(_) => {}
        }
        notify::status(&format!(
            "waiting for governance to add {address} to the registry"
        ));
        // Without this, systemd would time the start out after 90 s.
        notify::extend_start(LISTING_POLL.saturating_mul(2));
        tokio::select! {
            () = tokio::time::sleep(LISTING_POLL) => {}
            signal = signals.recv() => {
                info!(signal = signal?, "shutting down before the registry lists this node");
                return Ok(None);
            }
        }
    }
}

/// Starts one task per venue. Returns their events and the connection count.
fn spawn_ingest(
    binance: oracle_ingest::binance::BinanceConfig,
    venues: Vec<(
        oracle_types::Venue,
        Vec<oracle_node::config::VenueConnection>,
    )>,
    record: Option<&Path>,
    clock: &MonotonicClock,
    shutdown: &CancellationToken,
) -> anyhow::Result<(mpsc::Receiver<IngestEvent>, usize)> {
    // The same adapters either way; `--record` only wraps the transport. The
    // snapshot connector sits under the recorder, so a recording holds Binance's
    // REST snapshots and funding intervals, and a replay never calls REST. The
    // KuCoin and MEXC connectors sit there too, for tokens and contract records.
    let snapshots = SnapshotConnector::new(WebSocketConnector, binance.snapshot_routes())?
        .with_funding_info(binance.funding_info_routes())
        .with_open_interest(binance.open_interest_routes());
    let snapshots = MexcConnector::new(KucoinConnector::new(snapshots)?)?;
    let adapters = match record {
        Some(path) => {
            info!(path = %path.display(), "recording raw venue frames");
            let recorder = Recorder::to_file(path)?.with_clock(clock.clone());
            let connector = RecordingConnector::new(snapshots, recorder);
            build_adapters(binance, venues, connector, clock.clone())?
        }
        None => build_adapters(binance, venues, snapshots, clock.clone())?,
    };

    let (ingest_tx, ingest_rx) = mpsc::channel::<IngestEvent>(INGEST_CAPACITY);
    for adapter in adapters.adapters {
        let shutdown = shutdown.clone();
        let ingest_tx = ingest_tx.clone();
        let label = adapter.label().to_owned();
        tokio::spawn(async move {
            let result = adapter.run(ingest_tx, shutdown.clone()).await;
            // After shutdown the pipeline is gone, so a failed send is expected.
            if let Err(error) = result
                && !shutdown.is_cancelled()
            {
                error!(venue = %label, %error, "ingest stopped");
            }
        });
    }
    Ok((ingest_rx, adapters.connections))
}

/// One task owns the pipeline. Events are applied in arrival order, which is
/// what preserves the disconnect-before-reconnect guarantee.
struct PipelineTask {
    pipeline: Pipeline,
    ingest: mpsc::Receiver<IngestEvent>,
    state: Arc<ServerState>,
    tick: Duration,
    tail: bool,
    feeds: usize,
    /// Names each feed id in the tail.
    symbols: HashMap<FeedId, Symbol>,
    connections: usize,
    latency: NodeLatency,
    clock: MonotonicClock,
    shutdown: CancellationToken,
}

impl PipelineTask {
    fn apply(&mut self, event: &IngestEvent) {
        if self.tail {
            log_observation(event);
        }
        if let IngestEvent::Observation(observation) = event {
            self.latency.observed(observation);
        }
        self.pipeline.observe(event);
    }

    /// `timed` is `Some` after new input. Only a move or a flag change counts
    /// as latency: a heartbeat repeats old data, and a halt carries none.
    fn publish(
        &mut self,
        (signed, errors): (Vec<SignedUpdate>, Vec<AggError>),
        published: &mut HashSet<FeedId>,
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
            let reaction = self
                .pipeline
                .last_trigger(feed_id)
                .filter(|trigger| matches!(trigger.cause, Cause::Moved | Cause::Flags))
                .filter(|_| !update.update().flags.is_halted());
            published.insert(feed_id);
            let _ = self.state.publish(update);
            if let (Some(clock), Some(trigger)) = (timed, reaction) {
                self.latency.signed(trigger.observed_ns, clock.now_ns());
            }
        }
    }

    /// Venue reports, book frames and funding frames go out after each
    /// evaluation.
    fn publish_venues(&mut self, now_ns: u64) {
        let hub = Arc::clone(self.state.hub());
        let (reports, errors) = self
            .pipeline
            .venue_reports(now_ns, |feed| hub.has_subscriber(Channel::Venues, feed));
        for error in errors {
            warn!(%error, "venue report could not be encoded");
        }
        for report in reports {
            let _ = self.state.publish_venues(report);
        }
        let (books, errors) = self
            .pipeline
            .book_updates(now_ns, |book| hub.has_book_subscriber(book));
        for error in errors {
            warn!(%error, "book update could not be encoded");
        }
        for update in books {
            let _ = self.state.publish_book(update);
        }
        let (funding, errors) = self.pipeline.funding_updates(now_ns);
        for error in errors {
            warn!(%error, "funding update could not be encoded");
        }
        for update in funding {
            let _ = self.state.publish_funding(update);
        }
    }

    async fn run(mut self) {
        let clock = self.clock.clone();
        let mut ticker = tokio::time::interval(self.tick);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // `interval` fires at once; the first status is due after a full interval.
        let mut status_ticker =
            tokio::time::interval_at(tokio::time::Instant::now() + STATUS_EVERY, STATUS_EVERY);
        let mut published: HashSet<FeedId> = HashSet::new();
        let mut updates_before = 0;
        loop {
            let retry = self
                .pipeline
                .next_retry_ns()
                .map(|at| Duration::from_nanos(at.saturating_sub(clock.now_ns())));
            tokio::select! {
                biased;
                () = self.shutdown.cancelled() => break,
                event = self.ingest.recv() => {
                    let Some(event) = event else { break };
                    self.apply(&event);
                    for _ in 1..BATCH_MAX {
                        let Ok(event) = self.ingest.try_recv() else { break };
                        self.apply(&event);
                    }
                    let polled = self.pipeline.flush(clock.now_ns());
                    self.publish(polled, &mut published, Some(&clock));
                    self.publish_venues(clock.now_ns());
                }
                () = tokio::time::sleep(retry.unwrap_or_default()), if retry.is_some() => {
                    let polled = self.pipeline.flush(clock.now_ns());
                    self.publish(polled, &mut published, Some(&clock));
                    self.publish_venues(clock.now_ns());
                }
                _ = ticker.tick() => {
                    let polled = self.pipeline.tick(clock.now_ns());
                    self.publish(polled, &mut published, None);
                    self.publish_venues(clock.now_ns());
                }
                _ = status_ticker.tick() => {
                    let stats = self.pipeline.stats();
                    let (signed, venues) = self.latency.take();
                    let status = NodeStatus {
                        feeds_published: published.len(),
                        feeds: self.feeds,
                        clients: self.state.transport().session_count(),
                        connections_up: stats.connections_up(),
                        connections: self.connections,
                        updates: stats.published.saturating_sub(updates_before),
                        client_list_version: self.state.transport().clients_version(),
                        signed,
                    };
                    status.log();
                    log_venue_lag(&venues);
                    notify::status(&status.to_string());
                    published.clear();
                    updates_before = stats.published;
                }
            }
        }
        let stats = self.pipeline.stats();
        info!(
            observations = stats.observations,
            published = stats.published,
            connects = stats.connects,
            disconnects = stats.disconnects,
            unencodable = stats.encode_errors,
            "pipeline stopped"
        );
    }
}

/// SIGTERM and SIGINT, registered once at start. A signal that arrives
/// between two waits then stays queued, and is not lost.
struct Signals {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
}

impl Signals {
    fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                terminate: signal(SignalKind::terminate())?,
                interrupt: signal(SignalKind::interrupt())?,
            })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }

    /// Waits for the next signal, and names it.
    async fn recv(&mut self) -> std::io::Result<&'static str> {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.terminate.recv() => Ok("SIGTERM"),
                _ = self.interrupt.recv() => Ok("SIGINT"),
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await?;
            Ok("ctrl-c")
        }
    }
}

/// Runs the transport's clock: key rotation and deadlines every second, and a
/// client-list poll when it comes from a URL.
/// Keeps the node clock on wall time. A consumer compares publish times with its
/// own clock.
fn spawn_clock_sync(clock: MonotonicClock, shutdown: CancellationToken) {
    tokio::spawn(async move {
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
    });
}

fn spawn_transport_tasks(
    transport: Arc<NodeTransport>,
    config: NodeConfig,
    shutdown: CancellationToken,
) {
    {
        let transport = Arc::clone(&transport);
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    _ = ticker.tick() => transport.tick(unix_now()),
                }
            }
        });
    }
    let Some(poll_secs) = config
        .clients
        .as_ref()
        .filter(|clients| clients.url.is_some())
        .map(|clients| clients.poll_secs.max(1))
    else {
        return;
    };
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(poll_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                _ = ticker.tick() => {}
            }
            match config.fetch_client_list().await {
                Ok(Some(list)) => match transport.offer_clients(&list, unix_now()) {
                    Ok(Some(revoked)) => {
                        info!(version = list.version, revoked, "adopted client list");
                    }
                    Ok(None) => {}
                    Err(error) => warn!(%error, "client list refused"),
                },
                Ok(None) => {}
                Err(error) => warn!(%error, "client list fetch failed"),
            }
        }
    });
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use nix::sys::resource::{Resource, getrlimit};

    #[test]
    fn the_open_file_limit_rises_to_what_the_node_needs() {
        let (_, hard) = getrlimit(Resource::RLIMIT_NOFILE).expect("readable");
        raise_open_files(2_048);
        let (soft, _) = getrlimit(Resource::RLIMIT_NOFILE).expect("readable");
        assert!(soft >= hard.min(2_048), "soft {soft}, hard {hard}");
    }
}
