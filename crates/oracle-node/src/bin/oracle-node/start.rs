//! `oracle-node start`: ingest, aggregate, sign, serve.
//!
//! Startup proves everything that would make the node useless before it binds
//! the port: the key opens, the registry lists this node, the client list
//! verifies. Then it serves until SIGTERM or SIGINT.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::Args;
use oracle_ingest::IngestEvent;
use oracle_ingest::clock::{MonotonicClock, wall_clock_unix_nanos};
use oracle_ingest::transport::WebSocketConnector;
use oracle_ingest::{Recorder, RecordingConnector};
use oracle_node::{LogFormat, NodeConfig, Pipeline, ResolvedConfig, build_adapters, logging};
use oracle_server::{NodeTransport, ServerState, TransportConfig, router, unix_now};
use oracle_types::FeedId;
use oracle_wire::{Address, Registry, Signer, VerifiedClientList};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::notify;
use crate::status::{NodeStatus, STATUS_EVERY, Summary};
use crate::tail::{log_observation, log_update};

/// Bound on the ingest queue.
///
/// Bounded so a stalled pipeline applies backpressure to ingest rather than
/// growing without limit. Dropping the socket is recoverable; running out of
/// memory is not.
const INGEST_CAPACITY: usize = 8_192;

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
    let Node {
        config,
        resolved,
        signer,
        governance,
        registry,
        clients,
    } = load(&args.config).await?;
    let address = signer.address();
    let registry_version = registry.version;
    let feeds = resolved.symbols.len();

    // Sequence numbers must never go backwards for this node, including across
    // restarts. Milliseconds since the epoch outrun any publish counter.
    let aggregator = oracle_agg::Aggregator::new(resolved.feeds)?
        .with_sequence_floor(wall_clock_unix_nanos() / 1_000_000);
    let pipeline = Pipeline::new(aggregator, Arc::clone(&signer));

    // Freshness limits catch a withheld canister update. An operator's own file
    // cannot be withheld, and is never refreshed, so it is exempt.
    let limits = if config.clients.as_ref().is_some_and(|c| c.path.is_some()) {
        TransportConfig {
            admit_within: u64::MAX,
            serve_within: u64::MAX,
            ..TransportConfig::default()
        }
    } else {
        TransportConfig::default()
    };
    let transport = NodeTransport::new(
        signer,
        clients,
        limits,
        config.server.max_pending_feeds,
        unix_now(),
    );
    let state = ServerState::new(&resolved.symbols, registry, transport);
    let shutdown = CancellationToken::new();
    spawn_transport_tasks(
        Arc::clone(state.transport()),
        config.clone(),
        shutdown.clone(),
    );

    let (ingest, connections) = spawn_ingest(
        resolved.binance,
        resolved.venues,
        args.record.as_deref(),
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
            connections,
            shutdown: shutdown.clone(),
        }
        .run(),
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

    let server = axum::serve(listener, router(state)).with_graceful_shutdown({
        let shutdown = shutdown.clone();
        async move { shutdown.cancelled().await }
    });
    tokio::select! {
        result = server => result?,
        signal = shutdown_signal() => {
            info!(signal = signal?, "shutting down");
        }
    }

    notify::stopping();
    shutdown.cancel();
    let _ = pipeline_task.await;
    Ok(())
}

/// Loads the config and the key, and proves the registry lists this node.
async fn load(path: &Path) -> anyhow::Result<Node> {
    notify::status("loading the config and the key");
    let config = NodeConfig::load(path)?;
    let resolved = config.resolve()?;
    // Both fail loudly at startup rather than at the first publish.
    let signer = Arc::new(config.load_signing_key()?);
    let governance = config.governance()?;
    notify::status("fetching the registry");
    let registry = config.fetch_registry().await?;

    info!(
        address = %signer.address(),
        feeds = resolved.feeds.len(),
        "starting"
    );
    // The registry must list this node's signing address, or nothing it
    // publishes will verify. Catching it here beats discovering it downstream.
    let verified = registry.verify(governance, 0)?;
    // A hard failure, not a warning. An unauthorised node keeps ingesting,
    // aggregating and signing perfectly well — every node-local metric reads
    // healthy — while every subscriber discards the output. Refusing to start is
    // the only version of that failure anyone notices.
    if let Err(error) = verified.authorize(signer.address()) {
        anyhow::bail!(
            "node {} is not listed in registry v{}: {error}. \
             Nothing this node publishes would be accepted.",
            signer.address(),
            verified.version()
        );
    }

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
    Ok(Node {
        config,
        resolved,
        signer,
        governance,
        registry,
        clients,
    })
}

/// Starts one task per venue. Returns their events and the connection count.
fn spawn_ingest(
    binance: oracle_ingest::binance::BinanceConfig,
    venues: Vec<(
        oracle_types::Venue,
        Vec<oracle_node::config::VenueConnection>,
    )>,
    record: Option<&Path>,
    shutdown: &CancellationToken,
) -> anyhow::Result<(mpsc::Receiver<IngestEvent>, usize)> {
    // The same adapters either way; `--record` only wraps the transport.
    let adapters = match record {
        Some(path) => {
            info!(path = %path.display(), "recording raw venue frames");
            let connector = RecordingConnector::new(WebSocketConnector, Recorder::to_file(path)?);
            build_adapters(binance, venues, connector, MonotonicClock::new())?
        }
        None => build_adapters(binance, venues, WebSocketConnector, MonotonicClock::new())?,
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
    connections: usize,
    shutdown: CancellationToken,
}

impl PipelineTask {
    async fn run(mut self) {
        let clock = MonotonicClock::new();
        let mut ticker = tokio::time::interval(self.tick);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // `interval` fires at once; the first status is due after a full interval.
        let mut status_ticker =
            tokio::time::interval_at(tokio::time::Instant::now() + STATUS_EVERY, STATUS_EVERY);
        let mut published: HashSet<FeedId> = HashSet::new();
        let mut updates_before = 0;
        loop {
            tokio::select! {
                biased;
                () = self.shutdown.cancelled() => break,
                event = self.ingest.recv() => {
                    let Some(event) = event else { break };
                    if self.tail {
                        log_observation(&event);
                    }
                    self.pipeline.observe(&event);
                }
                _ = ticker.tick() => {
                    let (signed, errors) = self.pipeline.tick(clock.now_ns());
                    for error in errors {
                        warn!(%error, "feed could not be encoded");
                    }
                    for update in signed {
                        if self.tail {
                            log_update(&update);
                        }
                        published.insert(update.update().feed_id);
                        let _ = self.state.publish(update);
                    }
                }
                _ = status_ticker.tick() => {
                    let stats = self.pipeline.stats();
                    let status = NodeStatus {
                        feeds_published: published.len(),
                        feeds: self.feeds,
                        clients: self.state.transport().session_count(),
                        connections_up: stats.connections_up(),
                        connections: self.connections,
                        updates: stats.published.saturating_sub(updates_before),
                        client_list_version: self.state.transport().clients_version(),
                    };
                    status.log();
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

/// Waits for SIGTERM, which systemd sends to stop the node, or SIGINT.
async fn shutdown_signal() -> std::io::Result<&'static str> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        tokio::select! {
            _ = terminate.recv() => Ok("SIGTERM"),
            _ = interrupt.recv() => Ok("SIGINT"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok("ctrl-c")
    }
}

/// Runs the transport's clock: key rotation and deadlines every second, and a
/// client-list poll when it comes from a URL.
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
