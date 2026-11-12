//! `oracle-node start`: ingest, aggregate, sign, serve.
//!
//! Startup proves everything that would make the node useless before it binds
//! the port: the key opens, the registry lists this node, the client list
//! verifies. A node that the registry does not list yet waits for governance.
//! Then it serves until SIGTERM or SIGINT.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context as _;
use clap::Args;
use oracle_ingest::IngestEvent;
use oracle_ingest::clock::{MonotonicClock, wall_clock_unix_nanos};
use oracle_ingest::{Recorder, RecordingConnector};
use oracle_node::feed_set;
use oracle_node::ingest::{Ingest, connectors};
use oracle_node::publish::PushTarget;
use oracle_node::run::{INGEST_CAPACITY, sync_clock};
use oracle_node::{
    Adapter, LogFormat, NodeConfig, Pipeline, ResolvedConfig, build_adapters, logging,
};
use oracle_server::{NodeTransport, ServerState, TransportConfig, router, unix_now};
use oracle_wire::{Address, Registry, Signer, VerifiedClientList, VerifiedFeedSet};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::live_feeds::{FeedSetTask, Pace, Reconfigure, books_of, first_feed_set, names};
use crate::notify;
use crate::pipeline_task::PipelineTask;
use crate::process::Signals;
#[cfg(unix)]
use crate::process::raise_open_files;
use crate::status::{NodeLatency, Summary};

/// Open files beyond the client sockets and the venue connections: logs,
/// recordings, the runtime.
const SPARE_FILES: usize = 256;
/// How often a node that the registry does not list fetches it again.
const LISTING_POLL: Duration = Duration::from_secs(30);

/// The node stops so that systemd starts it again on the cached new feed set.
/// It exits 75, which the unit restarts.
#[derive(Debug, thiserror::Error)]
#[error("restarting on the new network feed set")]
pub(crate) struct RestartForFeeds;

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
    /// The network's feed set that `config` holds, if the node serves one.
    feed_set: Option<VerifiedFeedSet>,
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
        feed_set,
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
    let slot_registry = registry.clone();
    let symbols = names(&resolved.feeds);

    // Sequence numbers must never go backwards for this node, including across
    // restarts. Milliseconds since the epoch outrun any publish counter.
    let books = books_of(&resolved.feeds);
    let feeds_in_force = resolved.feeds.clone();
    let subscriptions = feed_set::subscriptions(&resolved);
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
    // A network feed set can hold more feeds than the config was written for.
    let max_pending = config.max_pending_for(feeds);
    let transport = NodeTransport::new(signer, clients, limits, max_pending, unix_now());
    let version = feed_set.as_ref().map_or(0, VerifiedFeedSet::version);
    let state = ServerState::with_books(&resolved.symbols, books, version, registry, transport);
    let shutdown = CancellationToken::new();
    spawn_transport_tasks(
        Arc::clone(state.transport()),
        config.clone(),
        shutdown.clone(),
    );
    let pace = push.map(|target| {
        info!(canister = %target.canister, gateway = %target.gateway, "pushing frames to the registry canister");
        let (pace, paced) = Pace::new(target.pace, feed_set.as_ref());
        crate::publish::spawn(Arc::clone(&state), push_signer, target, paced, shutdown.clone());
        pace
    });

    // One clock for receipt times and publish times, so a resync moves both.
    let clock = MonotonicClock::new();
    tokio::spawn(sync_clock(clock.clone(), shutdown.clone()));
    let (events, ingest) = mpsc::channel::<IngestEvent>(INGEST_CAPACITY);
    let mut adapters = Ingest::new(events, clock.clone(), shutdown.clone());
    adapters.start(first_adapters(
        resolved.binance,
        resolved.venues,
        args.record.as_deref(),
        &clock,
    )?);
    let connections = adapters.connections();
    let health = adapters.health();
    let (reconfigure, reconfigured) = mpsc::channel::<Reconfigure>(1);
    let restart = CancellationToken::new();
    let pipeline_task = tokio::spawn(
        PipelineTask {
            pipeline,
            ingest,
            reconfigure: reconfigured,
            state: Arc::clone(&state),
            tick: resolved.tick_interval,
            tail: args.tail,
            symbols,
            connections: Arc::clone(&connections),
            health,
            latency: NodeLatency::default(),
            clock,
            watchdog: notify::Watchdog::from_env(),
            shutdown: shutdown.clone(),
        }
        .run(),
    );
    if let Some(settings) = &config.network_feeds {
        tokio::spawn(
            FeedSetTask {
                config: config.clone(),
                feeds_in_force,
                subscriptions,
                version,
                governance,
                address,
                registry: slot_registry,
                slots: settings.slots(),
                poll: Duration::from_secs(settings.poll_secs.max(1)),
                cache: feed_set::cache_path(&args.config),
                state: Arc::clone(&state),
                ingest: adapters,
                pipeline: reconfigure,
                pace,
                recording: args.record.is_some(),
                restart: restart.clone(),
                shutdown: shutdown.clone(),
            }
            .run(),
        );
    }
    let connections = connections.load(Ordering::Relaxed);

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
    let mut restarting = false;
    tokio::select! {
        () = server => {},
        signal = signals.recv() => {
            info!(signal = signal?, "shutting down");
        }
        () = restart.cancelled() => {
            restarting = true;
        }
    }

    notify::stopping();
    shutdown.cancel();
    let _ = pipeline_task.await;
    if restarting {
        return Err(RestartForFeeds.into());
    }
    Ok(())
}

/// Loads the config and the key, and waits until the registry lists this
/// node. Returns `None` if a signal stops the wait.
async fn load(path: &Path, signals: &mut Signals) -> anyhow::Result<Option<Node>> {
    notify::status("loading the config and the key");
    let config = NodeConfig::load(path)?;
    // Both fail loudly at startup rather than at the first publish.
    let signer = Arc::new(config.load_signing_key()?);
    let governance = config.governance()?;
    let (config, resolved, feed_set) = match first_feed_set(&config, path, governance).await {
        Some(chosen) => (
            chosen.checked.config,
            chosen.checked.resolved,
            Some(chosen.set),
        ),
        None => {
            let resolved = config.resolve()?;
            (config, resolved, None)
        }
    };

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
        feed_set,
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

/// The venue adapters at start. With `--record`, the recorder sits under them,
/// so a recording holds Binance's REST snapshots and funding intervals, the
/// KuCoin and MEXC tokens and contract records, and Toobit's books: a replay
/// never calls REST.
fn first_adapters(
    binance: oracle_ingest::binance::BinanceConfig,
    venues: Vec<(
        oracle_types::Venue,
        Vec<oracle_node::config::VenueConnection>,
    )>,
    record: Option<&Path>,
    clock: &MonotonicClock,
) -> anyhow::Result<Vec<Adapter>> {
    let snapshots = connectors(&binance)?;
    Ok(match record {
        Some(path) => {
            info!(path = %path.display(), "recording raw venue frames");
            let recorder = Recorder::to_file(path)?.with_clock(clock.clone());
            let connector = RecordingConnector::new(snapshots, recorder);
            build_adapters(binance, venues, connector, clock.clone())?
        }
        None => build_adapters(binance, venues, snapshots, clock.clone())?,
    })
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
