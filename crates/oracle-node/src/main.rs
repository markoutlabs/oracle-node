//! The node binary.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, CommandFactory as _, Parser, Subcommand};
use oracle_ingest::clock::{MonotonicClock, wall_clock_unix_nanos};
use oracle_ingest::transport::WebSocketConnector;
use oracle_ingest::{IngestEvent, Recorder, RecordingConnector};
use oracle_node::keyfile;
use oracle_node::{
    InitOptions, NodeConfig, NodeKeys, PassphraseSource, Pipeline, Rotation, build_adapters,
    candid_call,
};
use oracle_server::{NodeTransport, ServerState, TransportConfig, router, unix_now};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Bound on the ingest queue.
///
/// Bounded so a stalled pipeline applies backpressure to ingest rather than
/// growing without limit. Dropping the socket is recoverable; running out of
/// memory is not.
const INGEST_CAPACITY: usize = 8_192;

#[tokio::main]
async fn main() -> ExitCode {
    match dispatch().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Plainly, not through `tracing`. Usage text wearing a timestamp and
            // an ERROR level reads as a crash rather than as an instruction, and
            // for `init` the subscriber is not even running.
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Price oracle node: ingest, aggregate, sign, serve.
#[derive(Parser)]
#[command(
    name = "oracle-node",
    version,
    after_help = "`oracle-node start <CONFIG> --tail` logs every decoded observation going into \
                  the aggregator and every signed update coming out, which is how you see what \
                  a venue is actually sending."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate this node's keys and print what to do with them.
    Init(InitArgs),
    /// Generate a new signing key for an existing node and print the registry
    /// call that swaps it in.
    Rotate(RotateArgs),
    /// Run the node: ingest, aggregate, sign, serve.
    Start {
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
    },
}

#[derive(Args)]
struct InitArgs {
    /// This node's identifier.
    #[arg(long, default_value_t = InitOptions::default().node_id)]
    node_id: String,
    /// Who runs it. Operator diversity is what makes the median mean anything.
    #[arg(long, default_value_t = InitOptions::default().operator)]
    operator: String,
    /// The WebSocket endpoint subscribers will connect to.
    #[arg(long, default_value_t = InitOptions::default().endpoint)]
    endpoint: String,
    /// Write the keys, registry entry, and a starter config to DIR instead of
    /// printing the secrets to the terminal. The keys are encrypted at rest.
    #[arg(long, value_name = "DIR")]
    out: Option<PathBuf>,
    /// A 0600 file holding the passphrase that encrypts the keys. Without it,
    /// `--out` prompts at the terminal. Recorded in the starter config.
    #[arg(long, value_name = "FILE", requires = "out")]
    passphrase_file: Option<PathBuf>,
    /// The registry canister id. Prints the `dfx` call governance runs to add the node.
    #[arg(long, value_name = "CANISTER_ID")]
    canister: Option<String>,
}

#[derive(Args)]
struct RotateArgs {
    /// The directory `init --out` wrote: identity.key, signing.key, config.toml.
    #[arg(long, value_name = "DIR")]
    dir: PathBuf,
    /// The registry canister id. Prints the `dfx` call governance runs to swap the key.
    #[arg(long, value_name = "CANISTER_ID")]
    canister: Option<String>,
    /// A 0600 file holding the passphrase that opens the identity key and
    /// encrypts the new signing key. Defaults to the config's
    /// `signing.passphrase_file`, then to a prompt.
    #[arg(long, value_name = "FILE")]
    passphrase_file: Option<PathBuf>,
}

async fn dispatch() -> Result<(), Box<dyn std::error::Error>> {
    // The bare-path form this binary used to take. Say so, rather than failing
    // with "unrecognized subcommand" at someone following an older README.
    if let Some(first) = std::env::args().nth(1)
        && first.ends_with(".toml")
    {
        return Err(format!(
            "did you mean `oracle-node start {first}`?\n\n{}",
            Cli::command().render_usage()
        )
        .into());
    }
    match Cli::parse().command {
        Command::Init(args) => init_command(args),
        Command::Rotate(args) => rotate_command(args),
        Command::Start {
            config,
            tail,
            record,
        } => start(config, tail, record).await,
    }
}

async fn start(
    path: PathBuf,
    tail: bool,
    record: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = NodeConfig::load(&path)?;
    let resolved = config.resolve()?;
    // Both fail loudly at startup rather than at the first publish.
    let signer = Arc::new(config.load_signing_key()?);
    let signer_address = signer.address();
    let registry = config.fetch_registry().await?;

    info!(
        node_id = %config.node_id,
        signer = %signer.address(),
        feeds = resolved.feeds.len(),
        "starting"
    );
    // The registry must list this node's signing address, or nothing it
    // publishes will verify. Catching it here beats discovering it downstream.
    let verified = registry.verify(config.registry.governance_address.parse()?, 0)?;
    // A hard failure, not a warning. An unauthorised node keeps ingesting,
    // aggregating and signing perfectly well — every node-local metric reads
    // healthy — while every subscriber discards the output. Refusing to start is
    // the only version of that failure anyone notices.
    if let Err(error) = verified.authorize(signer_address, wall_clock_unix_nanos()) {
        return Err(format!(
            "signing key {signer_address} is not authorised by registry v{}: {error}. \
             Nothing this node publishes would be accepted.",
            verified.version()
        )
        .into());
    }

    // Sequence numbers must never go backwards for this node, including across
    // restarts. Milliseconds since the epoch outrun any publish counter.
    let aggregator = oracle_agg::Aggregator::new(resolved.feeds)?
        .with_sequence_floor(wall_clock_unix_nanos() / 1_000_000);
    let mut pipeline = Pipeline::new(aggregator, Arc::clone(&signer));

    // Prices go only to listed clients (SPEC §6.1), so the node fails closed:
    // no client list, no start.
    let clients = config
        .fetch_client_list()
        .await?
        .ok_or("the config needs a [clients] section: nodes serve only listed clients")?
        .verify(config.governance()?, 0)?;
    info!(
        version = clients.version(),
        clients = clients.clients().len(),
        "client list verified"
    );
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
        &config.node_id,
        Arc::clone(&signer),
        clients,
        limits,
        config.server.max_pending_feeds,
        unix_now(),
    );
    let state = ServerState::new(&config.node_id, &resolved.symbols, registry, transport);
    let shutdown = CancellationToken::new();
    spawn_transport_tasks(
        Arc::clone(state.transport()),
        config.clone(),
        shutdown.clone(),
    );
    let (ingest_tx, mut ingest_rx) = mpsc::channel::<IngestEvent>(INGEST_CAPACITY);

    // The same adapters either way; `--record` only wraps the transport.
    let adapters = match &record {
        Some(path) => {
            info!(path = %path.display(), "recording raw venue frames");
            let connector = RecordingConnector::new(WebSocketConnector, Recorder::to_file(path)?);
            build_adapters(
                resolved.binance,
                resolved.venues,
                connector,
                MonotonicClock::new(),
            )?
        }
        None => build_adapters(
            resolved.binance,
            resolved.venues,
            WebSocketConnector,
            MonotonicClock::new(),
        )?,
    };

    for adapter in adapters {
        let shutdown = shutdown.clone();
        let ingest_tx = ingest_tx.clone();
        let label = adapter.label().to_owned();
        tokio::spawn(async move {
            if let Err(error) = adapter.run(ingest_tx, shutdown).await {
                error!(venue = %label, %error, "ingest stopped");
            }
        });
    }
    drop(ingest_tx);

    // One task owns the pipeline. Events are applied in arrival order, which is
    // what preserves the disconnect-before-reconnect guarantee.
    let pipeline_task = {
        let state = Arc::clone(&state);
        let shutdown = shutdown.clone();
        let tick = resolved.tick_interval;
        tokio::spawn(async move {
            let clock = oracle_ingest::clock::MonotonicClock::new();
            let mut ticker = tokio::time::interval(tick);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    event = ingest_rx.recv() => {
                        let Some(event) = event else { break };
                        if tail {
                            log_observation(&event);
                        }
                        pipeline.observe(&event);
                    }
                    _ = ticker.tick() => {
                        let (signed, errors) = pipeline.tick(clock.now_ns());
                        for error in errors {
                            warn!(%error, "feed could not be encoded");
                        }
                        for update in signed {
                            if tail {
                                log_update(&update);
                            }
                            let _ = state.publish(update);
                        }
                    }
                }
            }
            info!(stats = ?pipeline.stats(), "pipeline stopped");
        })
    };

    let listener = tokio::net::TcpListener::bind(&config.server.listen).await?;
    info!(listen = %listener.local_addr()?, "serving subscribers");
    let server = axum::serve(listener, router(state)).with_graceful_shutdown({
        let shutdown = shutdown.clone();
        async move { shutdown.cancelled().await }
    });

    tokio::select! {
        result = server => result?,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            info!("shutting down");
        }
    }

    shutdown.cancel();
    let _ = pipeline_task.await;
    Ok(())
}

/// Runs the transport's clock: key rotation and deadlines every second, and a
/// client-list poll when it comes from a URL.
fn spawn_transport_tasks(
    transport: Arc<NodeTransport>,
    config: oracle_node::NodeConfig,
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
                Ok(Some(list)) if list.version > transport.clients_version() => {
                    match transport.replace_clients(&list, unix_now()) {
                        Ok(revoked) => {
                            info!(version = list.version, revoked, "adopted client list")
                        }
                        Err(error) => warn!(%error, "client list refused"),
                    }
                }
                // The certificate proves the canister still serves this version.
                Ok(Some(list)) if list.version == transport.clients_version() => {
                    transport.confirm_clients(unix_now());
                }
                Ok(_) => {}
                Err(error) => warn!(%error, "client list fetch failed"),
            }
        }
    });
}

/// Generates a node identity and prints everything needed to run it.
fn init_command(args: InitArgs) -> Result<(), Box<dyn std::error::Error>> {
    let options = InitOptions {
        node_id: args.node_id,
        operator: args.operator,
        endpoint: args.endpoint,
    };
    let out = args.out;

    let now = wall_clock_unix_nanos() / oracle_types::NANOS_PER_SEC;
    let keys = NodeKeys::generate(options, now)?;
    let entry = serde_json::to_string_pretty(&keys.registry_entry())?;
    let add_call = args.canister.as_deref().map(|canister| {
        let compact = serde_json::to_string(&keys.registry_entry()).expect("entry serialises");
        candid_call(canister, "add_node", &[&compact])
    });

    println!("Generated a new identity for `{}`.\n", keys.options.node_id);
    println!("  identity  {}", keys.identity.address());
    println!(
        "            Long-lived. Signs certificates, never prices. Keep it out of\n\
         \x20           the node process, encrypted at rest on this machine."
    );
    println!("  signing   {}", keys.signing.address());
    println!(
        "            What your price updates recover to. Lives in node memory.\n\
         \x20           It never expires; rotate it if you think it leaked."
    );
    println!("  valid     from unix {}, no expiry", keys.cert.not_before);

    match &out {
        Some(dir) => {
            // Asked for before anything is written, so a refused prompt leaves
            // no half-initialised directory behind.
            let passphrase = PassphraseSource::from_file(args.passphrase_file.clone())
                .read("the new key files", true)?;
            let (identity_path, signing_path) = keys.write_keys(dir, &passphrase)?;
            let entry_path = dir.join("node-entry.json");
            let config_path = dir.join("config.toml");
            let registry_path = dir.join("registry.json");
            std::fs::write(&entry_path, format!("{entry}\n"))?;
            std::fs::write(
                &config_path,
                keys.config_template(
                    &signing_path,
                    &registry_path,
                    args.passphrase_file.as_deref(),
                ),
            )?;

            println!("\nWritten");
            println!("  {}  (age, 0600 — keep offline)", identity_path.display());
            println!(
                "  {}  (age, 0600 — the node reads this)",
                signing_path.display()
            );
            println!("  {}  (send to governance)", entry_path.display());
            println!("  {}  (starter config)", config_path.display());
        }
        None => {
            println!("\nSecret keys");
            println!("  identity  {}", &*keys.identity.to_secret_hex());
            println!("  signing   {}", &*keys.signing.to_secret_hex());
            println!(
                "\n  These are now in your terminal scrollback and shell history. Re-run\n  \
                 with `--out DIR` to write them to 0600 files instead."
            );
            println!("\nSend to governance\n\n{entry}");
        }
    }
    if let Some(call) = add_call {
        println!("\nGovernance adds the node to the registry canister with:\n\n{call}");
    }

    println!("\nNext");
    println!(
        "  1. Send the entry to governance. Nodes never call the canister. Until\n     \
         governance adds it, nothing this node signs verifies for anyone."
    );
    println!(
        "  2. Point `registry.url` and `clients.url` in the config at the canister's\n     \
         /registry.json and /clients.json, and set `registry.canister_id`."
    );
    println!(
        "  3. Set `governance_address` in the config. Ask governance for it —\n     \
         reading it out of the registry file you were sent would let that\n     \
         document vouch for its own author."
    );
    println!(
        "  4. oracle-node start {}",
        out.as_ref().map_or_else(
            || "config.toml".to_owned(),
            |dir| dir.join("config.toml").display().to_string()
        )
    );
    println!(
        "\nFor a self-contained local playground instead, which generates its own\n\
         governance key and registry:\n  \
         cargo run -p oracle-node --example gen_local_registry -- --nodes 5"
    );
    Ok(())
}

/// Logs one decoded observation on its way into the aggregator.
///
/// This is the venue's own view, after normalisation and before anything is
/// weighted, filtered or aggregated — which is what makes it the right place to
/// see whether an adapter is actually reading a feed correctly.
fn log_observation(event: &IngestEvent) {
    match event {
        IngestEvent::Observation(observation) => {
            let instrument = &observation.instrument;
            info!(
                target: "tail",
                venue = %instrument.venue,
                market = %instrument.market,
                symbol = %instrument.symbol,
                kind = observation.kind.as_str(),
                // The venue's own update id, where it sends one. Two lines with
                // the same price and a different seq are two real book updates
                // — `bookTicker` pushes on size-only changes too — which is
                // otherwise indistinguishable from a duplicate at a glance.
                seq = observation.seq.map(|s| s.to_string()).unwrap_or_default(),
                price = %observation.price,
                bid = observation.bid.map(|b| b.to_string()).unwrap_or_default(),
                ask = observation.ask.map(|a| a.to_string()).unwrap_or_default(),
                bid_qty = observation.bid_qty.map(|q| q.to_string()).unwrap_or_default(),
                ask_qty = observation.ask_qty.map(|q| q.to_string()).unwrap_or_default(),
                // `None` on venues that send no timestamp, and never used for
                // staleness — that is measured with our own clock.
                lag_ms = observation
                    .exchange_time_ns
                    .map(|venue_ns| {
                        (i128::from(observation.local_recv_ns) - i128::from(venue_ns)) / 1_000_000
                    })
                    .map(|ms| ms.to_string())
                    .unwrap_or_default(),
                "observation"
            );
        }
        IngestEvent::Connected { stream } => {
            info!(target: "tail", %stream, "stream up");
        }
        IngestEvent::Disconnected { stream, reason } => {
            warn!(target: "tail", %stream, %reason, "stream down — venue state invalidated");
        }
        // `IngestEvent` is non-exhaustive. A tail that silently skipped a new
        // variant would be least useful exactly when something new appeared.
        other => info!(target: "tail", ?other, "event"),
    }
}

/// Logs one signed update on its way out to subscribers.
fn log_update(update: &oracle_wire::SignedUpdate) {
    let payload = update.update();
    let status = if payload.flags.is_halted() {
        "HALTED"
    } else if payload.flags.is_degraded() {
        "degraded"
    } else {
        "ok"
    };
    info!(
        target: "tail",
        status,
        price = payload.price_fixed().map(|p| p.to_string()).unwrap_or_default(),
        conf = payload.conf_fixed().map(|c| c.to_string()).unwrap_or_default(),
        seq = payload.seq,
        sources = payload.num_sources,
        venues = ?payload.sources,
        "published"
    );
}

/// Generates a new signing key for an existing node.
///
/// Nothing on the node changes yet. The canister swaps keys atomically, so the
/// node keeps signing with its old key until the registry lists the new one.
fn rotate_command(args: RotateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = NodeConfig::load(&args.dir.join("config.toml"))?;
    // One passphrase opens the identity key and seals the new signing key, so
    // the node's `signing.passphrase_file` keeps working after the swap.
    let passphrase = PassphraseSource::from_file(
        args.passphrase_file
            .clone()
            .or_else(|| config.signing.passphrase_file.clone()),
    )
    .read("identity.key", false)?;
    let identity = keyfile::load_signer(&args.dir.join("identity.key"), Some(&passphrase))?;

    let now = wall_clock_unix_nanos() / oracle_types::NANOS_PER_SEC;
    let rotation = Rotation::generate(&identity, &config.node_id, now)?;
    let (key_path, cert_path) = rotation.write(&args.dir, &passphrase)?;

    println!("Generated a new signing key for `{}`.\n", config.node_id);
    println!("  new signing  {}", rotation.signing.address());
    println!(
        "  valid        from unix {}, no expiry",
        rotation.cert.not_before
    );
    println!("\nWritten");
    println!("  {}  (age, 0600 — not loaded yet)", key_path.display());
    println!("  {}  (send to governance)", cert_path.display());

    let call = args.canister.as_deref().map_or_else(
        || {
            "dfx canister call <CANISTER_ID> rotate_key '(<node-id>, <rotation-cert.json>)'"
                .to_owned()
        },
        |canister| rotation.canister_call(canister),
    );
    println!(
        "\nNext\n\n  1. Send the certificate to governance. They swap the key in with:\n\n     \
         {call}\n\n  \
         2. Once the call succeeds the registry lists only the new key. Move it into \
         place and restart:\n\n     mv {key} {live}\n\n  \
         3. Consumers pick the new key up from the first frame it signs. The old key \
         is retired on the canister and can never be listed again.",
        key = key_path.display(),
        live = args.dir.join("signing.key").display(),
    );
    Ok(())
}
