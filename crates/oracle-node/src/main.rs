//! The node binary.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Args, CommandFactory as _, Parser, Subcommand};
use oracle_ingest::binance::BinanceAdapter;
use oracle_ingest::clock::wall_clock_unix_nanos;
use oracle_ingest::transport::WebSocketConnector;
use oracle_ingest::venues::VenueAdapter;
use oracle_ingest::{ExchangeAdapter, IngestEvent};
use oracle_node::{InitOptions, NodeConfig, NodeKeys, Pipeline, Rotation, candid_call};
use oracle_server::{ServerState, router};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Bound on the ingest queue.
///
/// Bounded so a stalled pipeline applies backpressure to ingest rather than
/// growing without limit. Dropping the socket is recoverable; running out of
/// memory is not.
const INGEST_CAPACITY: usize = 8_192;

/// Remaining certificate validity below which the operator is warned (SPEC §9.3).
const CERT_EXPIRY_WARNING: std::time::Duration = std::time::Duration::from_secs(7 * 86_400);

/// How often the certificate countdown is re-checked while running.
///
/// Checked repeatedly rather than only at startup: nodes run for months, and a
/// certificate issued with 30 days of validity will lapse mid-flight long before
/// anything else prompts a restart.
const CERT_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3_600);

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
    /// Signing certificate lifetime, in days.
    #[arg(long, default_value_t = InitOptions::default().validity_days)]
    validity_days: u64,
    /// Write the keys, registry entry, and a starter config to DIR instead of
    /// printing the secrets to the terminal.
    #[arg(long, value_name = "DIR")]
    out: Option<PathBuf>,
    /// The registry canister id. Prints the `dfx` call that submits the entry.
    #[arg(long, value_name = "CANISTER_ID")]
    canister: Option<String>,
}

#[derive(Args)]
struct RotateArgs {
    /// The directory `init --out` wrote: identity.key, signing.key, config.toml.
    #[arg(long, value_name = "DIR")]
    dir: PathBuf,
    /// The registry canister id. Prints the `dfx` call that swaps the key.
    #[arg(long, value_name = "CANISTER_ID")]
    canister: Option<String>,
    /// Signing certificate lifetime, in days.
    #[arg(long, default_value_t = InitOptions::default().validity_days)]
    validity_days: u64,
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
        Command::Start { config, tail } => start(config, tail).await,
    }
}

async fn start(path: PathBuf, tail: bool) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = NodeConfig::load(&path)?;
    let resolved = config.resolve()?;
    // Both fail loudly at startup rather than at the first publish.
    let signer = config.load_signing_key()?;
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
    report_cert_expiry(&verified, signer_address);

    let aggregator = oracle_agg::Aggregator::new(resolved.feeds)?;
    let mut pipeline = Pipeline::new(aggregator, signer);

    let state = ServerState::new(
        &config.node_id,
        &resolved.symbols,
        registry,
        config.server.max_pending_feeds,
    );
    let shutdown = CancellationToken::new();
    let (ingest_tx, mut ingest_rx) = mpsc::channel::<IngestEvent>(INGEST_CAPACITY);

    let mut adapters: Vec<Box<dyn ExchangeAdapter>> = Vec::new();
    if !resolved.binance.spot.is_empty() || !resolved.binance.perp.is_empty() {
        let adapter = BinanceAdapter::new(resolved.binance, WebSocketConnector)?;
        for (session, market, _) in adapter.plan()? {
            info!(venue = "binance", %market, url = %session.url, "ingest endpoint");
        }
        adapters.push(Box::new(adapter));
    }
    for (venue, connections) in resolved.venues {
        // Each connection carries its own decoder: a venue can speak different
        // protocols on different markets, and config resolution has already
        // refused any market this build cannot serve.
        let specs = connections
            .into_iter()
            .map(|connection| {
                info!(%venue, market = %connection.spec.market, url = %connection.spec.url,
                      "ingest endpoint");
                (connection.spec, connection.instruments)
            })
            .collect();
        adapters.push(Box::new(VenueAdapter::new(
            venue,
            specs,
            WebSocketConnector,
        )?));
    }
    if adapters.is_empty() {
        return Err("no venue adapters configured".into());
    }

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

    {
        let verified = verified.clone();
        let address = signer_address;
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(CERT_CHECK_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await; // The immediate first tick; startup already reported.
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    _ = ticker.tick() => report_cert_expiry(&verified, address),
                }
            }
        });
    }

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

/// Generates a node identity and prints everything needed to run it.
fn init_command(args: InitArgs) -> Result<(), Box<dyn std::error::Error>> {
    let options = InitOptions {
        node_id: args.node_id,
        operator: args.operator,
        endpoint: args.endpoint,
        validity_days: args.validity_days,
    };
    let out = args.out;

    let now = wall_clock_unix_nanos() / oracle_types::NANOS_PER_SEC;
    let keys = NodeKeys::generate(options, now)?;
    let entry = serde_json::to_string_pretty(&keys.registry_entry())?;
    let submit_call = args.canister.as_deref().map(|canister| {
        let compact = serde_json::to_string(&keys.registry_entry()).expect("entry serialises");
        candid_call(canister, "submit_entry", &[&compact])
    });

    println!("Generated a new identity for `{}`.\n", keys.options.node_id);
    println!("  identity  {}", keys.identity.address());
    println!(
        "            Long-lived. Signs certificates, never prices. Keep it out of\n\
         \x20           the node — a KMS, an HSM, or age-encrypted at rest."
    );
    println!("  signing   {}", keys.signing.address());
    println!(
        "            What your price updates recover to. Lives in node memory and\n\
         \x20           is what you rotate every {} days.",
        keys.options.validity_days
    );
    println!(
        "  valid     unix {} .. {} ({} days)",
        keys.cert.not_before, keys.cert.not_after, keys.options.validity_days
    );
    println!(
        "            The node refuses to start once this lapses, and warns from\n\
         \x20           seven days out. Rotate before then."
    );

    match &out {
        Some(dir) => {
            let (identity_path, signing_path) = keys.write_keys(dir)?;
            let entry_path = dir.join("node-entry.json");
            let config_path = dir.join("config.toml");
            let registry_path = dir.join("registry.json");
            std::fs::write(&entry_path, format!("{entry}\n"))?;
            std::fs::write(
                &config_path,
                keys.config_template(&signing_path, &registry_path),
            )?;

            println!("\nWritten");
            println!("  {}  (0600 — keep offline)", identity_path.display());
            println!("  {}  (0600 — the node reads this)", signing_path.display());
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
    if let Some(call) = submit_call {
        println!(
            "\nSubmit the entry to the registry canister as this node's operator, then \
             ask governance to approve it:\n\n{call}"
        );
    }

    println!("\nNext");
    println!(
        "  1. Governance adds that entry and publishes a new registry version.\n     \
         Until it does, nothing this node signs verifies for anyone."
    );
    println!("  2. Put the governance-signed registry.json on disk.");
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
    let identity_hex =
        zeroize::Zeroizing::new(std::fs::read_to_string(args.dir.join("identity.key"))?);
    let identity = oracle_wire::Signer::from_hex(identity_hex.trim())?;

    let now = wall_clock_unix_nanos() / oracle_types::NANOS_PER_SEC;
    let rotation = Rotation::generate(&identity, &config.node_id, args.validity_days, now)?;
    let (key_path, cert_path) = rotation.write(&args.dir)?;

    println!("Generated a new signing key for `{}`.\n", config.node_id);
    println!("  new signing  {}", rotation.signing.address());
    println!(
        "  valid        unix {} .. {} ({} days)",
        rotation.cert.not_before, rotation.cert.not_after, args.validity_days
    );
    println!("\nWritten");
    println!("  {}  (0600 — not loaded yet)", key_path.display());
    println!("  {}  (send to the registry)", cert_path.display());

    let call = args.canister.as_deref().map_or_else(
        || {
            "dfx canister call <CANISTER_ID> rotate_key '(<node-id>, <rotation-cert.json>)'"
                .to_owned()
        },
        |canister| rotation.canister_call(canister),
    );
    println!(
        "\nNext\n\n  1. Submit the rotation as this node's operator:\n\n     {call}\n\n  \
         2. Once the call succeeds the registry lists only the new key. Move it into \
         place and restart:\n\n     mv {key} {live}\n\n  \
         3. Consumers pick the new key up from the first frame it signs. The old key \
         is retired on the canister and can never be listed again.",
        key = key_path.display(),
        live = args.dir.join("signing.key").display(),
    );
    Ok(())
}

/// Logs how long this node's signing certificate remains valid.
///
/// SPEC §9.3 alerts on an expiry under seven days, because a lapsed certificate
/// is the quietest way for a node to fail: it keeps publishing, and consumers
/// silently stop counting it toward their quorum.
fn report_cert_expiry(registry: &oracle_wire::VerifiedRegistry, signer: oracle_wire::Address) {
    let Some(not_after) = registry.authorized_until(signer) else {
        return;
    };
    let remaining = not_after.saturating_sub(wall_clock_unix_nanos() / oracle_types::NANOS_PER_SEC);
    if remaining <= CERT_EXPIRY_WARNING.as_secs() {
        warn!(
            %signer,
            not_after,
            remaining_secs = remaining,
            "signing certificate expires soon; rotate now — once it lapses every \
             subscriber refuses this node while it goes on looking healthy here"
        );
    } else {
        info!(
            %signer,
            not_after,
            remaining_days = remaining / 86_400,
            "signing certificate valid"
        );
    }
}
