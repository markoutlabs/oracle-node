//! The node binary.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use oracle_ingest::binance::BinanceAdapter;
use oracle_ingest::transport::WebSocketConnector;
use oracle_ingest::{ExchangeAdapter as _, IngestEvent};
use oracle_node::{NodeConfig, Pipeline};
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

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let path: PathBuf = std::env::args()
        .nth(1)
        .ok_or("usage: oracle-node <config.toml>")?
        .into();

    let config = NodeConfig::load(&path)?;
    let resolved = config.resolve()?;
    // Both fail loudly at startup rather than at the first publish.
    let signer = config.load_signing_key()?;
    let registry = config.load_registry()?;

    info!(
        node_id = %config.node_id,
        signer = %signer.address(),
        feeds = resolved.feeds.len(),
        "starting"
    );
    // The registry must list this node's signing address, or nothing it
    // publishes will verify. Catching it here beats discovering it downstream.
    let verified = registry.verify(config.registry.governance_address.parse()?, 0)?;
    if verified.authorize(signer.address(), now_ns()).is_err() {
        warn!(
            signer = %signer.address(),
            "this signing key is not authorised by the registry; \
             subscribers will reject everything this node publishes"
        );
    }

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

    let adapter = Box::new(BinanceAdapter::new(resolved.binance, WebSocketConnector)?);
    for (session, market, _) in adapter.plan()? {
        info!(%market, url = %session.url, "ingest endpoint");
    }
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(error) = adapter.run(ingest_tx, shutdown).await {
                error!(%error, "ingest stopped");
            }
        });
    }

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
                        pipeline.observe(&event);
                    }
                    _ = ticker.tick() => {
                        let (signed, errors) = pipeline.tick(clock.now_ns());
                        for error in errors {
                            warn!(%error, "feed could not be encoded");
                        }
                        for update in signed {
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

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}
