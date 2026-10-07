//! `oracle-proxy <config.toml>`: serves verified oracle data to web clients.

use std::future::IntoFuture as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use oracle_proxy::config::ProxyConfig;
use oracle_proxy::hub::Hub;
use oracle_proxy::{upstream, web};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Serves verified oracle data to web clients as JSON over one WebSocket.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// The proxy config file.
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let config = ProxyConfig::load(&args.config)?;

    let client = upstream::connect(&config.upstream, &config.feeds).await?;
    let hub = Arc::new(Hub::new(
        &config.feeds.prices,
        &config.feeds.venues,
        config.limits.max_subscriptions,
        config.limits.max_book_queue,
    ));
    let feeding = tokio::spawn(upstream::run(
        client,
        Arc::clone(&hub),
        config.feeds.prices.clone(),
        Duration::from_millis(config.limits.book_interval_ms),
    ));

    let listener = TcpListener::bind(config.listen).await?;
    info!(listen = %listener.local_addr()?, "serving web clients on /v1/ws");
    let app =
        web::router(hub, config.limits.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::select! {
        served = axum::serve(listener, app).into_future() => served?,
        fed = feeding => fed??,
        signal = shutdown_signal() => info!(signal = signal?, "shutting down"),
    }
    Ok(())
}

/// Waits for SIGTERM, which systemd sends to stop a service, or SIGINT.
async fn shutdown_signal() -> std::io::Result<&'static str> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map(|()| "SIGINT"),
            _ = terminate.recv() => Ok("SIGTERM"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.map(|()| "SIGINT")
    }
}
