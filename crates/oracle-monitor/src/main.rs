//! `oracle-monitor`: the internal consumer SPEC §9.3 asks for.
//!
//! It subscribes to every node exactly as the SDK does, resolves every feed,
//! and exports what it sees: per feed, the status, the node count, the
//! inter-node spread and the confidence; per node, how far that node sits from
//! the resolved price. Cross-node divergence is the highest-signal metric in
//! the system. It catches a subtly wrong node that every node-local metric
//! reports as perfectly healthy.
//!
//! ```sh
//! oracle-monitor https://<canister>.icp0.io/registry.json 0x<governance> \
//!   CRYPTO.BTC/USD CRYPTO.ETH/USD --listen 127.0.0.1:9108
//! curl -s 127.0.0.1:9108/metrics
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use clap::Parser;
use metrics_exporter_prometheus::PrometheusBuilder;
use oracle_client::{FeedView, HttpRegistrySource, OracleClient, Resolved, Status};
use oracle_types::{FeedId, Fixed, Symbol};
use oracle_wire::feed_id;
use tracing::{info, warn};

/// Subscribe to every node and export cross-node divergence.
#[derive(Parser)]
#[command(name = "oracle-monitor", version)]
struct Args {
    /// A registry JSON file, or an `http(s)://` URL that serves one.
    registry: String,
    /// The pinned governance address, `0x`-hex.
    governance: oracle_wire::Address,
    /// Feed symbols to watch.
    #[arg(required = true)]
    symbols: Vec<Symbol>,
    /// Where to serve `/metrics`.
    #[arg(long, default_value = "127.0.0.1:9108")]
    listen: String,
    /// Nodes required for a price. Below three needs the acknowledgement.
    #[arg(long, default_value_t = 3)]
    quorum: usize,
    /// Allow a quorum below three. The monitor then reports a price one bad
    /// node can move, which is still worth watching, but is not a price to act on.
    #[arg(long)]
    i_understand_a_low_quorum_is_unsafe: bool,
    /// Treat updates older than this as gone.
    #[arg(long, default_value_t = 2)]
    max_age_secs: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    let prometheus = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|error| format!("cannot install the metrics recorder: {error}"))?;
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    info!(listen = %listener.local_addr()?, "serving /metrics");
    let app = Router::new().route(
        "/metrics",
        get(move || {
            let body = prometheus.render();
            async move {
                (
                    [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
                    body,
                )
            }
        }),
    );
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            warn!(%error, "metrics server stopped");
        }
    });

    let builder = if args.registry.starts_with("http://") || args.registry.starts_with("https://") {
        let source = Arc::new(HttpRegistrySource::new(args.registry.clone())?);
        OracleClient::builder_from_source(source, args.governance).await?
    } else {
        let registry: oracle_wire::Registry =
            serde_json::from_str(&std::fs::read_to_string(&args.registry)?)?;
        OracleClient::builder(registry.verify(args.governance, 0)?)
    };
    let mut builder = builder
        .quorum(args.quorum)
        .max_age(Duration::from_secs(args.max_age_secs));
    if args.i_understand_a_low_quorum_is_unsafe {
        builder = builder.i_understand_this_provides_no_protection_against_a_bad_node();
    }
    let mut client = builder.build()?;
    info!(version = client.registry_version(), "registry verified");

    let names: HashMap<FeedId, String> = args
        .symbols
        .iter()
        .map(|symbol| (feed_id(symbol), symbol.to_string()))
        .collect();
    let by_id: HashMap<FeedId, Symbol> = args
        .symbols
        .iter()
        .map(|symbol| (feed_id(symbol), *symbol))
        .collect();
    let refs: Vec<String> = args.symbols.iter().map(ToString::to_string).collect();
    let refs: Vec<&str> = refs.iter().map(String::as_str).collect();
    client.subscribe(&refs).await?;
    info!(feeds = refs.len(), "subscribed");

    loop {
        tokio::select! {
            resolved = client.next() => {
                let Some(resolved) = resolved else { break };
                let Some(name) = names.get(&resolved.feed_id) else { continue };
                export_feed(name, &resolved);
                if let Some(view) = by_id.get(&resolved.feed_id).and_then(|s| client.view(s)) {
                    export_nodes(name, &resolved, view);
                }
                export_client(&client);
            }
            signal = tokio::signal::ctrl_c() => {
                signal?;
                break;
            }
        }
    }
    client.shutdown();
    Ok(())
}

fn export_feed(feed: &str, resolved: &Resolved) {
    let status = match resolved.status {
        Status::Ok => 0.0,
        Status::Degraded => 1.0,
        Status::Halted => 2.0,
    };
    metrics::gauge!("oracle_monitor_status", "feed" => feed.to_owned()).set(status);
    metrics::gauge!("oracle_monitor_nodes", "feed" => feed.to_owned()).set(count(resolved.nodes));
    if let Some(spread) = resolved.spread_bps {
        metrics::gauge!("oracle_monitor_spread_bps", "feed" => feed.to_owned()).set(fixed(spread));
    }
    if let (Some(price), Some(conf)) = (resolved.price, resolved.conf)
        && price.is_positive()
        && let Some(bps) = conf.to_bps_of(price)
    {
        metrics::gauge!("oracle_monitor_conf_bps", "feed" => feed.to_owned()).set(fixed(bps));
    }
}

/// How far each node sits from the resolved price, in basis points.
fn export_nodes(feed: &str, resolved: &Resolved, view: &FeedView) {
    let Some(price) = resolved.price.filter(|p| p.is_positive()) else {
        return;
    };
    for (node, update) in view.latest() {
        let Ok(reported) = update.price_fixed() else {
            continue;
        };
        let Some(deviation) = deviation_bps(reported, price) else {
            continue;
        };
        metrics::gauge!(
            "oracle_monitor_node_deviation_bps",
            "feed" => feed.to_owned(),
            "node" => node.to_string()
        )
        .set(fixed(deviation));
    }
}

fn export_client(client: &OracleClient) {
    let stats = client.stats();
    metrics::gauge!("oracle_monitor_registry_version").set(count_u64(client.registry_version()));
    metrics::gauge!("oracle_monitor_registry_age_seconds").set(
        client
            .registry_age(oracle_client::now_unix_nanos())
            .as_secs_f64(),
    );
    metrics::gauge!("oracle_monitor_frames_accepted").set(count_u64(stats.accepted));
    metrics::gauge!("oracle_monitor_frames_untrusted").set(count_u64(stats.untrusted));
    metrics::gauge!("oracle_monitor_frames_retired").set(count_u64(stats.retired));
    metrics::gauge!("oracle_monitor_frames_replayed").set(count_u64(stats.replayed));
    metrics::gauge!("oracle_monitor_registry_refreshes").set(count_u64(stats.refreshes));
    metrics::gauge!("oracle_monitor_registry_refresh_failures")
        .set(count_u64(stats.refresh_failures));
}

/// Signed distance of `reported` from `reference`, in basis points of the
/// reference. Positive means the node is above the resolved price.
fn deviation_bps(reported: Fixed, reference: Fixed) -> Option<Fixed> {
    let (distance, negative) = if reported >= reference {
        (reported.checked_sub(reference)?, false)
    } else {
        (reference.checked_sub(reported)?, true)
    };
    let bps = distance.to_bps_of(reference)?;
    if negative {
        Fixed::ZERO.checked_sub(bps)
    } else {
        Some(bps)
    }
}

fn fixed(value: Fixed) -> f64 {
    value.to_string().parse().unwrap_or(f64::NAN)
}

fn count(value: usize) -> f64 {
    u32::try_from(value).map_or(f64::MAX, f64::from)
}

fn count_u64(value: u64) -> f64 {
    u32::try_from(value).map_or(f64::MAX, f64::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deviation_is_signed_basis_points_of_the_reference() {
        let reference: Fixed = "10000".parse().expect("valid");
        let above: Fixed = "10010".parse().expect("valid");
        let below: Fixed = "9990".parse().expect("valid");
        assert_eq!(
            deviation_bps(above, reference).map(|b| b.to_string()),
            Some("10".to_owned())
        );
        assert_eq!(
            deviation_bps(below, reference).map(|b| b.to_string()),
            Some("-10".to_owned())
        );
        assert_eq!(
            deviation_bps(reference, reference).map(|b| b.to_string()),
            Some("0".to_owned())
        );
    }
}
