//! Subscribes to live nodes and prints verified prices.
//!
//! ```sh
//! # From a registry file.
//! cargo run -p oracle-client --example subscribe -- \
//!   registry.json 0x<governance-address> CRYPTO.BTC/USDT
//! # From the registry canister, refreshing on rotation.
//! cargo run -p oracle-client --example subscribe -- \
//!   https://<canister-id>.icp0.io/registry.json 0x<governance-address> CRYPTO.BTC/USDT
//! ```
//!
//! Uses a quorum of one so it can run against a single local node. That is
//! explicitly unsafe, and the API makes you say so.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use oracle_client::{HttpRegistrySource, OracleClient, Status};

/// Subscribe to live nodes and print verified prices.
#[derive(Parser)]
struct Args {
    /// A registry JSON file, or an `http(s)://` URL that serves one.
    registry: String,
    /// The pinned governance address, `0x`-hex.
    governance: oracle_wire::Address,
    /// Feed symbols, such as `CRYPTO.BTC/USDT`.
    #[arg(required = true)]
    symbols: Vec<String>,
    /// How long to run.
    #[arg(long, default_value_t = 12)]
    seconds: u64,
    /// Print every Nth resolved price.
    #[arg(long, default_value_t = 20)]
    every: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // A URL refreshes on its own when a node rotates. A file is pinned until
    // the process restarts.
    let builder = if args.registry.starts_with("http://") || args.registry.starts_with("https://") {
        let source = Arc::new(HttpRegistrySource::new(args.registry.clone())?);
        OracleClient::builder_from_source(source, args.governance).await?
    } else {
        let registry: oracle_wire::Registry =
            serde_json::from_str(&std::fs::read_to_string(&args.registry)?)?;
        OracleClient::builder(registry.verify(args.governance, 0)?)
    };

    let mut client = builder
        .quorum(1)
        .i_understand_this_provides_no_protection_against_a_bad_node()
        .max_age(Duration::from_secs(5))
        .build()?;
    println!(
        "registry v{} verified against {}",
        client.registry_version(),
        args.governance
    );

    let refs: Vec<&str> = args.symbols.iter().map(String::as_str).collect();
    client.subscribe(&refs).await?;
    println!("subscribed to {refs:?} for {}s\n", args.seconds);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.seconds);
    let mut seen = 0_u32;
    let mut version = client.registry_version();
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(price)) = tokio::time::timeout_at(deadline, client.next()).await else {
            break;
        };
        seen += 1;
        if client.registry_version() != version {
            version = client.registry_version();
            println!("--- adopted registry v{version} ---");
        }
        if seen % args.every != 1 {
            continue;
        }
        let status = match price.status {
            Status::Ok => "ok",
            Status::Degraded => "degraded",
            Status::Halted => "HALTED",
        };
        println!(
            "{status:<9} price={:<18} conf={:<14} nodes={} concerns={:?}",
            price
                .price
                .map_or_else(|| "-".to_owned(), |p| p.to_string()),
            price.conf.map_or_else(|| "-".to_owned(), |c| c.to_string()),
            price.nodes,
            price.concerns
        );
    }

    let stats = client.stats();
    println!(
        "\nverified {} update(s) on registry v{}: {stats:?}",
        stats.accepted,
        client.registry_version()
    );
    if stats.accepted == 0 {
        return Err("no updates verified".into());
    }
    Ok(())
}
