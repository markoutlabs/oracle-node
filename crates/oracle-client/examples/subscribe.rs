//! Subscribes to live nodes and prints verified prices.
//!
//! ```sh
//! # From a registry file.
//! cargo run -p oracle-client --example subscribe -- \
//!   registry.json 0x<governance-address> CRYPTO.BTC/USDT
//! # From the registry canister, refreshing on rotation.
//! cargo run -p oracle-client --example subscribe -- \
//!   https://<canister-id>.raw.icp0.io/registry.json 0x<governance-address> CRYPTO.BTC/USDT
//! ```
//!
//! Uses a quorum of one so it can run against a single local node. That is
//! explicitly unsafe, and the API makes you say so.

use std::sync::Arc;
use std::time::Duration;

use oracle_client::{HttpRegistrySource, OracleClient, Status};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let registry_arg = args
        .next()
        .ok_or("usage: subscribe <registry.json|https://.../registry.json> <gov> <symbol...>")?;
    let governance: oracle_wire::Address =
        args.next().ok_or("missing governance address")?.parse()?;
    let symbols: Vec<String> = args.collect();
    if symbols.is_empty() {
        return Err("give at least one symbol".into());
    }

    // A URL refreshes on its own when a node rotates. A file is pinned until
    // the process restarts.
    let builder = if registry_arg.starts_with("http://") || registry_arg.starts_with("https://") {
        let source = Arc::new(HttpRegistrySource::new(registry_arg)?);
        OracleClient::builder_from_source(source, governance).await?
    } else {
        let registry: oracle_wire::Registry =
            serde_json::from_str(&std::fs::read_to_string(&registry_arg)?)?;
        OracleClient::builder(registry.verify(governance, 0)?)
    };

    let mut client = builder
        .quorum(1)
        .i_understand_this_provides_no_protection_against_a_bad_node()
        .max_age(Duration::from_secs(5))
        .build()?;
    println!(
        "registry v{} verified against {governance}",
        client.registry_version()
    );

    let refs: Vec<&str> = symbols.iter().map(String::as_str).collect();
    client.subscribe(&refs).await?;
    println!("subscribed to {refs:?}\n");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    let mut seen = 0_u32;
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(price)) = tokio::time::timeout_at(deadline, client.next()).await else {
            break;
        };
        seen += 1;
        if seen % 20 != 1 {
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
    println!("\nverified {} update(s): {stats:?}", stats.accepted);
    if stats.accepted == 0 {
        return Err("no updates verified".into());
    }
    Ok(())
}
