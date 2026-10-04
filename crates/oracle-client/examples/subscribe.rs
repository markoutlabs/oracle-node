//! Subscribes to live nodes as a listed client and prints verified prices.
//!
//! ```sh
//! # From a registry file.
//! cargo run -p oracle-client --example subscribe -- \
//!   registry.json 0x<governance-address> CRYPTO.BTC/USDT \
//!   --client-id c-1 --client-key client.key
//! # From the registry canister, refreshing on rotation. Add `--root-key`
//! # off mainnet.
//! cargo run -p oracle-client --example subscribe -- \
//!   https://<canister-id>.raw.icp0.io/registry.json 0x<governance-address> CRYPTO.BTC/USDT \
//!   --canister-id <canister-id> --client-id c-1 --client-key client.key
//! ```
//!
//! The `client_key` example makes a key; governance lists it with `add_client`.
//!
//! Uses a quorum of one so it can run against a single local node. That is
//! explicitly unsafe, and the API makes you say so.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use oracle_client::{Certification, HttpRegistrySource, OracleClient, Status};

/// Subscribe to live nodes and print verified prices.
#[derive(Parser)]
struct Args {
    /// A registry JSON file, or the canister's `/registry.json` URL.
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
    /// Client id in the nodes' client list.
    #[arg(long)]
    client_id: String,
    /// File holding the client API key as hex.
    #[arg(long)]
    client_key: std::path::PathBuf,
    /// The registry canister, whose certificate a URL response must carry.
    #[arg(long)]
    canister_id: Option<String>,
    /// The network's root key in hex. Mainnet if not set.
    #[arg(long)]
    root_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // A URL refreshes on its own when a node rotates. A file is pinned until
    // the process restarts.
    let builder = if args.registry.starts_with("http://") || args.registry.starts_with("https://") {
        let canister = args
            .canister_id
            .as_deref()
            .ok_or("--canister-id is needed with a URL")?;
        let certification = match &args.root_key {
            Some(root_key) => Certification::new(canister, root_key)?,
            None => Certification::mainnet(canister)?,
        };
        let source = Arc::new(HttpRegistrySource::new(&args.registry, certification)?);
        OracleClient::builder_from_source(source, args.governance).await?
    } else {
        let registry: oracle_wire::Registry =
            serde_json::from_str(&std::fs::read_to_string(&args.registry)?)?;
        OracleClient::builder(registry.verify(args.governance, 0)?)
    };

    let key = oracle_wire::Signer::from_hex(std::fs::read_to_string(&args.client_key)?.trim())?;
    let builder = builder.client_key(args.client_id.clone(), key);
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
