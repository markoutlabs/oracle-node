//! Live latency on one machine: the registry canister on PocketIC, the
//! `oracle-node` binary on every feed in `node/all-feeds.toml` against the real
//! venues, and the SDK as a listed client.
//!
//! Ignored by default because it needs the internet. `make latency` runs it in
//! release mode; `LATENCY_SECS` sets the measured span (default 60).
#![cfg(unix)]

mod common;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oracle_client::{ClientStats, HttpRegistrySource, LatencyReport, OracleClient};
use oracle_registry_canister::testing::Harness;
use oracle_server::unix_now;
use oracle_wire::{NodeEntry, Signer};
use serde_json::Value;
use tokio::runtime::Runtime;

use common::{BINARY, Node, READY, fields_of, free_port};

/// Venue connections and local books settle in this time; it is not measured.
const WARM_UP: Duration = Duration::from_secs(15);
const STATUS: &str = "status";
const VENUE_LAG: &str = "venue lag";

#[test]
#[ignore = "needs the internet; run with `make latency`"]
fn live_latency_from_the_venues_to_the_sdk() {
    let span = std::env::var("LATENCY_SECS")
        .ok()
        .and_then(|secs| secs.parse().ok())
        .map_or(Duration::from_secs(60), Duration::from_secs);
    let mut canister = Harness::new(1, "dfx_test_key", None);
    let gateway = canister.make_live();
    let governance = canister.refresh_governance_key();
    let dir = common::scratch("latency");
    std::fs::create_dir_all(&dir).expect("creates");

    let node_dir = dir.join("node");
    let passphrase_file = common::passphrase_file(&node_dir);
    let port = free_port();
    let output = Command::new(BINARY)
        .arg("init")
        .arg("--out")
        .arg(&node_dir)
        .args(["--passphrase-file", &passphrase_file])
        .args(["--endpoint", &format!("ws://127.0.0.1:{port}/v2/ws")])
        .args(["--canister", &canister.canister.to_text()])
        .args(["--gateway", &gateway])
        .args(["--root-key", &canister.root_key()])
        .args(["--governance", &governance.to_checksummed()])
        .output()
        .expect("init runs");
    assert!(output.status.success(), "{output:?}");
    let entry = std::fs::read_to_string(node_dir.join("node-entry.json")).expect("init wrote it");
    let entry: NodeEntry = serde_json::from_str(&entry).expect("an entry");
    assert_eq!(canister.add_node(&entry), Ok(1));
    let config = node_dir.join("config.toml");
    let symbols = serve_every_feed(&config, port);

    let key = Signer::generate().expect("a key");
    assert_eq!(
        canister.add_client(key.address(), unix_now() + 86_400),
        Ok(1)
    );
    let node = Node::spawn(common::start(&config, "json"), dir.join("node.log"));
    node.wait(READY);

    let source = HttpRegistrySource::new(&canister.url("registry.json"), canister.certification())
        .expect("builds");
    let runtime = Runtime::new().expect("runtime");
    let (latency, stats) = runtime.block_on(async {
        let mut client = OracleClient::builder_from_source(Arc::new(source), governance)
            .await
            .expect("the registry verifies")
            .client_key(key)
            .quorum(1)
            .i_understand_this_provides_no_protection_against_a_bad_node()
            .build()
            .expect("builds");
        let names: Vec<&str> = symbols.iter().map(String::as_str).collect();
        client.subscribe(&names).await.expect("subscribes");
        drain(&mut client, WARM_UP).await;
        client.reset_latency();
        let before = client.stats();
        drain(&mut client, span).await;
        let mut stats = client.stats();
        stats.accepted = stats.accepted.saturating_sub(before.accepted);
        (client.latency(), stats)
    });
    let status = second_report(&node, STATUS);
    let lag = second_report(&node, VENUE_LAG);
    drop(node);
    report(span, symbols.len(), &stats, &latency, &status, &lag);
    assert!(stats.accepted > 0, "no update arrived: {stats:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Merges the feeds of `node/all-feeds.toml` into the config `init` wrote, and
/// returns their symbols.
fn serve_every_feed(config: &Path, port: u16) -> Vec<String> {
    let all = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../node/all-feeds.toml");
    let all: toml::Table =
        toml::from_str(&std::fs::read_to_string(all).expect("reads")).expect("all-feeds is TOML");
    let mut table: toml::Table =
        toml::from_str(&std::fs::read_to_string(config).expect("init wrote it")).expect("TOML");
    for key in ["feeds", "tick_interval_ms"] {
        if let Some(value) = all.get(key) {
            table.insert(key.to_owned(), value.clone());
        }
    }
    let server: toml::Table =
        toml::from_str(&format!("listen = \"127.0.0.1:{port}\"")).expect("TOML");
    match table.get_mut("server") {
        Some(toml::Value::Table(section)) => section.extend(server),
        _ => {
            table.insert("server".to_owned(), toml::Value::Table(server));
        }
    }
    std::fs::write(config, toml::to_string(&table).expect("serialises")).expect("writes");
    all.get("feeds")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|feed| feed.get("symbol")?.as_str().map(str::to_owned))
        .collect()
}

async fn drain(client: &mut OracleClient, span: Duration) {
    let deadline = tokio::time::Instant::now() + span;
    while let Ok(Some(_)) = tokio::time::timeout_at(deadline, client.next()).await {}
}

/// The node reports once a minute. The second report is the first one with no
/// startup in it.
fn second_report(node: &Node, message: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(150);
    loop {
        if let Some(found) = node
            .log()
            .lines()
            .filter_map(|line| event(line, message))
            .nth(1)
        {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "the node logged no second {message} line"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn event(line: &str, message: &str) -> Option<Value> {
    let fields = fields_of(line)?;
    (fields.get("message")?.as_str()? == message).then_some(fields)
}

fn report(
    span: Duration,
    feeds: usize,
    stats: &ClientStats,
    latency: &LatencyReport,
    status: &Value,
    lag: &Value,
) {
    let field = |fields: &Value, name: &str| match fields.get(name) {
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    };
    println!(
        "\nlatency over {} s: {feeds} feeds, {} updates accepted\n",
        span.as_secs(),
        stats.accepted
    );
    println!(
        "venue to node (venue clocks)  p50/p99 {}",
        field(lag, "p50_p99")
    );
    println!(
        "venue data to signed (node)   p50 {} ms, p99 {} ms",
        field(status, "signed_p50_ms"),
        field(status, "signed_p99_ms")
    );
    println!("signed to SDK (delivery)      {}", latency.delivery);
    println!("venue data to SDK (data age)  {}", latency.data_age);
    println!("SDK processing                {}", latency.processing);
}
