//! The whole system in one test: the registry canister on PocketIC behind a
//! live HTTP gateway, the `oracle-node` binary, and the SDK as a listed client
//! over the encrypted transport (SPEC §6.1).
//!
//! The node rotates its key under a live client, then governance revokes that
//! client and lists another one that expires. A local Binance-shaped venue
//! feeds the node, so the test needs no internet. `scripts/smoke.sh` covers
//! the icp-cli side: `icp.yaml`, `icp deploy`, and the calls `init` and
//! `rotate` print.
#![cfg(unix)]

mod common;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::routing::get;
use oracle_client::{ClientStats, HttpRegistrySource, OracleClient};
use oracle_registry_canister::prices::PriceStatus;
use oracle_registry_canister::testing::Harness;
use oracle_server::unix_now;
use oracle_wire::{Address, NodeEntry, Signer};
use serde_json::Value;
use tokio::runtime::{Handle, Runtime};
use tokio::sync::watch;

use common::{BINARY, Node, READY, WAIT, fields_of, free_port};

const FEED: &str = "CRYPTO.BTC/USDT";
/// A funding feed from the venue's perpetual, for the funding frames.
const FUNDING: &str = "CRYPTO.BTC/USD.FUNDING_8H";
/// Short broadcast-key epochs, so a client's deadline falls inside the test.
const EPOCH_SECS: u64 = 5;
/// Several node heartbeats: a client that gets nothing for this long is cut off.
const SILENCE: Duration = Duration::from_secs(3);

#[test]
fn a_client_follows_a_rotation_and_loses_access_on_revocation_and_expiry() {
    let mut canister = Harness::new(1, "dfx_test_key", Some(EPOCH_SECS));
    let gateway = canister.make_live();
    let governance = canister.refresh_governance_key();
    let runtime = Runtime::new().expect("runtime");
    let venue = start_venue(&runtime);
    let dir = common::scratch("e2e");
    std::fs::create_dir_all(&dir).expect("creates");

    // The operator runs `init`; governance lists the entry it wrote.
    let node_dir = dir.join("node");
    let passphrase_file = common::passphrase_file(&node_dir);
    let port = free_port();
    run(Command::new(BINARY)
        .arg("init")
        .arg("--out")
        .arg(&node_dir)
        .args(["--passphrase-file", &passphrase_file])
        .args(["--endpoint", &format!("ws://127.0.0.1:{port}/v2/ws")])
        .args(["--canister", &canister.canister.to_text()])
        .args(["--gateway", &gateway])
        .args(["--root-key", &canister.root_key()])
        .args(["--governance", &governance.to_checksummed()]));
    let entry = std::fs::read_to_string(node_dir.join("node-entry.json")).expect("init wrote it");
    let entry: NodeEntry = serde_json::from_str(&entry).expect("an entry");
    let old = entry.address;
    assert_eq!(canister.add_node(&entry), Ok(1));
    let config = node_dir.join("config.toml");
    run_locally(&config, port, &venue);

    let c1 = Signer::generate().expect("a key");
    let c1_address = c1.address();
    assert_eq!(canister.add_client(c1_address, unix_now() + 86_400), Ok(1));

    let node = Node::spawn(common::start(&config, "json"), dir.join("node1.log"));
    let serving = event(&node, READY, |_| true);
    assert_eq!(address_in(&serving, "address"), Some(old));
    let mut client = Subscriber::start(&runtime, &canister, governance, c1);
    client.until("verified a price", |seen| seen.stats.accepted >= 3);
    client.until("verified a venue report", |seen| {
        seen.stats.venue_reports >= 1
    });
    client.until("verified a funding frame", |seen| {
        seen.stats.funding_updates >= 1
    });

    // Rotation under the live client: a new key, `replace_node`, a restart.
    run(Command::new(BINARY)
        .arg("rotate")
        .arg("--dir")
        .arg(&node_dir));
    let next_key = node_dir.join("signing.key.next");
    let new = common::load_key(&next_key).address();
    assert_eq!(canister.replace_node(old, new), Ok(2));
    std::fs::rename(&next_key, node_dir.join("signing.key")).expect("moves the key");
    let first_log = node.stop();
    assert!(
        events(&first_log, "shutting down").any(|fields| text(&fields, "signal") == "SIGTERM"),
        "the node did not stop on SIGTERM"
    );
    let node = Node::spawn(common::start(&config, "json"), dir.join("node2.log"));
    let serving = event(&node, READY, |_| true);
    assert_eq!(address_in(&serving, "address"), Some(new));
    assert_eq!(serving.get("registry").and_then(Value::as_u64), Some(2));
    let before = client.seen().stats.accepted;
    let stats = client
        .until("adopted registry v2", |seen| {
            seen.registry == 2 && seen.stats.accepted >= before + 3
        })
        .stats;
    assert_eq!(stats.untrusted, 0, "{stats:?}");
    assert_eq!(stats.replayed, 0, "{stats:?}");
    assert_eq!(stats.refresh_failures, 0, "{stats:?}");
    // A scheduled poll can adopt the new key first, so none is fine too.
    assert!(stats.refreshes <= 1, "{stats:?}");

    // Revocation: the node closes the live session and rotates its broadcast key.
    assert_eq!(canister.remove_client(c1_address), Ok(2));
    event(&node, "client session closed", |fields| {
        address_in(fields, "client") == Some(c1_address) && text(fields, "reason") == "Revoked"
    });
    event(
        &node,
        "client sessions revoked; broadcast keys rotated",
        |_| true,
    );
    client.assert_cut_off("revoked");
    client.stop();

    // Expiry: a client listed for 15 s gets prices, then loses its session at
    // the last epoch boundary before it expires.
    let c2 = Signer::generate().expect("a key");
    let c2_address = c2.address();
    let expires_at = unix_now() + 15;
    assert_eq!(canister.add_client(c2_address, expires_at), Ok(3));
    event(&node, "adopted client list", |fields| {
        fields.get("version").and_then(Value::as_u64) == Some(3)
    });
    let mut late = Subscriber::start(&runtime, &canister, governance, c2);
    late.until("verified a price", |seen| seen.stats.accepted >= 1);
    event(&node, "client session closed", |fields| {
        address_in(fields, "client") == Some(c2_address) && text(fields, "reason") == "Expired"
    });
    // The node checks deadlines once a second.
    let closed_at = unix_now();
    assert!(
        closed_at >= expires_at - EPOCH_SECS && closed_at <= expires_at + 1,
        "closed at {closed_at}, expiry {expires_at}"
    );
    late.assert_cut_off("expired");
    late.stop();

    // The canister keeps the old address as retired, so it is never listed again.
    let retired = canister.listing(old).expect("the old address is known");
    assert!(retired.removed_at.is_some(), "{retired:?}");
    let listed = canister.listing(new).expect("the new address is listed");
    assert_eq!(listed.removed_at, None);

    // Every line is a JSON event, so nothing panicked or wrote around the logger.
    for line in first_log.lines().chain(node.stop().lines()) {
        assert!(fields_of(line).is_some(), "not a log event: {line}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A Binance-shaped venue: one `bookTicker` frame every 100 ms, and a
/// `markPrice` frame with funding every 500 ms, on every connection. Returns
/// the URL for the node's `[[endpoints]]`.
/// The node pushes its frames to the registry canister, which resolves the
/// median and serves it to other canisters (SPEC §3.7).
#[test]
fn a_node_pushes_its_frames_and_the_canister_prices_them() {
    let mut canister = Harness::new(1, "dfx_test_key", None);
    let gateway = canister.make_live();
    let governance = canister.refresh_governance_key();
    let runtime = Runtime::new().expect("runtime");
    let venue = start_venue(&runtime);
    let dir = common::scratch("push");
    std::fs::create_dir_all(&dir).expect("creates");

    let node_dir = dir.join("node");
    let passphrase_file = common::passphrase_file(&node_dir);
    let port = free_port();
    run(Command::new(BINARY)
        .arg("init")
        .arg("--out")
        .arg(&node_dir)
        .args(["--passphrase-file", &passphrase_file])
        .args(["--endpoint", &format!("ws://127.0.0.1:{port}/v2/ws")])
        .args(["--canister", &canister.canister.to_text()])
        .args(["--gateway", &gateway])
        .args(["--root-key", &canister.root_key()])
        .args(["--governance", &governance.to_checksummed()]));
    let entry = std::fs::read_to_string(node_dir.join("node-entry.json")).expect("init wrote it");
    let entry: NodeEntry = serde_json::from_str(&entry).expect("an entry");
    assert_eq!(canister.add_node(&entry), Ok(1));
    assert_eq!(canister.set_quorum(1, 1), Ok(2));
    let client = Signer::generate().expect("a key").address();
    assert_eq!(canister.add_client(client, unix_now() + 86_400), Ok(1));
    canister
        .set_feeds(&[FEED])
        .expect("governance sets the feeds");

    // `init` wrote a [publish] section for this network; push faster than a
    // deployed node does.
    let config = node_dir.join("config.toml");
    run_locally(&config, port, &venue);
    let text = std::fs::read_to_string(&config).expect("the config");
    let mut table: toml::Table = toml::from_str(&text).expect("TOML");
    let publish = table
        .get_mut("publish")
        .and_then(toml::Value::as_table_mut)
        .expect("init wrote a [publish] section");
    assert_eq!(
        publish.get("gateway").and_then(toml::Value::as_str),
        Some(gateway.as_str())
    );
    publish.insert("heartbeat_secs".to_owned(), toml::Value::Integer(2));
    publish.insert("min_interval_secs".to_owned(), toml::Value::Integer(1));
    std::fs::write(&config, toml::to_string(&table).expect("serialises")).expect("writes");

    let node = Node::spawn(common::start(&config, "json"), dir.join("node.log"));
    event(&node, READY, |_| true);
    event(&node, "pushing frames to the registry canister", |_| true);
    let deadline = std::time::Instant::now() + WAIT;
    let record = loop {
        if let Some(record) = canister.price(FEED)
            && record.status == PriceStatus::Ok
        {
            break record;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the canister got no price from the node:\n{}",
            node.log()
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    assert_eq!(record.nodes, 1);
    assert!(record.price.is_some_and(|price| price > 0), "{record:?}");
    let first = record.publish_time_ns;
    // The heartbeat keeps the price fresh while the venue is quiet.
    let deadline = std::time::Instant::now() + WAIT;
    while canister
        .price(FEED)
        .is_none_or(|record| record.publish_time_ns <= first)
    {
        assert!(std::time::Instant::now() < deadline, "no second push");
        std::thread::sleep(Duration::from_millis(500));
    }
    node.stop();
}

/// The node takes each new network feed set while it runs (SPEC §3.8): new
/// feeds start, removed feeds stop, only the changed venue reconnects, and a
/// set that the node cannot serve is refused.
#[test]
fn a_node_takes_each_new_feed_set_while_it_runs() {
    let mut canister = Harness::new(1, "dfx_test_key", None);
    let gateway = canister.make_live();
    let governance = canister.refresh_governance_key();
    let runtime = Runtime::new().expect("runtime");
    let venue = start_venue(&runtime);
    let dir = common::scratch("feed-set");
    std::fs::create_dir_all(&dir).expect("creates");

    let node_dir = dir.join("node");
    let passphrase_file = common::passphrase_file(&node_dir);
    let port = free_port();
    run(Command::new(BINARY)
        .arg("init")
        .arg("--out")
        .arg(&node_dir)
        .args(["--passphrase-file", &passphrase_file])
        .args(["--endpoint", &format!("ws://127.0.0.1:{port}/v2/ws")])
        .args(["--canister", &canister.canister.to_text()])
        .args(["--gateway", &gateway])
        .args(["--root-key", &canister.root_key()])
        .args(["--governance", &governance.to_checksummed()]));
    let entry = std::fs::read_to_string(node_dir.join("node-entry.json")).expect("init wrote it");
    let entry: NodeEntry = serde_json::from_str(&entry).expect("an entry");
    assert_eq!(canister.add_node(&entry), Ok(1));
    assert_eq!(canister.set_quorum(1, 1), Ok(2));
    let client = Signer::generate().expect("a key").address();
    assert_eq!(canister.add_client(client, unix_now() + 86_400), Ok(1));

    let spot = |symbol: &str, venue_symbol: &str| {
        serde_json::json!({ "symbol": symbol, "min_sources": 1,
            "sources": [{ "venue": "binance", "market": "spot", "symbol": venue_symbol }] })
    };
    let funding = serde_json::json!({ "symbol": FUNDING, "min_sources": 1,
        "sources": [{ "venue": "binance", "market": "linear_perp", "symbol": "BTCUSDT" }] });
    let content = |feeds: Vec<Value>| serde_json::json!({ "feeds": feeds }).to_string();
    let first = content(vec![spot(FEED, "BTCUSDT"), funding.clone()]);
    assert_eq!(canister.set_feed_set(&first), Ok(1));
    canister
        .set_feeds(&[FEED])
        .expect("governance prices the feed");

    // `init` wrote [network_feeds] for this canister. A test network changes
    // at once, and the node pushes fast, so the price shows it keeps working.
    let config = node_dir.join("config.toml");
    run_locally(&config, port, &venue);
    let written = std::fs::read_to_string(&config).expect("the config");
    let mut table: toml::Table = toml::from_str(&written).expect("TOML");
    let section = table
        .get_mut("network_feeds")
        .and_then(toml::Value::as_table_mut)
        .expect("init wrote a [network_feeds] section");
    for (key, value) in [("poll_secs", 1), ("lead_secs", 1), ("slot_secs", 1)] {
        section.insert(key.to_owned(), toml::Value::Integer(value));
    }
    let publish = table
        .get_mut("publish")
        .and_then(toml::Value::as_table_mut)
        .expect("a [publish] section");
    publish.insert("heartbeat_secs".to_owned(), toml::Value::Integer(2));
    publish.insert("min_interval_secs".to_owned(), toml::Value::Integer(1));
    std::fs::write(&config, toml::to_string(&table).expect("serialises")).expect("writes");

    let node = Node::spawn(common::start(&config, "json"), dir.join("node.log"));
    let started = event(&node, "serving the network feed set", |_| true);
    assert_eq!(started.get("version").and_then(Value::as_u64), Some(1));
    event(&node, READY, |_| true);
    assert!(
        node_dir.join("network-feeds.json").exists(),
        "the node cached the set it serves"
    );
    let price_after = |at_ns: u64| {
        let deadline = std::time::Instant::now() + WAIT;
        while canister.price(FEED).is_none_or(|record| {
            record.status != PriceStatus::Ok || record.publish_time_ns <= at_ns
        }) {
            assert!(
                std::time::Instant::now() < deadline,
                "no fresh price after the change:\n{}",
                node.log()
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    price_after(0);

    // A new Binance market: Binance alone reconnects, and the price goes on.
    let second = content(vec![
        spot(FEED, "BTCUSDT"),
        funding.clone(),
        spot("CRYPTO.ETH/USDT", "ETHUSDT"),
    ]);
    assert_eq!(canister.set_feed_set(&second), Ok(2));
    let applied = event(&node, "network feed set applied", |fields| {
        fields.get("version").and_then(Value::as_u64) == Some(2)
    });
    assert_eq!(applied.get("feeds").and_then(Value::as_u64), Some(3));
    assert!(text(&applied, "venues").contains("binance"), "{applied}");
    event(&node, "venue reconnects for the new feed set", |_| true);
    let changed_at = unix_now() * 1_000_000_000;
    price_after(changed_at);

    // The new feed leaves again.
    assert_eq!(canister.set_feed_set(&first), Ok(3));
    let applied = event(&node, "network feed set applied", |fields| {
        fields.get("version").and_then(Value::as_u64) == Some(3)
    });
    assert_eq!(applied.get("feeds").and_then(Value::as_u64), Some(2));

    // The canister takes a Coinbase perpetual; a node cannot serve one.
    let perp = serde_json::json!({ "symbol": "CRYPTO.ETH/USD.PERP_MARK", "min_sources": 1,
        "sources": [{ "venue": "coinbase", "market": "linear_perp", "symbol": "ETH-PERP" }] });
    assert_eq!(
        canister.set_feed_set(&content(vec![spot(FEED, "BTCUSDT"), funding, perp])),
        Ok(4)
    );
    let refused = event(
        &node,
        "network feed set refused; the node keeps its feeds",
        |fields| fields.get("version").and_then(Value::as_u64) == Some(4),
    );
    assert!(
        text(&refused, "reason").to_lowercase().contains("coinbase"),
        "{refused}"
    );
    let still = unix_now() * 1_000_000_000;
    price_after(still);
    let log = node.stop();
    assert!(
        !log.contains("\"version\":4,\"feeds\""),
        "the refused set was never applied"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn start_venue(runtime: &Runtime) -> String {
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("binds");
    let url = format!("ws://{}/stream", listener.local_addr().expect("bound"));
    let app = Router::new().route(
        "/stream",
        get(|upgrade: WebSocketUpgrade| async { upgrade.on_upgrade(quote) }),
    );
    runtime.spawn(async move { axum::serve(listener, app).await });
    url
}

async fn quote(mut socket: WebSocket) {
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    for update_id in 1_u64.. {
        ticker.tick().await;
        let mut frames = vec![serde_json::json!({
            "stream": "btcusdt@bookTicker",
            "data": {
                "u": update_id, "s": "BTCUSDT",
                "b": "60000.00", "B": "1.5", "a": "60000.10", "A": "2.0",
            },
        })];
        if update_id % 5 == 0 {
            frames.push(serde_json::json!({
                "stream": "btcusdt@markPrice@1s",
                "data": {
                    "e": "markPriceUpdate", "E": unix_now() * 1_000, "s": "BTCUSDT",
                    "p": "60000.05", "i": "60001.00", "r": "0.00010000",
                    "T": (unix_now() / 28_800 + 1) * 28_800_000,
                },
            }));
        }
        for frame in frames {
            if socket
                .send(Message::Text(frame.to_string().into()))
                .await
                .is_err()
            {
                return;
            }
        }
    }
}

/// Edits the starter config `init` wrote: loopback only, one feed from the
/// local venue, and a client-list poll every second so a revocation lands fast.
fn run_locally(config: &Path, port: u16, venue: &str) {
    let text = std::fs::read_to_string(config).expect("init wrote a config");
    let mut table: toml::Table = toml::from_str(&text).expect("the config is TOML");
    let local: toml::Table = toml::from_str(&format!(
        r#"
[server]
listen = "127.0.0.1:{port}"

[clients]
poll_secs = 1

[[feeds]]
symbol = "{FEED}"
min_sources = 1
sources = [{{ venue = "binance", market = "spot", symbol = "BTCUSDT" }}]

[[feeds]]
symbol = "{FUNDING}"
min_sources = 1
sources = [{{ venue = "binance", market = "linear_perp", symbol = "BTCUSDT" }}]

[[endpoints]]
venue = "binance"
market = "spot"
url = "{venue}"

[[endpoints]]
venue = "binance"
market = "linear_perp"
url = "{venue}"
"#
    ))
    .expect("TOML");
    for (key, value) in local {
        match (table.get_mut(&key), value) {
            (Some(toml::Value::Table(section)), toml::Value::Table(edits)) => section.extend(edits),
            (_, value) => {
                table.insert(key, value);
            }
        }
    }
    std::fs::write(config, toml::to_string(&table).expect("serialises")).expect("writes");
}

/// The events in a log with this message.
fn events<'a>(log: &'a str, message: &'a str) -> impl Iterator<Item = Value> + 'a {
    log.lines()
        .filter_map(fields_of)
        .filter(move |fields| text(fields, "message") == message)
}

/// Waits for an event with this message that `accept` takes, and returns its fields.
fn event(node: &Node, message: &str, accept: impl Fn(&Value) -> bool) -> Value {
    node.wait_for(message, |line| {
        let fields = fields_of(line)?;
        (text(&fields, "message") == message && accept(&fields)).then_some(fields)
    })
}

fn text<'a>(fields: &'a Value, name: &str) -> &'a str {
    fields.get(name).and_then(Value::as_str).unwrap_or_default()
}

/// The node logs addresses in lowercase; parsing compares them by value.
fn address_in(fields: &Value, name: &str) -> Option<Address> {
    text(fields, name).parse().ok()
}

/// What a running client has seen.
#[derive(Clone, Copy, Debug)]
struct Seen {
    stats: ClientStats,
    registry: u64,
}

fn seen(client: &OracleClient) -> Seen {
    Seen {
        stats: client.stats(),
        registry: client.registry_version(),
    }
}

/// The SDK as one listed client, subscribed to `FEED` until stopped.
struct Subscriber {
    handle: Handle,
    seen: watch::Receiver<Seen>,
    task: tokio::task::JoinHandle<()>,
}

impl Subscriber {
    fn start(runtime: &Runtime, canister: &Harness, governance: Address, key: Signer) -> Self {
        let source =
            HttpRegistrySource::new(&canister.url("registry.json"), canister.certification())
                .expect("builds");
        let mut client = runtime.block_on(async {
            let mut client = OracleClient::builder_from_source(Arc::new(source), governance)
                .await
                .expect("the registry verifies")
                .client_key(key)
                .quorum(1)
                .i_understand_this_provides_no_protection_against_a_bad_node()
                .max_age(Duration::from_secs(5))
                .build()
                .expect("builds");
            client.subscribe(&[FEED]).await.expect("subscribes");
            client
                .subscribe_venues(&[FEED])
                .await
                .expect("subscribes to venue reports");
            client
                .subscribe_funding(&["*"])
                .await
                .expect("subscribes to funding");
            client
        });
        let (tx, rx) = watch::channel(seen(&client));
        let task = runtime.spawn(async move {
            while client.next().await.is_some() {
                tx.send_replace(seen(&client));
            }
        });
        Self {
            handle: runtime.handle().clone(),
            seen: rx,
            task,
        }
    }

    fn seen(&self) -> Seen {
        *self.seen.borrow()
    }

    fn until(&mut self, what: &str, done: impl FnMut(&Seen) -> bool) -> Seen {
        // The timer needs the runtime, so it is made inside `block_on`.
        let reached = self
            .handle
            .block_on(async { tokio::time::timeout(WAIT, self.seen.wait_for(done)).await })
            .ok()
            .and_then(Result::ok)
            .map(|seen| *seen);
        reached.unwrap_or_else(|| panic!("the client never {what}: {:?}", self.seen()))
    }

    /// The node cut this client off: no price arrives for several heartbeats.
    fn assert_cut_off(&self, why: &str) {
        let before = self.seen().stats.accepted;
        std::thread::sleep(SILENCE);
        let after = self.seen().stats.accepted;
        assert_eq!(after, before, "a {why} client still gets prices");
    }

    /// Dropping the client closes its connections.
    fn stop(self) {
        self.task.abort();
    }
}

/// Runs an `oracle-node` command that must succeed.
fn run(command: &mut Command) {
    let output = command.output().expect("oracle-node runs");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
