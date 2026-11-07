//! The whole system: the registry canister on PocketIC behind a live HTTP
//! gateway, the `oracle-node` binary, and the SDK as a listed client over the
//! encrypted transport (SPEC §6.1).
//!
//! Each test builds a [`Stack`]: the canister, a local Binance-shaped venue,
//! so no test needs the internet, and one node that `init` wrote and
//! governance listed. `scripts/smoke.sh` covers the icp-cli side: `icp.yaml`,
//! `icp deploy`, and the calls `init` and `rotate` print.
#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::routing::get;
use oracle_client::{ClientStats, HttpRegistrySource, OracleClient};
use oracle_registry_api::{PriceRecord, PriceStatus};
use oracle_registry_canister::testing::{Harness, Scenario, ScenarioBuilder};
use oracle_server::unix_now;
use oracle_types::NANOS_PER_SEC;
use oracle_wire::{Address, NodeEntry, Signer};
use serde_json::Value;
use tokio::runtime::{Handle, Runtime};
use tokio::sync::watch;

use common::{BINARY, Node, Scratch, WAIT, eventually, fields_of, free_port, get_json};

const FEED: &str = "CRYPTO.BTC/USDT";
/// A funding feed from the venue's perpetual, for the funding frames.
const FUNDING: &str = "CRYPTO.BTC/USD.FUNDING_8H";
/// Short broadcast-key epochs, so a client's deadline falls inside the test.
const EPOCH_SECS: u64 = 5;
/// Several node heartbeats: a client that gets nothing for this long is cut off.
const SILENCE: Duration = Duration::from_secs(3);
/// Three epochs: time for a client to connect and get a price before it expires.
const SHORT_LIFETIME_SECS: u64 = 15;
/// A client lifetime past the end of every test.
const DAY_SECS: u64 = 86_400;
/// More than one price, so the client verifies a stream and not one frame.
const SOME_PRICES: u64 = 3;
/// Faster than a deployed node pushes, so a test sees a heartbeat push.
const PUSH_HEARTBEAT_SECS: i64 = 2;
const PUSH_MIN_INTERVAL_SECS: i64 = 1;
const PUSH_DEVIATION_BPS: i64 = 10;
/// A test network changes its feed set at once: poll, lead and slot of 1 s.
const FEED_SET_STEP_SECS: i64 = 1;
/// The local venue sends a `bookTicker` frame this often.
const QUOTE_EVERY: Duration = Duration::from_millis(100);
/// And a `markPrice` frame with funding once in this many quotes.
const QUOTES_PER_MARK: u64 = 5;
/// Binance's funding interval: eight hours.
const FUNDING_INTERVAL_SECS: u64 = 8 * 3_600;
const MILLIS_PER_SEC: u64 = 1_000;
/// The client refuses older prices; the node signs each feed every second.
const CLIENT_MAX_AGE: Duration = Duration::from_secs(5);

/// The registry canister behind a live gateway, a local venue, and one node
/// that `init` wrote and governance listed. The node runs once a test starts it.
struct Stack {
    canister: Scenario,
    governance: Address,
    runtime: Runtime,
    dir: Scratch,
    node_dir: PathBuf,
    config: PathBuf,
    port: u16,
    /// The node address that `init` wrote.
    address: Address,
}

/// What a test changes before its node starts.
struct StackBuilder {
    name: &'static str,
    canister: ScenarioBuilder,
    quorum_of_one: bool,
    client: bool,
    fast_push: bool,
    fast_feed_sets: bool,
}

impl StackBuilder {
    fn epoch_secs(mut self, secs: u64) -> Self {
        self.canister = self.canister.epoch_secs(secs);
        self
    }

    /// One node is enough for the canister to price a feed.
    fn quorum_of_one(mut self) -> Self {
        self.quorum_of_one = true;
        self
    }

    /// A listed client: the node starts only with a client list (SPEC §6.1).
    fn client(mut self) -> Self {
        self.client = true;
        self
    }

    fn fast_push(mut self) -> Self {
        self.fast_push = true;
        self
    }

    fn fast_feed_sets(mut self) -> Self {
        self.fast_feed_sets = true;
        self
    }

    /// The operator runs `init`, and governance lists the entry it wrote.
    fn build(self) -> Stack {
        let mut canister = self.canister.build();
        let gateway = canister.make_live();
        let governance = canister.refresh_governance_key();
        let runtime = Runtime::new().expect("runtime");
        let venue = start_venue(&runtime);
        let dir = common::scratch(self.name);
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
        let entry =
            std::fs::read_to_string(node_dir.join("node-entry.json")).expect("init wrote it");
        let entry: NodeEntry = serde_json::from_str(&entry).expect("an entry");
        assert_eq!(canister.add_node(&entry), Ok(1));
        if self.quorum_of_one {
            assert_eq!(canister.set_quorum(1, 1), Ok(2));
        }
        if self.client {
            let client = Signer::generate().expect("a key").address();
            assert_eq!(canister.add_client(client, unix_now() + DAY_SECS), Ok(1));
        }

        let config = node_dir.join("config.toml");
        run_locally(&config, port, &venue);
        if self.fast_push {
            edit_config(&config, "publish", |publish| {
                assert_eq!(
                    publish.get("gateway").and_then(toml::Value::as_str),
                    Some(gateway.as_str()),
                    "init wrote a [publish] section for this network"
                );
                publish.insert(
                    "heartbeat_secs".to_owned(),
                    toml::Value::Integer(PUSH_HEARTBEAT_SECS),
                );
                publish.insert(
                    "min_interval_secs".to_owned(),
                    toml::Value::Integer(PUSH_MIN_INTERVAL_SECS),
                );
            });
        }
        if self.fast_feed_sets {
            edit_config(&config, "network_feeds", |section| {
                for key in ["poll_secs", "lead_secs", "slot_secs"] {
                    section.insert(key.to_owned(), toml::Value::Integer(FEED_SET_STEP_SECS));
                }
            });
        }
        Stack {
            canister,
            governance,
            runtime,
            dir,
            node_dir,
            config,
            port,
            address: entry.address,
        }
    }
}

impl Stack {
    fn builder(name: &'static str) -> StackBuilder {
        StackBuilder {
            name,
            canister: Scenario::builder(),
            quorum_of_one: false,
            client: false,
            fast_push: false,
            fast_feed_sets: false,
        }
    }

    /// Starts the node with JSON logs in `log`, in the stack directory.
    fn start(&self, log: &str) -> Node {
        Node::spawn(common::start(&self.config, "json"), self.dir.join(log))
    }

    /// Waits until the node serves, and returns its `/v2/health`.
    fn serving(&self, node: &Node) -> Value {
        node.serving(self.port)
    }

    /// Waits until the node's last client session closed.
    fn no_subscribers(&self, node: &Node) {
        node.health_until(self.port, "closed its last session", |health| {
            health.get("subscribers").and_then(Value::as_u64) == Some(0)
        });
    }

    /// Waits until the node admits clients from client list `version`.
    fn client_list_served(&self, node: &Node, version: u64) {
        node.health_until(self.port, "adopted the client list", |health| {
            health.get("client_list").and_then(Value::as_u64) == Some(version)
        });
    }

    /// Waits until the node serves feed set `version`, and returns its feed count.
    fn feed_set_served(&self, node: &Node, version: u64) -> Option<u64> {
        let health = node.health_until(self.port, "served the new feed set", |health| {
            health.get("feed_set").and_then(Value::as_u64) == Some(version)
        });
        health.get("feeds").and_then(Value::as_u64)
    }

    /// The registry version that the running node serves.
    fn node_registry(&self) -> Option<u64> {
        get_json(self.port, "/v2/registry")?
            .get("version")?
            .as_u64()
    }

    fn subscribe(&self, key: Signer) -> Subscriber {
        Subscriber::start(&self.runtime, &self.canister, self.governance, key)
    }

    /// Waits for an `Ok` price of `FEED` that the node published after `at_ns`.
    fn price_after(&self, node: &Node, at_ns: u64) -> PriceRecord {
        eventually(WAIT, || {
            self.canister
                .price(FEED)
                .filter(|record| record.status == PriceStatus::Ok && record.publish_time_ns > at_ns)
        })
        .unwrap_or_else(|| {
            panic!(
                "the canister got no fresh price from the node:\n{}",
                node.log()
            )
        })
    }

    /// Runs `oracle-node rotate`, and returns the address of the key that it
    /// wrote beside the live one.
    fn next_key(&self) -> Address {
        run(Command::new(BINARY)
            .arg("rotate")
            .arg("--dir")
            .arg(&self.node_dir));
        common::load_key(&self.node_dir.join("signing.key.next")).address()
    }

    /// The operator moves the next key in place once governance replaced the node.
    fn adopt_next_key(&self) {
        std::fs::rename(
            self.node_dir.join("signing.key.next"),
            self.node_dir.join("signing.key"),
        )
        .expect("moves the key");
    }
}

/// The node rotates its key under a live client: a new key, `replace_node`,
/// a restart. The client adopts the new registry and refuses nothing.
#[test]
fn a_client_follows_a_rotation_of_the_node_key() {
    let stack = Stack::builder("rotation").epoch_secs(EPOCH_SECS).build();
    let key = Signer::generate().expect("a key");
    assert_eq!(
        stack
            .canister
            .add_client(key.address(), unix_now() + DAY_SECS),
        Ok(1)
    );
    let old = stack.address;
    let first = stack.start("node1.log");
    assert_eq!(address_in(&stack.serving(&first), "address"), Some(old));
    let mut client = stack.subscribe(key);
    client.until("verified a price", |seen| {
        seen.stats.accepted >= SOME_PRICES
    });
    client.until("verified a venue report", |seen| {
        seen.stats.venue_reports >= 1
    });
    client.until("verified a funding frame", |seen| {
        seen.stats.funding_updates >= 1
    });

    let new = stack.next_key();
    assert_eq!(stack.canister.replace_node(old, new), Ok(2));
    stack.adopt_next_key();
    let first_log = first.stop();
    let second = stack.start("node2.log");
    assert_eq!(address_in(&stack.serving(&second), "address"), Some(new));
    assert_eq!(stack.node_registry(), Some(2));
    let before = client.seen().stats.accepted;
    let stats = client
        .until("adopted registry v2", |seen| {
            seen.registry == 2 && seen.stats.accepted >= before + SOME_PRICES
        })
        .stats;
    assert_eq!(stats.untrusted, 0, "{stats:?}");
    assert_eq!(stats.replayed, 0, "{stats:?}");
    assert_eq!(stats.refresh_failures, 0, "{stats:?}");
    // A scheduled poll can adopt the new key first, so none is fine too.
    assert!(stats.refreshes <= 1, "{stats:?}");
    client.stop();

    // The canister keeps the old address as retired, so it is never listed again.
    let retired = stack
        .canister
        .listing(old)
        .expect("the old address is known");
    assert!(retired.removed_at.is_some(), "{retired:?}");
    let listed = stack
        .canister
        .listing(new)
        .expect("the new address is listed");
    assert_eq!(listed.removed_at, None);
    assert_json_log(&first_log);
    assert_json_log(&second.stop());
}

/// The node closes the live session of a revoked client and rotates its
/// broadcast key.
#[test]
fn a_revoked_client_is_cut_off_at_once() {
    let stack = Stack::builder("revocation").epoch_secs(EPOCH_SECS).build();
    let key = Signer::generate().expect("a key");
    let address = key.address();
    assert_eq!(
        stack.canister.add_client(address, unix_now() + DAY_SECS),
        Ok(1)
    );
    let node = stack.start("node.log");
    stack.serving(&node);
    let mut client = stack.subscribe(key);
    client.until("verified a price", |seen| {
        seen.stats.accepted >= SOME_PRICES
    });

    assert_eq!(stack.canister.remove_client(address), Ok(2));
    stack.no_subscribers(&node);
    client.assert_cut_off("revoked");
    client.stop();
    let log = node.stop();
    assert!(closed(&log, address, "Revoked"), "{log}");
    assert!(
        events(&log, "client sessions revoked; broadcast keys rotated")
            .next()
            .is_some(),
        "{log}"
    );
    assert_json_log(&log);
}

/// A client listed for a short time gets prices, then loses its session at
/// the last epoch boundary before it expires.
#[test]
fn an_expiring_client_is_cut_off_at_the_last_epoch_before_its_expiry() {
    let stack = Stack::builder("expiry")
        .epoch_secs(EPOCH_SECS)
        .client()
        .build();
    let node = stack.start("node.log");
    stack.serving(&node);
    let key = Signer::generate().expect("a key");
    let address = key.address();
    let expires_at = unix_now() + SHORT_LIFETIME_SECS;
    assert_eq!(stack.canister.add_client(address, expires_at), Ok(2));
    stack.client_list_served(&node, 2);
    let mut client = stack.subscribe(key);
    client.until("verified a price", |seen| seen.stats.accepted >= 1);

    stack.no_subscribers(&node);
    // The node checks deadlines once a second.
    let closed_at = unix_now();
    assert!(
        closed_at >= expires_at - EPOCH_SECS && closed_at <= expires_at + 1,
        "closed at {closed_at}, expiry {expires_at}"
    );
    client.assert_cut_off("expired");
    client.stop();
    let log = node.stop();
    assert!(closed(&log, address, "Expired"), "{log}");
    assert_json_log(&log);
}

/// The node pushes its frames to the registry canister, which resolves the
/// median and serves it to other canisters (SPEC §3.7).
#[test]
fn a_node_pushes_its_frames_and_the_canister_prices_them() {
    let stack = feed_set_stack("push");
    let node = stack.start("node.log");
    stack.serving(&node);
    let record = stack.price_after(&node, 0);
    assert_eq!(record.nodes, 1);
    assert!(record.price.is_some_and(|price| price > 0), "{record:?}");
    // The heartbeat keeps the price fresh while the venue is quiet.
    stack.price_after(&node, record.publish_time_ns);
    node.stop();
}

/// The node takes each new network feed set while it runs (SPEC §3.8): new
/// feeds start, removed feeds stop, and only the changed venue reconnects.
#[test]
fn a_node_takes_each_new_feed_set_while_it_runs() {
    let stack = feed_set_stack("feed-set");
    let node = stack.start("node.log");
    let health = stack.serving(&node);
    assert_eq!(health.get("feed_set").and_then(Value::as_u64), Some(1));
    assert!(
        stack.node_dir.join("network-feeds.json").exists(),
        "the node cached the set it serves"
    );
    stack.price_after(&node, 0);

    // A new Binance market, and the price goes on.
    let eth = spot("CRYPTO.ETH/USDT", "ETHUSDT");
    assert_eq!(
        stack
            .canister
            .set_feed_set(&feed_set(vec![btc(), funding(), eth])),
        Ok(2)
    );
    assert_eq!(stack.feed_set_served(&node, 2), Some(3));
    stack.price_after(&node, unix_now() * NANOS_PER_SEC);

    // The new feed leaves again.
    assert_eq!(
        stack
            .canister
            .set_feed_set(&feed_set(vec![btc(), funding()])),
        Ok(3)
    );
    assert_eq!(stack.feed_set_served(&node, 3), Some(2));
    let log = node.stop();
    // Binance alone reconnected for the new market.
    let applied = events(&log, "network feed set applied")
        .find(|fields| version(fields) == Some(2))
        .expect("v2 applied");
    assert!(text(&applied, "venues").contains("binance"), "{applied}");
    assert!(
        events(&log, "venue reconnects for the new feed set")
            .next()
            .is_some(),
        "{log}"
    );
}

/// The canister takes a Coinbase perpetual; a node cannot serve one, so it
/// keeps its feeds and goes on pricing.
#[test]
fn a_node_refuses_a_feed_set_it_cannot_serve_and_keeps_its_feeds() {
    let stack = feed_set_stack("feed-set-refused");
    let node = stack.start("node.log");
    stack.serving(&node);
    stack.price_after(&node, 0);

    let perp = serde_json::json!({ "symbol": "CRYPTO.ETH/USD.PERP_MARK", "min_sources": 1,
        "sources": [{ "venue": "coinbase", "market": "linear_perp", "symbol": "ETH-PERP" }] });
    assert_eq!(
        stack
            .canister
            .set_feed_set(&feed_set(vec![btc(), funding(), perp])),
        Ok(2)
    );
    let refused = event(
        &node,
        "network feed set refused; the node keeps its feeds",
        |fields| version(fields) == Some(2),
    );
    assert!(
        text(&refused, "reason").to_lowercase().contains("coinbase"),
        "{refused}"
    );
    stack.price_after(&node, unix_now() * NANOS_PER_SEC);
    let log = node.stop();
    assert!(
        events(&log, "network feed set applied").all(|fields| version(&fields) != Some(2)),
        "the refused set was never applied"
    );
}

/// A stack whose node serves the network feed set: `FEED` and `FUNDING` from
/// the local venue, with `FEED` priced on-chain.
fn feed_set_stack(name: &'static str) -> Stack {
    let stack = Stack::builder(name)
        .quorum_of_one()
        .client()
        .fast_push()
        .fast_feed_sets()
        .build();
    assert_eq!(
        stack
            .canister
            .set_feed_set(&feed_set(vec![btc(), funding()])),
        Ok(1)
    );
    stack
        .canister
        .set_feeds(&[FEED])
        .expect("governance prices the feed");
    stack
}

fn spot(symbol: &str, venue_symbol: &str) -> Value {
    serde_json::json!({ "symbol": symbol, "min_sources": 1,
        "sources": [{ "venue": "binance", "market": "spot", "symbol": venue_symbol }] })
}

fn btc() -> Value {
    spot(FEED, "BTCUSDT")
}

fn funding() -> Value {
    serde_json::json!({ "symbol": FUNDING, "min_sources": 1,
        "sources": [{ "venue": "binance", "market": "linear_perp", "symbol": "BTCUSDT" }] })
}

/// The content of a feed set with the test pace: the canister refuses a set
/// without a pace while it prices feeds (SPEC §3.7).
fn feed_set(feeds: Vec<Value>) -> String {
    serde_json::json!({
        "feeds": feeds,
        "push": {
            "heartbeat_secs": PUSH_HEARTBEAT_SECS,
            "deviation_bps": PUSH_DEVIATION_BPS,
            "min_interval_secs": PUSH_MIN_INTERVAL_SECS,
        },
    })
    .to_string()
}

/// Every line is a JSON event, so nothing panicked or wrote around the logger.
fn assert_json_log(log: &str) {
    for line in log.lines() {
        assert!(fields_of(line).is_some(), "not a log event: {line}");
    }
}

/// A Binance-shaped venue: one `bookTicker` frame every 100 ms, and a
/// `markPrice` frame with funding every 500 ms, on every connection. Returns
/// the URL for the node's `[[endpoints]]`.
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
    let mut ticker = tokio::time::interval(QUOTE_EVERY);
    for update_id in 1_u64.. {
        ticker.tick().await;
        let mut frames = vec![serde_json::json!({
            "stream": "btcusdt@bookTicker",
            "data": {
                "u": update_id, "s": "BTCUSDT",
                "b": "60000.00", "B": "1.5", "a": "60000.10", "A": "2.0",
            },
        })];
        if update_id % QUOTES_PER_MARK == 0 {
            frames.push(serde_json::json!({
                "stream": "btcusdt@markPrice@1s",
                "data": {
                    "e": "markPriceUpdate", "E": unix_now() * MILLIS_PER_SEC, "s": "BTCUSDT",
                    "p": "60000.05", "i": "60001.00", "r": "0.00010000",
                    "T": (unix_now() / FUNDING_INTERVAL_SECS + 1) * FUNDING_INTERVAL_SECS * MILLIS_PER_SEC,
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

/// Edits one table of the config that `init` wrote.
fn edit_config(config: &Path, name: &str, edit: impl FnOnce(&mut toml::Table)) {
    let text = std::fs::read_to_string(config).expect("the config");
    let mut table: toml::Table = toml::from_str(&text).expect("TOML");
    let section = table
        .get_mut(name)
        .and_then(toml::Value::as_table_mut)
        .unwrap_or_else(|| panic!("init wrote a [{name}] section"));
    edit(section);
    std::fs::write(config, toml::to_string(&table).expect("serialises")).expect("writes");
}

/// The events in a log with this message.
fn events<'a>(log: &'a str, message: &'a str) -> impl Iterator<Item = Value> + 'a {
    log.lines()
        .filter_map(fields_of)
        .filter(move |fields| text(fields, "message") == message)
}

/// `true` when the log closed the session of `client` for `reason`.
fn closed(log: &str, client: Address, reason: &str) -> bool {
    events(log, "client session closed").any(|fields| {
        address_in(&fields, "client") == Some(client) && text(&fields, "reason") == reason
    })
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

fn version(fields: &Value) -> Option<u64> {
    fields.get("version").and_then(Value::as_u64)
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
                .max_age(CLIENT_MAX_AGE)
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
