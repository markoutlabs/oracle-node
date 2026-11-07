//! A node in the test's process, read by the SDK with no socket: one scripted
//! venue, one feed, and the local registry.

use std::sync::Arc;
use std::time::Duration;

use oracle_client::{Event, OracleClient, Status, Subscription, now_unix_nanos};
use oracle_ingest::testing::{Script, ScriptedConnector};
use oracle_node::config::{DEFAULT_TICK_MS, FeedSettings};
use oracle_node::embed::{EmbedConfig, LocalNode, MonotonicClock, local_registry};
use oracle_types::{Fixed, Symbol};
use oracle_wire::Signer;
use tokio_util::sync::CancellationToken;

const FEED: &str = "CRYPTO.BTC/USDT";
/// The longest wait for one frame.
const WAIT: Duration = Duration::from_secs(10);
/// A Binance spot `bookTicker` on the combined stream.
const QUOTE: &str = r#"{"stream":"btcusdt@bookTicker","data":{"u":1,"s":"BTCUSDT","b":"60000.00","B":"1.5","a":"60000.10","A":"2.0"}}"#;

fn btc() -> FeedSettings {
    let feed = serde_json::json!({
        "symbol": FEED,
        "min_sources": 1,
        "sources": [{ "venue": "binance", "market": "spot", "symbol": "BTCUSDT" }],
    });
    serde_json::from_value(feed).expect("a feed")
}

#[tokio::test]
async fn a_local_node_signs_frames_that_the_sdk_accepts_with_no_socket() {
    let signer = Arc::new(Signer::from_secret(&[0x51; 32].into()).expect("a key"));
    let governance = Signer::from_secret(&[0x52; 32].into()).expect("a key");
    let connector = ScriptedConnector::repeating(
        Script::new()
            .pong_on_ping()
            .then_repeat(Script::new().text(QUOTE).delay(Duration::from_millis(50))),
    );
    let config = EmbedConfig {
        feeds: vec![btc()],
        endpoints: Vec::new(),
        tick_interval_ms: DEFAULT_TICK_MS,
        signer: Arc::clone(&signer),
        clock: MonotonicClock::new(),
        venue_reports: true,
        books: false,
        funding: false,
    };
    let mut node = LocalNode::start_with_connector(config, connector, CancellationToken::new())
        .expect("starts");
    let mut frames = node.take_frames().expect("the first call");
    assert!(node.take_frames().is_none());

    let registry = local_registry(signer.address(), &governance, 1, 0).expect("signs");
    let mut client = OracleClient::builder(registry)
        .quorum(1)
        .i_understand_this_provides_no_protection_against_a_bad_node()
        .build()
        .expect("one node, acknowledged");
    client
        .subscribe_local(Subscription {
            prices: &[FEED],
            venues: &[FEED],
            ..Subscription::default()
        })
        .expect("a valid symbol");

    let (mut price, mut venues) = (None, false);
    while price.is_none() || !venues {
        let frame = tokio::time::timeout(WAIT, frames.recv())
            .await
            .expect("a frame in time")
            .expect("the node runs");
        match client.ingest_event(&frame.encode_frame(), now_unix_nanos()) {
            Ok(Event::Price(resolved)) => price = Some(resolved),
            Ok(Event::Venues(_)) => venues = true,
            other => panic!("only prices and venue reports are asked for: {other:?}"),
        }
    }
    let price = price.expect("a price");
    let symbol: Symbol = FEED.parse().expect("a symbol");
    assert_eq!(price.symbol, Some(symbol));
    assert_eq!((price.status, price.nodes), (Status::Ok, 1), "{price:?}");
    let quote = price.price.expect("a price");
    let (bid, ask): (Fixed, Fixed) = (
        "60000.00".parse().expect("a bid"),
        "60000.10".parse().expect("an ask"),
    );
    assert!(bid < quote && quote < ask, "{quote:?} is outside the quote");
    assert!(
        node.health()
            .iter()
            .any(|health| health.counts().connects > 0)
    );
    assert_eq!(node.dropped_frames(), 0);
    // On another task, so the stop is proved `Send` as an app needs.
    tokio::spawn(node.stop()).await.expect("stops");
}
