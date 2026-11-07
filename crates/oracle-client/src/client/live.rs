//! The live path, with no network: each frame enters where a node's task hands
//! it over, and leaves through [`OracleClient::next_event`]. The `ingest`
//! tests skip this path, and with it the subscription filter.
#![expect(
    clippy::indexing_slicing,
    reason = "a fixed fleet of three; an out-of-range index is a failing test"
)]

use std::time::Duration;

use oracle_types::{MarketKind, Symbol, Venue};
use oracle_wire::{NodeEntry, Signer, feed_id};
use tokio::net::TcpListener;

use super::*;
use crate::quorum::Status;
use crate::testing::{TestNode, book_at, governance, signed_registry, update_at};

const BTC: &str = "CRYPTO.BTC/USD";
const ETH: &str = "CRYPTO.ETH/USD";

/// The path has no wait of its own; this only stops a failing test.
const PATIENCE: Duration = Duration::from_secs(2);

/// A subscribed client whose node tasks dial a refused port, so every frame
/// comes from the test.
struct Driver {
    client: OracleClient,
}

impl Driver {
    /// Subscribes to the price of `BTC` and the books of its sources.
    async fn subscribed(nodes: &[TestNode]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let refused = format!("ws://{}/v2/ws", listener.local_addr().expect("bound"));
        drop(listener);
        let entries = nodes
            .iter()
            .map(|node| NodeEntry {
                endpoints: vec![refused.clone()],
                ..node.entry()
            })
            .collect();
        let registry = signed_registry(1, entries)
            .verify(governance().address(), 0)
            .expect("the test registry verifies");
        let mut client = OracleClient::builder(registry)
            .client_key(Signer::from_secret(&[0x51; 32].into()).expect("a valid key"))
            .build()
            .expect("three nodes");
        let subscription = Subscription {
            prices: &[BTC],
            books: &[BTC],
            ..Subscription::default()
        };
        client
            .subscribe_all(subscription)
            .await
            .expect("subscribes");
        Self { client }
    }

    /// Hands `frame` over as a node's task does: recovered there, then queued.
    async fn deliver(&self, frame: Vec<u8>) {
        let recovered = RecoveredFrame::of(&frame);
        let inbound = Inbound::Frame {
            frame,
            received_ns: now_unix_nanos(),
            recovered,
        };
        self.client
            .inbound_tx
            .send(inbound)
            .await
            .expect("the client is open");
    }

    async fn next_event(&mut self) -> Event {
        tokio::time::timeout(PATIENCE, self.client.next_event())
            .await
            .expect("an event in time")
            .expect("the client is open")
    }
}

fn fleet() -> Vec<TestNode> {
    (1..=3).map(TestNode::new).collect()
}

/// A price of `symbol`, signed now by `node`.
fn price(node: &TestNode, symbol: &str, seq: u64) -> Vec<u8> {
    let mut update = update_at(now_unix_nanos(), seq);
    update.feed_id = feed_id(&symbol.parse::<Symbol>().expect("a symbol"));
    node.sign(&update)
}

/// Each accepted frame yields a resolution; the third node completes the quorum.
#[tokio::test]
async fn subscribed_prices_resolve_through_next_event() {
    let nodes = fleet();
    let mut driver = Driver::subscribed(&nodes).await;
    let mut events = Vec::new();
    for node in &nodes {
        driver.deliver(price(node, BTC, 1)).await;
        events.push(driver.next_event().await);
    }
    let Some(Event::Price(resolved)) = events.last() else {
        panic!("three prices: {events:?}");
    };
    assert_eq!(resolved.status, Status::Ok);
    assert_eq!(resolved.symbol, BTC.parse().ok());
    assert_eq!(resolved.nodes, 3);
    assert_eq!(driver.client.stats().accepted, 3);
}

/// A node sends only the feeds a client asked for, so another feed is a
/// faulty or hostile node. Its frame reaches neither the verifier nor the maps.
#[tokio::test]
async fn a_feed_the_client_did_not_ask_for_is_dropped() {
    let nodes = fleet();
    let mut driver = Driver::subscribed(&nodes).await;
    driver.deliver(price(&nodes[0], ETH, 1)).await;
    driver.deliver(price(&nodes[0], BTC, 1)).await;
    let event = driver.next_event().await;
    assert!(
        matches!(&event, Event::Price(resolved) if resolved.symbol == BTC.parse().ok()),
        "{event:?}"
    );
    assert_eq!(driver.client.stats().accepted, 1);
    assert!(
        driver
            .client
            .view(&ETH.parse().expect("a symbol"))
            .is_none()
    );
}

/// The node task only recovers the signer: the client still refuses a key
/// that the registry does not list.
#[tokio::test]
async fn a_frame_from_an_unlisted_key_is_refused_and_counted() {
    let nodes = fleet();
    let mut driver = Driver::subscribed(&nodes).await;
    driver.deliver(price(&TestNode::new(9), BTC, 1)).await;
    driver.deliver(price(&nodes[0], BTC, 1)).await;
    assert!(matches!(driver.next_event().await, Event::Price(_)));
    let stats = driver.client.stats();
    assert_eq!((stats.untrusted, stats.accepted), (1, 1));
}

#[tokio::test]
async fn a_book_frame_builds_the_node_book() {
    let nodes = fleet();
    let mut driver = Driver::subscribed(&nodes).await;
    let snapshot = book_at(now_unix_nanos(), 1, true, 100);
    driver.deliver(nodes[0].sign_book(&snapshot)).await;
    assert!(matches!(driver.next_event().await, Event::Book(_)));
    let instrument = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");
    let book = driver
        .client
        .book(&instrument, now_unix_nanos())
        .expect("a fresh book");
    assert_eq!(book.node, nodes[0].signing_address());
    assert_eq!(book.best_bid().map(|level| level.qty), Some(100));
}
