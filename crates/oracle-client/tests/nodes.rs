//! The per-node report: each node's connection, its frames, and its word on a feed.

use std::time::Duration;

use oracle_client::testing::{TestNode, governance, signed_registry, update_at};
use oracle_client::{ConnectionState, NodeFeedState, NodeReport, OracleClient, now_unix_nanos};
use oracle_types::{Fixed, NANOS_PER_SEC, PriceUpdate, Symbol};
use oracle_wire::{Address, NodeEntry, Signer, feed_id};
use tokio::net::TcpListener;

const SYMBOL: &str = "CRYPTO.BTC/USD";

/// An endpoint that refuses connections: the port was bound, then freed.
async fn closed_endpoint() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let addr = listener.local_addr().expect("bound");
    drop(listener);
    format!("ws://{addr}/v2/ws")
}

fn fleet() -> Vec<TestNode> {
    (1..=3).map(TestNode::new).collect()
}

fn client(nodes: &[TestNode], endpoint: &str) -> OracleClient {
    let entries = nodes
        .iter()
        .map(|node| NodeEntry {
            endpoints: vec![endpoint.to_owned()],
            ..node.entry()
        })
        .collect();
    let verified = signed_registry(1, entries)
        .verify(governance().address(), 0)
        .expect("test registry verifies");
    OracleClient::builder(verified)
        .quorum(3)
        .client_key(Signer::from_secret_bytes([0x51; 32]).expect("valid key"))
        .build()
        .expect("builds")
}

fn of(report: &[NodeReport], node: Address) -> &NodeReport {
    report
        .iter()
        .find(|entry| entry.address == node)
        .expect("every registry node is reported")
}

fn decimal(text: &str) -> Fixed {
    text.parse().expect("decimal")
}

#[tokio::test]
async fn an_unreachable_node_shows_its_failures_and_backoff() {
    let nodes = fleet();
    let mut client = client(&nodes, &closed_endpoint().await);
    assert!(
        client
            .nodes(now_unix_nanos())
            .iter()
            .all(|node| node.connection == ConnectionState::Idle),
        "no connection before a subscribe"
    );

    client.subscribe(&[SYMBOL]).await.expect("subscribes");
    let report = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let report = client.nodes(now_unix_nanos());
            if report.iter().all(|node| node.failures >= 1) {
                return report;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("every connection fails within five seconds");

    for node in &report {
        assert!(
            matches!(
                node.connection,
                ConnectionState::Backoff { .. } | ConnectionState::Connecting
            ),
            "{:?}",
            node.connection
        );
        assert_eq!(node.connects, 0);
        assert!(node.last_error.is_some());
        assert_eq!(node.last_frame_ns, None);
    }
}

#[tokio::test]
async fn each_node_reports_its_frames_and_its_distance_from_the_median() {
    let nodes = fleet();
    let [first, second, third] = nodes.as_slice() else {
        panic!("three nodes")
    };
    let mut client = client(&nodes, &closed_endpoint().await);
    // Only subscribed feeds are reported; the frames below arrive by hand.
    client.subscribe(&[SYMBOL]).await.expect("subscribes");

    let at = now_unix_nanos();
    let symbol: Symbol = SYMBOL.parse().expect("valid");
    let priced = |price: i64, seq: u64| -> PriceUpdate {
        let mut update = update_at(at, seq);
        update.feed_id = feed_id(&symbol);
        update.price = price;
        update
    };
    let frame = first.sign(&priced(6_400_000_000_000, 1));
    client.ingest(&frame, at).expect("accepted");
    assert!(client.ingest(&frame, at).is_err(), "a replay");
    client
        .ingest(&second.sign(&priced(6_400_000_000_000, 1)), at)
        .expect("accepted");
    client
        .ingest(&third.sign(&priced(6_464_000_000_000, 1)), at)
        .expect("accepted");

    let report = client.nodes(at);
    let honest = of(&report, first.signing_address());
    assert_eq!(honest.frames.accepted, 1);
    assert_eq!(honest.frames.replayed, 1);
    assert_eq!(honest.last_frame_ns, Some(at));
    assert_eq!(honest.delivery.map(|window| window.count), Some(1));
    let [feed] = honest.feeds.as_slice() else {
        panic!("one subscribed feed")
    };
    assert_eq!(feed.symbol, symbol);
    assert_eq!(feed.state, Some(NodeFeedState::Live));
    assert_eq!(feed.price, Some(decimal("64000")));
    assert_eq!(feed.deviation_bps, Some(Fixed::ZERO));
    assert_eq!(feed.seq, Some(1));

    let high = of(&report, third.signing_address());
    assert_eq!(high.frames.replayed, 0);
    assert_eq!(
        high.feeds.first().and_then(|feed| feed.deviation_bps),
        Some(decimal("100")),
        "64640 is 100 bps above the median of 64000"
    );

    let later = client.nodes(at + 3 * NANOS_PER_SEC);
    assert!(
        later
            .iter()
            .flat_map(|node| &node.feeds)
            .all(|feed| feed.state == Some(NodeFeedState::Stale)),
        "past max_age every update is stale"
    );
}

#[tokio::test]
async fn a_funding_feed_is_live_between_its_heartbeats() {
    const FUNDING: &str = "CRYPTO.BTC/USD.FUNDING_8H";
    let nodes = fleet();
    let [first, ..] = nodes.as_slice() else {
        panic!("three nodes")
    };
    let mut client = client(&nodes, &closed_endpoint().await);
    client.subscribe(&[FUNDING]).await.expect("subscribes");

    // Nine seconds old: between two heartbeats of a slow feed.
    let now = now_unix_nanos();
    let symbol: Symbol = FUNDING.parse().expect("valid");
    let mut update = update_at(now - 9 * NANOS_PER_SEC, 1);
    update.feed_id = feed_id(&symbol);
    client
        .ingest(&first.sign(&update), now)
        .expect("a slow feed takes it");

    let report = client.nodes(now);
    let feed = of(&report, first.signing_address())
        .feeds
        .first()
        .expect("the funding feed");
    assert_eq!(feed.state, Some(NodeFeedState::Live));
}
