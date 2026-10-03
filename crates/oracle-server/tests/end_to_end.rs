//! End to end: a signing node serves a real socket, an SDK client verifies it.
//!
//! This is M3's exit criterion. It runs the actual axum server over a real TCP
//! listener and drives it with the actual `oracle-client` verification and
//! quorum code — no mocks on either side of the wire.
//!
//! The scenarios that matter are not "does a price arrive". They are the ones
//! where something is wrong: a forged frame, a replay, a stale update, a node
//! disagreeing with its peers. Each asserts that the client refuses or degrades
//! rather than passing the price through.

use std::sync::Arc;
use std::time::Duration;

use oracle_client::{OracleClient, Status, testing as client_testing};
use oracle_server::testing::{NODE_ID, sample_update, signing_key};
use oracle_server::{ServerState, router};
use oracle_types::{FeedId, Flags, NANOS_PER_SEC, PriceUpdate, Symbol};
use oracle_wire::{Registry, Signer, VerifiedRegistry, feed_id};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// A minimal HTTP/1.1 GET, to keep an HTTP client out of the dev-dependencies.
async fn get(addr: &str, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connects");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("sends");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("reads");
    let text = String::from_utf8_lossy(&raw).into_owned();

    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map_or(String::new(), |(_, body)| body.to_owned());
    (status, body)
}

const BTC: &str = "CRYPTO.BTC/USD";

fn symbol() -> Symbol {
    BTC.parse().expect("valid symbol")
}

fn btc_feed() -> FeedId {
    feed_id(&symbol())
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// A running server, plus everything needed to talk to it.
struct Node {
    addr: String,
    state: Arc<ServerState>,
    signer: Signer,
    registry: VerifiedRegistry,
}

/// Starts a server on an ephemeral port with a registry naming its own address.
async fn start_node() -> Node {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let addr = listener.local_addr().expect("has an address");

    // The registry must advertise the port we actually got, so the client can
    // find us the same way it would in production.
    let identity = oracle_server::testing::identity_key();
    let governance = oracle_server::testing::governance_key();
    let cert = oracle_wire::SigningKeyCert::issue(
        &identity,
        NODE_ID,
        signing_key().address(),
        0,
        4_102_444_800,
    )
    .expect("issues");
    let entry = oracle_wire::NodeEntry {
        node_id: NODE_ID.to_owned(),
        operator: "test".to_owned(),
        identity_pubkey: identity.public_key(),
        endpoints: vec![format!("ws://{addr}/v1/ws")],
        signing_keys: vec![cert],
        weight: 1,
    };
    let registry = Registry::sign(
        &governance,
        1,
        now_ns() / NANOS_PER_SEC,
        vec![entry],
        oracle_wire::Quorum {
            min_nodes: 1,
            recommended: 3,
        },
    )
    .expect("signs");
    let verified = registry.verify(governance.address(), 0).expect("verifies");

    let state = ServerState::new(NODE_ID, &[symbol()], registry, 64);
    let app = router(Arc::clone(&state));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Node {
        addr: addr.to_string(),
        state,
        signer: signing_key(),
        registry: verified,
    }
}

fn update(seq: u64, price: i64, flags: Flags) -> PriceUpdate {
    let mut update = sample_update(btc_feed());
    update.publish_time_ns = now_ns();
    update.observation_time_ns = update.publish_time_ns.saturating_sub(1_000_000);
    update.prev_publish_time_ns = update.publish_time_ns.saturating_sub(NANOS_PER_SEC);
    update.seq = seq;
    update.price = price;
    update.flags = flags;
    update
}

// ------------------------------------------------------------------- tests

/// The headline path: node signs, socket carries, client verifies.
#[tokio::test]
async fn a_signed_update_travels_the_wire_and_verifies() {
    let node = start_node().await;

    let mut client = OracleClient::builder(node.registry.clone())
        .quorum(1)
        .i_understand_this_provides_no_protection_against_a_bad_node()
        .build()
        .expect("valid configuration");
    client.subscribe(&[BTC]).await.expect("subscribes");

    // Publish until the subscription has actually landed on the server side.
    let resolved = tokio::time::timeout(Duration::from_secs(5), async {
        let mut seq = 1;
        loop {
            let _ = node.state.publish(node.signer.sign_update(&update(
                seq,
                6_400_000_000_000,
                Flags::NONE,
            )));
            seq += 1;
            tokio::select! {
                resolved = client.next() => {
                    if let Some(resolved) = resolved {
                        return resolved;
                    }
                }
                () = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
    })
    .await
    .expect("a verified price within five seconds");

    assert_eq!(resolved.status, Status::Ok);
    assert_eq!(resolved.nodes, 1);
    assert!(resolved.is_usable());
    assert_eq!(
        resolved.price.expect("a price"),
        "64000".parse().expect("valid decimal")
    );
    assert!(client.stats().accepted >= 1);
    assert_eq!(client.stats().untrusted, 0);
}

/// A frame signed by a key the registry does not list must be refused, however
/// well-formed. This is the whole point of the registry.
#[tokio::test]
async fn a_frame_from_an_unregistered_key_is_refused() {
    let node = start_node().await;
    let mut client = OracleClient::builder(node.registry.clone())
        .quorum(1)
        .i_understand_this_provides_no_protection_against_a_bad_node()
        .build()
        .expect("valid configuration");

    let impostor = Signer::from_secret_bytes([0xDD; 32]).expect("valid key");
    let frame = impostor
        .sign_update(&update(1, 1, Flags::NONE))
        .encode_frame();

    assert!(client.ingest(&frame, now_ns()).is_err());
    assert_eq!(client.stats().untrusted, 1);
    assert_eq!(client.stats().accepted, 0);
}

/// A relay that captures a genuine frame and rebroadcasts it later passes every
/// signature check. Only the sequence number and the clock catch it.
#[tokio::test]
async fn a_captured_frame_replayed_later_is_refused_twice_over() {
    let node = start_node().await;
    let mut client = OracleClient::builder(node.registry.clone())
        .quorum(1)
        .i_understand_this_provides_no_protection_against_a_bad_node()
        .build()
        .expect("valid configuration");

    let frame = node
        .signer
        .sign_update(&update(1, 6_400_000_000_000, Flags::NONE))
        .encode_frame();
    let at = now_ns();

    assert!(client.ingest(&frame, at).is_ok());
    // Immediately: caught by the sequence number.
    assert!(client.ingest(&frame, at).is_err());
    assert_eq!(client.stats().replayed, 1);

    // Much later, and the sequence check is not even needed — it is stale.
    let mut fresh_client = OracleClient::builder(node.registry)
        .quorum(1)
        .i_understand_this_provides_no_protection_against_a_bad_node()
        .build()
        .expect("valid configuration");
    assert!(
        fresh_client
            .ingest(&frame, at + 60 * NANOS_PER_SEC)
            .is_err()
    );
    assert_eq!(fresh_client.stats().out_of_time, 1);
}

/// A node reporting its own feed halted must not count toward the quorum.
#[tokio::test]
async fn a_halted_node_stops_counting() {
    let node = start_node().await;
    let mut client = OracleClient::builder(node.registry)
        .quorum(1)
        .i_understand_this_provides_no_protection_against_a_bad_node()
        .build()
        .expect("valid configuration");

    let at = now_ns();
    let healthy = node
        .signer
        .sign_update(&update(1, 6_400_000_000_000, Flags::NONE))
        .encode_frame();
    assert_eq!(
        client.ingest(&healthy, at).expect("accepted").status,
        Status::Ok
    );

    let halted = node
        .signer
        .sign_update(&update(2, 6_400_000_000_000, Flags::HALTED))
        .encode_frame();
    let resolved = client.ingest(&halted, at).expect("accepted");
    assert_eq!(resolved.status, Status::Halted);
    assert!(!resolved.is_usable());
    assert_eq!(
        resolved.price, None,
        "a halted feed offers no price to misuse"
    );
}

/// Three nodes, one lying. The median holds and the band widens — without the
/// consumer writing a line of logic for it.
#[tokio::test]
async fn one_lying_node_among_three_is_outvoted_and_visible() {
    let nodes: Vec<client_testing::TestNode> = (1..=3_u8)
        .map(|seed| client_testing::TestNode::new(seed, &format!("oracle-{seed}")))
        .collect();
    let registry = client_testing::registry_with(&nodes.iter().collect::<Vec<_>>());

    let mut client = OracleClient::builder(registry)
        .quorum(3)
        .build()
        .expect("valid configuration");
    let at = now_ns();

    let mut honest = client_testing::update_at(at, 1);
    honest.price = 6_400_000_000_000;
    let mut liar = client_testing::update_at(at, 1);
    liar.price = 1;

    let [first, second, third] = nodes.as_slice() else {
        panic!("three nodes")
    };
    client.ingest(&first.sign(&honest), at).expect("accepted");
    client.ingest(&second.sign(&honest), at).expect("accepted");
    let resolved = client.ingest(&third.sign(&liar), at).expect("accepted");

    assert_eq!(
        resolved.price.expect("a price"),
        honest.price_fixed().expect("representable"),
        "the median must ignore the liar"
    );
    assert_eq!(
        resolved.status,
        Status::Degraded,
        "and the disagreement must show"
    );
    assert!(resolved.is_usable());
}

/// The REST surface a consumer needs before it can subscribe to anything.
#[tokio::test]
async fn rest_serves_the_catalogue_health_and_the_latest_price() {
    let node = start_node().await;
    let _ = node.state.publish(
        node.signer
            .sign_update(&update(1, 6_400_000_000_000, Flags::NONE)),
    );

    let (status, body) = get(&node.addr, "/v1/feeds").await;
    assert_eq!(status, 200);
    assert!(
        body.contains(BTC),
        "the catalogue must list the feed: {body}"
    );

    let (status, body) = get(&node.addr, "/v1/health").await;
    assert_eq!(status, 200);
    assert!(
        body.contains(NODE_ID),
        "health must identify the node: {body}"
    );

    let (status, body) = get(&node.addr, "/v1/price/CRYPTO.BTC%2FUSD/latest").await;
    assert_eq!(status, 200);
    assert!(
        body.contains("\"payload\""),
        "the signed bytes must be served: {body}"
    );
    // The field a JSON-number parser would silently mangle.
    assert!(
        body.contains("\"publish_time_ns\":\""),
        "timestamps must be strings: {body}"
    );

    let (status, _) = get(&node.addr, "/v1/price/CRYPTO.DOGE%2FUSD/latest").await;
    assert_eq!(
        status, 404,
        "an unknown feed must 404, not 200 with nothing"
    );
}

/// The registry a node serves is a convenience, not authority. Verifying it
/// requires a governance key the consumer pinned elsewhere.
#[tokio::test]
async fn a_node_served_registry_still_requires_the_pinned_governance_key() {
    let node = start_node().await;
    let served: Registry = node.registry.as_registry().clone();

    let impostor = Signer::from_secret_bytes([0x99; 32]).expect("valid key");
    assert!(
        served.verify(impostor.address(), 0).is_err(),
        "a registry must not verify against the wrong governance key"
    );
    assert!(
        served
            .verify(oracle_server::testing::governance_key().address(), 0)
            .is_ok(),
        "and must verify against the right one"
    );
}
