//! The connection set follows the registry (SPEC §7).

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use oracle_client::OracleClient;
use oracle_client::testing::{TestNode, TestSource, governance, signed_registry};
use oracle_transport::{NodeHandshake, os_rng};
use oracle_wire::{Address, NodeEntry, Registry};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

use Seen::{Closed, Connected};

const POLL: Duration = Duration::from_millis(100);
const SYMBOL: &str = "CRYPTO.BTC/USD";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Seen {
    Connected(&'static str),
    Closed(&'static str),
}

async fn fake_node(label: &'static str, events: mpsc::UnboundedSender<Seen>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let url = format!("ws://{}/v2/ws", listener.local_addr().expect("bound"));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let events = events.clone();
            tokio::spawn(async move {
                let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let _ = events.send(Seen::Connected(label));
                while let Some(Ok(_)) = socket.next().await {}
                let _ = events.send(Seen::Closed(label));
            });
        }
    });
    url
}

fn entry_at(node: &TestNode, url: &str) -> NodeEntry {
    let mut entry = node.entry();
    entry.endpoints = vec![url.to_owned()];
    entry
}

fn client_for(registry: &Registry, source: Arc<TestSource>) -> OracleClient {
    let verified = registry
        .verify(governance().address(), 0)
        .expect("test registry verifies");
    OracleClient::builder(verified)
        .quorum(3)
        .registry_source(source)
        .registry_poll_interval(POLL)
        .client_key(oracle_wire::Signer::from_secret_bytes([0x51; 32]).expect("valid key"))
        .build()
        .expect("builds")
}

// Waits a few polls after `want` arrives, so that an extra reconnect fails the test.
async fn collect(
    client: &mut OracleClient,
    events: &mut mpsc::UnboundedReceiver<Seen>,
    want: &[Seen],
) -> Vec<Seen> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = Vec::new();
    let mut settle_until: Option<Instant> = None;
    loop {
        if settle_until.is_none() && want.iter().all(|event| seen.contains(event)) {
            settle_until = Some(Instant::now() + 3 * POLL);
        }
        let stop = settle_until.unwrap_or(deadline);
        tokio::select! {
            _ = client.next() => {}
            Some(event) = events.recv() => seen.push(event),
            () = tokio::time::sleep_until(stop) => break,
        }
    }
    assert!(
        settle_until.is_some(),
        "timed out waiting for {want:?}; saw {seen:?}"
    );
    seen.sort();
    seen
}

fn sorted(mut events: Vec<Seen>) -> Vec<Seen> {
    events.sort();
    events
}

/// v2 removes node 4, adds node 5, and moves node 2 to a new endpoint.
#[tokio::test]
async fn connections_follow_the_registry() {
    let (tx, mut events) = mpsc::unbounded_channel();
    let nodes: Vec<TestNode> = (1..=5_u8).map(TestNode::new).collect();
    let [one, two, three, four, five] = nodes.as_slice() else {
        unreachable!()
    };
    let a = fake_node("a", tx.clone()).await;
    let b = fake_node("b", tx.clone()).await;
    let b2 = fake_node("b2", tx.clone()).await;
    let c = fake_node("c", tx.clone()).await;
    let d = fake_node("d", tx.clone()).await;
    let e = fake_node("e", tx.clone()).await;

    let v1 = signed_registry(
        1,
        vec![
            entry_at(one, &a),
            entry_at(two, &b),
            entry_at(three, &c),
            entry_at(four, &d),
        ],
    );
    let source = TestSource::serving(v1.clone());
    let mut client = client_for(&v1, Arc::clone(&source));
    client.subscribe(&[SYMBOL]).await.expect("subscribes");

    let initial = [
        Connected("a"),
        Connected("b"),
        Connected("c"),
        Connected("d"),
    ];
    assert_eq!(
        collect(&mut client, &mut events, &initial).await,
        sorted(initial.to_vec())
    );

    source.serve(signed_registry(
        2,
        vec![
            entry_at(one, &a),
            entry_at(two, &b2),
            entry_at(three, &c),
            entry_at(five, &e),
        ],
    ));
    let change = [Closed("b"), Connected("b2"), Closed("d"), Connected("e")];
    assert_eq!(
        collect(&mut client, &mut events, &change).await,
        sorted(change.to_vec()),
        "only the changed nodes reconnect"
    );
    assert_eq!(client.registry_version(), 2);
}

/// A new version with the same nodes, such as a `republish`, moves no connection.
#[tokio::test]
async fn a_re_sign_is_adopted_without_reconnecting() {
    let (tx, mut events) = mpsc::unbounded_channel();
    let labels = ["a", "b", "c"];
    let mut entries = Vec::new();
    for (seed, label) in (1..=3_u8).zip(labels) {
        let url = fake_node(label, tx.clone()).await;
        entries.push(entry_at(&TestNode::new(seed), &url));
    }

    let v1 = signed_registry(1, entries.clone());
    let source = TestSource::serving(v1.clone());
    let mut client = client_for(&v1, Arc::clone(&source));
    client.subscribe(&[SYMBOL]).await.expect("subscribes");
    let initial = labels.map(Connected);
    collect(&mut client, &mut events, &initial).await;

    source.serve(signed_registry(2, entries));
    let seen = collect(&mut client, &mut events, &[]).await;
    assert!(seen.is_empty(), "no reconnects; saw {seen:?}");
    assert_eq!(client.registry_version(), 2);
    assert!(client.stats().polls >= 1);
    assert_eq!(
        client.stats().refreshes,
        0,
        "no unknown signer was involved"
    );
}

#[tokio::test]
async fn a_second_subscribe_keeps_one_connection_per_node() {
    let (tx, mut events) = mpsc::unbounded_channel();
    let labels = ["a", "b", "c"];
    let mut entries = Vec::new();
    for (seed, label) in (1..=3_u8).zip(labels) {
        let url = fake_node(label, tx.clone()).await;
        entries.push(entry_at(&TestNode::new(seed), &url));
    }

    let v1 = signed_registry(1, entries);
    let mut client = client_for(&v1, TestSource::serving(v1.clone()));
    client.subscribe(&[SYMBOL]).await.expect("subscribes");
    let initial = labels.map(Connected);
    collect(&mut client, &mut events, &initial).await;

    client
        .subscribe(&["CRYPTO.ETH/USD"])
        .await
        .expect("subscribes");
    let restart: Vec<Seen> = labels
        .into_iter()
        .flat_map(|label| [Closed(label), Connected(label)])
        .collect();
    assert_eq!(
        collect(&mut client, &mut events, &restart).await,
        sorted(restart)
    );
}

/// A rotation lists a new address at the same endpoint. The connection is
/// keyed by address, so it is replaced.
#[tokio::test]
async fn a_rotation_reconnects_at_the_same_endpoint() {
    let (tx, mut events) = mpsc::unbounded_channel();
    let labels = ["a", "b", "c"];
    let mut nodes: Vec<TestNode> = (1..=3_u8).map(TestNode::new).collect();
    let mut urls = Vec::new();
    for label in labels {
        urls.push(fake_node(label, tx.clone()).await);
    }
    let entries = |nodes: &[TestNode]| -> Vec<NodeEntry> {
        nodes
            .iter()
            .zip(&urls)
            .map(|(node, url)| entry_at(node, url))
            .collect()
    };

    let v1 = signed_registry(1, entries(&nodes));
    let source = TestSource::serving(v1.clone());
    let mut client = client_for(&v1, Arc::clone(&source));
    client.subscribe(&[SYMBOL]).await.expect("subscribes");
    collect(&mut client, &mut events, &labels.map(Connected)).await;

    nodes.first_mut().expect("a node").rotate();
    source.serve(signed_registry(2, entries(&nodes)));
    let change = [Closed("a"), Connected("a")];
    assert_eq!(
        collect(&mut client, &mut events, &change).await,
        sorted(change.to_vec())
    );
}

/// After a rotation the node restarts with its new key before this client has
/// the new registry. The challenge names the new address, and that costs one
/// fetch, not a wait for the next poll.
#[tokio::test]
async fn a_challenge_from_a_new_address_fetches_the_registry_once() {
    let mut node = TestNode::new(1);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let url = format!("ws://{}/v2/ws", listener.local_addr().expect("bound"));
    let v1 = signed_registry(1, vec![entry_at(&node, &url)]);
    node.rotate();
    let moved: Address = node.signing_address();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (_, challenge) = NodeHandshake::start(moved, &mut os_rng());
                let text = serde_json::to_string(&challenge).expect("serialises");
                let _ = socket.send(Message::Text(text.into())).await;
                while let Some(Ok(_)) = socket.next().await {}
            });
        }
    });

    let source = TestSource::serving(v1.clone());
    let mut client = OracleClient::builder(v1.verify(governance().address(), 0).expect("verifies"))
        .quorum(1)
        .i_understand_this_provides_no_protection_against_a_bad_node()
        .registry_source(source.clone())
        .client_key(oracle_wire::Signer::from_secret_bytes([0x51; 32]).expect("valid key"))
        .build()
        .expect("builds");
    client.subscribe(&[SYMBOL]).await.expect("subscribes");
    source.serve(signed_registry(2, vec![entry_at(&node, &url)]));

    let deadline = Instant::now() + Duration::from_secs(5);
    while client.registry_version() < 2 && Instant::now() < deadline {
        let _ = tokio::time::timeout(Duration::from_millis(50), client.next()).await;
    }
    assert_eq!(client.registry_version(), 2);
    assert_eq!(client.stats().refreshes, 1);
    assert_eq!(client.stats().polls, 0, "the poll did not do it");
}

#[tokio::test]
async fn subscribing_without_a_client_key_is_refused() {
    let registry = signed_registry(1, vec![TestNode::new(1).entry()]);
    let mut client = OracleClient::builder(
        registry
            .verify(governance().address(), 0)
            .expect("verifies"),
    )
    .quorum(1)
    .i_understand_this_provides_no_protection_against_a_bad_node()
    .build()
    .expect("builds");
    assert!(matches!(
        client.subscribe(&[SYMBOL]).await,
        Err(oracle_client::ClientError::NoClientKey)
    ));
}
