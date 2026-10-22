//! The SDK against a real node, through a relay that can go silent without a
//! close, as a network outage does. A dead session must end; a quiet one must
//! not.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use oracle_client::{OracleClient, now_unix_nanos};
use oracle_server::testing::{
    client_key, governance_key, sample_update, signing_key, test_registry, test_transport,
};
use oracle_server::{Limits, ServerState, router};
use oracle_types::{NANOS_PER_SEC, Symbol};
use oracle_wire::{NodeEntry, Quorum, Registry, VerifiedRegistry, feed_id};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

const BTC: &str = "CRYPTO.BTC/USD";
const IDLE: Duration = Duration::from_millis(600);
const WAIT: Duration = Duration::from_secs(10);

fn btc() -> Symbol {
    BTC.parse().expect("valid")
}

/// A node that serves BTC and, with `publish`, signs a fresh price every 50 ms.
async fn start_node(publish: bool) -> SocketAddr {
    let state = ServerState::new(&[btc()], test_registry(), test_transport());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let addr = listener.local_addr().expect("bound");
    let app = router(Arc::clone(&state), &Limits::default());
    tokio::spawn(async move { axum::serve(listener, app).await });
    if publish {
        tokio::spawn(async move {
            let signer = signing_key();
            for seq in 1_u64.. {
                let mut update = sample_update(feed_id(&btc()));
                update.publish_time_ns = now_unix_nanos();
                update.observation_time_ns = update.publish_time_ns - 1_000_000;
                update.prev_publish_time_ns = update.publish_time_ns - NANOS_PER_SEC;
                update.seq = seq;
                let _ = state.publish(signer.sign_update(&update));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
    }
    addr
}

/// A TCP relay. `cut` silences every connection open now: bytes stop, and
/// nothing closes. New connections pass.
struct Relay {
    addr: SocketAddr,
    opened: Arc<AtomicU64>,
    cut_below: Arc<AtomicU64>,
}

impl Relay {
    async fn start(node: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("bound");
        let opened = Arc::new(AtomicU64::new(0));
        let cut_below = Arc::new(AtomicU64::new(0));
        let (count, cut) = (Arc::clone(&opened), Arc::clone(&cut_below));
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let id = count.fetch_add(1, Ordering::SeqCst);
                let Ok(upstream) = TcpStream::connect(node).await else {
                    continue;
                };
                let (client_read, client_write) = client.into_split();
                let (node_read, node_write) = upstream.into_split();
                tokio::spawn(forward(client_read, node_write, id, Arc::clone(&cut)));
                tokio::spawn(forward(node_read, client_write, id, Arc::clone(&cut)));
            }
        });
        Self {
            addr,
            opened,
            cut_below,
        }
    }

    fn cut(&self) {
        self.cut_below
            .store(self.opened.load(Ordering::SeqCst), Ordering::SeqCst);
    }
}

async fn forward(mut from: OwnedReadHalf, mut to: OwnedWriteHalf, id: u64, cut: Arc<AtomicU64>) {
    let mut buffer = vec![0; 16 * 1024];
    while let Ok(read) = from.read(&mut buffer).await {
        if read == 0 {
            return;
        }
        if id < cut.load(Ordering::SeqCst) {
            // Silent, and still open: the halves stay held.
            std::future::pending::<()>().await;
        }
        let Some(bytes) = buffer.get(..read) else {
            return;
        };
        if to.write_all(bytes).await.is_err() {
            return;
        }
    }
}

fn registry(endpoint: SocketAddr) -> VerifiedRegistry {
    let entry = NodeEntry {
        address: signing_key().address(),
        endpoints: vec![format!("ws://{endpoint}/v2/ws")],
        weight: 1,
    };
    let quorum = Quorum {
        min_nodes: 1,
        recommended: 3,
    };
    Registry::sign(
        &governance_key(),
        1,
        now_unix_nanos() / NANOS_PER_SEC,
        vec![entry],
        quorum,
    )
    .expect("signs")
    .verify(governance_key().address(), 0)
    .expect("verifies")
}

/// What the client has seen of its one node.
#[derive(Clone, Debug, Default)]
struct Seen {
    accepted: u64,
    connects: u64,
    failures: u64,
    last_error: Option<String>,
}

/// Runs a client of the node at `endpoint` and reports what it sees.
async fn run_client(endpoint: SocketAddr) -> watch::Receiver<Seen> {
    let mut client = OracleClient::builder(registry(endpoint))
        .quorum(1)
        .i_understand_this_provides_no_protection_against_a_bad_node()
        .client_key(client_key())
        .idle_timeout(IDLE)
        .build()
        .expect("builds");
    client.subscribe(&[BTC]).await.expect("subscribes");
    let (tx, rx) = watch::channel(Seen::default());
    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = client.next_event() => if event.is_none() { return },
                () = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
            let node = client.nodes(now_unix_nanos()).into_iter().next();
            tx.send_replace(Seen {
                accepted: client.stats().accepted,
                connects: node.as_ref().map_or(0, |node| node.connects),
                failures: node.as_ref().map_or(0, |node| node.failures),
                last_error: node.and_then(|node| node.last_error),
            });
        }
    });
    rx
}

async fn until(seen: &mut watch::Receiver<Seen>, what: &str, done: impl FnMut(&Seen) -> bool) {
    let reached = tokio::time::timeout(WAIT, seen.wait_for(done))
        .await
        .is_ok_and(|result| result.is_ok());
    assert!(reached, "never {what}: {:?}", *seen.borrow());
}

#[tokio::test]
async fn a_node_that_goes_silent_is_dropped_and_dialled_again() {
    let relay = Relay::start(start_node(true).await).await;
    let mut seen = run_client(relay.addr).await;
    until(&mut seen, "verified prices", |seen| seen.accepted >= 3).await;

    relay.cut();
    until(&mut seen, "dropped the silent session", |seen| {
        seen.failures >= 1
            && seen
                .last_error
                .as_deref()
                .is_some_and(|error| error.starts_with("no message from the node"))
    })
    .await;
    let before = seen.borrow().accepted;
    until(&mut seen, "got prices on a new session", |seen| {
        seen.connects >= 2 && seen.accepted > before + 3
    })
    .await;
}

#[tokio::test]
async fn a_quiet_node_keeps_its_session_with_pings() {
    let mut seen = run_client(start_node(false).await).await;
    until(&mut seen, "connected", |seen| seen.connects >= 1).await;
    // Four idle timeouts with no price: only the pings and pongs move.
    tokio::time::sleep(IDLE * 4).await;
    let seen = seen.borrow().clone();
    assert_eq!((seen.connects, seen.failures), (1, 0), "{seen:?}");
}
