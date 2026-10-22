//! The node's network limits over real sockets, through the accept loop.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use oracle_server::testing::{test_registry, test_transport};
use oracle_server::{Limits, ServerState, router};
use oracle_types::Symbol;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_tungstenite::connect_async;
use tokio_util::sync::CancellationToken;

/// Long enough for a refused socket to close, short against the header timeout.
const AT_ONCE: Duration = Duration::from_secs(1);

struct Node {
    addr: SocketAddr,
    shutdown: CancellationToken,
    served: JoinHandle<()>,
}

async fn start(limits: Limits) -> Node {
    let btc: Symbol = "CRYPTO.BTC/USD".parse().expect("valid");
    let state = ServerState::new(&[btc], test_registry(), test_transport());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let addr = listener.local_addr().expect("bound");
    let shutdown = CancellationToken::new();
    let app = router(state, &limits);
    let served = tokio::spawn(oracle_server::serve(
        listener,
        app,
        limits,
        shutdown.clone(),
    ));
    Node {
        addr,
        shutdown,
        served,
    }
}

/// The per-address limits for 127.0.0.1, the only address a test has.
fn per_address(limits: Limits) -> Limits {
    Limits {
        limit_loopback: true,
        ..limits
    }
}

/// Whether the node closes a fresh socket that sends nothing within `wait`.
async fn closes_within(addr: SocketAddr, wait: Duration) -> bool {
    let mut socket = TcpStream::connect(addr).await.expect("connects");
    let mut byte = [0_u8; 1];
    matches!(
        tokio::time::timeout(wait, socket.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    )
}

/// The status line of a plain GET, or `None` when the socket closes first.
async fn get(addr: SocketAddr, path: &str) -> Option<String> {
    let mut socket = TcpStream::connect(addr).await.ok()?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    socket.write_all(request.as_bytes()).await.ok()?;
    let mut response = String::new();
    socket.read_to_string(&mut response).await.ok()?;
    response.lines().next().map(str::to_owned)
}

/// A GET once a freed place is back: the node sees a close a moment later.
async fn get_soon(addr: SocketAddr, path: &str) -> String {
    let start = Instant::now();
    loop {
        if let Some(status) = get(addr, path).await {
            return status;
        }
        assert!(start.elapsed() < AT_ONCE, "the place came back");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_socket_that_sends_no_request_is_closed_after_the_header_timeout() {
    let node = start(Limits {
        header_timeout_ms: 200.try_into().expect("non-zero"),
        ..Limits::default()
    })
    .await;
    let start = Instant::now();
    assert!(closes_within(node.addr, Duration::from_secs(5)).await);
    assert!(start.elapsed() >= Duration::from_millis(150), "not at once");
}

#[tokio::test]
async fn sockets_past_an_address_share_close_at_once_and_free_on_close() {
    let node = start(per_address(Limits {
        sockets_per_ip: 2.try_into().expect("non-zero"),
        ..Limits::default()
    }))
    .await;
    let first = TcpStream::connect(node.addr).await.expect("connects");
    let _second = TcpStream::connect(node.addr).await.expect("connects");
    assert!(
        closes_within(node.addr, AT_ONCE).await,
        "the third is refused"
    );
    drop(first);
    assert_eq!(get_soon(node.addr, "/v2/health").await, "HTTP/1.1 200 OK");
}

#[tokio::test]
async fn loopback_counts_only_in_the_total_by_default() {
    let node = start(Limits {
        sockets_per_ip: 1.try_into().expect("non-zero"),
        ..Limits::default()
    })
    .await;
    let _held = TcpStream::connect(node.addr).await.expect("connects");
    assert!(
        !closes_within(node.addr, AT_ONCE).await,
        "a TLS proxy on the host"
    );
}

#[tokio::test]
async fn a_websocket_keeps_its_socket_place_until_it_closes() {
    let node = start(per_address(Limits {
        sockets_per_ip: 1.try_into().expect("non-zero"),
        ..Limits::default()
    }))
    .await;
    let (socket, _) = connect_async(format!("ws://{}/v2/ws", node.addr))
        .await
        .expect("upgrades");
    assert!(
        closes_within(node.addr, AT_ONCE).await,
        "the upgraded socket still holds the place"
    );
    drop(socket);
    assert_eq!(get_soon(node.addr, "/v2/health").await, "HTTP/1.1 200 OK");
}

#[tokio::test]
async fn handshakes_from_one_address_have_a_share_and_a_rate() {
    let node = start(per_address(Limits {
        handshakes_per_ip: 1.try_into().expect("non-zero"),
        handshakes_per_minute: 2.try_into().expect("non-zero"),
        ..Limits::default()
    }))
    .await;
    let url = format!("ws://{}/v2/ws", node.addr);
    let refused = |result: Result<_, tokio_tungstenite::tungstenite::Error>| match result {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => response.status() == 429,
        _ => false,
    };
    let (first, _) = connect_async(&url).await.expect("upgrades");
    assert!(
        refused(connect_async(&url).await),
        "one in progress at once"
    );
    drop(first);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (second, _) = connect_async(&url).await.expect("its place is free");
    drop(second);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(refused(connect_async(&url).await), "two a minute");
}

#[tokio::test]
async fn the_rest_routes_have_a_rate() {
    let node = start(per_address(Limits {
        requests_per_minute: 1.try_into().expect("non-zero"),
        ..Limits::default()
    }))
    .await;
    assert_eq!(
        get(node.addr, "/v2/feeds").await.as_deref(),
        Some("HTTP/1.1 200 OK")
    );
    assert_eq!(
        get(node.addr, "/v2/health").await.as_deref(),
        Some("HTTP/1.1 429 Too Many Requests")
    );
}

#[tokio::test]
async fn a_request_head_over_the_limit_gets_431() {
    let node = start(Limits::default()).await;
    let mut socket = TcpStream::connect(node.addr).await.expect("connects");
    let padding = "a".repeat(20 * 1024);
    let request = format!("GET /v2/health HTTP/1.1\r\nHost: x\r\nX-Pad: {padding}\r\n\r\n");
    let _ = socket.write_all(request.as_bytes()).await;
    let mut response = Vec::new();
    let _ = socket.read_to_end(&mut response).await;
    // The node closes with bytes of the head unread, so a reset can overtake the 431.
    assert!(
        response.is_empty() || response.starts_with(b"HTTP/1.1 431"),
        "{}",
        String::from_utf8_lossy(&response)
    );
}

#[tokio::test]
async fn shutdown_stops_the_loop() {
    let node = start(Limits::default()).await;
    assert_eq!(
        get(node.addr, "/v2/health").await.as_deref(),
        Some("HTTP/1.1 200 OK")
    );
    node.shutdown.cancel();
    tokio::time::timeout(AT_ONCE, node.served)
        .await
        .expect("the loop ends")
        .expect("no panic");
    assert!(
        get(node.addr, "/v2/health").await.is_none(),
        "nothing listens"
    );
}
