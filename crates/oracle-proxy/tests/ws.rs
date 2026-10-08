//! The proxy's web side over real sockets, fed through the hub directly.
#![expect(
    clippy::indexing_slicing,
    reason = "JSON replies of a known shape; a missing index is a failing test"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use oracle_client::{Book, Resolved, Status};
use oracle_proxy::config::Limits;
use oracle_proxy::hub::Hub;
use oracle_proxy::protocol::NodesSnapshot;
use oracle_proxy::web;
use oracle_types::{BookLevel, BookUpdate, Fixed, InstrumentId, MarketKind, Symbol, Venue};
use oracle_wire::{Address, feed_id};
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

const WAIT: Duration = Duration::from_secs(5);
const NOW: u64 = 1_754_582_400_000_000_000;

fn btc() -> Symbol {
    "CRYPTO.BTC/USD".parse().expect("valid")
}

async fn start(limits: Limits) -> (Arc<Hub>, SocketAddr) {
    let hub = Arc::new(Hub::new(
        &[btc()],
        &[btc()],
        limits.max_subscriptions,
        limits.max_book_queue,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let addr = listener.local_addr().expect("bound");
    let app =
        web::router(Arc::clone(&hub), limits).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (hub, addr)
}

async fn open(addr: SocketAddr) -> Socket {
    connect_async(format!("ws://{addr}/v1/ws"))
        .await
        .expect("upgrades")
        .0
}

async fn send(socket: &mut Socket, json: &str) {
    socket
        .send(Message::Text(json.into()))
        .await
        .expect("sends");
}

/// The next JSON message, or `None` once the socket closes.
async fn next(socket: &mut Socket) -> Option<Value> {
    loop {
        let message = tokio::time::timeout(WAIT, socket.next())
            .await
            .expect("a message in time");
        match message {
            Some(Ok(Message::Text(text))) => {
                return Some(serde_json::from_str(&text).expect("json"));
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(Message::Close(_)) | Err(_)) | None => return None,
            Some(Ok(other)) => panic!("unexpected {other:?}"),
        }
    }
}

/// A plain HTTP GET from a page on `origin`: the status line, the headers and the body.
async fn get(addr: SocketAddr, path: &str, origin: &str) -> (String, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connects");
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: {origin}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.expect("sends");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.expect("reads");
    let (head, body) = raw.split_once("\r\n\r\n").expect("a response");
    (head.to_ascii_lowercase(), body.to_owned())
}

fn resolved(price: &str) -> Resolved {
    Resolved {
        feed_id: feed_id(&btc()),
        symbol: None,
        status: Status::Ok,
        price: Some(price.parse::<Fixed>().expect("decimal")),
        conf: Some(Fixed::ONE),
        nodes: 3,
        halted_nodes: 0,
        concerns: Vec::new(),
        publish_time_ns: NOW,
        spread_bps: Some(Fixed::ZERO),
    }
}

#[tokio::test]
async fn a_web_client_subscribes_and_gets_prices_as_json() {
    let (hub, addr) = start(Limits::default()).await;
    hub.publish_price(&resolved("86599.95"));
    let mut socket = open(addr).await;
    send(
        &mut socket,
        r#"{"op":"subscribe","prices":["CRYPTO.BTC/USD"]}"#,
    )
    .await;
    let ack = next(&mut socket).await.expect("an ack");
    assert_eq!(ack["type"], "subscribed");
    let price = next(&mut socket).await.expect("the latest price");
    assert_eq!(price["type"], "price");
    assert_eq!(price["price"], "86599.95");
    assert_eq!(
        price["publish_time_ns"],
        NOW.to_string(),
        "a string, not a number"
    );

    hub.publish_price(&resolved("86600"));
    let price = next(&mut socket).await.expect("the next price");
    assert_eq!(price["price"], "86600");
    send(&mut socket, r#"{"op":"ping","id":7}"#).await;
    assert_eq!(next(&mut socket).await.expect("a pong")["id"], 7);
}

#[tokio::test]
async fn a_book_subscriber_gets_a_snapshot_first() {
    let (hub, addr) = start(Limits::default()).await;
    let instrument = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");
    let mut book = Book::new(Address::from_bytes([1; 20]), instrument.clone());
    book.apply(&BookUpdate {
        venue: Venue::Binance,
        market: MarketKind::Spot,
        symbol: "BTCUSDT".to_owned(),
        publish_time_ns: NOW,
        seq: 1,
        snapshot: true,
        exchange_time_ns: None,
        local_recv_ns: NOW,
        bids: vec![BookLevel {
            price: 8_377_800_000_000,
            qty: 494_541_000,
        }],
        asks: Vec::new(),
    });
    hub.update_book(&instrument, Some(&book));

    let mut socket = open(addr).await;
    send(
        &mut socket,
        r#"{"op":"subscribe","books":["binance:spot:BTCUSDT"]}"#,
    )
    .await;
    assert_eq!(
        next(&mut socket).await.expect("an ack")["books"][0],
        "binance:spot:BTCUSDT"
    );
    let snapshot = next(&mut socket).await.expect("a snapshot");
    assert_eq!(snapshot["snapshot"], true);
    assert_eq!(snapshot["bids"][0], serde_json::json!(["83778", "4.94541"]));
}

#[tokio::test]
async fn a_client_over_the_message_rate_is_told_and_closed() {
    let limits = Limits {
        messages_per_second: 1,
        ..Limits::default()
    };
    let (_hub, addr) = start(limits).await;
    let mut socket = open(addr).await;
    for id in 0..3 {
        send(&mut socket, &format!(r#"{{"op":"ping","id":{id}}}"#)).await;
    }
    assert_eq!(next(&mut socket).await.expect("a pong")["type"], "pong");
    let error = next(&mut socket).await.expect("an error");
    assert_eq!(error["code"], "rate_limited");
    assert!(next(&mut socket).await.is_none(), "then the socket closes");
}

#[tokio::test]
async fn one_address_gets_only_its_share_of_sockets() {
    let limits = Limits {
        connections_per_ip: 1,
        ..Limits::default()
    };
    let (_hub, addr) = start(limits).await;
    let _first = open(addr).await;
    let second = connect_async(format!("ws://{addr}/v1/ws")).await;
    let Err(tokio_tungstenite::tungstenite::Error::Http(response)) = second else {
        panic!("the second socket must be refused");
    };
    assert_eq!(response.status(), 429);
}

#[tokio::test]
async fn node_reports_arrive_on_the_socket_and_on_a_cross_origin_get() {
    let (hub, addr) = start(Limits::default()).await;
    hub.publish_nodes(&NodesSnapshot {
        time_ns: NOW,
        registry_version: 7,
        quorum: 3,
        nodes: Vec::new(),
    });

    let mut socket = open(addr).await;
    send(&mut socket, r#"{"op":"subscribe","nodes":true}"#).await;
    assert_eq!(next(&mut socket).await.expect("an ack")["nodes"], true);
    let nodes = next(&mut socket).await.expect("the latest report");
    assert_eq!(nodes["type"], "nodes");
    assert_eq!(nodes["registry_version"], 7);
    assert_eq!(nodes["time_ns"], NOW.to_string());

    let (head, body) = get(addr, "/v1/nodes", "https://dashboard.example").await;
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(head.contains("access-control-allow-origin: *"), "{head}");
    let json: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(json["quorum"], 3);

    let (head, body) = get(addr, "/v1/catalog", "https://dashboard.example").await;
    assert!(head.contains("access-control-allow-origin: *"), "{head}");
    let catalog: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        catalog["nodes"], true,
        "the catalog says node reports are served"
    );
}
