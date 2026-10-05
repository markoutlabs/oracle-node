//! The transport over real sockets: a fake client against the real router.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use oracle_server::testing::{governance_key, sample_update, signing_key, test_registry};
use oracle_server::{NodeTransport, ServerState, TransportConfig, router, unix_now};
use oracle_transport::{
    ClientHandshake, ClientSession, CloseReason, Control, HandshakeMessage, TYPE_CONTROL,
    TYPE_FRAME,
};
use oracle_types::Symbol;
use oracle_wire::{ClientEntry, ClientList, Signer, UnverifiedFrame, feed_id};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

const BTC: &str = "CRYPTO.BTC/USD";
const WAIT: Duration = Duration::from_secs(5);

fn key(seed: u8) -> Signer {
    Signer::from_secret_bytes([seed; 32]).expect("valid key")
}

fn client_list(version: u64, epoch_secs: u64, clients: &[(u8, u64)]) -> ClientList {
    ClientList::sign(
        &governance_key(),
        version,
        unix_now(),
        epoch_secs,
        clients
            .iter()
            .map(|&(seed, expires_at)| ClientEntry {
                address: key(seed).address(),
                expires_at,
            })
            .collect(),
    )
    .expect("signs")
}

struct Node {
    addr: std::net::SocketAddr,
    state: Arc<ServerState>,
    transport: Arc<NodeTransport>,
}

async fn start(list: &ClientList, config: TransportConfig) -> Node {
    start_confirmed_at(list, config, unix_now()).await
}

async fn start_confirmed_at(list: &ClientList, config: TransportConfig, confirmed_at: u64) -> Node {
    let verified = list
        .verify(governance_key().address(), 0)
        .expect("verifies");
    let transport = NodeTransport::new(Arc::new(signing_key()), verified, config, 64, confirmed_at);
    let symbols: Vec<Symbol> = vec![BTC.parse().expect("valid")];
    let state = ServerState::new(&symbols, test_registry(), Arc::clone(&transport));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let addr = listener.local_addr().expect("bound");
    let app = router(Arc::clone(&state));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Node {
        addr,
        state,
        transport,
    }
}

async fn open(node: &Node) -> Socket {
    connect_async(format!("ws://{}/v2/ws", node.addr))
        .await
        .expect("upgrades")
        .0
}

async fn next(socket: &mut Socket) -> Option<Message> {
    tokio::time::timeout(WAIT, socket.next())
        .await
        .ok()
        .flatten()
        .and_then(Result::ok)
}

async fn next_handshake(socket: &mut Socket) -> Option<HandshakeMessage> {
    match next(socket).await? {
        Message::Text(text) => serde_json::from_str(&text).ok(),
        _ => None,
    }
}

async fn connect(node: &Node, api_key: &Signer) -> (Socket, ClientSession) {
    let mut socket = open(node).await;
    let challenge = next_handshake(&mut socket).await.expect("challenge");
    let (auth, waiting) =
        ClientHandshake::new(signing_key().address(), &mut oracle_transport::os_rng())
            .respond(&challenge, api_key)
            .expect("responds");
    send_json(&mut socket, &auth).await;
    let auth_ok = next_handshake(&mut socket).await.expect("auth_ok");
    let session = waiting.finish(&auth_ok).expect("a session");
    (socket, session)
}

async fn send_json(socket: &mut Socket, message: &HandshakeMessage) {
    socket
        .send(Message::Text(
            serde_json::to_string(message).expect("serialises").into(),
        ))
        .await
        .expect("sends");
}

async fn send_app(socket: &mut Socket, session: &mut ClientSession, json: &str) {
    let sealed = session
        .sealer
        .seal(&Control::App(json.as_bytes().to_vec()))
        .expect("seals");
    socket
        .send(Message::Binary(sealed.into()))
        .await
        .expect("sends");
}

/// What a v2 client reads off the socket.
#[derive(Debug)]
enum Received {
    Control(Control),
    Frame(Vec<u8>),
    Closed,
}

async fn receive(socket: &mut Socket, session: &mut ClientSession) -> Received {
    loop {
        match next(socket).await {
            Some(Message::Binary(bytes)) => match bytes.get(1).copied() {
                Some(TYPE_CONTROL) => {
                    let control = session.opener.open(&bytes).expect("a sealed control");
                    if let Control::KeyUpdate(grant) = &control {
                        session.keys.insert(grant.clone());
                    }
                    return Received::Control(control);
                }
                Some(TYPE_FRAME) => return Received::Frame(bytes.to_vec()),
                _ => panic!("unexpected binary message"),
            },
            Some(Message::Ping(_) | Message::Pong(_)) => {}
            Some(Message::Close(_)) | None => return Received::Closed,
            Some(other) => panic!("unexpected message {other:?}"),
        }
    }
}

fn publish(node: &Node, seq: u64) {
    let mut update = sample_update(feed_id(&BTC.parse::<Symbol>().expect("valid")));
    update.seq = seq;
    let _ = node.state.publish(signing_key().sign_update(&update));
}

async fn subscribe(socket: &mut Socket, session: &mut ClientSession) {
    send_app(
        socket,
        session,
        r#"{"op":"subscribe","feeds":["CRYPTO.BTC/USD"]}"#,
    )
    .await;
    loop {
        if let Received::Control(Control::App(json)) = receive(socket, session).await {
            assert!(
                String::from_utf8_lossy(&json).contains("subscribe_ack"),
                "{json:?}"
            );
            return;
        }
    }
}

async fn next_frame(socket: &mut Socket, session: &mut ClientSession) -> Vec<u8> {
    loop {
        match receive(socket, session).await {
            Received::Frame(frame) => return frame,
            Received::Closed => panic!("closed while waiting for a frame"),
            Received::Control(_) => {}
        }
    }
}

#[tokio::test]
async fn a_listed_client_receives_sealed_frames_signed_by_the_node() {
    let node = start(
        &client_list(1, 60, &[(1, unix_now() + 3_600)]),
        TransportConfig::default(),
    )
    .await;
    let (mut socket, mut session) = connect(&node, &key(1)).await;
    subscribe(&mut socket, &mut session).await;
    publish(&node, 7);

    let sealed = next_frame(&mut socket, &mut session).await;
    let frame = session.keys.open(&sealed).expect("opens");
    // Decryption proves nothing: the node signature is still the check.
    let parsed = UnverifiedFrame::parse(&frame).expect("a frame");
    assert_eq!(
        parsed.recover_signer().expect("recovers"),
        signing_key().address()
    );
    assert_eq!(node.transport.session_count(), 1);
}

#[tokio::test]
async fn unknown_clients_and_plaintext_are_refused_before_any_subscriber_exists() {
    let node = start(
        &client_list(1, 60, &[(1, unix_now() + 3_600)]),
        TransportConfig::default(),
    )
    .await;

    for api_key in [key(9), key(2)] {
        let mut socket = open(&node).await;
        let challenge = next_handshake(&mut socket).await.expect("challenge");
        let (auth, _) =
            ClientHandshake::new(signing_key().address(), &mut oracle_transport::os_rng())
                .respond(&challenge, &api_key)
                .expect("responds");
        send_json(&mut socket, &auth).await;
        assert!(matches!(
            next_handshake(&mut socket).await,
            Some(HandshakeMessage::Refused { .. })
        ));
        assert!(next(&mut socket).await.is_none_or(|m| m.is_close()));
    }

    let mut socket = open(&node).await;
    let _ = next_handshake(&mut socket).await;
    socket
        .send(Message::Text(r#"{"op":"subscribe","feeds":["*"]}"#.into()))
        .await
        .expect("sends");
    assert!(matches!(
        next_handshake(&mut socket).await,
        Some(HandshakeMessage::Refused { .. })
    ));
    assert_eq!(node.transport.session_count(), 0);
    assert_eq!(node.state.hub().subscriber_count(), 0);
}

#[tokio::test]
async fn a_silent_or_oversized_handshake_is_cut_off() {
    let config = TransportConfig {
        handshake_timeout: Duration::from_millis(200),
        ..TransportConfig::default()
    };
    let node = start(&client_list(1, 60, &[(1, unix_now() + 3_600)]), config).await;

    let mut silent = open(&node).await;
    let _ = next_handshake(&mut silent).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(next(&mut silent).await.is_none_or(|m| m.is_close()));

    let mut oversized = open(&node).await;
    let _ = next_handshake(&mut oversized).await;
    let _ = oversized
        .send(Message::Text("x".repeat(70 * 1024).into()))
        .await;
    assert!(next(&mut oversized).await.is_none_or(|m| m.is_close()));
    assert_eq!(node.transport.session_count(), 0);
}

#[tokio::test]
async fn handshakes_beyond_the_cap_get_503() {
    let config = TransportConfig {
        max_handshakes: 1,
        ..TransportConfig::default()
    };
    let node = start(&client_list(1, 60, &[(1, unix_now() + 3_600)]), config).await;
    let mut first = open(&node).await;
    let _ = next_handshake(&mut first).await;
    let second = connect_async(format!("ws://{}/v2/ws", node.addr)).await;
    let Err(tokio_tungstenite::tungstenite::Error::Http(response)) = second else {
        panic!("the second upgrade must be refused");
    };
    assert_eq!(response.status(), 503);
}

/// Check 7 over real sockets: B is revoked, A gets the rotated key, and B can
/// open neither the new frames nor A's key delivery.
#[tokio::test]
async fn a_revoked_client_is_closed_and_cannot_open_the_next_frames() {
    let expires = unix_now() + 3_600;
    let node = start(
        &client_list(1, 60, &[(1, expires), (2, expires)]),
        TransportConfig::default(),
    )
    .await;
    let (mut a, mut a_session) = connect(&node, &key(1)).await;
    let (mut b, mut b_session) = connect(&node, &key(2)).await;
    subscribe(&mut a, &mut a_session).await;
    subscribe(&mut b, &mut b_session).await;
    let before = node.transport.current_key();

    let revoked = node
        .transport
        .offer_clients(&client_list(2, 60, &[(1, expires)]), unix_now())
        .expect("adopts");
    assert_eq!(revoked, Some(1));
    assert_ne!(node.transport.current_key().key_id(), before.key_id());

    assert!(matches!(
        receive(&mut b, &mut b_session).await,
        Received::Control(Control::Close(CloseReason::Revoked))
    ));
    assert!(matches!(
        receive(&mut b, &mut b_session).await,
        Received::Closed
    ));

    publish(&node, 9);
    let sealed = next_frame(&mut a, &mut a_session).await;
    assert!(a_session.keys.open(&sealed).is_ok(), "A got the new key");
    assert!(
        b_session.keys.open(&sealed).is_err(),
        "B's old keys do not open the frame"
    );
    assert_eq!(node.transport.session_count(), 1);
}

#[tokio::test]
async fn a_session_closes_at_its_deadline() {
    let node = start(
        &client_list(1, 1, &[(1, unix_now() + 2)]),
        TransportConfig::default(),
    )
    .await;
    let (mut socket, mut session) = connect(&node, &key(1)).await;
    let deadline = session.deadline;
    loop {
        match receive(&mut socket, &mut session).await {
            Received::Control(Control::Close(reason)) => {
                assert_eq!(reason, CloseReason::Expired);
                break;
            }
            Received::Closed => panic!("closed without a reason"),
            _ => {}
        }
    }
    assert!(unix_now() >= deadline);
}

#[tokio::test]
async fn the_node_serves_no_prices_and_no_v1_routes() {
    let node = start(
        &client_list(1, 60, &[(1, unix_now() + 3_600)]),
        TransportConfig::default(),
    )
    .await;
    publish(&node, 1);
    for (path, status) in [
        ("/v1/price/latest", "404"),
        ("/v1/price/CRYPTO.BTC%2FUSD/latest", "404"),
        ("/v1/ws", "404"),
        ("/v1/feeds", "404"),
        ("/v2/feeds", "200"),
        ("/v2/health", "200"),
        ("/v2/registry", "200"),
    ] {
        let mut stream = TcpStream::connect(node.addr).await.expect("connects");
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .expect("writes");
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response).await;
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{path}: {response}"
        );
    }
}

/// A grid rotation through `tick`: the next key arrives before the switch, and
/// the first frame under it opens.
#[tokio::test]
async fn a_grid_rotation_delivers_the_next_key_before_using_it() {
    let node = start(
        &client_list(1, 2, &[(1, unix_now() + 3_600)]),
        TransportConfig::default(),
    )
    .await;
    let (mut socket, mut session) = connect(&node, &key(1)).await;
    subscribe(&mut socket, &mut session).await;
    let first = node.transport.current_key();

    // With 2 s epochs the 10 s lead has always passed: the next key is ready.
    node.transport.tick(unix_now());
    let Received::Control(Control::KeyUpdate(grant)) = receive(&mut socket, &mut session).await
    else {
        panic!("the next key must be delivered first");
    };
    assert_eq!(grant.not_before, first.context().not_after);

    tokio::time::sleep(Duration::from_secs(
        first.context().not_after.saturating_sub(unix_now()) + 1,
    ))
    .await;
    node.transport.tick(unix_now());
    assert_ne!(node.transport.current_key().key_id(), first.key_id());
    publish(&node, 3);
    let sealed = next_frame(&mut socket, &mut session).await;
    assert!(session.keys.open(&sealed).is_ok());
}

/// Freshness is the last fetch that confirmed the list, never its issue time:
/// the canister publishes only on change.
#[tokio::test]
async fn an_unconfirmed_client_list_stops_admissions_then_sessions() {
    let list = client_list(1, 60, &[(1, unix_now() + 3_600)]);
    let node = start(
        &list,
        TransportConfig {
            admit_within: 1_000,
            serve_within: 1_000,
            ..TransportConfig::default()
        },
    )
    .await;
    let (mut socket, mut session) = connect(&node, &key(1)).await;

    let refusing = start_confirmed_at(
        &list,
        TransportConfig {
            admit_within: 50,
            ..TransportConfig::default()
        },
        unix_now() - 100,
    )
    .await;
    let mut refused = open(&refusing).await;
    let challenge = next_handshake(&mut refused).await.expect("challenge");
    let (auth, _) = ClientHandshake::new(signing_key().address(), &mut oracle_transport::os_rng())
        .respond(&challenge, &key(1))
        .expect("responds");
    send_json(&mut refused, &auth).await;
    assert!(matches!(
        next_handshake(&mut refused).await,
        Some(HandshakeMessage::Refused { .. })
    ));

    // A fetch of the same version is a confirmation and keeps sessions open.
    let offered = node.transport.offer_clients(&list, unix_now() + 900);
    assert_eq!(offered.expect("the list in use"), None);
    node.transport.tick(unix_now() + 1_100);
    assert_eq!(node.transport.session_count(), 1);

    // Past the serve limit, live sessions close too. The earlier tick rotated
    // the keys, so key updates arrive first.
    node.transport.tick(unix_now() + 2_000);
    let reason = loop {
        match receive(&mut socket, &mut session).await {
            Received::Control(Control::KeyUpdate(_)) => {}
            Received::Control(Control::Close(reason)) => break reason,
            _ => panic!("expected key updates, then a close"),
        }
    };
    assert_eq!(reason, CloseReason::Stale);
    assert_eq!(node.transport.session_count(), 0);
}
