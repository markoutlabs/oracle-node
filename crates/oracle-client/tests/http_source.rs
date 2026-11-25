//! `HttpRegistrySource` against a plain HTTP server, which cannot certify.
//!
//! The certified path runs against a real canister and HTTP gateway in the
//! canister's PocketIC tests.

use axum::Router;
use axum::routing::get;
use oracle_client::testing::{TestNode, signed_registry};
use oracle_client::{
    Certification, FetchError, HttpRegistrySource, MAX_DOCUMENT_BYTES, RegistrySource,
};

#[tokio::test]
async fn a_document_without_the_canister_certificate_is_refused() {
    let nodes: Vec<TestNode> = (1..=3_u8).map(TestNode::new).collect();
    let registry = signed_registry(7, nodes.iter().map(TestNode::entry).collect());
    let json = serde_json::to_string(&registry).expect("serialises");

    let app = Router::new().route(
        "/registry.json",
        get(move || std::future::ready(json.clone())),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let address = listener.local_addr().expect("has an address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serves");
    });
    let certification = Certification::mainnet("aaaaa-aa").expect("valid");

    // A validly signed document proves nothing about freshness on its own.
    let source = HttpRegistrySource::new(
        &format!("http://{address}/registry.json"),
        certification.clone(),
    )
    .expect("builds");
    assert!(matches!(
        source.fetch().await,
        Err(FetchError::Uncertified(_))
    ));

    let missing = HttpRegistrySource::new(&format!("http://{address}/missing"), certification)
        .expect("builds");
    assert!(matches!(
        missing.fetch().await,
        Err(FetchError::Transport(_))
    ));
}

/// The body was read whole before its certificate was checked, so a hostile
/// gateway could stream until the timeout. A reply with no length stops at the cap.
#[tokio::test]
async fn a_document_larger_than_the_cap_is_refused_before_the_certificate() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let address = listener.local_addr().expect("has an address");
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accepts");
        let mut request = [0_u8; 4096];
        let _ = socket.read(&mut request).await;
        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
        let _ = socket.write_all(head.as_bytes()).await;
        let size = 1 << 20;
        let chunk = format!("{size:x}\r\n{}\r\n", " ".repeat(size));
        for _ in 0..(MAX_DOCUMENT_BYTES / size + 8) {
            if socket.write_all(chunk.as_bytes()).await.is_err() {
                return;
            }
        }
        let _ = socket.write_all(b"0\r\n\r\n").await;
    });
    let source = HttpRegistrySource::new(
        &format!("http://{address}/registry.json"),
        Certification::mainnet("aaaaa-aa").expect("valid"),
    )
    .expect("builds");
    let result = source.fetch().await;
    assert!(
        matches!(&result, Err(FetchError::Transport(why)) if why.contains("larger than")),
        "{result:?}"
    );
}
