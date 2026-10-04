//! `HttpRegistrySource` against a plain HTTP server, which cannot certify.
//!
//! The certified path runs against a real canister and HTTP gateway in the
//! canister's PocketIC tests.

use axum::Router;
use axum::routing::get;
use oracle_client::testing::{TestNode, signed_registry};
use oracle_client::{Certification, FetchError, HttpRegistrySource, RegistrySource};

#[tokio::test]
async fn a_document_without_the_canister_certificate_is_refused() {
    let nodes: Vec<TestNode> = (1..=3_u8)
        .map(|seed| TestNode::new(seed, &format!("oracle-{seed}")))
        .collect();
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
