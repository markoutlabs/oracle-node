//! `HttpRegistrySource` against a real HTTP server.
//!
//! Plain HTTP on a loopback port. TLS is exercised only as far as building the
//! client, in the unit test next to the source; the provider wiring is what
//! can go wrong there, not the request.

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use oracle_client::testing::{TestNode, signed_registry};
use oracle_client::{FetchError, HttpRegistrySource, RegistrySource};

#[tokio::test]
async fn fetches_and_parses_the_document_a_server_serves() {
    let nodes: Vec<TestNode> = (1..=3_u8)
        .map(|seed| TestNode::new(seed, &format!("oracle-{seed}")))
        .collect();
    let registry = signed_registry(7, nodes.iter().map(TestNode::entry).collect());
    let json = serde_json::to_string(&registry).expect("serialises");

    let app = Router::new()
        .route(
            "/registry.json",
            get(move || std::future::ready(json.clone())),
        )
        .route(
            "/broken.json",
            get(|| std::future::ready("not a registry".to_owned())),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let address = listener.local_addr().expect("has an address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serves");
    });

    let source =
        HttpRegistrySource::new(format!("http://{address}/registry.json")).expect("builds");
    let fetched = source.fetch().await.expect("fetches");
    assert_eq!(fetched, registry);

    let source: Arc<dyn RegistrySource> =
        Arc::new(HttpRegistrySource::new(format!("http://{address}/broken.json")).expect("builds"));
    assert!(matches!(
        source.fetch().await,
        Err(FetchError::Malformed(_))
    ));

    let missing = HttpRegistrySource::new(format!("http://{address}/missing")).expect("builds");
    assert!(matches!(
        missing.fetch().await,
        Err(FetchError::Transport(_))
    ));
}
