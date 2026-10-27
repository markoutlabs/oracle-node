//! The open routes: the feeds, the registry and the health. They carry no
//! price data, and each address has a rate for them.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use oracle_wire::Address;
use serde::Serialize;

use super::Web;
use super::peer::Peer;

/// What a refused peer is told to wait, in seconds.
const RETRY_SECS: &str = "60";

pub(super) fn too_many(reason: &'static str) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, RETRY_SECS)],
        reason,
    )
        .into_response()
}

pub(super) async fn limit_requests(
    State(web): State<Arc<Web>>,
    Peer(peer): Peer,
    request: Request,
    next: Next,
) -> Response {
    match peer.and_then(|peer| web.limits.key(peer)) {
        Some(key) if !web.requests.check(key) => too_many("too many requests from this address"),
        _ => next.run(request).await,
    }
}

pub(super) async fn feeds(State(web): State<Arc<Web>>) -> Response {
    axum::Json(web.state.feeds()).into_response()
}

/// Serves this node's view of the registry.
///
/// **A hint, never a trust root.** A consumer that accepted this as
/// authoritative would be letting the node vouch for itself, and therefore add
/// itself. Pin the governance key out of band and verify.
pub(super) async fn registry(State(web): State<Arc<Web>>) -> Response {
    axum::Json(&web.state.registry).into_response()
}

#[derive(Serialize)]
struct Health {
    address: Address,
    feeds: usize,
    /// The network's feed set version; zero for the node's own feeds.
    feed_set: u64,
    subscribers: usize,
    publishing: usize,
}

pub(super) async fn health(State(web): State<Arc<Web>>) -> Response {
    let state = &web.state;
    axum::Json(Health {
        address: state.transport.address(),
        feeds: state.feeds().len(),
        feed_set: state.feed_set_version(),
        subscribers: state.hub.subscriber_count(),
        publishing: state.hub.latest_all().len(),
    })
    .into_response()
}
