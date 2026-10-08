//! The web side: one WebSocket and two plain routes, open to anyone within the
//! limits.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::{SinkExt as _, StreamExt as _};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use tower_http::cors::{Any, CorsLayer};

use crate::config::Limits;
use crate::hub::Hub;
use crate::protocol::{self, ClientOp};

/// The largest message a web client may send. Requests are a few names long.
const MAX_MESSAGE: usize = 64 * 1024;

/// How long a closing socket may take to flush its last messages.
const FLUSH: Duration = Duration::from_secs(5);

/// Shared by every request.
pub struct WebState {
    hub: Arc<Hub>,
    limits: Limits,
    admission: Arc<Admission>,
}

/// Builds the router: `/v1/ws`, `/v1/catalog`, `/v1/nodes` and `/health`.
/// Serve it with `into_make_service_with_connect_info::<SocketAddr>()`, which
/// the limits need.
pub fn router(hub: Arc<Hub>, limits: Limits) -> Router {
    let state = Arc::new(WebState {
        admission: Arc::new(Admission::new(&limits)),
        hub,
        limits,
    });
    // Public, read-only data: a dashboard on any origin may read it.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET]);
    let open = Router::new()
        .route("/v1/catalog", get(catalog))
        .route("/v1/nodes", get(nodes))
        .route("/health", get(health))
        .layer(cors);
    Router::new()
        .route("/v1/ws", get(ws))
        .merge(open)
        .with_state(state)
}

async fn catalog(State(state): State<Arc<WebState>>) -> Response {
    Json(state.hub.catalog()).into_response()
}

async fn nodes(State(state): State<Arc<WebState>>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.hub.nodes().to_string(),
    )
        .into_response()
}

async fn health(State(state): State<Arc<WebState>>) -> Response {
    let upstream = state.hub.upstream();
    let stats = upstream.stats;
    let rejected = [
        stats.untrusted,
        stats.replayed,
        stats.out_of_time,
        stats.incoherent,
        stats.retired,
    ]
    .iter()
    .fold(0_u64, |sum, count| sum.saturating_add(*count));
    Json(serde_json::json!({
        "status": if stats.accepted > 0 { "ok" } else { "starting" },
        "registry_version": upstream.registry_version,
        "clients": state.hub.client_count(),
        "accepted": stats.accepted,
        "venue_reports": stats.venue_reports,
        "book_updates": stats.book_updates,
        "rejected": rejected,
    }))
    .into_response()
}

/// The client's address. Behind a reverse proxy it is the last
/// `X-Forwarded-For` entry: the one that proxy added. A client can forge the
/// entries before it.
fn client_ip(peer: SocketAddr, headers: &HeaderMap, trust_forwarded_for: bool) -> IpAddr {
    if !trust_forwarded_for {
        return peer.ip();
    }
    headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|last| last.trim().parse().ok())
        .unwrap_or_else(|| peer.ip())
}

async fn ws(
    State(state): State<Arc<WebState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    let ip = client_ip(peer, &headers, state.limits.trust_forwarded_for);
    match Admission::admit(&state.admission, ip) {
        Err(reason) => (StatusCode::TOO_MANY_REQUESTS, reason).into_response(),
        Ok(admitted) => upgrade
            .max_message_size(MAX_MESSAGE)
            .max_frame_size(MAX_MESSAGE)
            .on_upgrade(move |socket| session(socket, state, ip, admitted)),
    }
}

async fn session(socket: WebSocket, state: Arc<WebState>, ip: IpAddr, admitted: Admitted) {
    let _admitted = admitted;
    let client = state.hub.connect(ip);
    let (mut sink, mut stream) = socket.split();
    let mut writer = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            loop {
                let batch = client.drain().await;
                if batch.is_empty() {
                    break;
                }
                for message in batch {
                    if sink
                        .send(Message::Text(message.as_ref().into()))
                        .await
                        .is_err()
                    {
                        client.close();
                        return;
                    }
                }
            }
            let _ = sink.close().await;
        })
    };

    let per_second = NonZeroU32::new(state.limits.messages_per_second).unwrap_or(NonZeroU32::MIN);
    let limiter = RateLimiter::direct(Quota::per_second(per_second));
    while let Some(Ok(message)) = stream.next().await {
        let text = match message {
            Message::Text(text) => text,
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Binary(_) => {
                client.reply(protocol::error("bad_request", "send JSON text messages"));
                break;
            }
            Message::Close(_) => break,
        };
        if limiter.check().is_err() {
            let limit = state.limits.messages_per_second;
            client.reply(protocol::error(
                "rate_limited",
                &format!("at most {limit} messages a second"),
            ));
            break;
        }
        let reply = match serde_json::from_str::<ClientOp>(&text) {
            Ok(ClientOp::Subscribe(topics)) => state.hub.subscribe(&client, &topics),
            Ok(ClientOp::Unsubscribe(topics)) => state.hub.unsubscribe(&client, &topics),
            Ok(ClientOp::Ping { id }) => protocol::pong(id),
            Err(error) => protocol::error("bad_request", &error.to_string()),
        };
        client.reply(reply);
    }
    // Closing lets the writer send what waits, such as a last error, and stop.
    state.hub.disconnect(client.id());
    if tokio::time::timeout(FLUSH, &mut writer).await.is_err() {
        writer.abort();
    }
}

#[derive(Default)]
struct Open {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// Connection limits, in total and for each address.
pub struct Admission {
    open: Mutex<Open>,
    connects: DefaultKeyedRateLimiter<IpAddr>,
    checks: AtomicU64,
    max_connections: usize,
    connections_per_ip: usize,
}

impl Admission {
    fn new(limits: &Limits) -> Self {
        let per_minute = NonZeroU32::new(limits.connects_per_minute).unwrap_or(NonZeroU32::MIN);
        Self {
            open: Mutex::new(Open::default()),
            connects: RateLimiter::keyed(Quota::per_minute(per_minute)),
            checks: AtomicU64::new(0),
            max_connections: limits.max_connections,
            connections_per_ip: limits.connections_per_ip,
        }
    }

    fn admit(this: &Arc<Self>, ip: IpAddr) -> Result<Admitted, &'static str> {
        // The rate limiter keeps a state per address; old ones go now and then.
        if this.checks.fetch_add(1, Ordering::Relaxed) % 1_024 == 0 {
            this.connects.retain_recent();
        }
        if this.connects.check_key(&ip).is_err() {
            return Err("too many new connections from this address");
        }
        let mut open = this.open.lock().unwrap_or_else(PoisonError::into_inner);
        if open.total >= this.max_connections {
            return Err("the proxy is full");
        }
        let count = open.per_ip.entry(ip).or_default();
        if *count >= this.connections_per_ip {
            return Err("too many connections from this address");
        }
        *count = count.saturating_add(1);
        open.total = open.total.saturating_add(1);
        Ok(Admitted {
            admission: Arc::clone(this),
            ip,
        })
    }
}

/// One admitted connection. Dropping it frees its place.
pub struct Admitted {
    admission: Arc<Admission>,
    ip: IpAddr,
}

impl Drop for Admitted {
    fn drop(&mut self) {
        let mut open = self
            .admission
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        open.total = open.total.saturating_sub(1);
        if let Some(count) = open.per_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.per_ip.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn the_forwarded_address_is_the_last_entry_and_only_when_trusted() {
        let peer = SocketAddr::from(([127, 0, 0, 1], 9000));
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("6.6.6.6, 203.0.113.7"),
        );
        assert_eq!(client_ip(peer, &headers, false), peer.ip());
        assert_eq!(
            client_ip(peer, &headers, true),
            "203.0.113.7".parse::<IpAddr>().expect("an address")
        );
        assert_eq!(client_ip(peer, &HeaderMap::new(), true), peer.ip());
    }

    #[test]
    fn admission_counts_each_address_and_frees_on_drop() {
        let limits = Limits {
            connections_per_ip: 1,
            ..Limits::default()
        };
        let admission = Arc::new(Admission::new(&limits));
        let ip: IpAddr = "203.0.113.7".parse().expect("an address");
        let first = Admission::admit(&admission, ip).expect("first");
        assert!(Admission::admit(&admission, ip).is_err(), "one per address");
        drop(first);
        assert!(Admission::admit(&admission, ip).is_ok(), "freed on drop");
    }
}
