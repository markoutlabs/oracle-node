//! Server state, HTTP routes, and the WebSocket handler.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::{SinkExt as _, StreamExt as _};
use oracle_types::{FeedId, Symbol};
use oracle_wire::{Registry, SignedUpdate, feed_id};
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::debug;

use crate::hub::{Hub, PreparedUpdate};
use crate::protocol::{ClientMessage, Encoding, FIREHOSE, JsonUpdate, ServerMessage};

/// How many control messages may queue for one connection.
const CONTROL_CAPACITY: usize = 32;

/// A feed this node serves.
#[derive(Clone, Debug, Serialize)]
pub struct FeedEntry {
    /// Canonical symbol.
    pub symbol: String,
    /// Derived feed id, `0x`-hex.
    pub feed_id: String,
    /// Publication exponent.
    pub expo: i32,
}

/// Renders the process's metrics in Prometheus text format.
///
/// A closure rather than an exporter handle, so this crate does not choose the
/// exporter: the node installs one and hands over its `render`.
pub type MetricsRender = Arc<dyn Fn() -> String + Send + Sync>;

/// Shared server state.
pub struct ServerState {
    hub: Arc<Hub>,
    catalog: HashMap<FeedId, Symbol>,
    by_symbol: HashMap<String, FeedId>,
    registry: Registry,
    node_id: String,
    metrics: Option<MetricsRender>,
}

impl ServerState {
    /// Builds server state for a fixed feed catalogue, with no `/metrics`.
    #[must_use]
    pub fn new(
        node_id: impl Into<String>,
        feeds: &[Symbol],
        registry: Registry,
        max_pending: usize,
    ) -> Arc<Self> {
        Self::with_metrics(node_id, feeds, registry, max_pending, None)
    }

    /// Builds server state that serves `/metrics` from `metrics`, if given.
    #[must_use]
    pub fn with_metrics(
        node_id: impl Into<String>,
        feeds: &[Symbol],
        registry: Registry,
        max_pending: usize,
        metrics: Option<MetricsRender>,
    ) -> Arc<Self> {
        let mut catalog = HashMap::with_capacity(feeds.len());
        let mut by_symbol = HashMap::with_capacity(feeds.len());
        for symbol in feeds {
            let id = feed_id(symbol);
            catalog.insert(id, *symbol);
            by_symbol.insert(symbol.to_string(), id);
        }
        Arc::new(Self {
            hub: Arc::new(Hub::new(max_pending)),
            catalog,
            by_symbol,
            registry,
            node_id: node_id.into(),
            metrics,
        })
    }

    /// Returns the fanout hub.
    #[must_use]
    pub fn hub(&self) -> &Arc<Hub> {
        &self.hub
    }

    /// Publishes a signed update to subscribers.
    ///
    /// Updates for feeds outside the catalogue are ignored rather than served
    /// under an unknown symbol.
    #[must_use]
    pub fn publish(&self, signed: SignedUpdate) -> Option<Arc<PreparedUpdate>> {
        let symbol = *self.catalog.get(&signed.update().feed_id)?;
        Some(self.hub.publish(symbol, signed))
    }

    /// Resolves a symbol to a feed id.
    #[must_use]
    pub fn lookup(&self, symbol: &str) -> Option<FeedId> {
        self.by_symbol.get(symbol).copied()
    }

    /// Returns the feed catalogue.
    #[must_use]
    pub fn feeds(&self) -> Vec<FeedEntry> {
        let mut feeds: Vec<FeedEntry> = self
            .catalog
            .iter()
            .map(|(id, symbol)| FeedEntry {
                symbol: symbol.to_string(),
                feed_id: id.to_string(),
                expo: symbol.expo(),
            })
            .collect();
        feeds.sort_by(|a, b| a.symbol.cmp(&b.symbol));
        feeds
    }
}

/// Builds the HTTP and WebSocket router.
pub fn router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/v1/ws", get(ws_upgrade))
        .route("/v1/feeds", get(feeds))
        .route("/v1/price/{symbol}/latest", get(latest_one))
        .route("/v1/price/latest", get(latest_batch))
        .route("/v1/registry", get(registry))
        .route("/v1/health", get(health))
        .route("/metrics", get(metrics))
        .with_state(state)
}

// ------------------------------------------------------------------- routes

async fn feeds(State(state): State<Arc<ServerState>>) -> Response {
    axum::Json(state.feeds()).into_response()
}

async fn latest_one(State(state): State<Arc<ServerState>>, Path(symbol): Path<String>) -> Response {
    let Some(id) = state.lookup(&symbol) else {
        return not_found(
            "unknown_feed",
            format!("this node does not serve `{symbol}`"),
        );
    };
    match state.hub.latest(id) {
        Some(prepared) => {
            axum::Json(JsonUpdate::new(&prepared.symbol, prepared.signed())).into_response()
        }
        None => not_found("no_data", format!("`{symbol}` has not published yet")),
    }
}

#[derive(serde::Deserialize)]
struct BatchQuery {
    #[serde(default)]
    ids: String,
}

async fn latest_batch(
    State(state): State<Arc<ServerState>>,
    Query(query): Query<BatchQuery>,
) -> Response {
    let wanted: Vec<&str> = query.ids.split(',').filter(|s| !s.is_empty()).collect();
    let updates: Vec<JsonUpdate> = if wanted.is_empty() {
        state
            .hub
            .latest_all()
            .iter()
            .map(|prepared| JsonUpdate::new(&prepared.symbol, prepared.signed()))
            .collect()
    } else {
        wanted
            .iter()
            .filter_map(|symbol| state.lookup(symbol))
            .filter_map(|id| state.hub.latest(id))
            .map(|prepared| JsonUpdate::new(&prepared.symbol, prepared.signed()))
            .collect()
    };
    axum::Json(updates).into_response()
}

/// Serves this node's view of the registry.
///
/// **A hint, never a trust root.** A consumer that accepted this as
/// authoritative would be letting the node vouch for itself, and therefore add
/// itself. Pin the governance key out of band and verify.
async fn registry(State(state): State<Arc<ServerState>>) -> Response {
    axum::Json(&state.registry).into_response()
}

#[derive(Serialize)]
struct Health {
    node_id: String,
    feeds: usize,
    subscribers: usize,
    publishing: usize,
}

async fn health(State(state): State<Arc<ServerState>>) -> Response {
    axum::Json(Health {
        node_id: state.node_id.clone(),
        feeds: state.catalog.len(),
        subscribers: state.hub.subscriber_count(),
        publishing: state.hub.latest_all().len(),
    })
    .into_response()
}

/// Prometheus text format, or 404 when the node installed no exporter.
async fn metrics(State(state): State<Arc<ServerState>>) -> Response {
    match &state.metrics {
        Some(render) => (
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            render(),
        )
            .into_response(),
        None => not_found(
            "metrics_disabled",
            "no metrics exporter installed".to_owned(),
        ),
    }
}

fn not_found(code: &str, message: String) -> Response {
    (
        StatusCode::NOT_FOUND,
        axum::Json(ServerMessage::error(code, message)),
    )
        .into_response()
}

// ---------------------------------------------------------------- websocket

async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<Arc<ServerState>>) -> Response {
    ws.on_upgrade(move |socket| serve_socket(socket, state))
}

/// Serves one subscriber connection until it closes.
async fn serve_socket(socket: WebSocket, state: Arc<ServerState>) {
    let subscriber = state.hub.subscribe(Encoding::Binary);
    let (mut sink, mut stream) = socket.split();
    let (control_tx, mut control_rx) = mpsc::channel::<Message>(CONTROL_CAPACITY);

    // The writer owns the sink. Control replies reach it through a channel so the
    // reader never needs to share it.
    let writer = {
        let subscriber = Arc::clone(&subscriber);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    control = control_rx.recv() => {
                        let Some(message) = control else { break };
                        if sink.send(message).await.is_err() {
                            break;
                        }
                    }
                    batch = subscriber.drain() => {
                        if batch.is_empty() {
                            if subscriber.is_lagged() {
                                metrics::counter!("oracle_server_lagged_disconnects_total")
                                    .increment(1);
                                // Tell them why. A consumer that silently misses
                                // updates cannot know its prices went stale.
                                let notice = ServerMessage::Lagged {
                                    dropped: subscriber.dropped(),
                                };
                                let _ = sink.send(text(&notice)).await;
                            }
                            break;
                        }
                        let encoding = subscriber.encoding();
                        for update in batch {
                            let payload = update.encoded(encoding);
                            let message = match encoding {
                                Encoding::Binary => Message::Binary(payload),
                                Encoding::Json => Message::Text(
                                    String::from_utf8_lossy(&payload).into_owned().into(),
                                ),
                            };
                            if sink.send(message).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
            let _ = sink.close().await;
        })
    };

    while let Some(Ok(message)) = stream.next().await {
        let text = match message {
            Message::Text(text) => text.to_string(),
            Message::Binary(_) => continue,
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => continue,
        };
        let reply = handle_control(&text, &state, &subscriber);
        if control_tx.send(reply).await.is_err() {
            break;
        }
    }

    state.hub.unsubscribe(subscriber.id());
    drop(control_tx);
    let _ = writer.await;
}

/// Applies one control message and returns the reply.
fn handle_control(raw: &str, state: &ServerState, subscriber: &crate::hub::Subscriber) -> Message {
    let parsed: ClientMessage = match serde_json::from_str(raw) {
        Ok(parsed) => parsed,
        Err(error) => {
            debug!(%error, "malformed control message");
            return text(&ServerMessage::error("bad_request", error.to_string()));
        }
    };

    match parsed {
        ClientMessage::Subscribe { feeds, encoding } => {
            if let Some(encoding) = encoding {
                subscriber.set_encoding(encoding);
            }
            if feeds.iter().any(|feed| feed == FIREHOSE) {
                subscriber.select_firehose();
                return text(&ServerMessage::SubscribeAck {
                    feeds: vec![FIREHOSE.to_owned()],
                    unknown: Vec::new(),
                });
            }
            let mut known = Vec::new();
            let mut unknown = Vec::new();
            let mut ids = Vec::new();
            for feed in feeds {
                match state.lookup(&feed) {
                    Some(id) => {
                        ids.push(id);
                        known.push(feed);
                    }
                    None => unknown.push(feed),
                }
            }
            subscriber.add(ids);
            text(&ServerMessage::SubscribeAck {
                feeds: known,
                unknown,
            })
        }
        ClientMessage::Unsubscribe { feeds } => {
            let ids: Vec<FeedId> = feeds.iter().filter_map(|feed| state.lookup(feed)).collect();
            subscriber.remove(ids);
            text(&ServerMessage::UnsubscribeAck { feeds })
        }
        ClientMessage::Ping { id } => text(&ServerMessage::Pong { id }),
    }
}

/// Serializes a control message to a text frame.
fn text(message: &ServerMessage) -> Message {
    Message::Text(
        serde_json::to_string(message)
            .unwrap_or_else(|_| r#"{"op":"error","code":"internal","message":""}"#.to_owned())
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_registry;

    fn symbols() -> Vec<Symbol> {
        ["CRYPTO.BTC/USD", "CRYPTO.ETH/USD"]
            .into_iter()
            .map(|text| text.parse().expect("valid symbol"))
            .collect()
    }

    fn state() -> Arc<ServerState> {
        ServerState::new("oracle-test-1", &symbols(), test_registry(), 64)
    }

    #[test]
    fn the_catalogue_is_sorted_and_carries_derived_ids() {
        let feeds = state().feeds();
        let symbols: Vec<&str> = feeds.iter().map(|feed| feed.symbol.as_str()).collect();
        assert_eq!(symbols, ["CRYPTO.BTC/USD", "CRYPTO.ETH/USD"]);

        let btc = feeds.first().expect("a feed");
        let expected = feed_id(&"CRYPTO.BTC/USD".parse::<Symbol>().expect("valid"));
        assert_eq!(btc.feed_id, expected.to_string());
        assert_eq!(btc.expo, -8);
    }

    #[test]
    fn subscribing_selects_known_feeds_and_reports_unknown_ones() {
        let state = state();
        let subscriber = state.hub().subscribe(Encoding::Binary);
        let reply = handle_control(
            r#"{"op":"subscribe","feeds":["CRYPTO.BTC/USD","CRYPTO.DOGE/USD"]}"#,
            &state,
            &subscriber,
        );
        let Message::Text(json) = reply else {
            panic!("expected a text reply")
        };
        assert!(json.contains("subscribe_ack"));
        assert!(
            json.contains("CRYPTO.DOGE/USD"),
            "unknown feeds must be reported: {json}"
        );

        assert!(subscriber.wants(state.lookup("CRYPTO.BTC/USD").expect("known")));
        assert!(!subscriber.wants(state.lookup("CRYPTO.ETH/USD").expect("known")));
    }

    #[test]
    fn the_firehose_selects_everything() {
        let state = state();
        let subscriber = state.hub().subscribe(Encoding::Binary);
        let _ = handle_control(r#"{"op":"subscribe","feeds":["*"]}"#, &state, &subscriber);
        assert!(subscriber.wants(state.lookup("CRYPTO.BTC/USD").expect("known")));
        assert!(subscriber.wants(state.lookup("CRYPTO.ETH/USD").expect("known")));
    }

    #[test]
    fn unsubscribing_removes_the_feed() {
        let state = state();
        let subscriber = state.hub().subscribe(Encoding::Binary);
        let _ = handle_control(
            r#"{"op":"subscribe","feeds":["CRYPTO.BTC/USD"]}"#,
            &state,
            &subscriber,
        );
        let _ = handle_control(
            r#"{"op":"unsubscribe","feeds":["CRYPTO.BTC/USD"]}"#,
            &state,
            &subscriber,
        );
        assert!(!subscriber.wants(state.lookup("CRYPTO.BTC/USD").expect("known")));
    }

    #[test]
    fn encoding_is_negotiated_by_the_subscribe_message() {
        let state = state();
        let subscriber = state.hub().subscribe(Encoding::Binary);
        assert_eq!(subscriber.encoding(), Encoding::Binary);
        let _ = handle_control(
            r#"{"op":"subscribe","feeds":["CRYPTO.BTC/USD"],"encoding":"json"}"#,
            &state,
            &subscriber,
        );
        assert_eq!(subscriber.encoding(), Encoding::Json);
    }

    #[test]
    fn a_ping_is_answered_with_its_id() {
        let state = state();
        let subscriber = state.hub().subscribe(Encoding::Binary);
        let reply = handle_control(r#"{"op":"ping","id":99}"#, &state, &subscriber);
        let Message::Text(json) = reply else {
            panic!("expected a text reply")
        };
        assert!(json.contains(r#""op":"pong""#));
        assert!(json.contains(r#""id":99"#));
    }

    #[test]
    fn a_malformed_control_message_is_answered_not_fatal() {
        let state = state();
        let subscriber = state.hub().subscribe(Encoding::Binary);
        let reply = handle_control("{not json", &state, &subscriber);
        let Message::Text(json) = reply else {
            panic!("expected a text reply")
        };
        assert!(json.contains(r#""op":"error""#));
        assert!(json.contains("bad_request"));
    }

    #[test]
    fn updates_for_uncatalogued_feeds_are_not_published() {
        let state = state();
        let signer = oracle_wire::Signer::from_secret_bytes([5; 32]).expect("valid key");
        let mut update = crate::testing::sample_update(feed_id(
            &"CRYPTO.BTC/USD".parse::<Symbol>().expect("valid"),
        ));
        update.feed_id = FeedId::from_bytes([0xAB; 32]);
        assert!(state.publish(signer.sign_update(&update)).is_none());
    }
}
