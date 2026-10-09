//! Server state, HTTP routes, and the WebSocket handler (SPEC §6.1).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};
use oracle_transport::{CloseReason, Control, HandshakeMessage, KeyGrant};
use oracle_types::{FeedId, InstrumentId, Symbol};
use oracle_wire::{
    Address, Registry, SignedBookUpdate, SignedFundingUpdate, SignedUpdate, SignedVenueReport,
    feed_id,
};
use serde::Serialize;
use tokio::sync::OwnedSemaphorePermit;
use tracing::debug;

use crate::hub::{Hub, PreparedBook, PreparedFunding, PreparedUpdate, PreparedVenues};
use crate::protocol::{ClientMessage, FIREHOSE, ServerMessage};
use crate::transport::{Established, NodeTransport, Outbound, unix_now};

/// The largest WebSocket message a node accepts, before and after auth.
const MAX_MESSAGE: usize = 64 * 1024;

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

/// Shared server state.
pub struct ServerState {
    hub: Arc<Hub>,
    catalog: HashMap<FeedId, Symbol>,
    by_symbol: HashMap<String, FeedId>,
    /// The books of each feed's sources.
    books: HashMap<FeedId, Vec<InstrumentId>>,
    registry: Registry,
    transport: Arc<NodeTransport>,
}

impl ServerState {
    /// Builds server state for a fixed feed catalogue. The hub is the
    /// transport's, so every update is sealed once before fan-out.
    #[must_use]
    pub fn new(feeds: &[Symbol], registry: Registry, transport: Arc<NodeTransport>) -> Arc<Self> {
        Self::with_books(feeds, HashMap::new(), registry, transport)
    }

    /// Builds server state that also serves the books of each feed's sources.
    #[must_use]
    pub fn with_books(
        feeds: &[Symbol],
        books: HashMap<FeedId, Vec<InstrumentId>>,
        registry: Registry,
        transport: Arc<NodeTransport>,
    ) -> Arc<Self> {
        let hub = Arc::clone(transport.hub());
        let mut catalog = HashMap::with_capacity(feeds.len());
        let mut by_symbol = HashMap::with_capacity(feeds.len());
        for symbol in feeds {
            let id = feed_id(symbol);
            catalog.insert(id, *symbol);
            by_symbol.insert(symbol.to_string(), id);
        }
        Arc::new(Self {
            hub,
            catalog,
            by_symbol,
            books,
            registry,
            transport,
        })
    }

    /// Returns the transport: admission, key rotation, revocation.
    #[must_use]
    pub const fn transport(&self) -> &Arc<NodeTransport> {
        &self.transport
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

    /// Publishes a signed book frame to the subscribers of that book.
    #[must_use]
    pub fn publish_book(&self, signed: SignedBookUpdate) -> Arc<PreparedBook> {
        self.hub.publish_book(signed)
    }

    /// Publishes a signed funding frame to the subscribers of that perpetual.
    #[must_use]
    pub fn publish_funding(&self, signed: SignedFundingUpdate) -> Arc<PreparedFunding> {
        self.hub.publish_funding(signed)
    }

    /// Publishes a signed venue report to the subscribers that asked for it.
    #[must_use]
    pub fn publish_venues(&self, signed: SignedVenueReport) -> Option<Arc<PreparedVenues>> {
        let symbol = *self.catalog.get(&signed.report().feed_id)?;
        Some(self.hub.publish_venues(symbol, signed))
    }

    /// The books of these feeds' sources, each once.
    #[must_use]
    pub fn books_of(&self, feeds: &[FeedId]) -> Vec<InstrumentId> {
        let mut books: Vec<InstrumentId> = Vec::new();
        for book in feeds
            .iter()
            .filter_map(|feed| self.books.get(feed))
            .flatten()
        {
            if !books.contains(book) {
                books.push(book.clone());
            }
        }
        books
    }

    /// The perpetual sources of these feeds, each once.
    #[must_use]
    pub fn perps_of(&self, feeds: &[FeedId]) -> Vec<InstrumentId> {
        let mut perps = self.books_of(feeds);
        perps.retain(|instrument| instrument.market.is_perp());
        perps
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

/// Builds the HTTP and WebSocket router. Prices go only to authenticated
/// clients over `/v2/ws`; the open routes carry no price data.
pub fn router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/v2/ws", get(ws_upgrade))
        .route("/v2/feeds", get(feeds))
        .route("/v2/registry", get(registry))
        .route("/v2/health", get(health))
        .with_state(state)
}

// ------------------------------------------------------------------- routes

async fn feeds(State(state): State<Arc<ServerState>>) -> Response {
    axum::Json(state.feeds()).into_response()
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
    address: Address,
    feeds: usize,
    subscribers: usize,
    publishing: usize,
}

async fn health(State(state): State<Arc<ServerState>>) -> Response {
    axum::Json(Health {
        address: state.transport.address(),
        feeds: state.catalog.len(),
        subscribers: state.hub.subscriber_count(),
        publishing: state.hub.latest_all().len(),
    })
    .into_response()
}

/// Applies one control message and returns the reply.
fn handle_control(
    raw: &str,
    state: &ServerState,
    subscriber: &crate::hub::Subscriber,
) -> ServerMessage {
    let parsed: ClientMessage = match serde_json::from_str(raw) {
        Ok(parsed) => parsed,
        Err(error) => {
            debug!(%error, "malformed control message");
            return ServerMessage::error("bad_request", error.to_string());
        }
    };

    match parsed {
        ClientMessage::Subscribe {
            feeds,
            venues,
            books,
            funding,
        } => {
            let mut unknown = Vec::new();
            let (venues, venue_ids) = known(state, venues, &mut unknown);
            subscriber.add_venues(venue_ids);
            let (books, book_ids) = known(state, books, &mut unknown);
            let instruments = state.books_of(&book_ids);
            subscriber.add_books(instruments.iter().cloned());
            state.hub.replay_books(subscriber, &instruments);
            let funding = if funding.iter().any(|feed| feed == FIREHOSE) {
                subscriber.add_all_funding();
                vec![FIREHOSE.to_owned()]
            } else {
                let (funding, funding_ids) = known(state, funding, &mut unknown);
                subscriber.add_funding(state.perps_of(&funding_ids));
                funding
            };
            state.hub.replay_funding(subscriber);
            if feeds.iter().any(|feed| feed == FIREHOSE) {
                subscriber.select_firehose();
                return ServerMessage::SubscribeAck {
                    feeds: vec![FIREHOSE.to_owned()],
                    venues,
                    books,
                    funding,
                    unknown,
                };
            }
            let (feeds, ids) = known(state, feeds, &mut unknown);
            subscriber.add(ids);
            ServerMessage::SubscribeAck {
                feeds,
                venues,
                books,
                funding,
                unknown,
            }
        }
        ClientMessage::Unsubscribe {
            feeds,
            venues,
            books,
            funding,
        } => {
            let ids = |symbols: &[String]| -> Vec<FeedId> {
                symbols
                    .iter()
                    .filter_map(|feed| state.lookup(feed))
                    .collect()
            };
            subscriber.remove(ids(&feeds));
            subscriber.remove_venues(ids(&venues));
            subscriber.remove_books(&state.books_of(&ids(&books)));
            subscriber.remove_funding(
                &state.perps_of(&ids(&funding)),
                funding.iter().any(|feed| feed == FIREHOSE),
            );
            ServerMessage::UnsubscribeAck {
                feeds,
                venues,
                books,
                funding,
            }
        }
        ClientMessage::Ping { id } => ServerMessage::Pong { id },
    }
}

/// Splits symbols into those this node serves, with their ids, and the rest.
fn known(
    state: &ServerState,
    symbols: Vec<String>,
    unknown: &mut Vec<String>,
) -> (Vec<String>, Vec<FeedId>) {
    let mut known = Vec::new();
    let mut ids = Vec::new();
    for symbol in symbols {
        match state.lookup(&symbol) {
            Some(id) => {
                ids.push(id);
                known.push(symbol);
            }
            None => unknown.push(symbol),
        }
    }
    (known, ids)
}

// ---------------------------------------------------------------- websocket

async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<Arc<ServerState>>) -> Response {
    let transport = Arc::clone(&state.transport);
    let Ok(permit) = transport.handshakes().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many handshakes in progress",
        )
            .into_response();
    };
    ws.max_message_size(MAX_MESSAGE)
        .max_frame_size(MAX_MESSAGE)
        .on_upgrade(move |socket| serve(socket, state, transport, permit))
}

type Sink = SplitSink<WebSocket, Message>;
type Stream = SplitStream<WebSocket>;

/// Serves one connection: handshake under the cap and the timeout, then the
/// sealed session until the deadline, a revocation or a disconnect.
async fn serve(
    socket: WebSocket,
    state: Arc<ServerState>,
    transport: Arc<NodeTransport>,
    permit: OwnedSemaphorePermit,
) {
    let (mut sink, mut stream) = socket.split();
    let established = handshake(&mut sink, &mut stream, &transport).await;
    drop(permit);
    let Some(Established {
        subscriber,
        mut sealer,
        mut opener,
        mut outbox,
        replies,
        deadline,
    }) = established
    else {
        let _ = sink.close().await;
        return;
    };

    let mut writer = {
        let subscriber = Arc::clone(&subscriber);
        tokio::spawn(async move {
            let mut deadline_at = instant_at(deadline);
            loop {
                let next = tokio::select! {
                    biased;
                    pushed = outbox.recv() => match pushed {
                        Some(Outbound::App(json)) => Control::App(json),
                        Some(Outbound::Key(key)) => Control::KeyUpdate(KeyGrant::from_key(&key)),
                        Some(Outbound::Deadline(moved)) => {
                            deadline_at = instant_at(moved);
                            Control::SessionUpdate { deadline: moved }
                        }
                        Some(Outbound::Close(reason)) => Control::Close(reason),
                        None => break,
                    },
                    () = tokio::time::sleep_until(deadline_at) => Control::Close(CloseReason::Expired),
                    batch = subscriber.drain() => {
                        if batch.is_empty() {
                            if subscriber.is_lagged() {
                                let _ = send_sealed(&mut sink, &mut sealer, &Control::Close(CloseReason::Lagged)).await;
                            }
                            break;
                        }
                        let mut failed = false;
                        for update in batch {
                            if sink.send(Message::Binary(update.sealed())).await.is_err() {
                                failed = true;
                                break;
                            }
                        }
                        if failed {
                            break;
                        }
                        continue;
                    }
                };
                if let Control::Close(reason) = &next {
                    tracing::info!(
                        client = %subscriber.client(),
                        ?reason,
                        "client session closed"
                    );
                }
                let last = matches!(next, Control::Close(_));
                if send_sealed(&mut sink, &mut sealer, &next).await.is_err() || last {
                    break;
                }
            }
            let _ = sink.close().await;
        })
    };

    let reader = async {
        while let Some(Ok(message)) = stream.next().await {
            let bytes = match message {
                Message::Binary(bytes) => bytes,
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Text(_) | Message::Close(_) => break,
            };
            let Ok(Control::App(json)) = opener.open(&bytes) else {
                break;
            };
            let raw = String::from_utf8_lossy(&json);
            let reply = handle_control(&raw, &state, &subscriber);
            let reply = serde_json::to_vec(&reply).unwrap_or_default();
            if replies.send(Outbound::App(reply)).await.is_err() {
                break;
            }
        }
    };
    // A finished `JoinHandle` panics when polled again.
    let writer_done = tokio::select! {
        () = reader => false,
        _ = &mut writer => true,
    };
    transport.release(subscriber.id());
    if !writer_done {
        let _ = writer.await;
    }
}

async fn handshake(
    sink: &mut Sink,
    stream: &mut Stream,
    transport: &NodeTransport,
) -> Option<Established> {
    let limit = transport.config().handshake_timeout;
    let (handshake, challenge) = transport.start();
    let auth = tokio::time::timeout(limit, async {
        sink.send(json_message(&challenge)).await.ok()?;
        loop {
            match stream.next().await? {
                Ok(Message::Text(text)) => return Some(text.to_string()),
                Ok(Message::Ping(_) | Message::Pong(_)) => {}
                _ => return None,
            }
        }
    })
    .await
    .ok()??;
    let auth: HandshakeMessage = match serde_json::from_str(&auth) {
        Ok(auth) => auth,
        Err(error) => {
            refuse(sink, &error.to_string()).await;
            return None;
        }
    };
    match transport.admit(handshake, &auth, unix_now()) {
        Ok((auth_ok, established)) => {
            let sent = tokio::time::timeout(limit, sink.send(json_message(&auth_ok))).await;
            if matches!(sent, Ok(Ok(()))) {
                Some(established)
            } else {
                transport.release(established.subscriber.id());
                None
            }
        }
        Err(error) => {
            debug!(%error, "client refused");
            refuse(sink, &error.to_string()).await;
            None
        }
    }
}

async fn refuse(sink: &mut Sink, reason: &str) {
    let message = HandshakeMessage::Refused {
        reason: reason.to_owned(),
    };
    let _ = sink.send(json_message(&message)).await;
}

async fn send_sealed(
    sink: &mut Sink,
    sealer: &mut oracle_transport::Sealer,
    message: &Control,
) -> Result<(), ()> {
    let sealed = sealer.seal(message).map_err(|_| ())?;
    sink.send(Message::Binary(sealed.into()))
        .await
        .map_err(|_| ())
}

fn json_message(message: &HandshakeMessage) -> Message {
    Message::Text(serde_json::to_string(message).unwrap_or_default().into())
}

fn instant_at(deadline: u64) -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(deadline.saturating_sub(unix_now()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::Channel;
    use crate::testing::{test_registry, test_transport};

    fn symbols() -> Vec<Symbol> {
        ["CRYPTO.BTC/USD", "CRYPTO.ETH/USD"]
            .into_iter()
            .map(|text| text.parse().expect("valid symbol"))
            .collect()
    }

    fn state() -> Arc<ServerState> {
        ServerState::new(&symbols(), test_registry(), test_transport())
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
        let subscriber = state
            .hub()
            .subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        let json = serde_json::to_string(&handle_control(
            r#"{"op":"subscribe","feeds":["CRYPTO.BTC/USD","CRYPTO.DOGE/USD"]}"#,
            &state,
            &subscriber,
        ))
        .expect("serialises");
        assert!(json.contains("subscribe_ack"));
        assert!(
            json.contains("CRYPTO.DOGE/USD"),
            "unknown feeds must be reported: {json}"
        );

        assert!(subscriber.wants(
            Channel::Prices,
            state.lookup("CRYPTO.BTC/USD").expect("known")
        ));
        assert!(!subscriber.wants(
            Channel::Prices,
            state.lookup("CRYPTO.ETH/USD").expect("known")
        ));
    }

    #[test]
    fn venue_reports_are_subscribed_apart_from_prices() {
        let state = state();
        let subscriber = state
            .hub()
            .subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        let json = serde_json::to_string(&handle_control(
            r#"{"op":"subscribe","feeds":["*"],"venues":["CRYPTO.BTC/USD","CRYPTO.DOGE/USD"]}"#,
            &state,
            &subscriber,
        ))
        .expect("serialises");
        assert!(json.contains(r#""venues":["CRYPTO.BTC/USD"]"#), "{json}");
        assert!(json.contains("CRYPTO.DOGE/USD"), "{json}");
        let btc = state.lookup("CRYPTO.BTC/USD").expect("known");
        let eth = state.lookup("CRYPTO.ETH/USD").expect("known");
        assert!(subscriber.wants(Channel::Venues, btc));
        assert!(
            !subscriber.wants(Channel::Venues, eth),
            "the price firehose does not cover venue reports"
        );

        let _ = handle_control(
            r#"{"op":"unsubscribe","venues":["CRYPTO.BTC/USD"]}"#,
            &state,
            &subscriber,
        );
        assert!(!subscriber.wants(Channel::Venues, btc));
        assert!(subscriber.wants(Channel::Prices, btc));
    }

    #[test]
    fn the_firehose_selects_everything() {
        let state = state();
        let subscriber = state
            .hub()
            .subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        let _ = handle_control(r#"{"op":"subscribe","feeds":["*"]}"#, &state, &subscriber);
        assert!(subscriber.wants(
            Channel::Prices,
            state.lookup("CRYPTO.BTC/USD").expect("known")
        ));
        assert!(subscriber.wants(
            Channel::Prices,
            state.lookup("CRYPTO.ETH/USD").expect("known")
        ));
    }

    #[test]
    fn unsubscribing_removes_the_feed() {
        let state = state();
        let subscriber = state
            .hub()
            .subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
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
        assert!(!subscriber.wants(
            Channel::Prices,
            state.lookup("CRYPTO.BTC/USD").expect("known")
        ));
    }

    #[test]
    fn a_ping_is_answered_with_its_id() {
        let state = state();
        let subscriber = state
            .hub()
            .subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        let json = serde_json::to_string(&handle_control(
            r#"{"op":"ping","id":99}"#,
            &state,
            &subscriber,
        ))
        .expect("serialises");
        assert!(json.contains(r#""op":"pong""#));
        assert!(json.contains(r#""id":99"#));
    }

    #[test]
    fn a_malformed_control_message_is_answered_not_fatal() {
        let state = state();
        let subscriber = state
            .hub()
            .subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        let json = serde_json::to_string(&handle_control("{not json", &state, &subscriber))
            .expect("serialises");
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
