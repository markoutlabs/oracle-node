//! Subscriptions and node connections. One task for each node does the
//! handshake, opens the sealed frames and recovers each signer; it decides no trust.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};
use futures_util::{SinkExt as _, StreamExt as _};
use oracle_transport::{
    ClientHandshake, ClientSession, Control, HandshakeMessage, KEY_GRACE_SECS, TYPE_CONTROL,
    TYPE_FRAME, TransportError, os_rng,
};
use oracle_types::{NANOS_PER_SEC, Symbol};
use oracle_wire::{Address, Signer, feed_id};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::{ClientError, Inbound, OracleClient, RecoveredFrame, Subscription, now_unix_nanos};
use crate::nodes::{ConnectionState, Links};
use crate::quorum::FeedView;

pub(super) struct NodeConnection {
    endpoints: Vec<String>,
    cancel: CancellationToken,
}

impl OracleClient {
    /// Connects to every node in the registry and subscribes to `symbols`.
    ///
    /// A later call adds symbols and reconnects every node with the full set.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoClientKey`] without a client key,
    /// [`ClientError::InvalidSymbol`] for an unparseable symbol, or
    /// [`ClientError::NoEndpoints`] if the registry lists none.
    pub async fn subscribe(&mut self, symbols: &[&str]) -> Result<(), ClientError> {
        self.subscribe_all(Subscription {
            prices: symbols,
            ..Subscription::default()
        })
        .await
    }

    /// Subscribes to every list of `subscription` with one reconnect of each
    /// node. A bad symbol in any list changes nothing.
    ///
    /// # Errors
    ///
    /// The same as [`OracleClient::subscribe`].
    pub async fn subscribe_all(
        &mut self,
        subscription: Subscription<'_>,
    ) -> Result<(), ClientError> {
        if self.client_key.is_none() {
            return Err(ClientError::NoClientKey);
        }
        let prices = parse_symbols(subscription.prices)?;
        let venues = parse_symbols(subscription.venues)?;
        let books = parse_symbols(subscription.books)?;
        let (all, named): (Vec<&str>, Vec<&str>) = subscription
            .funding
            .iter()
            .partition(|symbol| **symbol == "*");
        let funding = parse_symbols(&named)?;

        for symbol in prices {
            let id = feed_id(&symbol);
            self.set_feed_kind(id, symbol.kind());
            self.symbols.insert(id, symbol);
            self.views
                .entry(id)
                .or_insert_with(|| FeedView::with_kind(id, symbol.kind()));
        }
        for symbol in venues {
            let id = feed_id(&symbol);
            self.set_feed_kind(id, symbol.kind());
            self.venue_symbols.insert(id, symbol);
        }
        for symbol in books {
            self.book_symbols.insert(feed_id(&symbol), symbol);
        }
        self.all_funding |= !all.is_empty();
        for symbol in funding {
            self.funding_symbols.insert(feed_id(&symbol), symbol);
        }
        self.resubscribe()
    }

    /// Adds feeds whose venue reports to receive, and reconnects every node with
    /// the full set. [`OracleClient::next_event`] yields them.
    ///
    /// # Errors
    ///
    /// The same as [`OracleClient::subscribe`].
    pub async fn subscribe_venues(&mut self, symbols: &[&str]) -> Result<(), ClientError> {
        self.subscribe_all(Subscription {
            venues: symbols,
            ..Subscription::default()
        })
        .await
    }

    /// Adds feeds whose sources' books to receive, and reconnects every node
    /// with the full set. [`OracleClient::book`] reads them.
    ///
    /// # Errors
    ///
    /// The same as [`OracleClient::subscribe`].
    pub async fn subscribe_books(&mut self, symbols: &[&str]) -> Result<(), ClientError> {
        self.subscribe_all(Subscription {
            books: symbols,
            ..Subscription::default()
        })
        .await
    }

    /// Adds feeds whose perpetual sources' funding to receive, and reconnects
    /// every node with the full set. `"*"` asks for every perpetual.
    /// [`OracleClient::funding`] reads them.
    ///
    /// # Errors
    ///
    /// The same as [`OracleClient::subscribe`].
    pub async fn subscribe_funding(&mut self, symbols: &[&str]) -> Result<(), ClientError> {
        self.subscribe_all(Subscription {
            funding: symbols,
            ..Subscription::default()
        })
        .await
    }

    fn resubscribe(&mut self) -> Result<(), ClientError> {
        let prices: Vec<Symbol> = self.symbols.values().copied().collect();
        let venues: Vec<Symbol> = self.venue_symbols.values().copied().collect();
        let books: Vec<Symbol> = self.book_symbols.values().copied().collect();
        let funding: Vec<String> = if self.all_funding {
            vec!["*".to_owned()]
        } else {
            self.funding_symbols
                .values()
                .map(ToString::to_string)
                .collect()
        };
        self.subscription = Some(subscribe_frame(&prices, &venues, &books, &funding));
        self.runtime = Some(Handle::current());
        for (_, connection) in self.connections.drain() {
            connection.cancel.cancel();
        }
        self.reconcile_connections();
        if self.connections.is_empty() {
            return Err(ClientError::NoEndpoints);
        }
        self.start_polling();
        Ok(())
    }

    pub(super) fn reconcile_connections(&mut self) {
        let (Some(request), Some(runtime), Some(client_key)) =
            (&self.subscription, &self.runtime, &self.client_key)
        else {
            return;
        };
        let wanted: HashMap<Address, &[String]> = self
            .registry
            .nodes()
            .iter()
            .filter(|node| !node.endpoints.is_empty())
            .map(|node| (node.address, node.endpoints.as_slice()))
            .collect();

        self.connections.retain(|node, connection| {
            let keep = wanted
                .get(node)
                .is_some_and(|endpoints| *endpoints == connection.endpoints.as_slice());
            if !keep {
                connection.cancel.cancel();
                info!(%node, endpoints = ?connection.endpoints, "disconnected from node");
            }
            keep
        });

        for (node, endpoints) in wanted {
            if self.connections.contains_key(&node) {
                continue;
            }
            let cancel = self.shutdown.child_token();
            runtime.spawn(node_loop(
                NodeTarget {
                    node,
                    endpoints: endpoints.to_vec(),
                    request: request.clone(),
                    client_key: Arc::clone(client_key),
                    links: self.links.clone(),
                    idle_timeout: self.idle_timeout,
                },
                self.inbound_tx.clone(),
                cancel.clone(),
            ));
            info!(%node, ?endpoints, "connecting to node");
            self.connections.insert(
                node,
                NodeConnection {
                    endpoints: endpoints.to_vec(),
                    cancel,
                },
            );
        }
    }
}

/// Builds the subscribe control frame.
fn subscribe_frame(
    prices: &[Symbol],
    venues: &[Symbol],
    books: &[Symbol],
    funding: &[String],
) -> String {
    let names =
        |symbols: &[Symbol]| -> Vec<String> { symbols.iter().map(ToString::to_string).collect() };
    serde_json::json!({
        "op": "subscribe",
        "feeds": names(prices),
        "venues": names(venues),
        "books": names(books),
        "funding": funding,
    })
    .to_string()
}

fn parse_symbols(symbols: &[&str]) -> Result<Vec<Symbol>, ClientError> {
    symbols
        .iter()
        .map(|text| {
            text.parse()
                .map_err(|_| ClientError::InvalidSymbol((*text).to_owned()))
        })
        .collect()
}

/// Ceiling on the reconnect delay, before jitter.
const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// A connection that lived this long was not a node that flaps, so the next
/// failure starts the ladder from the bottom again.
const RESET_AFTER: Duration = Duration::from_secs(60);

/// A fresh reconnect ladder: 100 ms to 30 s, doubling, and the jitter adds up
/// to as much again.
///
/// Jittered so every subscriber of a node that just restarted does not come
/// back at the same instant.
fn reconnect_ladder() -> backon::ExponentialBackoff {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(100))
        .with_max_delay(RECONNECT_MAX)
        .with_factor(2.0)
        .with_jitter()
        .without_max_times()
        .build()
}

/// Everything one connection task needs.
struct NodeTarget {
    node: Address,
    /// Never empty: a node with no endpoint gets no task.
    endpoints: Vec<String>,
    request: String,
    client_key: Arc<Signer>,
    links: Links,
    idle_timeout: Duration,
}

/// Time to open the socket: TCP, TLS and the upgrade. A host can accept TCP
/// and never answer, such as after a network outage.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time from connect to `auth_ok`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A session with no message of any kind for this long is dead, such as a
/// socket that a network outage cut without a close. The session pings the
/// node three times in this time, and the node answers each ping.
pub(super) const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Connects to one node and forwards its binary frames, reconnecting on failure.
///
/// A round tries each endpoint in turn, from the one that served last, until one
/// serves a session; the backoff comes after the round.
async fn node_loop(target: NodeTarget, tx: mpsc::Sender<Inbound>, shutdown: CancellationToken) {
    let mut backoff = reconnect_ladder();
    let mut first = 0;
    while !shutdown.is_cancelled() {
        for offset in 0..target.endpoints.len() {
            let index = (first + offset) % target.endpoints.len();
            let Some(endpoint) = target.endpoints.get(index) else {
                break;
            };
            target.links.update(target.node, |link| {
                link.state = ConnectionState::Connecting;
            });
            let started = tokio::time::Instant::now();
            // Also drops a de-listed node in the middle of a handshake.
            let attempt = tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                attempt = connect_and_pump(&target, endpoint, &tx) => attempt,
            };
            if let Err(reason) = attempt.outcome {
                warn!(%endpoint, %reason, "node connection failed");
                target.links.update(target.node, |link| {
                    link.failures = link.failures.saturating_add(1);
                    link.last_error = Some(reason);
                });
            }
            if attempt.served {
                // How long the session lived decides, not how it ended: a node
                // ends a session with a sealed close, which arrives as an error.
                if started.elapsed() >= RESET_AFTER {
                    backoff = reconnect_ladder();
                }
                first = index;
                break;
            }
        }
        if shutdown.is_cancelled() {
            break;
        }
        let delay = backoff.next().unwrap_or(RECONNECT_MAX);
        let retry_at_ns =
            now_unix_nanos().saturating_add(u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX));
        target.links.update(target.node, |link| {
            link.state = ConnectionState::Backoff { retry_at_ns };
        });
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(delay) => {}
        }
    }
}

/// How one attempt at one endpoint ended.
struct Attempt {
    /// The handshake passed: the endpoint serves this node.
    served: bool,
    outcome: Result<(), String>,
}

async fn connect_and_pump(
    target: &NodeTarget,
    endpoint: &str,
    tx: &mpsc::Sender<Inbound>,
) -> Attempt {
    let failed = |reason: String| Attempt {
        served: false,
        outcome: Err(reason),
    };
    // rustls panics at a wss:// handshake when the process has no provider, as
    // a client built from a pinned registry may not; an installed one wins.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let connecting = tokio_tungstenite::connect_async(endpoint);
    let mut socket = match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
        Err(_) => return failed("connect timed out".to_owned()),
        Ok(Err(error)) => return failed(error.to_string()),
        Ok(Ok((socket, _))) => socket,
    };
    let session =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut socket, target, tx)).await {
            Err(_) => return failed("handshake timed out".to_owned()),
            Ok(Err(reason)) => return failed(reason),
            Ok(Ok(session)) => session,
        };
    Attempt {
        served: true,
        outcome: pump(&mut socket, session, target, tx).await,
    }
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// One session after the handshake: sealed control and broadcast frames.
/// Opened frames go to the verifier like any other; decryption proves nothing.
async fn pump(
    socket: &mut Socket,
    mut session: ClientSession,
    target: &NodeTarget,
    tx: &mpsc::Sender<Inbound>,
) -> Result<(), String> {
    target.links.update(target.node, |link| {
        link.state = ConnectionState::Connected {
            since_ns: now_unix_nanos(),
        };
        link.connects = link.connects.saturating_add(1);
    });
    // Only now, after the node proved its key, do the subscriptions leave.
    let subscribe = session
        .sealer
        .seal(&Control::App(target.request.as_bytes().to_vec()))
        .map_err(|e| e.to_string())?;
    socket
        .send(Message::Binary(subscribe.into()))
        .await
        .map_err(|e| e.to_string())?;

    let mut missing_since: Option<u64> = None;
    let every = (target.idle_timeout / 3).max(Duration::from_millis(1));
    let mut keepalive = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    let mut last_message = tokio::time::Instant::now();
    loop {
        let message = tokio::select! {
            message = socket.next() => message,
            _ = keepalive.tick() => {
                if last_message.elapsed() >= target.idle_timeout {
                    return Err(format!(
                        "no message from the node for {:?}",
                        target.idle_timeout
                    ));
                }
                let ping = session
                    .sealer
                    .seal(&Control::App(br#"{"op":"ping"}"#.to_vec()))
                    .map_err(|e| e.to_string())?;
                socket
                    .send(Message::Binary(ping.into()))
                    .await
                    .map_err(|e| e.to_string())?;
                continue;
            }
        };
        let Some(message) = message else { break };
        last_message = tokio::time::Instant::now();
        let bytes = match message.map_err(|e| e.to_string())? {
            Message::Binary(bytes) => bytes,
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
            Message::Text(_) => return Err("plaintext after the handshake".to_owned()),
            Message::Close(_) => return Ok(()),
        };
        let received_ns = now_unix_nanos();
        let now = received_ns / NANOS_PER_SEC;
        match bytes.get(1).copied() {
            Some(TYPE_FRAME) => {
                session.keys.prune(now);
                match session.keys.open(&bytes) {
                    Ok(frame) => {
                        missing_since = None;
                        let recovered = RecoveredFrame::of(&frame);
                        if tx
                            .send(Inbound::Frame {
                                frame,
                                received_ns,
                                recovered,
                            })
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                    Err(TransportError::UnknownKey) => {
                        let since = *missing_since.get_or_insert(now);
                        if now.saturating_sub(since) > KEY_GRACE_SECS {
                            return Err("no key for the node's frames".to_owned());
                        }
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
            Some(TYPE_CONTROL) => match session.opener.open(&bytes).map_err(|e| e.to_string())? {
                Control::KeyUpdate(grant) => session.keys.insert(grant),
                Control::SessionUpdate { deadline } => session.deadline = deadline,
                Control::Close(reason) => {
                    return Err(format!("node closed the session: {reason:?}"));
                }
                Control::App(_) => {}
            },
            _ => return Err("unknown message type".to_owned()),
        }
    }
    Ok(())
}

async fn handshake(
    socket: &mut Socket,
    target: &NodeTarget,
    tx: &mpsc::Sender<Inbound>,
) -> Result<ClientSession, String> {
    let challenge = next_handshake(socket).await?;
    let (auth, waiting) = ClientHandshake::new(target.node, &mut os_rng())
        .respond(&challenge, &target.client_key)
        .map_err(|error| {
            if let TransportError::WrongNode { got, .. } = error {
                let _ = tx.try_send(Inbound::NodeMoved { got });
            }
            error.to_string()
        })?;
    let auth = serde_json::to_string(&auth).map_err(|e| e.to_string())?;
    socket
        .send(Message::Text(auth.into()))
        .await
        .map_err(|e| e.to_string())?;
    let auth_ok = next_handshake(socket).await?;
    waiting.finish(&auth_ok).map_err(|e| e.to_string())
}

async fn next_handshake(socket: &mut Socket) -> Result<HandshakeMessage, String> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(&text).map_err(|e| e.to_string());
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(other)) => return Err(format!("expected a handshake message, got {other:?}")),
            Some(Err(error)) => return Err(error.to_string()),
            None => return Err("closed during the handshake".to_owned()),
        }
    }
}
