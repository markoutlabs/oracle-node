//! One WebSocket connection: the upgrade within the handshake limits, the
//! handshake, then the sealed session until it ends.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};
use governor::{Quota, RateLimiter};
use oracle_transport::{CloseReason, Control, HandshakeMessage, KeyGrant};
use tracing::{debug, info};

use super::Web;
use super::control::handle_control;
use super::peer::Peer;
use super::rest::too_many;
use crate::limit::{Admission, Admitted, Limits, Refusal};
use crate::transport::{Established, NodeTransport, Outbound, unix_now};

/// The largest WebSocket message a node accepts, before and after auth.
const MAX_MESSAGE: usize = 64 * 1024;
/// A subscriber that cannot take a message for this long is dropped (SPEC §6.4).
const STALL: Duration = Duration::from_secs(5);
/// Pings and pongs a peer may send before its auth. Each costs a reply, and a
/// peer that answers a challenge at once needs none.
const PINGS_BEFORE_AUTH: usize = 4;

pub(super) async fn ws_upgrade(
    State(web): State<Arc<Web>>,
    Peer(peer): Peer,
    ws: WebSocketUpgrade,
) -> Response {
    let key = peer.and_then(|peer| web.limits.key(peer));
    let place = match Admission::admit(&web.handshakes, key) {
        Ok(place) => place,
        Err(Refusal::Full) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "too many handshakes in progress",
            )
                .into_response();
        }
        Err(Refusal::TooManyOpen | Refusal::TooManyNew) => {
            return too_many("too many handshakes from this address");
        }
    };
    ws.max_message_size(MAX_MESSAGE)
        .max_frame_size(MAX_MESSAGE)
        .on_upgrade(move |socket| serve(socket, web, place))
}

type Sink = SplitSink<WebSocket, Message>;
type Stream = SplitStream<WebSocket>;

/// Serves one connection: handshake under the cap and the timeout, then the
/// sealed session until the deadline, a revocation or a disconnect.
async fn serve(socket: WebSocket, web: Arc<Web>, place: Admitted) {
    let state = &web.state;
    let transport = &state.transport;
    let (mut sink, mut stream) = socket.split();
    let established = handshake(&mut sink, &mut stream, transport, &web.limits).await;
    drop(place);
    let Some(Established {
        subscriber,
        mut sealer,
        mut opener,
        mut outbox,
        replies,
        deadline,
    }) = established
    else {
        let _ = tokio::time::timeout(STALL, sink.close()).await;
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
                            if send(&mut sink, Message::Binary(update.sealed())).await.is_err() {
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
            let _ = tokio::time::timeout(STALL, sink.close()).await;
        })
    };

    let messages = RateLimiter::direct(Quota::per_second(web.limits.messages_per_second));
    let reader = async {
        while let Some(Ok(message)) = stream.next().await {
            // Each message costs an open and a reply, a ping a pong.
            if messages.check().is_err() {
                info!(client = %subscriber.client(), "client session closed: control messages over the rate");
                break;
            }
            let bytes = match message {
                Message::Binary(bytes) => bytes,
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Text(_) | Message::Close(_) => break,
            };
            let Ok(Control::App(json)) = opener.open(&bytes) else {
                break;
            };
            let raw = String::from_utf8_lossy(&json);
            let reply = handle_control(&raw, state, &subscriber);
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
    limits: &Limits,
) -> Option<Established> {
    let limit = limits.handshake_timeout();
    let (handshake, challenge) = transport.start();
    let auth = tokio::time::timeout(limit, async {
        sink.send(json_message(&challenge)).await.ok()?;
        let mut pings = 0_usize;
        loop {
            match stream.next().await? {
                Ok(Message::Text(text)) => return Some(text.to_string()),
                Ok(Message::Ping(_) | Message::Pong(_)) if pings < PINGS_BEFORE_AUTH => pings += 1,
                _ => return None,
            }
        }
    })
    .await
    .ok()??;
    let auth: HandshakeMessage = match serde_json::from_str(&auth) {
        Ok(auth) => auth,
        Err(error) => {
            debug!(%error, "client sent no valid auth");
            // The parse error quotes the input, so a stranger would size the reply.
            refuse(sink, "the auth message does not parse").await;
            return None;
        }
    };
    match transport.admit(handshake, &auth, unix_now(), limits.sessions_per_client) {
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
    // A peer that does not read must not hold its handshake place.
    let _ = tokio::time::timeout(STALL, sink.send(json_message(&message))).await;
}

async fn send(sink: &mut Sink, message: Message) -> Result<(), ()> {
    match tokio::time::timeout(STALL, sink.send(message)).await {
        Ok(Ok(())) => Ok(()),
        _ => Err(()),
    }
}

async fn send_sealed(
    sink: &mut Sink,
    sealer: &mut oracle_transport::Sealer,
    message: &Control,
) -> Result<(), ()> {
    let sealed = sealer.seal(message).map_err(|_| ())?;
    send(sink, Message::Binary(sealed.into())).await
}

fn json_message(message: &HandshakeMessage) -> Message {
    Message::Text(serde_json::to_string(message).unwrap_or_default().into())
}

fn instant_at(deadline: u64) -> tokio::time::Instant {
    // A client that never expires must not overflow the clock. Thirty years is
    // as far as tokio's own timers reach.
    let wait = Duration::from_secs(deadline.saturating_sub(unix_now()));
    tokio::time::Instant::now() + wait.min(Duration::from_secs(30 * 365 * 86_400))
}
