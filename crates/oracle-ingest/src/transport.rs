//! The WebSocket abstraction the session loop runs on.
//!
//! The session is generic over [`Connector`] so that reconnect behaviour can be
//! tested against a mock that fails on demand, in microseconds, with no network
//! and no exchange. Reconnect logic that is only exercised against a live venue
//! is, in practice, logic that is only exercised during an outage.

use std::future::Future;
use std::sync::LazyLock;

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

/// A transport-level failure. Always recoverable by reconnecting.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The connection could not be established.
    #[error("connect failed: {0}")]
    Connect(String),

    /// The connection failed while in use.
    #[error("connection lost: {0}")]
    Io(String),

    /// A frame could not be sent.
    #[error("send failed: {0}")]
    Send(String),
}

/// One received WebSocket frame.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Frame {
    /// A text frame, the only kind any venue in scope uses for market data.
    Text(String),
    /// A binary frame.
    Binary(Vec<u8>),
    /// A ping. Replying is the transport's job; the session counts it as liveness.
    Ping,
    /// A pong, usually answering our own probe.
    Pong,
}

impl Frame {
    /// Returns the payload bytes, for frames that carry one.
    #[must_use]
    pub fn payload(&self) -> Option<&[u8]> {
        match self {
            Self::Text(text) => Some(text.as_bytes()),
            Self::Binary(bytes) => Some(bytes),
            Self::Ping | Self::Pong => None,
        }
    }
}

/// An open connection.
///
/// # Cancel safety
///
/// [`Transport::recv`] **must** be cancel-safe: the session races it against
/// shutdown, keepalive, and session-age timers, so its future is routinely
/// dropped mid-poll. An implementation that loses a buffered message on cancel
/// would drop quotes under exactly the conditions that matter.
pub trait Transport: Send {
    /// Receives the next frame, or `None` once the peer closes.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] if the connection fails.
    fn recv(&mut self) -> impl Future<Output = Result<Option<Frame>, TransportError>> + Send;

    /// Sends a text frame.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Send`] if the frame cannot be written.
    fn send_text(
        &mut self,
        text: String,
    ) -> impl Future<Output = Result<(), TransportError>> + Send;

    /// Sends a WebSocket ping. The peer must answer with a pong (RFC 6455).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Send`] if the frame cannot be written.
    fn send_ping(&mut self) -> impl Future<Output = Result<(), TransportError>> + Send;
}

/// Opens connections.
pub trait Connector: Send + Sync {
    /// The connection type produced.
    type Conn: Transport;

    /// Connects to `url`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Connect`] if the connection cannot be opened.
    fn connect(&self, url: &str)
    -> impl Future<Output = Result<Self::Conn, TransportError>> + Send;
}

/// A live `tokio-tungstenite` WebSocket.
pub struct WebSocket {
    inner: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl Transport for WebSocket {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        loop {
            // `StreamExt::next` is cancel-safe, and polling it is also what
            // flushes the automatic pong tungstenite queues in reply to a ping.
            let Some(message) = self.inner.next().await else {
                return Ok(None);
            };
            let message = message.map_err(|e| TransportError::Io(e.to_string()))?;
            return Ok(Some(match message {
                Message::Text(text) => Frame::Text(text.to_string()),
                Message::Binary(bytes) => Frame::Binary(bytes.to_vec()),
                Message::Ping(_) => Frame::Ping,
                Message::Pong(_) => Frame::Pong,
                Message::Close(_) => return Ok(None),
                // Raw frames never surface from a client-side read.
                Message::Frame(_) => continue,
            }));
        }
    }

    async fn send_text(&mut self, text: String) -> Result<(), TransportError> {
        self.inner
            .send(Message::Text(text.into()))
            .await
            .map_err(|e| TransportError::Send(e.to_string()))
    }

    async fn send_ping(&mut self) -> Result<(), TransportError> {
        self.inner
            .send(Message::Ping(Default::default()))
            .await
            .map_err(|e| TransportError::Send(e.to_string()))
    }
}

/// Installs a `rustls` crypto provider, once per process.
///
/// `rustls` 0.23 refuses to choose a provider implicitly and **panics** on the
/// first handshake if none is installed. That panic surfaces inside a TLS worker
/// task at connect time, so it survives every test that uses a mock transport and
/// only appears against a live venue. Installing it here means a caller cannot
/// forget.
///
/// `install_default` returning `Err` means the process already has a provider —
/// an application that installed its own wins, which is the intent.
static TLS_PROVIDER: LazyLock<()> = LazyLock::new(|| {
    let _ = rustls::crypto::ring::default_provider().install_default();
});

/// Connects over TLS using `rustls` with the webpki root store.
#[derive(Clone, Copy, Debug, Default)]
pub struct WebSocketConnector;

impl Connector for WebSocketConnector {
    type Conn = WebSocket;

    async fn connect(&self, url: &str) -> Result<Self::Conn, TransportError> {
        LazyLock::force(&TLS_PROVIDER);
        let (inner, _response) = connect_async(url)
            .await
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        Ok(WebSocket { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_payloads() {
        assert_eq!(
            Frame::Text("hi".to_owned()).payload(),
            Some(b"hi".as_slice())
        );
        assert_eq!(Frame::Binary(vec![1, 2]).payload(), Some([1, 2].as_slice()));
        assert_eq!(Frame::Ping.payload(), None);
        assert_eq!(Frame::Pong.payload(), None);
    }
}
