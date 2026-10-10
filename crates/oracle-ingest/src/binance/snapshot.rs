//! The REST snapshot that Binance's diff-depth stream applies to, delivered as
//! a frame.
//!
//! Binance sends book changes on the socket and the book they change only over
//! REST. This connector fetches a symbol's snapshot once its first change has
//! arrived, as Binance's procedure asks: a snapshot fetched earlier can predate
//! the stream and leave a gap. It hands the snapshot to the session as one more
//! frame, `{"stream":"<symbol>@depthSnapshot","data":{…}}`, among the changes.
//! It sits under the recorder, so a recording holds the snapshot and a replay
//! never calls REST.

use std::time::Duration;

use futures_util::FutureExt as _;
use futures_util::future::BoxFuture;
use futures_util::stream::{FuturesUnordered, StreamExt as _};
use serde_json::value::RawValue;

use super::streams::StreamKind;
use crate::transport::{Connector, Frame, Transport, TransportError};

/// Levels requested per side.
pub const SNAPSHOT_LIMIT: usize = 1_000;

/// Spot's REST depth endpoint.
pub const SPOT_REST: &str = "https://api.binance.com/api/v3/depth";

/// USD-margined futures' REST depth endpoint.
pub const FUTURES_REST: &str = "https://fapi.binance.com/fapi/v1/depth";

const TIMEOUT: Duration = Duration::from_secs(10);

/// Wraps a connector: a Binance connection that subscribes to depth also gets
/// each depth stream's snapshot. Every other connection passes through.
#[derive(Clone)]
pub struct SnapshotConnector<C> {
    inner: C,
    /// Socket base URL, and the REST endpoint its snapshots come from.
    routes: Vec<(String, String)>,
    client: reqwest::Client,
}

impl<C> SnapshotConnector<C> {
    /// Wraps `inner`. `routes` pairs each Binance socket base URL with its REST
    /// depth endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Connect`] if the HTTP client cannot be built,
    /// which means TLS is misconfigured in this binary.
    pub fn new(inner: C, routes: Vec<(String, String)>) -> Result<Self, TransportError> {
        // reqwest leaves the crypto provider to the binary; tungstenite already
        // brings `ring`.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        Ok(Self {
            inner,
            routes,
            client,
        })
    }

    fn rest_for(&self, url: &str) -> Option<&str> {
        self.routes
            .iter()
            .find(|(socket, _)| url.starts_with(socket.as_str()))
            .map(|(_, rest)| rest.as_str())
    }
}

/// The symbols of the depth streams a combined-stream URL subscribes to.
fn depth_symbols(url: &str) -> Vec<String> {
    let Some((_, streams)) = url.split_once("streams=") else {
        return Vec::new();
    };
    streams
        .split('/')
        .filter(|stream| StreamKind::from_stream_name(stream) == Some(StreamKind::Depth))
        .filter_map(|stream| stream.split('@').next())
        .map(str::to_owned)
        .collect()
}

impl<C: Connector> Connector for SnapshotConnector<C> {
    type Conn = SnapshotTransport<C::Conn>;

    async fn connect(&self, url: &str) -> Result<Self::Conn, TransportError> {
        let conn = self.inner.connect(url).await?;
        let awaiting = match self.rest_for(url) {
            Some(rest) => depth_symbols(url)
                .into_iter()
                .map(|symbol| (symbol, rest.to_owned()))
                .collect(),
            None => Vec::new(),
        };
        Ok(SnapshotTransport {
            inner: conn,
            client: self.client.clone(),
            awaiting,
            pending: FuturesUnordered::new(),
        })
    }
}

/// A connection whose snapshots arrive among its frames.
pub struct SnapshotTransport<T> {
    inner: T,
    client: reqwest::Client,
    /// Depth symbols whose first change has not arrived, with their REST
    /// endpoint.
    awaiting: Vec<(String, String)>,
    pending: FuturesUnordered<BoxFuture<'static, Frame>>,
}

impl<T> SnapshotTransport<T> {
    /// Starts a symbol's fetch when its first change passes through.
    fn watch(&mut self, frame: &Frame) {
        if self.awaiting.is_empty() {
            return;
        }
        let Frame::Text(text) = frame else {
            return;
        };
        let Some(stream) = stream_name(text) else {
            return;
        };
        if StreamKind::from_stream_name(stream) != Some(StreamKind::Depth) {
            return;
        }
        let symbol = stream.split('@').next().unwrap_or(stream);
        if let Some(index) = self.awaiting.iter().position(|(s, _)| s == symbol) {
            let (symbol, rest) = self.awaiting.swap_remove(index);
            self.pending
                .push(fetch(self.client.clone(), rest, symbol).boxed());
        }
    }
}

/// The `stream` of a combined-stream frame, without parsing the rest.
fn stream_name(text: &str) -> Option<&str> {
    let start = text.find(r#""stream":""#)? + 10;
    let length = text.get(start..)?.find('"')?;
    text.get(start..start + length)
}

impl<T: Transport> Transport for SnapshotTransport<T> {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        let result = if self.pending.is_empty() {
            self.inner.recv().await
        } else {
            // Both arms are cancel-safe: the socket's `recv` is, and a pending
            // fetch stays in the set until it completes.
            tokio::select! {
                Some(frame) = self.pending.next() => return Ok(Some(frame)),
                result = self.inner.recv() => result,
            }
        };
        if let Ok(Some(frame)) = &result {
            self.watch(frame);
        }
        result
    }

    async fn send_text(&mut self, text: String) -> Result<(), TransportError> {
        self.inner.send_text(text).await
    }

    async fn send_ping(&mut self) -> Result<(), TransportError> {
        self.inner.send_ping().await
    }
}

/// Fetches one snapshot. A failure becomes a frame too, so the decoder can ask
/// for a resync rather than wait for a snapshot that will never come.
async fn fetch(client: reqwest::Client, rest: String, symbol: String) -> Frame {
    let stream = format!(
        "{}{}",
        symbol.to_ascii_lowercase(),
        StreamKind::DepthSnapshot.suffix()
    );
    let url = format!(
        "{rest}?symbol={}&limit={SNAPSHOT_LIMIT}",
        symbol.to_ascii_uppercase()
    );
    let body = async {
        let response = client.get(&url).send().await?.error_for_status()?;
        response.text().await
    };
    let text = match body.await {
        Ok(body) => match serde_json::from_str::<Box<RawValue>>(&body) {
            Ok(data) => serde_json::json!({ "stream": stream, "data": data }).to_string(),
            Err(error) => {
                serde_json::json!({ "stream": stream, "error": error.to_string() }).to_string()
            }
        },
        Err(error) => {
            serde_json::json!({ "stream": stream, "error": error.to_string() }).to_string()
        }
    };
    Frame::Text(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_name_is_read_without_parsing_the_frame() {
        assert_eq!(
            stream_name(r#"{"stream":"btcusdt@depth@100ms","data":{"U":1}}"#),
            Some("btcusdt@depth@100ms")
        );
        assert_eq!(stream_name(r#"{"result":null,"id":1}"#), None);
    }

    #[test]
    fn depth_symbols_are_read_from_the_url() {
        let url = "wss://stream.binance.com:9443/stream?streams=btcusdt@bookTicker/btcusdt@depth@100ms/ethusdt@aggTrade/ethusdt@depth@100ms";
        assert_eq!(depth_symbols(url), ["btcusdt", "ethusdt"]);
        assert!(
            depth_symbols("wss://stream.binance.com:9443/stream?streams=btcusdt@bookTicker")
                .is_empty()
        );
    }
}
