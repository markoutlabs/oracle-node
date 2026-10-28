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
//!
//! The mark price stream does not say how often a perpetual pays funding. A
//! connection that carries mark prices therefore also gets the list of adjusted
//! funding intervals, `{"stream":"!fundingInfo","data":[…]}`, when it opens and
//! each hour after.

use std::time::Duration;

use futures_util::FutureExt as _;
use futures_util::stream::{self, BoxStream, SelectAll, StreamExt as _};
use serde_json::value::RawValue;
use tracing::warn;

use super::streams::{FUNDING_INFO_STREAM, StreamKind};
use crate::transport::{Connector, Frame, Transport, TransportError};

/// Levels requested per side.
pub const SNAPSHOT_LIMIT: usize = 1_000;

/// Spot's REST depth endpoint.
pub const SPOT_REST: &str = "https://api.binance.com/api/v3/depth";

/// USD-margined futures' REST depth endpoint.
pub const FUTURES_REST: &str = "https://fapi.binance.com/fapi/v1/depth";

/// USD-margined futures' REST endpoint of the adjusted funding intervals.
pub const FUTURES_FUNDING_INFO_REST: &str = "https://fapi.binance.com/fapi/v1/fundingInfo";

/// USD-margined futures' REST endpoint of one perpetual's open interest.
/// Binance has no stream for it.
pub const FUTURES_OPEN_INTEREST_REST: &str = "https://fapi.binance.com/fapi/v1/openInterest";

const TIMEOUT: Duration = Duration::from_secs(10);

/// Binance changes an interval rarely, and announces it ahead.
const FUNDING_INFO_EVERY: Duration = Duration::from_secs(3_600);
const FUNDING_INFO_RETRY: Duration = Duration::from_secs(60);
/// Each perpetual's open interest, in turn, once a minute. 150 perpetuals are
/// 150 requests a minute, far under Binance's 2,400 a minute.
const OPEN_INTEREST_EVERY: Duration = Duration::from_secs(60);

/// Wraps a connector: it adds the REST frames that a Binance connection needs.
#[derive(Clone)]
pub struct SnapshotConnector<C> {
    inner: C,
    /// Socket base URL, and the REST endpoint its snapshots come from.
    routes: Vec<(String, String)>,
    /// Socket base URL, and the REST endpoint of the open interest.
    open_interest: Vec<(String, String)>,
    /// Socket base URL, and the REST endpoint of its funding intervals.
    funding_info: Vec<(String, String)>,
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
            funding_info: Vec::new(),
            open_interest: Vec::new(),
            client,
        })
    }

    /// Adds the funding intervals to mark-price connections: socket base URL, REST endpoint.
    #[must_use]
    pub fn with_funding_info(mut self, routes: Vec<(String, String)>) -> Self {
        self.funding_info = routes;
        self
    }

    /// Adds the open interest to mark-price connections: socket base URL, REST endpoint.
    #[must_use]
    pub fn with_open_interest(mut self, routes: Vec<(String, String)>) -> Self {
        self.open_interest = routes;
        self
    }

    fn rest_for(&self, url: &str) -> Option<&str> {
        route(&self.routes, url)
    }

    fn open_interest_for(&self, url: &str) -> Option<&str> {
        route(&self.open_interest, url).filter(|_| !mark_symbols(url).is_empty())
    }

    fn funding_info_for(&self, url: &str) -> Option<&str> {
        let marks = streams(url)
            .iter()
            .any(|stream| StreamKind::from_stream_name(stream) == Some(StreamKind::MarkPrice));
        route(&self.funding_info, url).filter(|_| marks)
    }
}

fn route<'a>(routes: &'a [(String, String)], url: &str) -> Option<&'a str> {
    routes
        .iter()
        .find(|(socket, _)| url.starts_with(socket.as_str()))
        .map(|(_, rest)| rest.as_str())
}

/// The streams that a combined-stream URL subscribes to.
fn streams(url: &str) -> Vec<String> {
    let Ok(url) = reqwest::Url::parse(url) else {
        return Vec::new();
    };
    url.query_pairs()
        .filter(|(key, _)| key == "streams")
        .flat_map(|(_, value)| value.split('/').map(str::to_owned).collect::<Vec<_>>())
        .collect()
}

/// The symbols of the depth streams a combined-stream URL subscribes to.
fn depth_symbols(url: &str) -> Vec<String> {
    symbols_of(url, StreamKind::Depth)
}

/// The symbols of the mark-price streams a combined-stream URL subscribes to.
fn mark_symbols(url: &str) -> Vec<String> {
    symbols_of(url, StreamKind::MarkPrice)
}

fn symbols_of(url: &str, kind: StreamKind) -> Vec<String> {
    streams(url)
        .iter()
        .filter(|stream| StreamKind::from_stream_name(stream) == Some(kind))
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
        let mut pending = SelectAll::new();
        if let Some(rest) = self.funding_info_for(url) {
            pending.push(funding_info(self.client.clone(), rest.to_owned()));
        }
        if let Some(rest) = self.open_interest_for(url) {
            pending.push(open_interest(
                self.client.clone(),
                rest.to_owned(),
                mark_symbols(url),
            ));
        }
        Ok(SnapshotTransport {
            inner: conn,
            client: self.client.clone(),
            awaiting,
            pending,
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
    /// One frame for each depth fetch; the funding intervals never end.
    pending: SelectAll<BoxStream<'static, Frame>>,
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
            self.pending.push(
                depth(self.client.clone(), rest, symbol)
                    .into_stream()
                    .boxed(),
            );
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
async fn depth(client: reqwest::Client, rest: String, symbol: String) -> Frame {
    let stream = format!(
        "{}{}",
        symbol.to_ascii_lowercase(),
        StreamKind::DepthSnapshot.suffix()
    );
    let url = format!(
        "{rest}?symbol={}&limit={SNAPSHOT_LIMIT}",
        symbol.to_ascii_uppercase()
    );
    frame(&stream, fetch(&client, &url).await)
}

/// The funding intervals now, then each hour, or a minute after a failed fetch.
fn funding_info(client: reqwest::Client, rest: String) -> BoxStream<'static, Frame> {
    stream::unfold(Duration::ZERO, move |wait| {
        let (client, rest) = (client.clone(), rest.clone());
        async move {
            tokio::time::sleep(wait).await;
            let fetched = fetch(&client, &rest).await;
            let next = match &fetched {
                Ok(_) => FUNDING_INFO_EVERY,
                Err(error) => {
                    // The decoder only counts the frame, so this is the one visible sign.
                    warn!(%error, "the Binance funding intervals could not be fetched");
                    FUNDING_INFO_RETRY
                }
            };
            Some((frame(FUNDING_INFO_STREAM, fetched), next))
        }
    })
    .boxed()
}

/// The open interest of each symbol in turn, so that the whole list comes
/// round once in [`OPEN_INTEREST_EVERY`]. A failed fetch is a frame too, which
/// the decoder counts; the last value stays.
fn open_interest(
    client: reqwest::Client,
    rest: String,
    symbols: Vec<String>,
) -> BoxStream<'static, Frame> {
    let wait = OPEN_INTEREST_EVERY / u32::try_from(symbols.len().max(1)).unwrap_or(u32::MAX);
    stream::unfold(0_usize, move |index| {
        let (client, rest) = (client.clone(), rest.clone());
        let symbol = symbols.get(index).cloned();
        let next = (index + 1) % symbols.len().max(1);
        async move {
            let symbol = symbol?;
            tokio::time::sleep(wait).await;
            let url = format!("{rest}?symbol={}", symbol.to_ascii_uppercase());
            let stream = format!(
                "{}{}",
                symbol.to_ascii_lowercase(),
                StreamKind::OpenInterest.suffix()
            );
            Some((frame(&stream, fetch(&client, &url).await), next))
        }
    })
    .boxed()
}

/// One REST reply, as JSON.
async fn fetch(client: &reqwest::Client, url: &str) -> Result<Box<RawValue>, String> {
    let body = async {
        let response = client.get(url).send().await?.error_for_status()?;
        response.text().await
    };
    let body = body.await.map_err(|error| error.to_string())?;
    serde_json::from_str(&body).map_err(|error| error.to_string())
}

/// A reply as a frame of `stream`: `data`, or `error` when the fetch failed.
fn frame(stream: &str, fetched: Result<Box<RawValue>, String>) -> Frame {
    let text = match fetched {
        Ok(data) => serde_json::json!({ "stream": stream, "data": data }),
        Err(error) => serde_json::json!({ "stream": stream, "error": error }),
    };
    Frame::Rest(text.to_string())
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
    fn only_a_mark_price_connection_gets_the_funding_intervals() {
        let connector = SnapshotConnector::new((), Vec::new())
            .expect("a client")
            .with_funding_info(vec![(
                "wss://fstream.binance.com/market/stream".to_owned(),
                FUTURES_FUNDING_INFO_REST.to_owned(),
            )]);
        let market = "wss://fstream.binance.com/market/stream?streams=";
        for marks in ["btcusdt@aggTrade/btcusdt@markPrice@1s", "btcusdt@markPrice"] {
            assert_eq!(
                connector.funding_info_for(&format!("{market}{marks}")),
                Some(FUTURES_FUNDING_INFO_REST)
            );
        }
        assert_eq!(
            connector.funding_info_for(&format!("{market}btcusdt@aggTrade")),
            None
        );
        assert_eq!(
            connector.funding_info_for(
                "wss://fstream.binance.com/public/stream?streams=btcusdt@markPrice@1s"
            ),
            None
        );
    }

    /// The open interest comes by REST, one symbol at a time, for the
    /// mark-price symbols of the connection.
    #[test]
    fn only_a_mark_price_connection_polls_the_open_interest() {
        let connector = SnapshotConnector::new((), Vec::new())
            .expect("a client")
            .with_open_interest(vec![(
                "wss://fstream.binance.com/market/stream".to_owned(),
                FUTURES_OPEN_INTEREST_REST.to_owned(),
            )]);
        let market = "wss://fstream.binance.com/market/stream?streams=";
        let url = format!("{market}btcusdt@aggTrade/btcusdt@markPrice@1s/ethusdt@markPrice@1s");
        assert_eq!(
            connector.open_interest_for(&url),
            Some(FUTURES_OPEN_INTEREST_REST)
        );
        assert_eq!(mark_symbols(&url), ["btcusdt", "ethusdt"]);
        assert_eq!(
            connector.open_interest_for(&format!("{market}btcusdt@aggTrade")),
            None
        );
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
