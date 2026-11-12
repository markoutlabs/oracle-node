//! REST records delivered as frames among a socket's frames, for the venues
//! whose socket leaves out what only REST gives, such as a perpetual's funding
//! interval (KuCoin, MEXC). A venue with no socket, such as Toobit, gets a
//! connection of records alone.
//!
//! A record is a frame `{"type":"rest","subject":"…","topic":"/rest:<contract>",
//! "data":{…}}`, or the same with `error` in place of `data` when the read
//! failed. A connector that adds them sits under the recorder, so a recording
//! holds them and a replay never calls REST.

use std::time::Duration;

use futures_util::stream::{self, BoxStream, SelectAll, StreamExt as _};
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, RETRY_AFTER};
use serde_json::value::RawValue;

use crate::transport::{Frame, Transport, TransportError, install_tls_provider};

const TIMEOUT: Duration = Duration::from_secs(10);

/// The largest reply, a Binance depth snapshot of 1,000 levels a side, is
/// about 70 KB; one contract's record is a few kilobytes.
const MAX_BODY: usize = 256 * 1024;

/// Takes the `data` of a venue's reply, or says why the reply failed.
pub(crate) type DataOf = fn(&[u8]) -> Result<Box<RawValue>, String>;

/// One REST read: the contract, the frame's subject, and the URL.
pub(crate) type Read = (String, &'static str, String);

/// Makes the frame of one read: the subject, the contract, and the reply.
pub(crate) type FrameOf = fn(&str, &str, Result<Box<RawValue>, String>) -> Frame;

/// The whole body of a JSON reply.
pub(crate) fn whole_body(body: &[u8]) -> Result<Box<RawValue>, String> {
    serde_json::from_slice(body).map_err(|error| error.to_string())
}

/// An HTTP client that follows no redirect and gives up after 10 s.
pub(crate) fn client() -> Result<reqwest::Client, TransportError> {
    // reqwest leaves the crypto provider to the binary.
    install_tls_provider();
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| TransportError::Connect(e.to_string()))
}

/// Why a REST read failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ReadError {
    /// The reply has an error status. A venue that refuses the rate can say
    /// when to try again.
    #[error("HTTP {status} from {url}")]
    Status {
        status: StatusCode,
        /// `Retry-After`, when it gives whole seconds.
        retry_after: Option<Duration>,
        url: String,
    },
    /// No reply, or a reply that is too large or that the venue's `data_of` refused.
    #[error("{0}")]
    Failed(String),
}

/// Sends a request, and gives the `data` of a successful reply.
pub(crate) async fn read(
    request: reqwest::RequestBuilder,
    data_of: DataOf,
) -> Result<Box<RawValue>, ReadError> {
    let failed = |error: reqwest::Error| ReadError::Failed(error.to_string());
    let response = request.send().await.map_err(failed)?;
    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        return Err(ReadError::Status {
            status,
            retry_after: retry_after(response.headers()),
            url: response.url().to_string(),
        });
    }
    let too_large = |length: usize| length > MAX_BODY;
    let too_large_error = || ReadError::Failed("the reply is too large".to_owned());
    if response
        .content_length()
        .is_some_and(|length| usize::try_from(length).map_or(true, too_large))
    {
        return Err(too_large_error());
    }
    let body = response.bytes().await.map_err(failed)?;
    if too_large(body.len()) {
        return Err(too_large_error());
    }
    data_of(&body).map_err(ReadError::Failed)
}

/// The `Retry-After` of a reply in seconds. The date form gives none, and the
/// caller keeps its own wait.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?;
    let seconds = value.to_str().ok()?.trim().parse().ok()?;
    Some(Duration::from_secs(seconds))
}

/// `base` with the contracts that [`contracts_of`] reads back.
#[must_use]
pub(crate) fn with_contracts<'a>(base: &str, contracts: impl Iterator<Item = &'a str>) -> String {
    let contracts: Vec<&str> = contracts.collect();
    format!("{base}?contracts={}", contracts.join(","))
}

/// The contracts of a URL's `contracts=` query. A name that is not letters,
/// digits and `_` is left out, as it goes into a REST path.
pub(crate) fn contracts_of(query: &str) -> Vec<String> {
    query
        .split('&')
        .filter_map(|pair| pair.strip_prefix("contracts="))
        .flat_map(|list| list.split(','))
        .filter(|name| {
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
        .map(str::to_owned)
        .collect()
}

/// The reads in turn, round after round, each round spread over `every`. The
/// first two reads go at once, so a connection has its funding soon.
pub(crate) fn records(
    client: reqwest::Client,
    reads: Vec<Read>,
    every: Duration,
    data_of: DataOf,
) -> BoxStream<'static, Frame> {
    records_as(client, reads, every, data_of, frame)
}

/// As [`records`], each frame made by `frame_of`.
pub(crate) fn records_as(
    client: reqwest::Client,
    reads: Vec<Read>,
    every: Duration,
    data_of: DataOf,
    frame_of: FrameOf,
) -> BoxStream<'static, Frame> {
    let steps = reads.len().max(1);
    let wait = every / u32::try_from(steps).unwrap_or(u32::MAX);
    stream::unfold(0_usize, move |n| {
        let client = client.clone();
        let read_ = reads.get(n % steps).cloned();
        async move {
            let (contract, subject, url) = read_?;
            if n >= 2 {
                tokio::time::sleep(wait).await;
            }
            // A failed read is a frame too: the decoder counts it, and the
            // session warns at most once a minute.
            let fetched = read(client.get(url), data_of).await;
            let fetched = fetched.map_err(|error| error.to_string());
            Some((frame_of(subject, &contract, fetched), n + 1))
        }
    })
    .boxed()
}

/// A REST record as a frame: `data`, or `error` when the read failed.
pub(crate) fn frame(
    subject: &str,
    contract: &str,
    fetched: Result<Box<RawValue>, String>,
) -> Frame {
    Frame::Rest(record(subject, contract, fetched))
}

/// The text of a REST record: `data`, or `error` when the read failed.
pub(crate) fn record(
    subject: &str,
    contract: &str,
    fetched: Result<Box<RawValue>, String>,
) -> String {
    let topic = format!("/rest:{contract}");
    let text = match fetched {
        Ok(data) => {
            serde_json::json!({ "type": "rest", "subject": subject, "topic": topic, "data": data })
        }
        Err(error) => {
            serde_json::json!({ "type": "rest", "subject": subject, "topic": topic, "error": error })
        }
    };
    text.to_string()
}

/// A connection whose REST records arrive among its frames.
pub struct RestTransport<T> {
    /// The socket; none on a venue that only REST serves.
    inner: Option<T>,
    pending: SelectAll<BoxStream<'static, Frame>>,
}

impl<T> RestTransport<T> {
    /// A connection without records.
    pub(crate) fn plain(inner: T) -> Self {
        Self {
            inner: Some(inner),
            pending: SelectAll::new(),
        }
    }

    /// A connection that also gets `records`.
    pub(crate) fn with(inner: T, records: BoxStream<'static, Frame>) -> Self {
        let mut pending = SelectAll::new();
        pending.push(records);
        Self {
            inner: Some(inner),
            pending,
        }
    }

    /// A connection of `records` alone, with no socket. It ends when they all do.
    pub(crate) fn alone(records: impl IntoIterator<Item = BoxStream<'static, Frame>>) -> Self {
        Self {
            inner: None,
            pending: records.into_iter().collect(),
        }
    }
}

impl<T: Transport> Transport for RestTransport<T> {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        let Some(inner) = self.inner.as_mut() else {
            return Ok(self.pending.next().await);
        };
        if self.pending.is_empty() {
            return inner.recv().await;
        }
        // Both arms are cancel-safe: the socket's `recv` is, and a pending read
        // stays in the set until it completes. The session times out a silent
        // socket, because a REST record does not count as its frame.
        tokio::select! {
            Some(frame) = self.pending.next() => Ok(Some(frame)),
            result = inner.recv() => result,
        }
    }

    async fn send_text(&mut self, text: String) -> Result<(), TransportError> {
        match self.inner.as_mut() {
            Some(inner) => inner.send_text(text).await,
            None => Err(TransportError::Send(
                "the connection has no socket".to_owned(),
            )),
        }
    }

    async fn send_ping(&mut self) -> Result<(), TransportError> {
        match self.inner.as_mut() {
            Some(inner) => inner.send_ping().await,
            // A probe has no peer here. Only the records show that the
            // connection lives, and the idle timeout ends it when they stop.
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contracts_keep_only_plain_names() {
        assert_eq!(
            contracts_of("contracts=XBTUSDTM,BTC_USDT,../x,ETH%2FM"),
            ["XBTUSDTM", "BTC_USDT"]
        );
        assert!(contracts_of("other=1").is_empty());
    }

    #[test]
    fn retry_after_counts_only_whole_seconds() {
        let after = |value: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(RETRY_AFTER, value.parse().expect("a header value"));
            retry_after(&headers)
        };
        assert_eq!(after("120"), Some(Duration::from_secs(120)));
        assert_eq!(after(" 5 "), Some(Duration::from_secs(5)));
        assert_eq!(after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(retry_after(&HeaderMap::new()), None);
    }

    #[test]
    fn a_url_carries_its_contracts() {
        let url = with_contracts(
            "https://x.example/depth",
            ["ICPUSDT", "ETHUSDT"].into_iter(),
        );
        assert_eq!(url, "https://x.example/depth?contracts=ICPUSDT,ETHUSDT");
        let (_, query) = url.split_once('?').expect("a query");
        assert_eq!(contracts_of(query), ["ICPUSDT", "ETHUSDT"]);
    }

    #[tokio::test]
    async fn a_connection_of_records_alone_has_no_socket() {
        let records = stream::iter([Frame::Rest("a".to_owned())]).boxed();
        let mut conn = RestTransport::<crate::testing::ScriptedConn>::alone([records]);
        assert_eq!(conn.recv().await, Ok(Some(Frame::Rest("a".to_owned()))));
        assert_eq!(conn.recv().await, Ok(None), "it ends with its records");
        assert_eq!(conn.send_ping().await, Ok(()));
        assert!(conn.send_text("x".to_owned()).await.is_err());
    }

    #[test]
    fn a_record_frame_holds_its_data_or_its_error() {
        let data = RawValue::from_string(r#"{"value":0.0001}"#.to_owned()).expect("json");
        let Frame::Rest(text) = frame("funding.current", "XBTUSDTM", Ok(data)) else {
            panic!("a REST frame");
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("json");
        let field = |name: &str| parsed.get(name).and_then(serde_json::Value::as_str);
        assert_eq!(field("type"), Some("rest"));
        assert_eq!(field("subject"), Some("funding.current"));
        assert_eq!(field("topic"), Some("/rest:XBTUSDTM"));
        assert!(text.contains(r#""data":{"value":0.0001}"#), "{text}");
        let Frame::Rest(text) = frame("contract", "XBTUSDTM", Err("timeout".to_owned())) else {
            panic!("a REST frame");
        };
        assert!(text.contains(r#""error":"timeout""#), "{text}");
    }
}
