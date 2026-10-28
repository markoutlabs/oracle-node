//! REST records delivered as frames among a socket's frames, for the venues
//! whose socket leaves out what only REST gives, such as a perpetual's funding
//! interval (KuCoin, MEXC).
//!
//! A record is a frame `{"type":"rest","subject":"…","topic":"/rest:<contract>",
//! "data":{…}}`, or the same with `error` in place of `data` when the read
//! failed. A connector that adds them sits under the recorder, so a recording
//! holds them and a replay never calls REST.

use std::time::Duration;

use futures_util::stream::{self, BoxStream, SelectAll, StreamExt as _};
use serde_json::value::RawValue;
use tracing::warn;

use crate::transport::{Frame, Transport, TransportError};

const TIMEOUT: Duration = Duration::from_secs(10);

/// One contract's record is a few kilobytes.
const MAX_BODY: usize = 256 * 1024;

/// Takes the `data` of a venue's reply, or says why the reply failed.
pub(crate) type DataOf = fn(&[u8]) -> Result<Box<RawValue>, String>;

/// One REST read: the contract, the frame's subject, and the URL.
pub(crate) type Read = (String, &'static str, String);

/// An HTTP client that follows no redirect and gives up after 10 s.
pub(crate) fn client() -> Result<reqwest::Client, TransportError> {
    // reqwest leaves the crypto provider to the binary; tungstenite already
    // brings `ring`.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| TransportError::Connect(e.to_string()))
}

/// Sends a request, and gives the `data` of a successful reply.
pub(crate) async fn read(
    request: reqwest::RequestBuilder,
    data_of: DataOf,
) -> Result<Box<RawValue>, String> {
    let response = request
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| e.to_string())?;
    let too_large = |length: usize| length > MAX_BODY;
    if response
        .content_length()
        .is_some_and(|length| usize::try_from(length).map_or(true, too_large))
    {
        return Err("the reply is too large".to_owned());
    }
    let body = response.bytes().await.map_err(|e| e.to_string())?;
    if too_large(body.len()) {
        return Err("the reply is too large".to_owned());
    }
    data_of(&body)
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
            let fetched = read(client.get(url), data_of).await;
            if let Err(error) = &fetched {
                warn!(%contract, %error, "a contract record could not be read");
            }
            Some((frame(subject, &contract, fetched), n + 1))
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
    let topic = format!("/rest:{contract}");
    let text = match fetched {
        Ok(data) => {
            serde_json::json!({ "type": "rest", "subject": subject, "topic": topic, "data": data })
        }
        Err(error) => {
            serde_json::json!({ "type": "rest", "subject": subject, "topic": topic, "error": error })
        }
    };
    Frame::Rest(text.to_string())
}

/// A connection whose REST records arrive among its frames.
pub struct RestTransport<T> {
    inner: T,
    pending: SelectAll<BoxStream<'static, Frame>>,
}

impl<T> RestTransport<T> {
    /// A connection without records.
    pub(crate) fn plain(inner: T) -> Self {
        Self {
            inner,
            pending: SelectAll::new(),
        }
    }

    /// A connection that also gets `records`.
    pub(crate) fn with(inner: T, records: BoxStream<'static, Frame>) -> Self {
        let mut pending = SelectAll::new();
        pending.push(records);
        Self { inner, pending }
    }
}

impl<T: Transport> Transport for RestTransport<T> {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        if self.pending.is_empty() {
            return self.inner.recv().await;
        }
        // Both arms are cancel-safe: the socket's `recv` is, and a pending read
        // stays in the set until it completes. The session times out a silent
        // socket, because a REST record does not count as its frame.
        tokio::select! {
            Some(frame) = self.pending.next() => Ok(Some(frame)),
            result = self.inner.recv() => result,
        }
    }

    async fn send_text(&mut self, text: String) -> Result<(), TransportError> {
        self.inner.send_text(text).await
    }

    async fn send_ping(&mut self) -> Result<(), TransportError> {
        self.inner.send_ping().await
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
