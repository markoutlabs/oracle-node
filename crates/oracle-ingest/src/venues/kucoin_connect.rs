//! KuCoin's sockets open with a token from a REST call, and a perpetual's
//! funding interval, next funding time and last settled rate come only over REST.
//!
//! [`KucoinConnector`] takes a KuCoin token URL in place of a socket URL. It
//! asks for a token, checks the endpoint that comes back, and opens the socket
//! there. A futures URL names its contracts, `?contracts=XBTUSDTM,ETHUSDTM`, and
//! that connection also gets each contract's REST records as frames,
//! `{"type":"rest","subject":"funding.current","topic":"/rest:XBTUSDTM","data":{…}}`
//! and the same with `"subject":"contract"`. The contracts take turns, so the
//! list comes round once a minute. A failed read is a frame with `error` in
//! place of `data`. The connector sits under the recorder, so a recording holds
//! these frames, and a replay never calls REST.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_util::stream::{self, BoxStream, SelectAll, StreamExt as _};
use serde::Deserialize;
use serde_json::value::RawValue;
use tracing::warn;

use crate::transport::{Connector, Frame, Transport, TransportError};

/// The token endpoint of the spot socket.
pub const SPOT_TOKEN: &str = "https://api.kucoin.com/api/v1/bullet-public";

/// The token endpoint of the futures socket.
pub const FUTURES_TOKEN: &str = "https://api-futures.kucoin.com/api/v1/bullet-public";

const FUTURES_REST: &str = "https://api-futures.kucoin.com";

/// KuCoin's success code.
const OK: &str = "200000";

const TIMEOUT: Duration = Duration::from_secs(10);

/// Each contract's two records once in this period: about 2 requests a second
/// for 50 contracts.
const CONTRACTS_EVERY: Duration = Duration::from_secs(60);

/// A token or one contract's record is a few kilobytes.
const MAX_BODY: usize = 256 * 1024;

/// Numbers each connection, so that KuCoin's `connectId` differs between them.
static CONNECTIONS: AtomicU64 = AtomicU64::new(0);

/// The futures token URL for a set of contracts.
#[must_use]
pub fn futures_url<'a>(contracts: impl Iterator<Item = &'a str>) -> String {
    let contracts: Vec<&str> = contracts.collect();
    format!("{FUTURES_TOKEN}?contracts={}", contracts.join(","))
}

/// Wraps a connector: it turns a KuCoin token URL into a socket, and adds the
/// REST records that a futures connection needs. Any other URL passes through.
#[derive(Clone)]
pub struct KucoinConnector<C> {
    inner: C,
    client: reqwest::Client,
}

impl<C> KucoinConnector<C> {
    /// Wraps `inner`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Connect`] if the HTTP client cannot be built,
    /// which means TLS is misconfigured in this binary.
    pub fn new(inner: C) -> Result<Self, TransportError> {
        // reqwest leaves the crypto provider to the binary; tungstenite already
        // brings `ring`.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        Ok(Self { inner, client })
    }
}

impl<C: Connector> Connector for KucoinConnector<C> {
    type Conn = KucoinTransport<C::Conn>;

    async fn connect(&self, url: &str) -> Result<Self::Conn, TransportError> {
        let (base, query) = url.split_once('?').unwrap_or((url, ""));
        if base != SPOT_TOKEN && base != FUTURES_TOKEN {
            return Ok(KucoinTransport {
                inner: self.inner.connect(url).await?,
                pending: SelectAll::new(),
            });
        }
        let socket = socket_url(&self.client, base).await?;
        let inner = self.inner.connect(&socket).await?;
        let mut pending = SelectAll::new();
        let contracts = contracts_of(query);
        if base == FUTURES_TOKEN && !contracts.is_empty() {
            pending.push(records(self.client.clone(), contracts));
        }
        Ok(KucoinTransport { inner, pending })
    }
}

/// The contracts of a futures token URL's query. A name that is not plain
/// letters and digits is left out, as it goes into a REST path.
fn contracts_of(query: &str) -> Vec<String> {
    query
        .split('&')
        .filter_map(|pair| pair.strip_prefix("contracts="))
        .flat_map(|list| list.split(','))
        .filter(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(str::to_owned)
        .collect()
}

#[derive(Deserialize)]
struct Reply {
    code: String,
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    data: Option<Box<RawValue>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Token {
    token: String,
    instance_servers: Vec<Server>,
}

#[derive(Deserialize)]
struct Server {
    endpoint: String,
}

/// Asks `token_url` for a token, and gives the socket URL with it.
async fn socket_url(client: &reqwest::Client, token_url: &str) -> Result<String, TransportError> {
    let failed = |error: String| TransportError::Connect(format!("kucoin token: {error}"));
    let data = read(client.post(token_url)).await.map_err(failed)?;
    let token: Token = serde_json::from_str(data.get()).map_err(|e| failed(e.to_string()))?;
    let server = token
        .instance_servers
        .first()
        .ok_or_else(|| failed("no server in the reply".to_owned()))?;
    let mut url = endpoint(&server.endpoint).map_err(failed)?;
    let id = CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    url.query_pairs_mut()
        .append_pair("token", &token.token)
        .append_pair("connectId", &format!("oracle-{id}"));
    Ok(url.into())
}

/// The endpoint that a token reply names, if it is a `wss` host of KuCoin's.
/// The token goes to that host, so a reply must not choose an arbitrary one.
fn endpoint(text: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(text).map_err(|e| e.to_string())?;
    let host = url.host_str().unwrap_or_default();
    let kucoin = host == "kucoin.com" || host.ends_with(".kucoin.com");
    if url.scheme() != "wss" || !kucoin || url.query().is_some() {
        return Err(format!("unexpected endpoint {text}"));
    }
    Ok(url)
}

/// Sends a request, and gives the `data` of a successful KuCoin reply.
async fn read(request: reqwest::RequestBuilder) -> Result<Box<RawValue>, String> {
    let response = request
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| e.to_string())?;
    if response
        .content_length()
        .is_some_and(|length| usize::try_from(length).map_or(true, |length| length > MAX_BODY))
    {
        return Err("the reply is too large".to_owned());
    }
    let body = response.bytes().await.map_err(|e| e.to_string())?;
    if body.len() > MAX_BODY {
        return Err("the reply is too large".to_owned());
    }
    let reply: Reply = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    if reply.code != OK {
        return Err(format!(
            "code {}: {}",
            reply.code,
            reply.msg.unwrap_or_default()
        ));
    }
    reply.data.ok_or_else(|| "no data in the reply".to_owned())
}

/// The two REST records of each contract in turn, spread over
/// [`CONTRACTS_EVERY`], with the first records at once.
fn records(client: reqwest::Client, contracts: Vec<String>) -> BoxStream<'static, Frame> {
    let steps = contracts.len().saturating_mul(2).max(1);
    let wait = CONTRACTS_EVERY / u32::try_from(steps).unwrap_or(u32::MAX);
    stream::unfold(0_usize, move |step| {
        let client = client.clone();
        let contract = contracts.get(step / 2).cloned();
        async move {
            let contract = contract?;
            if step >= 2 {
                tokio::time::sleep(wait).await;
            }
            let (subject, path) = if step % 2 == 0 {
                (
                    "funding.current",
                    format!("/api/v1/funding-rate/{contract}/current"),
                )
            } else {
                ("contract", format!("/api/v1/contracts/{contract}"))
            };
            let fetched = read(client.get(format!("{FUTURES_REST}{path}"))).await;
            if let Err(error) = &fetched {
                warn!(%contract, %error, "a KuCoin contract record could not be read");
            }
            Some((frame(subject, &contract, fetched), (step + 1) % steps))
        }
    })
    .boxed()
}

/// A REST record as a frame: `data`, or `error` when the read failed.
fn frame(subject: &str, contract: &str, fetched: Result<Box<RawValue>, String>) -> Frame {
    let topic = format!("/rest:{contract}");
    let text = match fetched {
        Ok(data) => {
            serde_json::json!({ "type": "rest", "subject": subject, "topic": topic, "data": data })
        }
        Err(error) => {
            serde_json::json!({ "type": "rest", "subject": subject, "topic": topic, "error": error })
        }
    };
    Frame::Text(text.to_string())
}

/// A KuCoin connection whose REST records arrive among its frames.
pub struct KucoinTransport<T> {
    inner: T,
    pending: SelectAll<BoxStream<'static, Frame>>,
}

impl<T: Transport> Transport for KucoinTransport<T> {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        if self.pending.is_empty() {
            return self.inner.recv().await;
        }
        // Both arms are cancel-safe: the socket's `recv` is, and a pending read
        // stays in the set until it completes.
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
    fn a_token_reply_must_name_a_kucoin_wss_host() {
        assert!(endpoint("wss://ws-api-spot.kucoin.com/").is_ok());
        assert!(endpoint("wss://ws-api-futures.kucoin.com/").is_ok());
        for bad in [
            "ws://ws-api-spot.kucoin.com/",
            "wss://kucoin.com.example.org/",
            "wss://evilkucoin.com/",
            "https://ws-api-spot.kucoin.com/",
            "wss://ws-api-spot.kucoin.com/?token=x",
        ] {
            assert!(endpoint(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_futures_url_carries_its_contracts_and_drops_odd_names() {
        let url = futures_url(["XBTUSDTM", "ETHUSDTM"].into_iter());
        assert_eq!(
            url,
            "https://api-futures.kucoin.com/api/v1/bullet-public?contracts=XBTUSDTM,ETHUSDTM"
        );
        let (_, query) = url.split_once('?').expect("a query");
        assert_eq!(contracts_of(query), ["XBTUSDTM", "ETHUSDTM"]);
        assert_eq!(
            contracts_of("contracts=XBTUSDTM,../x,ETH%2FM"),
            ["XBTUSDTM"]
        );
    }

    #[test]
    fn a_record_frame_holds_its_data_or_its_error() {
        let data = RawValue::from_string(r#"{"value":0.0001}"#.to_owned()).expect("json");
        let Frame::Text(text) = frame("funding.current", "XBTUSDTM", Ok(data)) else {
            panic!("a text frame");
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("json");
        let field = |name: &str| parsed.get(name).and_then(serde_json::Value::as_str);
        assert_eq!(field("type"), Some("rest"));
        assert_eq!(field("subject"), Some("funding.current"));
        assert_eq!(field("topic"), Some("/rest:XBTUSDTM"));
        assert!(text.contains(r#""data":{"value":0.0001}"#), "{text}");
        let Frame::Text(text) = frame("contract", "XBTUSDTM", Err("timeout".to_owned())) else {
            panic!("a text frame");
        };
        assert!(text.contains(r#""error":"timeout""#), "{text}");
    }
}
