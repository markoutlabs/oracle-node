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

use serde::Deserialize;
use serde_json::value::RawValue;

use super::rest_frames::{self, Read, RestTransport};
use crate::transport::{Connector, TransportError};

/// The token endpoint of the spot socket.
pub const SPOT_TOKEN: &str = "https://api.kucoin.com/api/v1/bullet-public";

/// The token endpoint of the futures socket.
pub const FUTURES_TOKEN: &str = "https://api-futures.kucoin.com/api/v1/bullet-public";

const FUTURES_REST: &str = "https://api-futures.kucoin.com";

/// KuCoin's success code.
const OK: &str = "200000";

/// Each contract's two records once in this period: about 2 requests a second
/// for 50 contracts.
const CONTRACTS_EVERY: Duration = Duration::from_secs(60);

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
        Ok(Self {
            inner,
            client: rest_frames::client()?,
        })
    }
}

impl<C: Connector> Connector for KucoinConnector<C> {
    type Conn = RestTransport<C::Conn>;

    async fn connect(&self, url: &str) -> Result<Self::Conn, TransportError> {
        let (base, query) = url.split_once('?').unwrap_or((url, ""));
        if base != SPOT_TOKEN && base != FUTURES_TOKEN {
            return Ok(RestTransport::plain(self.inner.connect(url).await?));
        }
        let socket = socket_url(&self.client, base).await?;
        let inner = self.inner.connect(&socket).await?;
        let contracts = rest_frames::contracts_of(query);
        if base != FUTURES_TOKEN || contracts.is_empty() {
            return Ok(RestTransport::plain(inner));
        }
        let reads: Vec<Read> = contracts
            .iter()
            .flat_map(|contract| {
                [
                    (
                        contract.clone(),
                        "funding.current",
                        format!("{FUTURES_REST}/api/v1/funding-rate/{contract}/current"),
                    ),
                    (
                        contract.clone(),
                        "contract",
                        format!("{FUTURES_REST}/api/v1/contracts/{contract}"),
                    ),
                ]
            })
            .collect();
        let records = rest_frames::records(self.client.clone(), reads, CONTRACTS_EVERY, data_of);
        Ok(RestTransport::with(inner, records))
    }
}

#[derive(Deserialize)]
struct Reply {
    code: String,
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    data: Option<Box<RawValue>>,
}

/// The `data` of a KuCoin reply whose code is a success.
fn data_of(body: &[u8]) -> Result<Box<RawValue>, String> {
    let reply: Reply = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    if reply.code != OK {
        return Err(format!(
            "code {}: {}",
            reply.code,
            reply.msg.unwrap_or_default()
        ));
    }
    reply.data.ok_or_else(|| "no data in the reply".to_owned())
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
    let data = rest_frames::read(client.post(token_url), data_of)
        .await
        .map_err(failed)?;
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
    fn a_futures_url_carries_its_contracts() {
        let url = futures_url(["XBTUSDTM", "ETHUSDTM"].into_iter());
        assert_eq!(
            url,
            "https://api-futures.kucoin.com/api/v1/bullet-public?contracts=XBTUSDTM,ETHUSDTM"
        );
        let (_, query) = url.split_once('?').expect("a query");
        assert_eq!(rest_frames::contracts_of(query), ["XBTUSDTM", "ETHUSDTM"]);
    }

    #[test]
    fn only_a_success_code_gives_data() {
        assert!(data_of(br#"{"code":"200000","data":{"a":1}}"#).is_ok());
        assert!(data_of(br#"{"code":"400100","msg":"bad"}"#).is_err());
        assert!(data_of(br#"{"code":"200000"}"#).is_err());
    }
}
