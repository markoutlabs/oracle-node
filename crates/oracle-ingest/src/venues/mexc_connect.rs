//! MEXC's futures socket sends a perpetual's funding rate and next funding time,
//! but not its interval or its last settled rate; those come only over REST.
//!
//! [`MexcConnector`] takes the futures socket URL with its contracts,
//! `wss://contract.mexc.com/edge?contracts=BTC_USDT,ETH_USDT`. It opens the
//! socket without the query, and adds each contract's REST records as frames
//! (see [`super::rest_frames`]): `"subject":"funding.current"` from
//! `funding_rate/{symbol}` and `"subject":"funding.last"` from the newest row
//! of `funding_rate/history`. Any other URL passes through.

use std::time::Duration;

use serde::Deserialize;
use serde_json::value::RawValue;

use super::rest_frames::{self, Read, RestTransport};
use crate::transport::{Connector, TransportError};

/// The futures socket.
pub const FUTURES_URL: &str = "wss://contract.mexc.com/edge";

const FUTURES_REST: &str = "https://contract.mexc.com";

/// Each contract's two records once in this period: under 2 requests a second
/// for 50 contracts, of MEXC's 20 each 2 s.
const CONTRACTS_EVERY: Duration = Duration::from_secs(60);

/// The futures socket URL for a set of contracts.
#[must_use]
pub fn futures_url<'a>(contracts: impl Iterator<Item = &'a str>) -> String {
    let contracts: Vec<&str> = contracts.collect();
    format!("{FUTURES_URL}?contracts={}", contracts.join(","))
}

/// Wraps a connector: it opens MEXC's futures socket and adds the REST records
/// of its contracts. Any other URL passes through.
#[derive(Clone)]
pub struct MexcConnector<C> {
    inner: C,
    client: reqwest::Client,
}

impl<C> MexcConnector<C> {
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

impl<C: Connector> Connector for MexcConnector<C> {
    type Conn = RestTransport<C::Conn>;

    async fn connect(&self, url: &str) -> Result<Self::Conn, TransportError> {
        let (base, query) = url.split_once('?').unwrap_or((url, ""));
        if base != FUTURES_URL {
            return Ok(RestTransport::plain(self.inner.connect(url).await?));
        }
        let inner = self.inner.connect(base).await?;
        let contracts = rest_frames::contracts_of(query);
        if contracts.is_empty() {
            return Ok(RestTransport::plain(inner));
        }
        let reads: Vec<Read> = contracts
            .iter()
            .flat_map(|contract| {
                [
                    (
                        contract.clone(),
                        "funding.current",
                        format!("{FUTURES_REST}/api/v1/contract/funding_rate/{contract}"),
                    ),
                    (
                        contract.clone(),
                        "funding.last",
                        format!(
                            "{FUTURES_REST}/api/v1/contract/funding_rate/history?symbol={contract}&page_num=1&page_size=1"
                        ),
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
    success: bool,
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<Box<RawValue>>,
}

/// The `data` of a successful MEXC reply.
fn data_of(body: &[u8]) -> Result<Box<RawValue>, String> {
    let reply: Reply = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    if !reply.success || reply.code != 0 {
        return Err(format!(
            "code {}: {}",
            reply.code,
            reply.message.unwrap_or_default()
        ));
    }
    reply.data.ok_or_else(|| "no data in the reply".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_futures_url_carries_its_contracts() {
        let url = futures_url(["BTC_USDT", "ETH_USDT"].into_iter());
        assert_eq!(
            url,
            "wss://contract.mexc.com/edge?contracts=BTC_USDT,ETH_USDT"
        );
        let (_, query) = url.split_once('?').expect("a query");
        assert_eq!(rest_frames::contracts_of(query), ["BTC_USDT", "ETH_USDT"]);
    }

    #[test]
    fn only_a_success_gives_data() {
        assert!(data_of(br#"{"success":true,"code":0,"data":{"a":1}}"#).is_ok());
        assert!(data_of(br#"{"success":false,"code":1001,"message":"bad"}"#).is_err());
        assert!(data_of(br#"{"success":true,"code":0}"#).is_err());
    }
}
