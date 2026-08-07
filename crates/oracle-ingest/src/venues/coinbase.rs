//! Coinbase Exchange public feed.
//!
//! Uses `ws-feed.exchange.coinbase.com` rather than the Advanced Trade endpoint,
//! which now requires a JWT that has to be minted and refreshed. This feed is
//! public, and market data does not need an identity.
//!
//! One `ticker` message carries both a trade print and the top of book, so a
//! single channel gives everything the aggregator needs.
//!
//! **Coinbase quotes natively in USD.** With Kraken it is one of only two such
//! venues in scope, which makes losing both a distinct failure class rather than
//! just "two of five sources down" — every stablecoin-quoted price then has no
//! peg to convert through.

use oracle_types::{Fixed, ObsKind, Observation};
use serde::Deserialize;

use crate::{DecodeError, InstrumentMap};

use super::{decimal, rfc3339_to_unix_nanos};

/// The public endpoint.
pub const URL: &str = "wss://ws-feed.exchange.coinbase.com";

/// Builds the subscribe frame for a set of product ids.
#[must_use]
pub fn subscribe_frame<'a>(product_ids: impl Iterator<Item = &'a str>) -> String {
    let products: Vec<&str> = product_ids.collect();
    serde_json::json!({
        "type": "subscribe",
        "product_ids": products,
        "channels": ["ticker"],
    })
    .to_string()
}

#[derive(Deserialize)]
struct Message<'a> {
    #[serde(rename = "type", borrow)]
    kind: &'a str,
    #[serde(rename = "product_id", borrow, default)]
    product_id: Option<&'a str>,
    #[serde(borrow, default)]
    price: Option<&'a str>,
    #[serde(rename = "best_bid", borrow, default)]
    best_bid: Option<&'a str>,
    #[serde(rename = "best_bid_size", borrow, default)]
    best_bid_size: Option<&'a str>,
    #[serde(rename = "best_ask", borrow, default)]
    best_ask: Option<&'a str>,
    #[serde(rename = "best_ask_size", borrow, default)]
    best_ask_size: Option<&'a str>,
    #[serde(borrow, default)]
    time: Option<&'a str>,
    #[serde(default)]
    sequence: Option<u64>,
}

/// Decodes one Coinbase payload.
///
/// A `ticker` yields up to two observations: the book, and the trade that
/// triggered it.
///
/// # Errors
///
/// Returns [`DecodeError`]. Subscription confirmations and heartbeats are benign.
pub fn decode_payload(
    payload: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let message: Message<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;

    if message.kind == "error" {
        // Surfaced as malformed rather than benign: a subscribe that Coinbase
        // rejected is a configuration problem worth seeing in the counters.
        return Err(DecodeError::Malformed(
            "coinbase rejected a request".to_owned(),
        ));
    }
    if message.kind != "ticker" {
        return Err(DecodeError::Control);
    }

    let product_id = message
        .product_id
        .ok_or(DecodeError::MissingField("product_id"))?;
    let entry = map
        .lookup(product_id)
        .ok_or_else(|| DecodeError::UnknownInstrument(product_id.to_owned()))?;
    let exchange_time_ns = message.time.and_then(rfc3339_to_unix_nanos);

    if let (Some(bid), Some(bid_size), Some(ask), Some(ask_size)) = (
        message.best_bid,
        message.best_bid_size,
        message.best_ask,
        message.best_ask_size,
    ) {
        let bid = decimal("best_bid", bid)?;
        let ask = decimal("best_ask", ask)?;
        let mid = bid
            .checked_add(ask)
            .and_then(|sum| sum.checked_div(Fixed::from_int(2).ok()?))
            .unwrap_or(bid);
        out.push(Observation {
            instrument: entry.instrument.clone(),
            kind: ObsKind::BookTop,
            price: mid,
            bid: Some(bid),
            ask: Some(ask),
            bid_qty: Some(decimal("best_bid_size", bid_size)?),
            ask_qty: Some(decimal("best_ask_size", ask_size)?),
            depth_notional_1bp: None,
            exchange_time_ns,
            local_recv_ns,
            seq: message.sequence,
        });
    }

    if let Some(price) = message.price {
        out.push(Observation {
            instrument: entry.instrument.clone(),
            kind: ObsKind::Trade,
            price: decimal("price", price)?,
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            depth_notional_1bp: None,
            exchange_time_ns,
            local_recv_ns,
            seq: message.sequence,
        });
    }

    if out.is_empty() {
        Err(DecodeError::Control)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixtures are fixed-shape; an out-of-range index is a failing test, \
              which is exactly what should happen if decoding changed"
)]
mod tests {
    use super::*;
    use crate::InstrumentSpec;
    use oracle_types::{MarketKind, Venue};

    const RECV: u64 = 1_754_582_400_500_000_000;

    fn map() -> InstrumentMap {
        let specs = vec![
            InstrumentSpec::new("BTC-USD", MarketKind::Spot, "CRYPTO.BTC/USD").expect("valid"),
        ];
        InstrumentMap::new(Venue::Coinbase, MarketKind::Spot, &specs).expect("valid")
    }

    fn decode(payload: &str) -> Vec<Observation> {
        let mut out = Vec::new();
        decode_payload(payload.as_bytes(), &map(), RECV, &mut out).expect("decodes");
        out
    }

    const TICKER: &str = r#"{"type":"ticker","sequence":12345,"product_id":"BTC-USD",
        "price":"64312.10","open_24h":"63000","volume_24h":"100","low_24h":"62000",
        "high_24h":"65000","volume_30d":"3000","best_bid":"64312.00",
        "best_bid_size":"0.50000000","best_ask":"64313.00","best_ask_size":"0.25000000",
        "side":"buy","time":"2026-08-07T16:00:00.123456Z","trade_id":999,
        "last_size":"0.01"}"#;

    #[test]
    fn a_ticker_yields_both_a_book_and_a_trade() {
        let observations = decode(TICKER);
        assert_eq!(observations.len(), 2, "one channel gives both");
        let kinds: Vec<_> = observations.iter().map(|o| o.kind).collect();
        assert_eq!(kinds, [ObsKind::BookTop, ObsKind::Trade]);

        let book = &observations[0];
        assert_eq!(book.bid, Some("64312".parse().expect("valid")));
        assert_eq!(book.ask, Some("64313".parse().expect("valid")));
        assert_eq!(book.price, "64312.5".parse().expect("valid"));
        assert_eq!(book.seq, Some(12_345));

        let trade = &observations[1];
        assert_eq!(trade.price, "64312.1".parse().expect("valid"));
        assert!(trade.bid.is_none());
    }

    #[test]
    fn the_rfc3339_timestamp_is_parsed() {
        let observations = decode(TICKER);
        // 2026-08-07T16:00:00.123456Z
        assert_eq!(
            observations[0].exchange_time_ns,
            Some(1_786_118_400 * 1_000_000_000 + 123_456_000)
        );
    }

    #[test]
    fn a_ticker_without_a_book_still_yields_the_trade() {
        let no_book = r#"{"type":"ticker","product_id":"BTC-USD","price":"64312.10",
            "time":"2026-08-07T16:00:00Z"}"#;
        let observations = decode(no_book);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].kind, ObsKind::Trade);
    }

    #[test]
    fn subscriptions_and_heartbeats_are_benign() {
        let mut out = Vec::new();
        for control in [
            r#"{"type":"subscriptions","channels":[{"name":"ticker","product_ids":["BTC-USD"]}]}"#,
            r#"{"type":"heartbeat","sequence":1,"last_trade_id":1,"product_id":"BTC-USD","time":"2026-08-07T16:00:00Z"}"#,
        ] {
            let error = decode_payload(control.as_bytes(), &map(), RECV, &mut out)
                .expect_err("not market data");
            assert!(error.is_benign(), "got {error:?}");
        }
        assert!(out.is_empty());
    }

    /// A rejected subscribe is a configuration problem, not routine traffic.
    #[test]
    fn an_error_message_is_not_benign() {
        let mut out = Vec::new();
        let error = decode_payload(
            br#"{"type":"error","message":"Failed to subscribe","reason":"nope"}"#,
            &map(),
            RECV,
            &mut out,
        )
        .expect_err("an error");
        assert!(!error.is_benign(), "a rejected subscribe must be visible");
    }

    #[test]
    fn untracked_products_are_benign() {
        let other = TICKER.replace("BTC-USD", "ETH-USD");
        let mut out = Vec::new();
        let error =
            decode_payload(other.as_bytes(), &map(), RECV, &mut out).expect_err("untracked");
        assert!(error.is_benign());
    }

    #[test]
    fn the_subscribe_frame_names_the_ticker_channel() {
        let frame = subscribe_frame(["BTC-USD", "ETH-USD"].into_iter());
        assert!(frame.contains(r#""type":"subscribe""#));
        assert!(frame.contains("BTC-USD"));
        assert!(frame.contains(r#""ticker""#));
    }
}
