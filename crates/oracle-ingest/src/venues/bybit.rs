//! Bybit v5 public streams.
//!
//! - Spot and linear perpetuals live on **different hosts** and fail
//!   independently, so they get separate connections.
//! - Requires an application keepalive, `{"op":"ping"}`, roughly every 20s. A
//!   WebSocket ping is not enough.
//! - `tickers` on linear sends a **snapshot then deltas**: after the first
//!   message, fields that did not change are absent. Every numeric field is
//!   therefore optional, and a missing one means "unchanged", not "zero".

use std::time::Duration;

use oracle_types::{MarketKind, ObsKind, Observation};
use serde::Deserialize;

use crate::clock::millis_to_nanos;
use crate::{DecodeError, InstrumentMap};

use super::decimal;

/// Spot endpoint.
pub const SPOT_URL: &str = "wss://stream.bybit.com/v5/public/spot";
/// Linear perpetual endpoint.
pub const LINEAR_URL: &str = "wss://stream.bybit.com/v5/public/linear";
/// Inverse (coin-margined) perpetual endpoint.
///
/// Carries the same `tickers` shape as linear, so the decoder is unchanged; only
/// the host and the size units differ.
pub const INVERSE_URL: &str = "wss://stream.bybit.com/v5/public/inverse";

/// Keepalive period. Bybit drops connections idle for 30s.
pub const KEEPALIVE: Duration = Duration::from_secs(20);

/// The keepalive payload.
pub const KEEPALIVE_PAYLOAD: &str = r#"{"op":"ping"}"#;

/// Returns the endpoint for a market.
#[must_use]
pub const fn url(market: MarketKind) -> &'static str {
    match market {
        MarketKind::Spot => SPOT_URL,
        MarketKind::LinearPerp => LINEAR_URL,
        MarketKind::InversePerp => INVERSE_URL,
    }
}

/// Builds the subscribe frames for a market's instruments.
///
/// Chunked because Bybit caps arguments per request; separate frames on one
/// connection are cheaper than separate connections.
#[must_use]
pub fn subscribe_frames<'a>(
    symbols: impl Iterator<Item = &'a str>,
    market: MarketKind,
    chunk: usize,
) -> Vec<String> {
    let mut topics: Vec<String> = Vec::new();
    for symbol in symbols {
        topics.push(format!("orderbook.1.{symbol}"));
        topics.push(format!("publicTrade.{symbol}"));
        // `tickers` is where mark, index and funding live, and only perpetuals
        // have them — on spot it would be a throttled duplicate of the book.
        if market.is_perp() {
            topics.push(format!("tickers.{symbol}"));
        }
    }
    topics.sort_unstable();
    topics
        .chunks(chunk.max(1))
        .map(|group| serde_json::json!({ "op": "subscribe", "args": group }).to_string())
        .collect()
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow, default)]
    topic: Option<&'a str>,
    #[serde(default)]
    ts: Option<u64>,
    #[serde(borrow, default)]
    data: Option<&'a serde_json::value::RawValue>,
}

/// `orderbook.1`: one level each side, as `[price, size]` pairs.
#[derive(Deserialize)]
struct OrderBook<'a> {
    #[serde(rename = "s", borrow)]
    symbol: &'a str,
    #[serde(rename = "b", borrow, default)]
    bids: Vec<Vec<&'a str>>,
    #[serde(rename = "a", borrow, default)]
    asks: Vec<Vec<&'a str>>,
    #[serde(rename = "u", default)]
    update_id: Option<u64>,
}

#[derive(Deserialize)]
struct Trade<'a> {
    #[serde(rename = "T")]
    time_ms: u64,
    #[serde(rename = "s", borrow)]
    symbol: &'a str,
    #[serde(rename = "p", borrow)]
    price: &'a str,
}

#[derive(Deserialize)]
struct Ticker<'a> {
    #[serde(borrow)]
    symbol: &'a str,
    #[serde(rename = "markPrice", borrow, default)]
    mark_price: Option<&'a str>,
    #[serde(rename = "indexPrice", borrow, default)]
    index_price: Option<&'a str>,
    #[serde(rename = "fundingRate", borrow, default)]
    funding_rate: Option<&'a str>,
}

/// Decodes one Bybit payload.
///
/// # Errors
///
/// Returns [`DecodeError`]. Check [`DecodeError::is_benign`]: subscription
/// acknowledgements and pong replies arrive constantly.
pub fn decode_payload(
    payload: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let (Some(topic), Some(data)) = (envelope.topic, envelope.data) else {
        // Subscribe acknowledgements and pongs carry `op`, not `topic`.
        return Err(DecodeError::Control);
    };
    let data = data.get().as_bytes();

    if let Some(rest) = topic.strip_prefix("orderbook.") {
        // `orderbook.1.BTCUSDT`: skip the depth segment.
        let _ = rest;
        return decode_book(data, map, local_recv_ns, out);
    }
    if topic.starts_with("publicTrade.") {
        return decode_trades(data, map, local_recv_ns, out);
    }
    if topic.starts_with("tickers.") {
        return decode_ticker(data, map, envelope.ts, local_recv_ns, out);
    }
    Err(DecodeError::UnhandledStream(topic.to_owned()))
}

fn decode_book(
    data: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let book: OrderBook<'_> =
        serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let entry = map
        .lookup(book.symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(book.symbol.to_owned()))?;

    // A delta that removed a level leaves the side empty. That is not a quote.
    let (Some(bid_level), Some(ask_level)) = (book.bids.first(), book.asks.first()) else {
        return Err(DecodeError::Control);
    };
    let (Some(bid), Some(bid_qty)) = (bid_level.first(), bid_level.get(1)) else {
        return Err(DecodeError::MissingField("b"));
    };
    let (Some(ask), Some(ask_qty)) = (ask_level.first(), ask_level.get(1)) else {
        return Err(DecodeError::MissingField("a"));
    };

    let bid = decimal("b", bid)?;
    let ask = decimal("a", ask)?;
    let mid = bid
        .checked_add(ask)
        .and_then(|sum| sum.checked_div(oracle_types::Fixed::from_int(2).ok()?))
        .unwrap_or(bid);

    out.push(Observation {
        instrument: entry.instrument.clone(),
        kind: ObsKind::BookTop,
        price: mid,
        bid: Some(bid),
        ask: Some(ask),
        bid_qty: Some(decimal("b_qty", bid_qty)?),
        ask_qty: Some(decimal("a_qty", ask_qty)?),
        depth_notional_1bp: None,
        // `orderbook.1` carries no per-message timestamp of its own; the
        // envelope's `ts` is the publish time, not the book time.
        exchange_time_ns: None,
        local_recv_ns,
        seq: book.update_id,
    });
    Ok(())
}

fn decode_trades(
    data: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let trades: Vec<Trade<'_>> =
        serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let mut seen = false;
    for trade in trades {
        let Some(entry) = map.lookup(trade.symbol) else {
            continue;
        };
        seen = true;
        out.push(Observation {
            instrument: entry.instrument.clone(),
            kind: ObsKind::Trade,
            price: decimal("p", trade.price)?,
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            depth_notional_1bp: None,
            exchange_time_ns: Some(millis_to_nanos(trade.time_ms)),
            local_recv_ns,
            seq: None,
        });
    }
    if seen {
        Ok(())
    } else {
        Err(DecodeError::Control)
    }
}

fn decode_ticker(
    data: &[u8],
    map: &InstrumentMap,
    ts: Option<u64>,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let ticker: Ticker<'_> =
        serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let entry = map
        .lookup(ticker.symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(ticker.symbol.to_owned()))?;

    let exchange_time_ns = ts.map(millis_to_nanos);
    let mut push = |kind: ObsKind, price: oracle_types::Fixed| {
        out.push(Observation {
            instrument: entry.instrument.clone(),
            kind,
            price,
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            depth_notional_1bp: None,
            exchange_time_ns,
            local_recv_ns,
            seq: None,
        });
    };

    // Deltas omit unchanged fields. Absent means unchanged, not zero.
    let mut emitted = false;
    if let Some(mark) = ticker.mark_price {
        push(ObsKind::MarkPrice, decimal("markPrice", mark)?);
        emitted = true;
    }
    if let Some(index) = ticker.index_price {
        push(ObsKind::IndexPrice, decimal("indexPrice", index)?);
        emitted = true;
    }
    if let Some(rate) = ticker.funding_rate {
        push(ObsKind::Funding, decimal("fundingRate", rate)?);
        emitted = true;
    }
    if emitted {
        Ok(())
    } else {
        Err(DecodeError::Control)
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
    use oracle_types::Venue;

    const RECV: u64 = 1_754_582_400_500_000_000;

    fn map(market: MarketKind) -> InstrumentMap {
        let specs = vec![InstrumentSpec::new("BTCUSDT", market, "CRYPTO.BTC/USDT").expect("valid")];
        InstrumentMap::new(Venue::Bybit, market, &specs).expect("valid")
    }

    fn decode(payload: &str, market: MarketKind) -> Vec<Observation> {
        let mut out = Vec::new();
        decode_payload(payload.as_bytes(), &map(market), RECV, &mut out).expect("decodes");
        out
    }

    const BOOK: &str = r#"{"topic":"orderbook.1.BTCUSDT","type":"snapshot","ts":1754582400123,
        "data":{"s":"BTCUSDT","b":[["64312.00","0.500"]],"a":[["64313.00","0.250"]],
        "u":18521288,"seq":7961638724},"cts":1754582400120}"#;

    const TRADE: &str = r#"{"topic":"publicTrade.BTCUSDT","type":"snapshot","ts":1754582400123,
        "data":[{"T":1754582400100,"s":"BTCUSDT","S":"Buy","v":"0.001","p":"64312.10",
        "L":"PlusTick","i":"abc","BT":false}]}"#;

    const TICKER: &str = r#"{"topic":"tickers.BTCUSDT","type":"snapshot","ts":1754582400123,
        "data":{"symbol":"BTCUSDT","lastPrice":"64312.00","indexPrice":"64310.00",
        "markPrice":"64315.00","fundingRate":"0.0001"}}"#;

    #[test]
    fn a_book_yields_a_two_sided_quote() {
        let observations = decode(BOOK, MarketKind::Spot);
        let obs = observations.first().expect("one observation");
        assert_eq!(obs.kind, ObsKind::BookTop);
        assert_eq!(obs.bid, Some("64312".parse().expect("valid")));
        assert_eq!(obs.ask, Some("64313".parse().expect("valid")));
        assert_eq!(obs.bid_qty, Some("0.5".parse().expect("valid")));
        assert_eq!(obs.price, "64312.5".parse().expect("valid"));
        assert_eq!(obs.seq, Some(18_521_288));
        assert_eq!(obs.local_recv_ns, RECV);
    }

    #[test]
    fn a_trade_uses_its_own_timestamp() {
        let observations = decode(TRADE, MarketKind::Spot);
        let obs = observations.first().expect("one observation");
        assert_eq!(obs.kind, ObsKind::Trade);
        assert_eq!(obs.price, "64312.1".parse().expect("valid"));
        assert_eq!(obs.exchange_time_ns, Some(1_754_582_400_100_000_000));
    }

    #[test]
    fn a_ticker_yields_mark_index_and_funding() {
        let observations = decode(TICKER, MarketKind::LinearPerp);
        let kinds: Vec<_> = observations.iter().map(|o| o.kind).collect();
        assert_eq!(
            kinds,
            [ObsKind::MarkPrice, ObsKind::IndexPrice, ObsKind::Funding]
        );
        assert_eq!(observations[0].price, "64315".parse().expect("valid"));
    }

    /// After the first snapshot, `tickers` sends only what changed.
    #[test]
    fn a_ticker_delta_emits_only_the_fields_present() {
        let delta = r#"{"topic":"tickers.BTCUSDT","type":"delta","ts":1754582400123,
            "data":{"symbol":"BTCUSDT","markPrice":"64320.00"}}"#;
        let observations = decode(delta, MarketKind::LinearPerp);
        assert_eq!(observations.len(), 1, "absent means unchanged, not zero");
        assert_eq!(observations[0].kind, ObsKind::MarkPrice);
    }

    #[test]
    fn a_ticker_delta_with_nothing_we_track_is_benign() {
        let delta = r#"{"topic":"tickers.BTCUSDT","type":"delta","ts":1,
            "data":{"symbol":"BTCUSDT","volume24h":"123"}}"#;
        let mut out = Vec::new();
        let error = decode_payload(
            delta.as_bytes(),
            &map(MarketKind::LinearPerp),
            RECV,
            &mut out,
        )
        .expect_err("nothing to emit");
        assert!(error.is_benign());
        assert!(out.is_empty());
    }

    #[test]
    fn an_empty_book_side_is_benign_not_a_quote() {
        let emptied = r#"{"topic":"orderbook.1.BTCUSDT","type":"delta","ts":1,
            "data":{"s":"BTCUSDT","b":[],"a":[["64313.00","0.250"]],"u":2}}"#;
        let mut out = Vec::new();
        let error = decode_payload(emptied.as_bytes(), &map(MarketKind::Spot), RECV, &mut out)
            .expect_err("not a quote");
        assert!(error.is_benign());
        assert!(out.is_empty());
    }

    #[test]
    fn acknowledgements_and_pongs_are_benign() {
        let mut out = Vec::new();
        for control in [
            r#"{"success":true,"ret_msg":"","op":"subscribe","conn_id":"abc"}"#,
            r#"{"success":true,"ret_msg":"pong","op":"ping","conn_id":"abc"}"#,
        ] {
            let error = decode_payload(control.as_bytes(), &map(MarketKind::Spot), RECV, &mut out)
                .expect_err("not market data");
            assert!(error.is_benign(), "got {error:?}");
        }
        assert!(out.is_empty());
    }

    #[test]
    fn untracked_symbols_are_benign() {
        let other = BOOK.replace("BTCUSDT", "ETHUSDT");
        let mut out = Vec::new();
        let error = decode_payload(other.as_bytes(), &map(MarketKind::Spot), RECV, &mut out)
            .expect_err("untracked");
        assert!(error.is_benign());
    }

    #[test]
    fn subscribe_frames_cover_the_right_topics() {
        let spot = subscribe_frames(["BTCUSDT"].into_iter(), MarketKind::Spot, 10);
        assert_eq!(spot.len(), 1);
        assert!(spot[0].contains("orderbook.1.BTCUSDT"));
        assert!(spot[0].contains("publicTrade.BTCUSDT"));
        assert!(!spot[0].contains("tickers"), "spot has no mark price");

        let perp = subscribe_frames(["BTCUSDT"].into_iter(), MarketKind::LinearPerp, 10);
        assert!(perp[0].contains("tickers.BTCUSDT"));
    }

    #[test]
    fn subscribe_frames_are_chunked() {
        let symbols = ["BTCUSDT", "ETHUSDT", "SOLUSDT"];
        let frames = subscribe_frames(symbols.into_iter(), MarketKind::Spot, 2);
        assert_eq!(frames.len(), 3, "six topics at two per frame");
    }

    #[test]
    fn spot_and_linear_use_different_hosts() {
        assert_ne!(url(MarketKind::Spot), url(MarketKind::LinearPerp));
    }
}
