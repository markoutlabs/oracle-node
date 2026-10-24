//! Decoding Binance combined-stream payloads into observations.
//!
//! Pure: bytes and a receipt timestamp in, observations out. No clock, no socket,
//! no async. That is what lets the tests below run against captured payloads
//! rather than a live exchange.

use std::collections::HashMap;
use std::sync::Arc;

use oracle_types::{
    Fixed, FundingBasis, FundingInfo, Level, MarketKind, NANOS_PER_SEC, ObsKind, Observation,
    OpenInterestUnit,
};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::clock::millis_to_nanos;
use crate::{DecodeError, InstrumentMap};

use super::book::{Applied, BinanceBooks, Diff};
use super::streams::StreamKind;

/// The combined-stream envelope: `{"stream":"btcusdt@bookTicker","data":{…}}`.
/// A REST frame that could not be fetched carries `error` instead of `data`.
#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow)]
    stream: &'a str,
    #[serde(borrow, default)]
    data: Option<&'a RawValue>,
    #[serde(borrow, default)]
    error: Option<&'a str>,
}

/// A diff-depth event. Futures add `pu`.
#[derive(Deserialize)]
struct DepthDiff<'a> {
    #[serde(rename = "s", borrow)]
    symbol: &'a str,
    #[serde(rename = "U")]
    first: u64,
    #[serde(rename = "u")]
    last: u64,
    #[serde(rename = "pu", default)]
    previous: Option<u64>,
    #[serde(rename = "E", default)]
    event_time_ms: Option<u64>,
    #[serde(rename = "b", borrow)]
    bids: Vec<[&'a str; 2]>,
    #[serde(rename = "a", borrow)]
    asks: Vec<[&'a str; 2]>,
}

/// The REST snapshot, as `super::snapshot` delivers it.
#[derive(Deserialize)]
struct DepthSnapshot<'a> {
    #[serde(rename = "lastUpdateId")]
    last_update_id: u64,
    #[serde(borrow)]
    bids: Vec<[&'a str; 2]>,
    #[serde(borrow)]
    asks: Vec<[&'a str; 2]>,
}

#[derive(Deserialize)]
struct AdjustedFunding<'a> {
    #[serde(borrow)]
    symbol: &'a str,
    #[serde(rename = "fundingIntervalHours", default)]
    interval_hours: Option<u64>,
}

const HOUR_NS: u64 = 3_600 * NANOS_PER_SEC;
/// A perpetual that the list leaves out pays every 8 hours.
const DEFAULT_INTERVAL_NS: u64 = 8 * HOUR_NS;

/// The funding interval of each perpetual, from the list that
/// `super::snapshot` delivers.
#[derive(Debug, Default)]
pub(crate) struct FundingIntervals {
    /// Nanoseconds, by uppercase symbol. `None` until the first list arrives.
    by_symbol: Option<HashMap<String, u64>>,
    /// The last open interest of each perpetual, by uppercase symbol.
    open_interest: HashMap<String, Fixed>,
}

/// One `openInterest` REST reply.
#[derive(Deserialize)]
struct OpenInterestReply<'a> {
    #[serde(borrow)]
    symbol: &'a str,
    #[serde(rename = "openInterest", borrow)]
    open_interest: &'a str,
}

impl FundingIntervals {
    fn open_interest(&self, symbol: &str) -> Option<Fixed> {
        self.open_interest
            .get(symbol)
            .or_else(|| self.open_interest.get(&symbol.to_ascii_uppercase()))
            .copied()
    }

    fn apply_open_interest(&mut self, envelope: &Envelope<'_>) -> Result<(), DecodeError> {
        if let Some(error) = envelope.error {
            return Err(DecodeError::Malformed(format!(
                "{}: fetch failed: {error}",
                envelope.stream
            )));
        }
        let data = envelope.data.ok_or(DecodeError::MissingField("data"))?;
        let reply: OpenInterestReply<'_> = serde_json::from_slice(data.get().as_bytes())
            .map_err(|e| DecodeError::Malformed(e.to_string()))?;
        let open_interest = decimal("openInterest", reply.open_interest)?;
        self.open_interest
            .insert(reply.symbol.to_ascii_uppercase(), open_interest);
        // The value reaches the next mark price; this frame alone is no observation.
        Err(DecodeError::Control)
    }

    fn interval_ns(&self, symbol: &str) -> Option<u64> {
        let by_symbol = self.by_symbol.as_ref()?;
        // Uppercase only on a miss, as `InstrumentMap::lookup` does.
        let listed = by_symbol
            .get(symbol)
            .or_else(|| by_symbol.get(&symbol.to_ascii_uppercase()));
        Some(listed.copied().unwrap_or(DEFAULT_INTERVAL_NS))
    }

    fn apply(&mut self, envelope: &Envelope<'_>) -> Result<(), DecodeError> {
        // A failed fetch keeps the last list: the next fetch comes within a minute.
        if let Some(error) = envelope.error {
            return Err(DecodeError::Malformed(format!(
                "{}: fetch failed: {error}",
                envelope.stream
            )));
        }
        let data = envelope.data.ok_or(DecodeError::MissingField("data"))?;
        let list: Vec<AdjustedFunding<'_>> = serde_json::from_slice(data.get().as_bytes())
            .map_err(|e| DecodeError::Malformed(e.to_string()))?;
        self.by_symbol = Some(
            list.into_iter()
                .filter_map(|entry| {
                    let hours = entry.interval_hours.filter(|hours| *hours > 0)?;
                    Some((
                        entry.symbol.to_ascii_uppercase(),
                        hours.checked_mul(HOUR_NS)?,
                    ))
                })
                .collect(),
        );
        Ok(())
    }
}

fn levels(raw: &[[&str; 2]]) -> Result<Vec<Level>, DecodeError> {
    raw.iter()
        .map(|[price, qty]| crate::depth::level(price, qty))
        .collect()
}

/// The session's entry point: depth streams are kept in `books`, and mark
/// prices get their interval from `intervals`. Every other stream goes to
/// [`decode_payload`].
///
/// # Errors
///
/// As [`decode_payload`], and [`DecodeError::Resync`] when a diff does not
/// follow the book, or its snapshot could not be fetched.
/// [`DecodeError::Malformed`] when the funding intervals could not be fetched.
pub(crate) fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut BinanceBooks,
    intervals: &mut FundingIntervals,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let Ok(envelope) = serde_json::from_slice::<Envelope<'_>>(payload) else {
        return decode_payload(payload, map, local_recv_ns, out);
    };
    let kind = StreamKind::from_stream_name(envelope.stream);
    match kind {
        Some(StreamKind::FundingInfo) => return intervals.apply(&envelope),
        Some(StreamKind::OpenInterest) => return intervals.apply_open_interest(&envelope),
        Some(StreamKind::MarkPrice) => {
            let data = envelope.data.ok_or(DecodeError::MissingField("data"))?;
            return decode_mark_price(data.get().as_bytes(), map, intervals, local_recv_ns, out);
        }
        Some(StreamKind::Depth | StreamKind::DepthSnapshot) => {}
        _ => return decode_payload(payload, map, local_recv_ns, out),
    }
    if let Some(error) = envelope.error {
        return Err(DecodeError::Resync(format!(
            "{}: snapshot failed: {error}",
            envelope.stream
        )));
    }
    let data = envelope
        .data
        .ok_or(DecodeError::MissingField("data"))?
        .get()
        .as_bytes();
    let futures = map.market() != MarketKind::Spot;
    let (symbol, exchange_time_ns, applied) = if kind == Some(StreamKind::Depth) {
        let diff: DepthDiff<'_> =
            serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
        let symbol = diff.symbol.to_ascii_uppercase();
        let applied = books.on_diff(
            &symbol,
            futures,
            Diff {
                first: diff.first,
                last: diff.last,
                previous: diff.previous,
                bids: levels(&diff.bids)?,
                asks: levels(&diff.asks)?,
            },
        )?;
        (symbol, diff.event_time_ms.map(millis_to_nanos), applied)
    } else {
        let snapshot: DepthSnapshot<'_> =
            serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
        let symbol = envelope
            .stream
            .split('@')
            .next()
            .unwrap_or(envelope.stream)
            .to_ascii_uppercase();
        let applied = books.on_snapshot(
            &symbol,
            futures,
            snapshot.last_update_id,
            levels(&snapshot.bids)?,
            levels(&snapshot.asks)?,
        )?;
        (symbol, None, applied)
    };
    let entry = map
        .lookup(&symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(symbol.clone()))?;
    if applied == Applied::Changed {
        books.books.emit(
            &symbol,
            entry.instrument.clone(),
            exchange_time_ns,
            local_recv_ns,
            out,
        )?;
    }
    Ok(())
}

/// `bookTicker`. Spot omits every timestamp; futures adds `E` and `T`.
#[derive(Deserialize)]
struct BookTicker<'a> {
    #[serde(rename = "u")]
    update_id: u64,
    #[serde(rename = "s", borrow)]
    symbol: &'a str,
    #[serde(rename = "b", borrow)]
    bid: &'a str,
    #[serde(rename = "B", borrow)]
    bid_qty: &'a str,
    #[serde(rename = "a", borrow)]
    ask: &'a str,
    #[serde(rename = "A", borrow)]
    ask_qty: &'a str,
    #[serde(rename = "E", default)]
    event_time_ms: Option<u64>,
}

/// `aggTrade`.
#[derive(Deserialize)]
struct AggTrade<'a> {
    #[serde(rename = "a")]
    agg_id: u64,
    #[serde(rename = "s", borrow)]
    symbol: &'a str,
    #[serde(rename = "p", borrow)]
    price: &'a str,
    #[serde(rename = "T")]
    trade_time_ms: u64,
}

/// `markPriceUpdate`.
#[derive(Deserialize)]
struct MarkPrice<'a> {
    #[serde(rename = "E")]
    event_time_ms: u64,
    #[serde(rename = "s", borrow)]
    symbol: &'a str,
    #[serde(rename = "p", borrow)]
    mark: &'a str,
    #[serde(rename = "i", borrow, default)]
    index: Option<&'a str>,
    #[serde(rename = "r", borrow, default)]
    funding_rate: Option<&'a str>,
    /// The next funding time, in milliseconds.
    #[serde(rename = "T", default)]
    next_funding_time_ms: Option<u64>,
}

/// Parses a decimal field.
fn decimal(field: &'static str, value: &str) -> Result<Fixed, DecodeError> {
    value.parse().map_err(|_| DecodeError::BadDecimal {
        field,
        value: value.to_owned(),
    })
}

/// Decodes one combined-stream payload. Funding observations get no interval
/// here: it comes from the list that only a session has.
///
/// The `map` carries the market it serves, which is what disambiguates symbols
/// listed on both spot and perpetuals — every major pair is. A session must
/// therefore be built with the map for the market its connection subscribes to.
///
/// # Errors
///
/// Returns [`DecodeError`]. Check [`DecodeError::is_benign`] before treating one
/// as a fault: subscription acknowledgements and untracked streams arrive in
/// normal operation.
pub fn decode_payload(
    payload: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> = serde_json::from_slice(payload).map_err(|e| {
        // Subscription replies (`{"result":null,"id":1}`) and error objects share
        // this endpoint and have no `stream` field.
        if looks_like_control(payload) {
            DecodeError::Control
        } else {
            DecodeError::Malformed(e.to_string())
        }
    })?;

    let kind = StreamKind::from_stream_name(envelope.stream)
        .ok_or_else(|| DecodeError::UnhandledStream(envelope.stream.to_owned()))?;
    // Only a REST frame carries `error`, and `decode` handles those.
    let data = envelope
        .data
        .ok_or(DecodeError::MissingField("data"))?
        .get()
        .as_bytes();

    match kind {
        StreamKind::BookTicker => decode_book_ticker(data, map, local_recv_ns, out),
        StreamKind::AggTrade => decode_agg_trade(data, map, local_recv_ns, out),
        StreamKind::MarkPrice => {
            decode_mark_price(data, map, &FundingIntervals::default(), local_recv_ns, out)
        }
        // These need the session's state; see `decode`.
        StreamKind::Depth
        | StreamKind::DepthSnapshot
        | StreamKind::FundingInfo
        | StreamKind::OpenInterest => Err(DecodeError::UnhandledStream(envelope.stream.to_owned())),
    }
}

/// Returns `true` if the payload is a control response rather than market data.
fn looks_like_control(payload: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Control {
        #[serde(default)]
        id: Option<u64>,
        #[serde(default)]
        code: Option<i64>,
    }
    serde_json::from_slice::<Control>(payload).is_ok_and(|c| c.id.is_some() || c.code.is_some())
}

fn decode_book_ticker(
    data: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let ticker: BookTicker<'_> =
        serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let entry = map
        .lookup(ticker.symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(ticker.symbol.to_owned()))?;

    let bid = decimal("b", ticker.bid)?;
    let ask = decimal("a", ticker.ask)?;
    let bid_qty = decimal("B", ticker.bid_qty)?;
    let ask_qty = decimal("A", ticker.ask_qty)?;

    // The primary value for a two-sided quote is the mid. Consumers that want the
    // pressure-weighted view call `microprice()`; the sizes are carried for them.
    let price = bid
        .checked_add(ask)
        .and_then(|sum| sum.checked_div(Fixed::from_int(2).ok()?))
        .unwrap_or(bid);

    out.push(Observation {
        instrument: entry.instrument.clone(),
        kind: ObsKind::BookTop,
        price,
        bid: Some(bid),
        ask: Some(ask),
        bid_qty: Some(bid_qty),
        ask_qty: Some(ask_qty),
        // `bookTicker` is top-of-book only. Depth-derived weighting needs a depth
        // stream, which M2 will have to add before `w_depth` means anything.
        depth_notional_1bp: None,
        exchange_time_ns: ticker.event_time_ms.map(millis_to_nanos),
        local_recv_ns,
        seq: Some(ticker.update_id),
        book: None,
        funding: None,
    });
    Ok(())
}

fn decode_agg_trade(
    data: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let trade: AggTrade<'_> =
        serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let entry = map
        .lookup(trade.symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(trade.symbol.to_owned()))?;

    out.push(Observation {
        instrument: entry.instrument.clone(),
        kind: ObsKind::Trade,
        price: decimal("p", trade.price)?,
        bid: None,
        ask: None,
        bid_qty: None,
        ask_qty: None,
        depth_notional_1bp: None,
        // The trade time, not the event time: when it happened beats when it was
        // relayed.
        exchange_time_ns: Some(millis_to_nanos(trade.trade_time_ms)),
        local_recv_ns,
        seq: Some(trade.agg_id),
        book: None,
        funding: None,
    });
    Ok(())
}

fn decode_mark_price(
    data: &[u8],
    map: &InstrumentMap,
    intervals: &FundingIntervals,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let update: MarkPrice<'_> =
        serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let entry = map
        .lookup(update.symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(update.symbol.to_owned()))?;

    let exchange_time_ns = Some(millis_to_nanos(update.event_time_ms));
    let mut push = |kind: ObsKind, price: Fixed, funding: Option<Arc<FundingInfo>>| {
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
            book: None,
            funding,
        });
    };

    push(ObsKind::MarkPrice, decimal("p", update.mark)?, None);
    if let Some(index) = update.index {
        push(ObsKind::IndexPrice, decimal("i", index)?, None);
    }
    if let Some(rate) = update.funding_rate {
        let info = FundingInfo {
            interval_ns: intervals.interval_ns(update.symbol),
            next_funding_time_ns: update
                .next_funding_time_ms
                .filter(|ms| *ms > 0)
                .map(millis_to_nanos),
            open_interest: intervals
                .open_interest(update.symbol)
                .map(|oi| (oi, OpenInterestUnit::Base)),
            ..FundingInfo::new(FundingBasis::Interval)
        };
        push(ObsKind::Funding, decimal("r", rate)?, Some(Arc::new(info)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InstrumentSpec;
    use oracle_types::{MarketKind, Venue};

    const RECV_NS: u64 = 1_754_582_400_500_000_000;

    fn spot_map() -> InstrumentMap {
        let specs = vec![
            InstrumentSpec::new("BTCUSDT", MarketKind::Spot, "CRYPTO.BTC/USDT").expect("valid"),
        ];
        InstrumentMap::new(Venue::Binance, MarketKind::Spot, &specs).expect("valid")
    }

    fn perp_map() -> InstrumentMap {
        let specs = vec![
            InstrumentSpec::new(
                "BTCUSDT",
                MarketKind::LinearPerp,
                "CRYPTO.BTC/USDT.PERP_MARK",
            )
            .expect("valid"),
        ];
        InstrumentMap::new(Venue::Binance, MarketKind::LinearPerp, &specs).expect("valid")
    }

    fn decode(payload: &str, map: &InstrumentMap) -> Vec<Observation> {
        let mut out = Vec::new();
        decode_payload(payload.as_bytes(), map, RECV_NS, &mut out).expect("decodes");
        out
    }

    /// Captured shape of a spot `bookTicker`: no `e`, no `E`, no `T`.
    const SPOT_BOOK_TICKER: &str = r#"{"stream":"btcusdt@bookTicker","data":{
        "u":400900217,"s":"BTCUSDT",
        "b":"64312.00000000","B":"1.25000000",
        "a":"64313.00000000","A":"0.75000000"}}"#;

    /// Captured shape of a futures `bookTicker`: carries `e`, `u`, `E`, `T`.
    const PERP_BOOK_TICKER: &str = r#"{"stream":"btcusdt@bookTicker","data":{
        "e":"bookTicker","u":400900217,"E":1754582400123,"T":1754582400120,
        "s":"BTCUSDT","b":"64311.50","B":"3.0","a":"64312.50","A":"1.0"}}"#;

    /// Recorded from Binance spot on 2026-10-06, in the order the snapshot
    /// connector delivers it: five diffs, the REST snapshot, then 25 more.
    const RECORDED_DEPTH: &str = include_str!("../../tests/fixtures/binance-depth.jsonl");

    fn depth_map() -> InstrumentMap {
        let specs = vec![
            InstrumentSpec::new("BTCUSDT", MarketKind::Spot, "CRYPTO.BTC/USDT")
                .expect("valid")
                .with_depth(),
        ];
        InstrumentMap::new(Venue::Binance, MarketKind::Spot, &specs).expect("valid")
    }

    /// The diffs before the snapshot wait for it, and every one after it
    /// follows the last.
    #[test]
    fn a_recorded_book_joins_snapshot_and_diffs() {
        let map = depth_map();
        let mut books = BinanceBooks::default();
        let mut depths = Vec::new();
        for line in RECORDED_DEPTH.lines() {
            let mut out = Vec::new();
            super::decode(
                line.as_bytes(),
                &map,
                &mut books,
                &mut FundingIntervals::default(),
                RECV_NS,
                &mut out,
            )
            .unwrap_or_else(|error| panic!("{error}: {line}"));
            depths.extend(out);
        }
        assert!(depths.len() >= 25, "{}", depths.len());
        assert!(depths.iter().all(|o| o.kind == ObsKind::Depth));
        let last = depths.last().expect("a depth observation");
        assert!(last.bid < last.ask);
    }

    #[test]
    fn a_failed_snapshot_asks_for_a_resync() {
        let failed = r#"{"stream":"btcusdt@depthSnapshot","error":"HTTP status 429"}"#;
        assert!(matches!(
            super::decode(
                failed.as_bytes(),
                &depth_map(),
                &mut BinanceBooks::default(),
                &mut FundingIntervals::default(),
                RECV_NS,
                &mut Vec::new()
            ),
            Err(DecodeError::Resync(_))
        ));
    }

    const AGG_TRADE: &str = r#"{"stream":"btcusdt@aggTrade","data":{
        "e":"aggTrade","E":1754582400123,"s":"BTCUSDT","a":12345,
        "p":"64312.10","q":"0.05","f":100,"l":105,"T":1754582400100,"m":true,"M":true}}"#;

    const MARK_PRICE: &str = r#"{"stream":"btcusdt@markPrice@1s","data":{
        "e":"markPriceUpdate","E":1754582400000,"s":"BTCUSDT",
        "p":"64315.00000000","i":"64310.00000000","P":"64320.00000000",
        "r":"0.00010000","T":1754596800000}}"#;

    #[test]
    fn spot_book_ticker_has_no_exchange_timestamp() {
        let observations = decode(SPOT_BOOK_TICKER, &spot_map());
        assert_eq!(observations.len(), 1);
        let obs = observations.first().expect("one observation");
        assert_eq!(obs.kind, ObsKind::BookTop);
        assert_eq!(obs.bid, Some("64312".parse().expect("valid")));
        assert_eq!(obs.ask, Some("64313".parse().expect("valid")));
        assert_eq!(obs.bid_qty, Some("1.25".parse().expect("valid")));
        assert_eq!(obs.price, "64312.5".parse().expect("valid"));
        assert_eq!(obs.seq, Some(400_900_217));
        // The whole reason the field is optional.
        assert_eq!(obs.exchange_time_ns, None);
        assert_eq!(obs.venue_lag_ns(), None);
        assert_eq!(obs.local_recv_ns, RECV_NS);
    }

    #[test]
    fn futures_book_ticker_carries_an_exchange_timestamp() {
        let observations = decode(PERP_BOOK_TICKER, &perp_map());
        let obs = observations.first().expect("one observation");
        assert_eq!(obs.exchange_time_ns, Some(1_754_582_400_123_000_000));
        assert_eq!(obs.venue_lag_ns(), Some(377_000_000));
        assert_eq!(obs.instrument.market, MarketKind::LinearPerp);
    }

    #[test]
    fn agg_trade_uses_the_trade_time_not_the_event_time() {
        let observations = decode(AGG_TRADE, &spot_map());
        let obs = observations.first().expect("one observation");
        assert_eq!(obs.kind, ObsKind::Trade);
        assert_eq!(obs.price, "64312.1".parse().expect("valid"));
        // T = 1754582400100, not E = 1754582400123.
        assert_eq!(obs.exchange_time_ns, Some(1_754_582_400_100_000_000));
        assert_eq!(obs.seq, Some(12_345));
        assert!(obs.bid.is_none(), "a trade print carries no book");
    }

    #[test]
    fn mark_price_yields_three_observations() {
        let observations = decode(MARK_PRICE, &perp_map());
        assert_eq!(observations.len(), 3);
        let kinds: Vec<_> = observations.iter().map(|o| o.kind).collect();
        assert_eq!(
            kinds,
            [ObsKind::MarkPrice, ObsKind::IndexPrice, ObsKind::Funding]
        );
        let prices: Vec<_> = observations.iter().map(|o| o.price).collect();
        assert_eq!(
            prices,
            [
                "64315".parse().expect("valid"),
                "64310".parse().expect("valid"),
                "0.0001".parse().expect("valid"),
            ]
        );
    }

    /// Binance has no open-interest stream, so a REST frame holds the value
    /// until the next mark price carries it.
    #[test]
    fn the_open_interest_frame_reaches_the_next_funding_update() {
        let map = perp_map();
        let mut books = BinanceBooks::default();
        let mut intervals = FundingIntervals::default();
        let mut out = Vec::new();
        let frame = r#"{"stream":"btcusdt@openInterest","data":{"symbol":"BTCUSDT","openInterest":"93697.961","time":1754582400000}}"#;
        let error = super::decode(
            frame.as_bytes(),
            &map,
            &mut books,
            &mut intervals,
            RECV_NS,
            &mut out,
        )
        .expect_err("no observation of its own");
        assert!(error.is_benign());
        assert!(out.is_empty());

        super::decode(
            MARK_PRICE.as_bytes(),
            &map,
            &mut books,
            &mut intervals,
            RECV_NS,
            &mut out,
        )
        .expect("decodes");
        let funding = out
            .iter()
            .find(|o| o.kind == ObsKind::Funding)
            .expect("funding");
        let info = funding.funding.as_deref().expect("funding info");
        assert_eq!(
            info.open_interest,
            Some(("93697.961".parse().expect("valid"), OpenInterestUnit::Base))
        );

        // A failed fetch is counted, and the last value stays.
        let failed = r#"{"stream":"btcusdt@openInterest","error":"HTTP status 429"}"#;
        let error = super::decode(
            failed.as_bytes(),
            &map,
            &mut books,
            &mut intervals,
            RECV_NS,
            &mut Vec::new(),
        )
        .expect_err("a failed fetch");
        assert!(!error.is_benign());
        assert_eq!(
            intervals.open_interest("BTCUSDT"),
            Some("93697.961".parse().expect("valid"))
        );
    }

    #[test]
    fn mark_price_tolerates_a_missing_index_or_funding_rate() {
        let payload = r#"{"stream":"btcusdt@markPrice@1s","data":{
            "e":"markPriceUpdate","E":1754582400000,"s":"BTCUSDT",
            "p":"64315.0","T":1754596800000}}"#;
        let observations = decode(payload, &perp_map());
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations.first().map(|o| o.kind),
            Some(ObsKind::MarkPrice)
        );
    }

    #[test]
    fn negative_funding_rates_decode() {
        let payload = r#"{"stream":"btcusdt@markPrice@1s","data":{
            "e":"markPriceUpdate","E":1754582400000,"s":"BTCUSDT",
            "p":"64315.0","r":"-0.00012500","T":1754596800000}}"#;
        let observations = decode(payload, &perp_map());
        let funding = observations
            .iter()
            .find(|o| o.kind == ObsKind::Funding)
            .expect("funding");
        assert_eq!(funding.price, "-0.000125".parse().expect("valid"));
    }

    #[test]
    fn subscription_acknowledgements_are_benign() {
        let mut out = Vec::new();
        let err = decode_payload(br#"{"result":null,"id":1}"#, &spot_map(), RECV_NS, &mut out)
            .expect_err("not market data");
        assert_eq!(err, DecodeError::Control);
        assert!(err.is_benign());
        assert!(out.is_empty());
    }

    #[test]
    fn error_objects_are_benign() {
        let mut out = Vec::new();
        let err = decode_payload(
            br#"{"code":-1121,"msg":"Invalid symbol."}"#,
            &spot_map(),
            RECV_NS,
            &mut out,
        )
        .expect_err("not market data");
        assert!(err.is_benign(), "got {err:?}");
    }

    #[test]
    fn untracked_symbols_and_streams_are_benign() {
        let mut out = Vec::new();

        let unknown_symbol = r#"{"stream":"ethusdt@bookTicker","data":{
            "u":1,"s":"ETHUSDT","b":"1","B":"1","a":"2","A":"1"}}"#;
        let err = decode_payload(unknown_symbol.as_bytes(), &spot_map(), RECV_NS, &mut out)
            .expect_err("untracked");
        assert!(matches!(err, DecodeError::UnknownInstrument(_)));
        assert!(err.is_benign());

        let unknown_stream = r#"{"stream":"btcusdt@kline_1m","data":{}}"#;
        let err = decode_payload(unknown_stream.as_bytes(), &spot_map(), RECV_NS, &mut out)
            .expect_err("unhandled");
        assert!(matches!(err, DecodeError::UnhandledStream(_)));
        assert!(err.is_benign());

        assert!(out.is_empty());
    }

    #[test]
    fn malformed_payloads_are_not_benign() {
        let mut out = Vec::new();
        for payload in [
            &b"not json"[..],
            b"{}",
            br#"{"stream":"btcusdt@bookTicker","data":{"u":1,"s":"BTCUSDT"}}"#,
        ] {
            let err =
                decode_payload(payload, &spot_map(), RECV_NS, &mut out).expect_err("should fail");
            assert!(
                !err.is_benign(),
                "{payload:?} produced a benign error: {err:?}"
            );
        }
        assert!(out.is_empty());
    }

    #[test]
    fn non_numeric_prices_are_reported_with_the_offending_value() {
        let payload = r#"{"stream":"btcusdt@bookTicker","data":{
            "u":1,"s":"BTCUSDT","b":"not-a-price","B":"1","a":"2","A":"1"}}"#;
        let mut out = Vec::new();
        let err = decode_payload(payload.as_bytes(), &spot_map(), RECV_NS, &mut out)
            .expect_err("should fail");
        assert_eq!(
            err,
            DecodeError::BadDecimal {
                field: "b",
                value: "not-a-price".to_owned()
            }
        );
    }

    #[test]
    fn high_precision_quantities_survive_intact() {
        // Binance sends eight decimal places; nothing may be rounded away here.
        let payload = r#"{"stream":"btcusdt@bookTicker","data":{
            "u":1,"s":"BTCUSDT","b":"0.00000001","B":"12345.67891234",
            "a":"0.00000002","A":"0.00000001"}}"#;
        let observations = decode(payload, &spot_map());
        let obs = observations.first().expect("one observation");
        assert_eq!(obs.bid, Some("0.00000001".parse().expect("valid")));
        assert_eq!(obs.bid_qty, Some("12345.67891234".parse().expect("valid")));
        assert_eq!(obs.price, "0.000000015".parse().expect("valid"));
    }

    #[test]
    fn lowercase_symbols_in_payloads_still_map() {
        let payload = r#"{"stream":"btcusdt@bookTicker","data":{
            "u":1,"s":"btcusdt","b":"1","B":"1","a":"2","A":"1"}}"#;
        assert_eq!(decode(payload, &spot_map()).len(), 1);
    }

    #[test]
    fn a_crossed_book_decodes_and_is_flagged_rather_than_repaired() {
        // Dropping it is the aggregator's call; the decoder must not silently fix it.
        let payload = r#"{"stream":"btcusdt@bookTicker","data":{
            "u":1,"s":"BTCUSDT","b":"64313","B":"1","a":"64312","A":"1"}}"#;
        let observations = decode(payload, &spot_map());
        assert!(observations.first().is_some_and(Observation::is_crossed));
    }
}
