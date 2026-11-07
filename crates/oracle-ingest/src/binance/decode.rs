//! Decoding Binance combined-stream payloads into observations.
//!
//! Pure: bytes and a receipt timestamp in, observations out. No clock, no socket,
//! no async. That is what lets the tests below run against captured payloads
//! rather than a live exchange.

use std::collections::HashMap;
use std::sync::Arc;

use oracle_types::{
    Fixed, FundingBasis, FundingInfo, MarketKind, NANOS_PER_SEC, ObsKind, Observation,
    OpenInterestUnit,
};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{BookMsg, BookRule, Change, Continuity};
use crate::clock::millis_to_nanos;
use crate::instrument::InstrumentEntry;
use crate::venues::{mid, observation};
use crate::{DecodeError, InstrumentMap};

use super::book::{Applied, BinanceBooks, Diff};
use super::streams::StreamKind;

/// Each diff follows the last by its ids; [`BinanceBooks`] checks them, and a
/// diff that does not parse is lost, so the book resyncs.
const BOOK_RULE: BookRule = BookRule::new(Continuity::UpdateId);

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
    fn open_interest(&self, entry: &InstrumentEntry) -> Option<Fixed> {
        self.open_interest.get(&*entry.instrument.symbol).copied()
    }

    fn apply_open_interest(
        &mut self,
        envelope: &Envelope<'_>,
        map: &InstrumentMap,
    ) -> Result<(), DecodeError> {
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
        let entry = map
            .lookup(reply.symbol)
            .ok_or_else(|| DecodeError::UnknownInstrument(reply.symbol.to_owned()))?;
        self.open_interest
            .insert(entry.instrument.symbol.to_string(), open_interest);
        // The value reaches the next mark price; this frame alone is no observation.
        Err(DecodeError::Control)
    }

    fn interval_ns(&self, entry: &InstrumentEntry) -> Option<u64> {
        let by_symbol = self.by_symbol.as_ref()?;
        let listed = by_symbol
            .get(&*entry.instrument.symbol)
            .or_else(|| by_symbol.get(&entry.instrument.symbol.to_ascii_uppercase()));
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

fn change(&[price, qty]: &[&str; 2]) -> Result<Change<'static>, DecodeError> {
    Ok(Change::from(crate::depth::level(price, qty)?))
}

/// Decodes one combined-stream payload of the market that `map` serves. The map
/// is what tells `BTCUSDT` the perpetual from `BTCUSDT` the spot pair.
///
/// # Errors
///
/// Returns [`DecodeError`]; acknowledgements and untracked streams are benign.
/// A diff that does not follow its book, or a failed snapshot, is [`DecodeError::Resync`].
pub(crate) fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut BinanceBooks,
    intervals: &mut FundingIntervals,
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
    let data = || envelope.data.ok_or(DecodeError::MissingField("data"));
    match kind {
        StreamKind::BookTicker => decode_book_ticker(data()?, map, local_recv_ns, out),
        StreamKind::AggTrade => decode_agg_trade(data()?, map, local_recv_ns, out),
        StreamKind::MarkPrice => decode_mark_price(data()?, map, intervals, local_recv_ns, out),
        StreamKind::FundingInfo => intervals.apply(&envelope),
        StreamKind::OpenInterest => intervals.apply_open_interest(&envelope, map),
        StreamKind::Depth | StreamKind::DepthSnapshot => {
            decode_depth(&envelope, kind, map, books, local_recv_ns, out)
        }
    }
}

/// A diff, or the REST snapshot it applies to.
fn decode_depth(
    envelope: &Envelope<'_>,
    kind: StreamKind,
    map: &InstrumentMap,
    books: &mut BinanceBooks,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    if let Some(error) = envelope.error {
        return Err(DecodeError::Resync(format!(
            "{}: snapshot failed: {error}",
            envelope.stream
        )));
    }
    let data = envelope.data.ok_or(DecodeError::MissingField("data"))?;
    let futures = map.market() != MarketKind::Spot;
    let lost = |error| BOOK_RULE.unparsed(error);
    let (entry, exchange_time_ns, applied) = if kind == StreamKind::Depth {
        let diff: DepthDiff<'_> = serde_json::from_str(data.get())
            .map_err(|e| lost(DecodeError::Malformed(e.to_string())))?;
        let entry = map
            .lookup(diff.symbol)
            .ok_or_else(|| DecodeError::UnknownInstrument(diff.symbol.to_owned()))?;
        let changes = BookMsg::changes(&diff.bids, &diff.asks, change).map_err(lost)?;
        let parsed = Diff {
            first: diff.first,
            changes: BookMsg {
                prev_id: diff.previous,
                next_id: Some(diff.last),
                ..changes
            },
        };
        let applied = books.on_diff(&entry.instrument.symbol, futures, parsed)?;
        (entry, diff.event_time_ms.map(millis_to_nanos), applied)
    } else {
        let snapshot: DepthSnapshot<'_> = serde_json::from_str(data.get())
            .map_err(|e| lost(DecodeError::Malformed(e.to_string())))?;
        let symbol = envelope.stream.split('@').next().unwrap_or(envelope.stream);
        let entry = map
            .lookup(symbol)
            .ok_or_else(|| DecodeError::UnknownInstrument(symbol.to_owned()))?;
        let whole = BookMsg::whole(&snapshot.bids, &snapshot.asks, change).map_err(lost)?;
        let id = snapshot.last_update_id;
        let applied = books.on_snapshot(&entry.instrument.symbol, futures, id, &whole)?;
        (entry, None, applied)
    };
    if applied == Applied::Changed {
        books
            .keeper
            .emit(BOOK_RULE, entry, exchange_time_ns, local_recv_ns, out)?;
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
    data: &RawValue,
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let ticker: BookTicker<'_> = serde_json::from_str(data.get())?;
    let entry = map
        .lookup(ticker.symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(ticker.symbol.to_owned()))?;

    let parse = || {
        Ok::<_, DecodeError>((
            decimal("b", ticker.bid)?,
            decimal("a", ticker.ask)?,
            decimal("B", ticker.bid_qty)?,
            decimal("A", ticker.ask_qty)?,
        ))
    };
    let (bid, ask, bid_qty, ask_qty) =
        parse().map_err(|error| DecodeError::lost(&entry.instrument, error))?;

    // A zero side is not refused here: the aggregator marks the quote invalid,
    // which is the safer result.
    out.push(Observation {
        bid: Some(bid),
        ask: Some(ask),
        bid_qty: Some(bid_qty),
        ask_qty: Some(ask_qty),
        exchange_time_ns: ticker.event_time_ms.map(millis_to_nanos),
        seq: Some(ticker.update_id),
        ..observation(entry, ObsKind::BookTop, mid(bid, ask), local_recv_ns)
    });
    Ok(())
}

fn decode_agg_trade(
    data: &RawValue,
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let trade: AggTrade<'_> = serde_json::from_str(data.get())?;
    let entry = map
        .lookup(trade.symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(trade.symbol.to_owned()))?;

    out.push(Observation {
        // The trade time, not the event time: when it happened beats when it was
        // relayed.
        exchange_time_ns: Some(millis_to_nanos(trade.trade_time_ms)),
        seq: Some(trade.agg_id),
        ..observation(
            entry,
            ObsKind::Trade,
            decimal("p", trade.price)?,
            local_recv_ns,
        )
    });
    Ok(())
}

fn decode_mark_price(
    data: &RawValue,
    map: &InstrumentMap,
    intervals: &FundingIntervals,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let update: MarkPrice<'_> = serde_json::from_str(data.get())?;
    let entry = map
        .lookup(update.symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(update.symbol.to_owned()))?;

    let exchange_time_ns = Some(millis_to_nanos(update.event_time_ms));
    let mut push = |kind: ObsKind, price: Fixed, funding: Option<Arc<FundingInfo>>| {
        out.push(Observation {
            exchange_time_ns,
            funding,
            ..observation(entry, kind, price, local_recv_ns)
        });
    };

    push(ObsKind::MarkPrice, decimal("p", update.mark)?, None);
    if let Some(index) = update.index {
        push(ObsKind::IndexPrice, decimal("i", index)?, None);
    }
    if let Some(rate) = update.funding_rate {
        let info = FundingInfo {
            interval_ns: intervals.interval_ns(entry),
            next_funding_time_ns: update
                .next_funding_time_ms
                .filter(|ms| *ms > 0)
                .map(millis_to_nanos),
            open_interest: intervals
                .open_interest(entry)
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
    use crate::binance::BinanceHandler;
    use crate::testing::{Feed, RECV_NS, fixed, instrument, kinds};
    use oracle_types::{MarketKind, Venue};

    fn binance(market: MarketKind) -> Feed {
        let map = InstrumentMap::new(Venue::Binance, market, &[instrument("BTCUSDT", market)])
            .expect("valid");
        Feed::new(BinanceHandler::new(map))
    }

    fn spot() -> Feed {
        binance(MarketKind::Spot)
    }

    fn perp() -> Feed {
        binance(MarketKind::LinearPerp)
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

    const AGG_TRADE: &str = r#"{"stream":"btcusdt@aggTrade","data":{
        "e":"aggTrade","E":1754582400123,"s":"BTCUSDT","a":12345,
        "p":"64312.10","q":"0.05","f":100,"l":105,"T":1754582400100,"m":true,"M":true}}"#;

    const MARK_PRICE: &str = r#"{"stream":"btcusdt@markPrice@1s","data":{
        "e":"markPriceUpdate","E":1754582400000,"s":"BTCUSDT",
        "p":"64315.00000000","i":"64310.00000000","P":"64320.00000000",
        "r":"0.00010000","T":1754596800000}}"#;

    #[test]
    fn a_failed_snapshot_asks_for_a_resync() {
        let failed = r#"{"stream":"btcusdt@depthSnapshot","error":"HTTP status 429"}"#;
        assert!(matches!(spot().refused(failed), DecodeError::Resync(_)));
    }

    #[test]
    fn spot_book_ticker_has_no_exchange_timestamp() {
        let observations = spot().decoded(SPOT_BOOK_TICKER);
        let [quote] = observations.as_slice() else {
            panic!("one observation: {observations:?}");
        };
        assert_eq!(quote.kind, ObsKind::BookTop);
        assert_eq!(quote.bid, Some(fixed("64312")));
        assert_eq!(quote.ask, Some(fixed("64313")));
        assert_eq!(quote.bid_qty, Some(fixed("1.25")));
        assert_eq!(quote.price, fixed("64312.5"));
        assert_eq!(quote.seq, Some(400_900_217));
        // The whole reason the field is optional.
        assert_eq!(quote.exchange_time_ns, None);
        assert_eq!(quote.venue_lag_ns(), None);
        assert_eq!(quote.local_recv_ns, RECV_NS);
    }

    #[test]
    fn futures_book_ticker_carries_an_exchange_timestamp() {
        let quote = perp().decoded(PERP_BOOK_TICKER).remove(0);
        assert_eq!(
            quote.exchange_time_ns,
            Some(millis_to_nanos(1_754_582_400_123))
        );
        // `E` is 377 ms before the receipt.
        assert_eq!(quote.venue_lag_ns(), Some(377_000_000));
        assert_eq!(quote.instrument.market, MarketKind::LinearPerp);
    }

    #[test]
    fn agg_trade_uses_the_trade_time_not_the_event_time() {
        let trade = spot().decoded(AGG_TRADE).remove(0);
        assert_eq!(trade.kind, ObsKind::Trade);
        assert_eq!(trade.price, fixed("64312.1"));
        // T = 1754582400100, not E = 1754582400123.
        assert_eq!(
            trade.exchange_time_ns,
            Some(millis_to_nanos(1_754_582_400_100))
        );
        assert_eq!(trade.seq, Some(12_345));
        assert!(trade.bid.is_none(), "a trade print carries no book");
    }

    #[test]
    fn mark_price_yields_three_observations() {
        let observations = perp().decoded(MARK_PRICE);
        assert_eq!(
            kinds(&observations),
            [ObsKind::MarkPrice, ObsKind::IndexPrice, ObsKind::Funding]
        );
        let prices: Vec<_> = observations.iter().map(|o| o.price).collect();
        assert_eq!(prices, [fixed("64315"), fixed("64310"), fixed("0.0001")]);
    }

    /// Binance has no open-interest stream, so a REST frame holds the value
    /// until the next mark price carries it.
    #[test]
    fn the_open_interest_frame_reaches_the_next_funding_update() {
        let mut perp = perp();
        let frame = r#"{"stream":"btcusdt@openInterest","data":{"symbol":"BTCUSDT","openInterest":"93697.961","time":1754582400000}}"#;
        assert!(perp.refused(frame).is_benign(), "no observation of its own");
        let open_interest = |perp: &mut Feed| {
            let out = perp.decoded(MARK_PRICE);
            let funding = out
                .iter()
                .find(|o| o.kind == ObsKind::Funding)
                .expect("funding");
            funding
                .funding
                .as_deref()
                .and_then(|info| info.open_interest)
        };
        let expected = Some((fixed("93697.961"), OpenInterestUnit::Base));
        assert_eq!(open_interest(&mut perp), expected);

        // A failed fetch is counted, and the last value stays.
        let failed = r#"{"stream":"btcusdt@openInterest","error":"HTTP status 429"}"#;
        assert!(!perp.refused(failed).is_benign());
        assert_eq!(open_interest(&mut perp), expected);
    }

    #[test]
    fn mark_price_tolerates_a_missing_index_or_funding_rate() {
        let payload = r#"{"stream":"btcusdt@markPrice@1s","data":{
            "e":"markPriceUpdate","E":1754582400000,"s":"BTCUSDT",
            "p":"64315.0","T":1754596800000}}"#;
        assert_eq!(kinds(&perp().decoded(payload)), [ObsKind::MarkPrice]);
    }

    #[test]
    fn negative_funding_rates_decode() {
        let payload = r#"{"stream":"btcusdt@markPrice@1s","data":{
            "e":"markPriceUpdate","E":1754582400000,"s":"BTCUSDT",
            "p":"64315.0","r":"-0.00012500","T":1754596800000}}"#;
        let observations = perp().decoded(payload);
        let funding = observations
            .iter()
            .find(|o| o.kind == ObsKind::Funding)
            .expect("funding");
        assert_eq!(funding.price, fixed("-0.000125"));
    }

    #[test]
    fn subscription_acknowledgements_are_benign() {
        assert_eq!(
            spot().refused(r#"{"result":null,"id":1}"#),
            DecodeError::Control
        );
    }

    #[test]
    fn error_objects_are_benign() {
        let error = spot().refused(r#"{"code":-1121,"msg":"Invalid symbol."}"#);
        assert!(error.is_benign(), "got {error:?}");
    }

    #[test]
    fn untracked_symbols_and_streams_are_benign() {
        let unknown_symbol = r#"{"stream":"ethusdt@bookTicker","data":{
            "u":1,"s":"ETHUSDT","b":"1","B":"1","a":"2","A":"1"}}"#;
        let error = spot().refused(unknown_symbol);
        assert!(matches!(error, DecodeError::UnknownInstrument(_)) && error.is_benign());

        let unknown_stream = r#"{"stream":"btcusdt@kline_1m","data":{}}"#;
        let error = spot().refused(unknown_stream);
        assert!(matches!(error, DecodeError::UnhandledStream(_)) && error.is_benign());
    }

    #[test]
    fn malformed_payloads_are_not_benign() {
        for payload in [
            "not json",
            "{}",
            r#"{"stream":"btcusdt@bookTicker","data":{"u":1,"s":"BTCUSDT"}}"#,
        ] {
            let error = spot().refused(payload);
            assert!(
                !error.is_benign(),
                "{payload:?} produced a benign error: {error:?}"
            );
        }
    }

    #[test]
    fn non_numeric_prices_are_reported_with_the_offending_value() {
        let payload = r#"{"stream":"btcusdt@bookTicker","data":{
            "u":1,"s":"BTCUSDT","b":"not-a-price","B":"1","a":"2","A":"1"}}"#;
        let DecodeError::Lost { instrument, error } = spot().refused(payload) else {
            panic!("a lost quote");
        };
        assert_eq!(&*instrument.symbol, "BTCUSDT");
        assert_eq!(
            *error,
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
        let quote = spot().decoded(payload).remove(0);
        assert_eq!(quote.bid, Some(fixed("0.00000001")));
        assert_eq!(quote.bid_qty, Some(fixed("12345.67891234")));
        assert_eq!(quote.price, fixed("0.000000015"));
    }

    #[test]
    fn lowercase_symbols_in_payloads_still_map() {
        let payload = r#"{"stream":"btcusdt@bookTicker","data":{
            "u":1,"s":"btcusdt","b":"1","B":"1","a":"2","A":"1"}}"#;
        assert_eq!(spot().decoded(payload).len(), 1);
    }

    #[test]
    fn a_crossed_book_decodes_and_is_flagged_rather_than_repaired() {
        // Dropping it is the aggregator's call; the decoder must not silently fix it.
        let payload = r#"{"stream":"btcusdt@bookTicker","data":{
            "u":1,"s":"BTCUSDT","b":"64313","B":"1","a":"64312","A":"1"}}"#;
        assert!(
            spot()
                .decoded(payload)
                .first()
                .is_some_and(Observation::is_crossed)
        );
    }
}
