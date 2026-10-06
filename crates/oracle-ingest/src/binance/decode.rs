//! Decoding Binance combined-stream payloads into observations.
//!
//! Pure: bytes and a receipt timestamp in, observations out. No clock, no socket,
//! no async. That is what lets the tests below run against captured payloads
//! rather than a live exchange.

use oracle_types::{Fixed, ObsKind, Observation};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::clock::millis_to_nanos;
use crate::{DecodeError, InstrumentMap};

use super::streams::StreamKind;

/// The combined-stream envelope: `{"stream":"btcusdt@bookTicker","data":{…}}`.
#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow)]
    stream: &'a str,
    data: &'a RawValue,
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
}

/// Partial book depth. Spot sends `bids` and `asks` and no symbol, so the
/// symbol comes from the stream name; futures sends `b`, `a`, `s` and `E`.
#[derive(Deserialize)]
struct PartialDepth<'a> {
    #[serde(alias = "b", borrow)]
    bids: Vec<[&'a str; 2]>,
    #[serde(alias = "a", borrow)]
    asks: Vec<[&'a str; 2]>,
    #[serde(rename = "s", borrow, default)]
    symbol: Option<&'a str>,
    #[serde(rename = "E", default)]
    event_time_ms: Option<u64>,
    #[serde(rename = "lastUpdateId", alias = "u", default)]
    update_id: Option<u64>,
}

/// Parses a decimal field.
fn decimal(field: &'static str, value: &str) -> Result<Fixed, DecodeError> {
    value.parse().map_err(|_| DecodeError::BadDecimal {
        field,
        value: value.to_owned(),
    })
}

/// Decodes one combined-stream payload.
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
    let data = envelope.data.get().as_bytes();

    match kind {
        StreamKind::BookTicker => decode_book_ticker(data, map, local_recv_ns, out),
        StreamKind::AggTrade => decode_agg_trade(data, map, local_recv_ns, out),
        StreamKind::MarkPrice => decode_mark_price(data, map, local_recv_ns, out),
        StreamKind::Depth => decode_depth(envelope.stream, data, map, local_recv_ns, out),
    }
}

fn decode_depth(
    stream: &str,
    data: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let depth: PartialDepth<'_> =
        serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let symbol = depth
        .symbol
        .unwrap_or_else(|| stream.split('@').next().unwrap_or(stream));
    let entry = map
        .lookup(symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(symbol.to_owned()))?;
    let side = |levels: &[[&str; 2]]| {
        levels
            .iter()
            .map(|[price, qty]| crate::depth::level(price, qty))
            .collect::<Result<Vec<_>, _>>()
    };
    if let Some(observation) = crate::depth::observation(
        entry.instrument.clone(),
        side(&depth.bids)?,
        side(&depth.asks)?,
        depth.event_time_ms.map(millis_to_nanos),
        local_recv_ns,
        depth.update_id,
    ) {
        out.push(observation);
    }
    Ok(())
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
    });
    Ok(())
}

fn decode_mark_price(
    data: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let update: MarkPrice<'_> =
        serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let entry = map
        .lookup(update.symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(update.symbol.to_owned()))?;

    let exchange_time_ns = Some(millis_to_nanos(update.event_time_ms));
    let mut push = |kind: ObsKind, price: Fixed| {
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
        });
    };

    push(ObsKind::MarkPrice, decimal("p", update.mark)?);
    if let Some(index) = update.index {
        push(ObsKind::IndexPrice, decimal("i", index)?);
    }
    if let Some(rate) = update.funding_rate {
        // Emitted raw, over whatever interval Binance uses for this contract —
        // 8 hours for most, 4 for some, and the message does not say which. The
        // interval has to come from instrument metadata before this can be
        // normalized to the `FUNDING_8H` feed. See SPEC.md §13, open question 3.
        push(ObsKind::Funding, decimal("r", rate)?);
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

    /// Spot partial depth: `bids` and `asks`, no symbol, no event time.
    const SPOT_DEPTH: &str = r#"{"stream":"btcusdt@depth20@100ms","data":{
        "lastUpdateId":160,
        "bids":[["64312.00","1.5"],["64311.50","2.0"]],
        "asks":[["64313.00","0.8"],["64314.00","3.0"]]}}"#;

    /// Futures partial depth: `b`, `a`, `s` and `E`, bids not best first.
    const PERP_DEPTH: &str = r#"{"stream":"btcusdt@depth20@100ms","data":{
        "e":"depthUpdate","E":1754582400123,"T":1754582400120,"s":"BTCUSDT",
        "U":390497796,"u":390497878,"pu":390497794,
        "b":[["64311.0","2.0"],["64311.5","3.0"]],
        "a":[["64312.5","1.0"],["64313.0","4.0"]]}}"#;

    #[test]
    fn spot_depth_takes_its_symbol_from_the_stream_name() {
        let out = decode(SPOT_DEPTH, &spot_map());
        let [depth] = out.as_slice() else {
            panic!("one observation: {out:?}");
        };
        assert_eq!(depth.kind, ObsKind::Depth);
        assert_eq!(depth.bid, Some("64312.00".parse().expect("valid")));
        assert_eq!(depth.ask, Some("64313.00".parse().expect("valid")));
        assert_eq!(depth.seq, Some(160));
        let book = depth.book.as_deref().expect("levels");
        assert_eq!((book.bids.len(), book.asks.len()), (2, 2));
    }

    #[test]
    fn futures_depth_is_sorted_best_first() {
        let out = decode(PERP_DEPTH, &perp_map());
        let [depth] = out.as_slice() else {
            panic!("one observation: {out:?}");
        };
        assert_eq!(depth.bid, Some("64311.5".parse().expect("valid")));
        assert_eq!(depth.exchange_time_ns, Some(1_754_582_400_123_000_000));
        let book = depth.book.as_deref().expect("levels");
        assert!(
            book.bids
                .windows(2)
                .all(|pair| matches!(pair, [high, low] if high.price > low.price))
        );
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
