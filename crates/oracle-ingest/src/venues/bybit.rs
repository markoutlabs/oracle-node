//! Bybit v5 public streams.
//!
//! - Spot and linear perpetuals live on **different hosts** and fail
//!   independently, so they get separate connections.
//! - Requires an application keepalive, `{"op":"ping"}`, roughly every 20s. A
//!   WebSocket ping is not enough.
//! - `tickers` on linear sends a **snapshot then deltas**: after the first
//!   message, fields that did not change are absent. Every numeric field is
//!   therefore optional, and a missing one means "unchanged", not "zero".

use std::sync::Arc;
use std::time::Duration;

use oracle_types::{
    Fixed, FundingBasis, FundingInfo, MarketKind, NANOS_PER_SEC, ObsKind, Observation,
    OpenInterestUnit,
};
use serde::Deserialize;

use crate::book::{Books, LastFunding, Side};
use crate::clock::millis_to_nanos;
use crate::{DecodeError, InstrumentMap};

use super::{decimal, integer};

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

/// Book levels kept per side: Bybit's `orderbook.50`.
pub const BOOK_DEPTH: usize = 50;

/// Topics in one spot subscribe request. Bybit refuses the whole request past
/// this (`args size >10`); tested on 2026-10-10. Its perpetuals take more.
pub const SPOT_MAX_ARGS: usize = 10;

/// Builds the subscribe frames for a market's instruments, each with whether it
/// wants the book.
///
/// Chunked because Bybit caps arguments per request; separate frames on one
/// connection are cheaper than separate connections. A spot frame never has
/// more than [`SPOT_MAX_ARGS`].
#[must_use]
pub fn subscribe_frames<'a>(
    instruments: impl Iterator<Item = (&'a str, bool)>,
    market: MarketKind,
    chunk: usize,
) -> Vec<String> {
    let mut topics: Vec<String> = Vec::new();
    for (symbol, depth) in instruments {
        if depth {
            topics.push(format!("orderbook.{BOOK_DEPTH}.{symbol}"));
        }
        topics.push(format!("orderbook.1.{symbol}"));
        topics.push(format!("publicTrade.{symbol}"));
        // `tickers` is where mark, index and funding live, and only perpetuals
        // have them — on spot it would be a throttled duplicate of the book.
        if market.is_perp() {
            topics.push(format!("tickers.{symbol}"));
        }
    }
    topics.sort_unstable();
    let chunk = if market.is_perp() {
        chunk
    } else {
        chunk.min(SPOT_MAX_ARGS)
    };
    topics
        .chunks(chunk.max(1))
        .map(|group| serde_json::json!({ "op": "subscribe", "args": group }).to_string())
        .collect()
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow, default)]
    topic: Option<&'a str>,
    /// `snapshot` or `delta`, on book topics.
    #[serde(rename = "type", borrow, default)]
    kind: Option<&'a str>,
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
    #[serde(rename = "fundingIntervalHour", borrow, default)]
    funding_interval_hours: Option<&'a str>,
    /// Milliseconds, as a string.
    #[serde(rename = "nextFundingTime", borrow, default)]
    next_funding_time: Option<&'a str>,
    /// In the base asset for a linear contract.
    #[serde(rename = "openInterest", borrow, default)]
    open_interest: Option<&'a str>,
}

/// The session's entry point: `orderbook.50` is kept in `books`; every other
/// topic goes to [`decode_payload`].
///
/// # Errors
///
/// As [`decode_payload`], and [`DecodeError::Resync`] when an update id skips.
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let book_topic = format!("orderbook.{BOOK_DEPTH}.");
    let (Some(topic), Some(data)) = (envelope.topic, envelope.data) else {
        return decode_payload(payload, map, local_recv_ns, out);
    };
    if topic.starts_with("tickers.") {
        let data = data.get().as_bytes();
        return decode_ticker(data, map, envelope.ts, local_recv_ns, Some(books), out);
    }
    if !topic.starts_with(&book_topic) {
        return decode_payload(payload, map, local_recv_ns, out);
    }
    let message: OrderBook<'_> =
        serde_json::from_str(data.get()).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let entry = map
        .lookup(message.symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(message.symbol.to_owned()))?;
    let update_id = message.update_id.ok_or(DecodeError::MissingField("u"))?;
    let book = books.book(message.symbol);
    // An update id of 1 is Bybit restarting the book: a snapshot by another name.
    if envelope.kind == Some("snapshot") || update_id == 1 {
        book.clear();
    } else if book.last_id.and_then(|last| last.checked_add(1)) != Some(update_id) {
        return Err(DecodeError::Resync(format!(
            "{}: update {update_id} does not follow {:?}",
            message.symbol, book.last_id
        )));
    }
    book.last_id = Some(update_id);
    for (side, levels) in [(Side::Bid, &message.bids), (Side::Ask, &message.asks)] {
        for level in levels {
            let (Some(price), Some(size)) = (level.first(), level.get(1)) else {
                continue;
            };
            let parsed = crate::depth::level(price, size)?;
            book.set(side, parsed.price, parsed.qty);
        }
    }
    book.truncate(BOOK_DEPTH);
    books.emit(
        message.symbol,
        entry.instrument.clone(),
        envelope.ts.map(millis_to_nanos),
        local_recv_ns,
        out,
    )
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
        return decode_ticker(data, map, envelope.ts, local_recv_ns, None, out);
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
        book: None,
        funding: None,
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
            book: None,
            funding: None,
        });
    }
    if seen {
        Ok(())
    } else {
        Err(DecodeError::Control)
    }
}

/// Decodes a ticker. With the connection's `books`, a delta's funding fields
/// merge into the last ones, so each funding observation has the whole state.
fn decode_ticker(
    data: &[u8],
    map: &InstrumentMap,
    ts: Option<u64>,
    local_recv_ns: u64,
    books: Option<&mut Books>,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let ticker: Ticker<'_> =
        serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let entry = map
        .lookup(ticker.symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(ticker.symbol.to_owned()))?;

    let exchange_time_ns = ts.map(millis_to_nanos);
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

    // Deltas omit unchanged fields. Absent means unchanged, not zero.
    let mut emitted = false;
    if let Some(mark) = ticker.mark_price {
        push(ObsKind::MarkPrice, decimal("markPrice", mark)?, None);
        emitted = true;
    }
    if let Some(index) = ticker.index_price {
        push(ObsKind::IndexPrice, decimal("indexPrice", index)?, None);
        emitted = true;
    }
    let mut fresh = LastFunding {
        rate: ticker
            .funding_rate
            .map(|rate| decimal("fundingRate", rate))
            .transpose()?,
        interval_ns: ticker
            .funding_interval_hours
            .map(|hours| integer("fundingIntervalHour", hours))
            .transpose()?
            .map(|hours| hours.saturating_mul(3_600 * NANOS_PER_SEC)),
        next_funding_time_ns: ticker
            .next_funding_time
            .map(|ms| integer("nextFundingTime", ms))
            .transpose()?
            .filter(|ms| *ms > 0)
            .map(millis_to_nanos),
        open_interest: ticker
            .open_interest
            .map(|oi| decimal("openInterest", oi))
            .transpose()?,
        predicted: None,
        settled: None,
    };
    let changed = fresh != LastFunding::default();
    if let Some(books) = books {
        let last = books.funding(ticker.symbol);
        last.rate = fresh.rate.or(last.rate);
        last.interval_ns = fresh.interval_ns.or(last.interval_ns);
        last.next_funding_time_ns = fresh.next_funding_time_ns.or(last.next_funding_time_ns);
        last.open_interest = fresh.open_interest.or(last.open_interest);
        fresh = *last;
    }
    if let (true, Some(rate)) = (changed, fresh.rate) {
        let info = FundingInfo {
            interval_ns: fresh.interval_ns,
            next_funding_time_ns: fresh.next_funding_time_ns,
            open_interest: fresh.open_interest.map(|oi| (oi, OpenInterestUnit::Base)),
            ..FundingInfo::new(FundingBasis::Interval)
        };
        push(ObsKind::Funding, rate, Some(Arc::new(info)));
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
        let spot = subscribe_frames([("BTCUSDT", false)].into_iter(), MarketKind::Spot, 10);
        assert_eq!(spot.len(), 1);
        assert!(spot[0].contains("orderbook.1.BTCUSDT"));
        assert!(spot[0].contains("publicTrade.BTCUSDT"));
        assert!(!spot[0].contains("tickers"), "spot has no mark price");

        let perp = subscribe_frames([("BTCUSDT", false)].into_iter(), MarketKind::LinearPerp, 10);
        assert!(perp[0].contains("tickers.BTCUSDT"));
        assert!(!perp[0].contains("orderbook.50"));

        let depth = subscribe_frames([("BTCUSDT", true)].into_iter(), MarketKind::Spot, 10);
        assert!(depth[0].contains("orderbook.50.BTCUSDT"));
    }

    #[test]
    fn subscribe_frames_are_chunked() {
        let symbols = ["BTCUSDT", "ETHUSDT", "SOLUSDT"].map(|symbol| (symbol, false));
        let frames = subscribe_frames(symbols.into_iter(), MarketKind::Spot, 2);
        assert_eq!(frames.len(), 3, "six topics at two per frame");
    }

    /// Bybit refuses a whole spot request with more than ten topics, so a
    /// large chunk must not reach spot. Perpetuals keep the chunk asked for.
    #[test]
    fn spot_frames_never_exceed_ten_topics() {
        let symbols: Vec<String> = (0..40).map(|index| format!("A{index}USDT")).collect();
        let instruments = || symbols.iter().map(|symbol| (symbol.as_str(), false));
        for frame in subscribe_frames(instruments(), MarketKind::Spot, 100) {
            let value: serde_json::Value = serde_json::from_str(&frame).expect("json");
            let args = value
                .get("args")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len);
            assert!(args.is_some_and(|count| count <= SPOT_MAX_ARGS), "{frame}");
        }
        let linear = subscribe_frames(instruments(), MarketKind::LinearPerp, 100);
        assert_eq!(linear.len(), 2, "120 topics at 100 per frame");
    }

    #[test]
    fn spot_and_linear_use_different_hosts() {
        assert_ne!(url(MarketKind::Spot), url(MarketKind::LinearPerp));
    }

    /// Recorded from Bybit spot on 2026-10-06: the subscribe reply, a snapshot,
    /// and the deltas after it.
    const RECORDED_BOOK: &str = include_str!("../../tests/fixtures/bybit-book.jsonl");

    fn book_map() -> InstrumentMap {
        let specs = vec![
            InstrumentSpec::new("BTCUSDT", MarketKind::Spot, "CRYPTO.BTC/USDT")
                .expect("valid")
                .with_depth(),
        ];
        InstrumentMap::new(Venue::Bybit, MarketKind::Spot, &specs).expect("valid")
    }

    #[test]
    fn a_recorded_book_follows_its_update_ids() {
        let map = book_map();
        let mut books = Books::default();
        let mut depths = 0;
        for line in RECORDED_BOOK.lines() {
            let mut out = Vec::new();
            match super::decode(line.as_bytes(), &map, &mut books, RECV, &mut out) {
                Ok(()) => {}
                Err(error) if error.is_benign() => {}
                Err(error) => panic!("{error}: {line}"),
            }
            depths += out.iter().filter(|o| o.kind == ObsKind::Depth).count();
        }
        assert!(depths >= 12, "{depths}");
        let book = books.book("BTCUSDT");
        assert!(
            book.top(crate::book::Side::Bid, 1)[0].price
                < book.top(crate::book::Side::Ask, 1)[0].price
        );
    }

    #[test]
    fn a_skipped_update_asks_for_a_resync() {
        let map = book_map();
        let mut books = Books::default();
        let mut lines = RECORDED_BOOK
            .lines()
            .filter(|line| line.contains(r#""type":"#));
        let snapshot = lines.next().expect("a snapshot");
        super::decode(snapshot.as_bytes(), &map, &mut books, RECV, &mut Vec::new()).expect("valid");
        let _skipped = lines.next().expect("a delta");
        let after = lines.next().expect("a later delta");
        assert!(matches!(
            super::decode(after.as_bytes(), &map, &mut books, RECV, &mut Vec::new()),
            Err(DecodeError::Resync(_))
        ));
    }
}
