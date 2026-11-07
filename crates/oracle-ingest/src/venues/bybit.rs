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

use crate::book::{BookMsg, BookRule, Books, Change, Continuity, LastFunding};
use crate::clock::millis_to_nanos;
use crate::instrument::InstrumentEntry;
use crate::{DecodeError, InstrumentMap};

use super::{decimal, integer, observation, parse};

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

/// The topic prefix of the kept book, `orderbook.{BOOK_DEPTH}.`.
const BOOK_TOPIC: &str = "orderbook.50.";
const _: () = assert!(BOOK_DEPTH == 50);

/// The update id `u` rises by one; a snapshot, or `u = 1`, starts again.
const BOOK_RULE: BookRule = BookRule::new(Continuity::NextSequence).depth(BOOK_DEPTH);

/// `orderbook.1` follows the same rule at one level a side, so a delta applies
/// as a delta and gives only the best bid and ask.
const TOP_RULE: BookRule = BookRule::new(Continuity::NextSequence).depth(1).shown(1);

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

/// Decodes one Bybit payload. `orderbook.50` and the ticker's funding fields
/// are kept in `books`.
///
/// # Errors
///
/// Returns [`DecodeError`]. Subscription acknowledgements and pong replies are
/// benign; a book update id that skips is [`DecodeError::Resync`].
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> = serde_json::from_slice(payload)?;
    let (Some(topic), Some(data)) = (envelope.topic, envelope.data) else {
        // Subscribe acknowledgements and pongs carry `op`, not `topic`.
        return Err(DecodeError::Control);
    };
    if topic.starts_with(BOOK_TOPIC) {
        let message: OrderBook<'_> = parse(data).map_err(|e| BOOK_RULE.unparsed(e))?;
        let entry = lookup(map, message.symbol)?;
        let snapshot = envelope.kind == Some("snapshot");
        let parsed =
            book_message(&message, snapshot).map(|book| book.at(envelope.ts.map(millis_to_nanos)));
        return books
            .keeper
            .apply(BOOK_RULE, entry, parsed, local_recv_ns, out);
    }
    if topic.starts_with("orderbook.") {
        let snapshot = envelope.kind == Some("snapshot");
        return decode_top(data, snapshot, map, books, local_recv_ns, out);
    }
    if topic.starts_with("publicTrade.") {
        return decode_trades(data, map, local_recv_ns, out);
    }
    if topic.starts_with("tickers.") {
        return decode_ticker(data, map, envelope.ts, local_recv_ns, books, out);
    }
    Err(DecodeError::UnhandledStream(topic.to_owned()))
}

fn lookup<'m>(map: &'m InstrumentMap, symbol: &str) -> Result<&'m InstrumentEntry, DecodeError> {
    map.lookup(symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(symbol.to_owned()))
}

/// One `orderbook.50` message. An update id of 1 is Bybit restarting the
/// book: a snapshot by another name.
fn book_message<'a>(message: &OrderBook<'a>, snapshot: bool) -> Result<BookMsg<'a>, DecodeError> {
    let update_id = message.update_id.ok_or(DecodeError::MissingField("u"))?;
    let change = |level: &Vec<&'a str>| match level.as_slice() {
        [price, size, ..] => Ok(Change::from(crate::depth::level(price, size)?)),
        _ => Err(DecodeError::MissingField("book level")),
    };
    Ok(BookMsg {
        snapshot: snapshot || update_id == 1,
        next_id: Some(update_id),
        ..BookMsg::changes(&message.bids, &message.asks, change)?
    })
}

/// `orderbook.1`, the best level a side, kept apart from `orderbook.50`.
fn decode_top(
    data: &serde_json::value::RawValue,
    snapshot: bool,
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let message: OrderBook<'_> = parse(data).map_err(|e| TOP_RULE.unparsed(e))?;
    let entry = lookup(map, message.symbol)?;
    let parsed = book_message(&message, snapshot);
    books
        .tops
        .apply(TOP_RULE, entry, parsed, local_recv_ns, out)
}

fn decode_trades(
    data: &serde_json::value::RawValue,
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let trades: Vec<Trade<'_>> = parse(data)?;
    let mut seen = false;
    for trade in trades {
        let Some(entry) = map.lookup(trade.symbol) else {
            continue;
        };
        seen = true;
        out.push(Observation {
            exchange_time_ns: Some(millis_to_nanos(trade.time_ms)),
            ..observation(
                entry,
                ObsKind::Trade,
                decimal("p", trade.price)?,
                local_recv_ns,
            )
        });
    }
    if seen {
        Ok(())
    } else {
        Err(DecodeError::Control)
    }
}

/// Decodes a ticker. A delta's funding fields merge into the last ones in
/// `books`, so each funding observation has the whole state.
fn decode_ticker(
    data: &serde_json::value::RawValue,
    map: &InstrumentMap,
    ts: Option<u64>,
    local_recv_ns: u64,
    books: &mut Books,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let ticker: Ticker<'_> = parse(data)?;
    let entry = lookup(map, ticker.symbol)?;

    let exchange_time_ns = ts.map(millis_to_nanos);
    let mut push = |kind: ObsKind, price: Fixed, funding: Option<Arc<FundingInfo>>| {
        out.push(Observation {
            exchange_time_ns,
            funding,
            ..observation(entry, kind, price, local_recv_ns)
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
    let last = books.funding(&entry.instrument);
    last.rate = fresh.rate.or(last.rate);
    last.interval_ns = fresh.interval_ns.or(last.interval_ns);
    last.next_funding_time_ns = fresh.next_funding_time_ns.or(last.next_funding_time_ns);
    last.open_interest = fresh.open_interest.or(last.open_interest);
    fresh = *last;
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
    reason = "fixed payloads; an out-of-range index is a failing test"
)]
mod tests {
    use super::*;
    use crate::testing::{Feed, RECV_NS, fixed, instrument, kinds};
    use oracle_types::Venue;

    fn bybit(market: MarketKind) -> Feed {
        Feed::venue(
            decode,
            Venue::Bybit,
            market,
            &[instrument("BTCUSDT", market)],
        )
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
        let quote = &bybit(MarketKind::Spot).decoded(BOOK)[0];
        assert_eq!(quote.kind, ObsKind::BookTop);
        assert_eq!(quote.bid, Some(fixed("64312")));
        assert_eq!(quote.ask, Some(fixed("64313")));
        assert_eq!(quote.bid_qty, Some(fixed("0.5")));
        assert_eq!(quote.price, fixed("64312.5"));
        assert_eq!(quote.seq, Some(18_521_288));
        assert_eq!(quote.local_recv_ns, RECV_NS);
    }

    #[test]
    fn a_trade_uses_its_own_timestamp() {
        let trade = &bybit(MarketKind::Spot).decoded(TRADE)[0];
        assert_eq!(trade.kind, ObsKind::Trade);
        assert_eq!(trade.price, fixed("64312.1"));
        assert_eq!(
            trade.exchange_time_ns,
            Some(millis_to_nanos(1_754_582_400_100))
        );
    }

    #[test]
    fn a_ticker_yields_mark_index_and_funding() {
        let observations = bybit(MarketKind::LinearPerp).decoded(TICKER);
        assert_eq!(
            kinds(&observations),
            [ObsKind::MarkPrice, ObsKind::IndexPrice, ObsKind::Funding]
        );
        assert_eq!(observations[0].price, fixed("64315"));
    }

    /// After the first snapshot, `tickers` sends only what changed.
    #[test]
    fn a_ticker_delta_emits_only_the_fields_present() {
        let delta = r#"{"topic":"tickers.BTCUSDT","type":"delta","ts":1754582400123,
            "data":{"symbol":"BTCUSDT","markPrice":"64320.00"}}"#;
        let observations = bybit(MarketKind::LinearPerp).decoded(delta);
        assert_eq!(
            kinds(&observations),
            [ObsKind::MarkPrice],
            "absent means unchanged, not zero"
        );
    }

    #[test]
    fn a_ticker_delta_with_nothing_we_track_is_benign() {
        let delta = r#"{"topic":"tickers.BTCUSDT","type":"delta","ts":1,
            "data":{"symbol":"BTCUSDT","volume24h":"123"}}"#;
        assert!(bybit(MarketKind::LinearPerp).refused(delta).is_benign());
    }

    /// The level-1 change after [`BOOK`], with `bids` and `asks` as its levels.
    fn top_delta(bids: &str, asks: &str) -> String {
        format!(
            r#"{{"topic":"orderbook.1.BTCUSDT","type":"delta","ts":1,
            "data":{{"s":"BTCUSDT","b":{bids},"a":{asks},"u":18521289}}}}"#
        )
    }

    /// A level-1 delta changes only what it names: an empty list keeps that side.
    #[test]
    fn a_top_of_book_delta_applies_as_a_delta() {
        let mut spot = bybit(MarketKind::Spot);
        let _ = spot.decoded(BOOK);
        let quote = spot.decoded(top_delta("[]", r#"[["64313.50","0.1"]]"#));
        let [top] = quote.as_slice() else {
            panic!("one quote: {quote:?}");
        };
        assert_eq!(
            (top.bid, top.ask),
            (Some(fixed("64312")), Some(fixed("64313")))
        );
        assert_eq!(top.seq, Some(18_521_289));
    }

    #[test]
    fn a_top_of_book_delta_that_empties_a_side_halts_the_quote() {
        let mut spot = bybit(MarketKind::Spot);
        let _ = spot.decoded(BOOK);
        let (_, halted) = spot.halted(top_delta(r#"[["64312.00","0"]]"#, "[]"));
        assert_eq!(halted, ["BTCUSDT"]);
    }

    /// A delta before any snapshot has no book to change.
    #[test]
    fn a_top_of_book_delta_before_a_snapshot_resyncs() {
        let error = bybit(MarketKind::Spot).refused(top_delta("[]", "[]"));
        assert!(matches!(error, DecodeError::Resync(_)), "{error:?}");
    }

    #[test]
    fn acknowledgements_and_pongs_are_benign() {
        let mut spot = bybit(MarketKind::Spot);
        for control in [
            r#"{"success":true,"ret_msg":"","op":"subscribe","conn_id":"abc"}"#,
            r#"{"success":true,"ret_msg":"pong","op":"ping","conn_id":"abc"}"#,
        ] {
            let error = spot.refused(control);
            assert!(error.is_benign(), "got {error:?}");
        }
    }

    #[test]
    fn untracked_symbols_are_benign() {
        let other = BOOK.replace("BTCUSDT", "ETHUSDT");
        assert!(bybit(MarketKind::Spot).refused(other).is_benign());
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
}
