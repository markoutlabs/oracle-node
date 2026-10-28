//! Deribit v2 public streams.
//!
//! Deribit is a derivatives venue: perpetuals, futures and options, with no spot
//! market worth pricing from. Only its perpetuals are in scope.
//!
//! - **JSON-RPC 2.0**, not a bespoke envelope. Pushed data arrives as
//!   `{"method":"subscription","params":{"channel":…,"data":{…}}}`; anything with
//!   an `id` is a reply to something we sent.
//! - The `ticker` channel carries the whole picture in one message — book top,
//!   last trade, mark, index and funding — so one subscription per instrument is
//!   enough.
//! - **Bare JSON numbers**, like Kraken. Every numeric field goes through
//!   `RawValue` so the venue's own digits reach the aggregator.
//!
//! # Funding is already normalised
//!
//! Alone among the venues here, Deribit publishes `funding_8h` — a fraction over
//! a fixed eight-hour window, whatever its actual settlement cadence. It needs
//! no interval metadata to be comparable, which makes it the one funding source
//! that is safe to aggregate today. See SPEC.md §13, open question 3.
//!
//! # Inverse contracts quote size in USD
//!
//! `BTC-PERPETUAL` is coin-margined: its `best_bid_amount` is USD notional, not
//! BTC. Every other venue reports base units, so the amounts are converted on the
//! way in — see [`MarketKind::InversePerp`](oracle_types::MarketKind::InversePerp).

use std::sync::Arc;

use oracle_types::{
    Fixed, FundingBasis, FundingInfo, MarketKind, ObsKind, Observation, OpenInterestUnit,
};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{Books, Side};
use crate::clock::millis_to_nanos;
use crate::{DecodeError, InstrumentMap};

use super::decimal_literal;

/// The production endpoint.
pub const URL: &str = "wss://www.deribit.com/ws/api/v2";

/// A request that the session sends every [`KEEPALIVE_EVERY`]. Deribit closes a
/// public connection after 10 minutes without a request from the client, even
/// while it streams; tested on 2026-10-10.
pub const KEEPALIVE: &str = r#"{"jsonrpc":"2.0","id":0,"method":"public/test"}"#;

/// How often to send [`KEEPALIVE`].
pub const KEEPALIVE_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// The aggregation interval requested on the ticker channel.
///
/// `100ms` rather than `raw`, which is reserved for authenticated sessions, and
/// rather than `agg2`, whose two-second cadence would sit outside the staleness
/// threshold for a fast feed.
pub const TICKER_INTERVAL: &str = "100ms";

/// The book channel: a full snapshot, then the changes every 100ms, each
/// naming the change before it.
const BOOK_INTERVAL: &str = "100ms";

/// Builds the subscribe frames for a set of Deribit instrument names, each with
/// whether it wants depth snapshots.
///
/// One JSON-RPC request carrying every channel: Deribit accepts a list, and a
/// single request means a single reply to recognise and ignore.
#[must_use]
pub fn subscribe_frames<'a>(
    instruments: impl Iterator<Item = (&'a str, bool)>,
    chunk: usize,
) -> Vec<String> {
    let channels: Vec<String> = instruments
        .flat_map(|(name, depth)| {
            std::iter::once(format!("ticker.{name}.{TICKER_INTERVAL}"))
                .chain(depth.then(|| format!("book.{name}.{BOOK_INTERVAL}")))
        })
        .collect();
    channels
        .chunks(chunk.max(1))
        .enumerate()
        .map(|(index, group)| {
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": index + 1,
                "method": "public/subscribe",
                "params": { "channels": group },
            })
            .to_string()
        })
        .collect()
}

/// Returns `true` if a Deribit instrument name is coin-margined.
///
/// Deribit spells linear perpetuals with their settlement currency —
/// `BTC_USDC-PERPETUAL`, `BTC_USDT-PERPETUAL` — and inverse ones without —
/// `BTC-PERPETUAL`. The distinction decides whether `amount` is base or quote.
#[must_use]
pub fn is_inverse(instrument_name: &str) -> bool {
    !instrument_name.contains('_')
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow, default)]
    method: Option<&'a str>,
    #[serde(borrow, default)]
    params: Option<Params<'a>>,
}

#[derive(Deserialize)]
struct Params<'a> {
    #[serde(borrow, default)]
    channel: Option<&'a str>,
    #[serde(borrow, default)]
    data: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct Ticker<'a> {
    #[serde(rename = "instrument_name", borrow)]
    instrument_name: &'a str,
    #[serde(borrow, default)]
    state: Option<&'a str>,
    /// Milliseconds.
    #[serde(default)]
    timestamp: Option<u64>,
    #[serde(rename = "best_bid_price", borrow, default)]
    best_bid_price: Option<&'a RawValue>,
    #[serde(rename = "best_bid_amount", borrow, default)]
    best_bid_amount: Option<&'a RawValue>,
    #[serde(rename = "best_ask_price", borrow, default)]
    best_ask_price: Option<&'a RawValue>,
    #[serde(rename = "best_ask_amount", borrow, default)]
    best_ask_amount: Option<&'a RawValue>,
    #[serde(rename = "last_price", borrow, default)]
    last_price: Option<&'a RawValue>,
    #[serde(rename = "mark_price", borrow, default)]
    mark_price: Option<&'a RawValue>,
    #[serde(rename = "index_price", borrow, default)]
    index_price: Option<&'a RawValue>,
    /// Funding over a fixed eight-hour window, as a fraction.
    #[serde(rename = "funding_8h", borrow, default)]
    funding_8h: Option<&'a RawValue>,
    /// USD for an inverse perpetual, the base coin for a linear one.
    #[serde(rename = "open_interest", borrow, default)]
    open_interest: Option<&'a RawValue>,
}

/// A book message: a snapshot, or the levels that changed. Entries are
/// `[action, price, amount]`, the action `new`, `change` or `delete`.
#[derive(Deserialize)]
struct Book<'a> {
    #[serde(rename = "instrument_name", borrow)]
    instrument_name: &'a str,
    #[serde(rename = "type", borrow)]
    kind: &'a str,
    /// Milliseconds.
    #[serde(default)]
    timestamp: Option<u64>,
    change_id: u64,
    #[serde(default)]
    prev_change_id: Option<u64>,
    #[serde(borrow, default)]
    bids: Vec<(&'a str, &'a RawValue, &'a RawValue)>,
    #[serde(borrow, default)]
    asks: Vec<(&'a str, &'a RawValue, &'a RawValue)>,
}

/// The session's entry point: the book channel is kept in `books`; every other
/// channel goes to [`decode_payload`].
///
/// # Errors
///
/// As [`decode_payload`], and [`DecodeError::Resync`] when a change does not
/// follow the last one.
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let book_data = match envelope.params {
        Some(Params {
            channel: Some(channel),
            data: Some(data),
        }) if envelope.method == Some("subscription") && channel.starts_with("book.") => data,
        _ => return decode_payload(payload, map, local_recv_ns, out),
    };
    let message: Book<'_> =
        serde_json::from_str(book_data.get()).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let name = message.instrument_name;
    let Some(entry) = map.lookup(name) else {
        return Err(DecodeError::Control);
    };
    let inverse = entry.instrument.market == MarketKind::InversePerp;
    let book = books.book(name);
    if message.kind == "snapshot" {
        book.clear();
    } else if message.prev_change_id != book.last_id {
        return Err(DecodeError::Resync(format!(
            "{name}: change follows {:?} but the book is at {:?}",
            message.prev_change_id, book.last_id
        )));
    }
    book.last_id = Some(message.change_id);
    for (side, levels) in [(Side::Bid, &message.bids), (Side::Ask, &message.asks)] {
        for (action, price, amount) in levels {
            let price = decimal_literal("book price", price)?;
            let qty = if *action == "delete" {
                Fixed::ZERO
            } else {
                let amount = decimal_literal("book amount", amount)?;
                to_base_units(amount, price, inverse).unwrap_or(Fixed::ZERO)
            };
            book.set(side, price, qty);
        }
    }
    books.emit(
        name,
        entry.instrument.clone(),
        message.timestamp.map(millis_to_nanos),
        local_recv_ns,
        out,
    )
}

/// Decodes one Deribit payload.
///
/// # Errors
///
/// Returns [`DecodeError`]. Subscribe replies and heartbeats are benign.
pub fn decode_payload(
    payload: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;

    // Replies to our own requests carry `id` and `result`, never `method`.
    let Some("subscription") = envelope.method else {
        return Err(DecodeError::Control);
    };
    let (Some(channel), Some(data)) = envelope
        .params
        .map_or((None, None), |params| (params.channel, params.data))
    else {
        return Err(DecodeError::Control);
    };
    if !channel.starts_with("ticker.") {
        return Err(DecodeError::UnhandledStream(channel.to_owned()));
    }

    let ticker: Ticker<'_> =
        serde_json::from_str(data.get()).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let Some(entry) = map.lookup(ticker.instrument_name) else {
        return Err(DecodeError::Control);
    };
    // Deribit keeps publishing a ticker for a closed instrument. The session
    // stops confirming its last values, so the staleness filter sheds them.
    if ticker.state.is_some_and(|state| state != "open") {
        return Err(DecodeError::Halted(entry.instrument.clone()));
    }
    let exchange_time_ns = ticker.timestamp.map(millis_to_nanos);
    let inverse = entry.instrument.market == MarketKind::InversePerp;

    let mut emitted = false;
    if let (Some(bid), Some(ask)) = (ticker.best_bid_price, ticker.best_ask_price) {
        let bid = decimal_literal("best_bid_price", bid)?;
        let ask = decimal_literal("best_ask_price", ask)?;
        // Deribit reports a zero top of book on an empty side rather than
        // omitting it, and a zero bid is not a quote.
        if bid.is_positive() && ask.is_positive() {
            let mid = bid
                .checked_add(ask)
                .and_then(|sum| sum.checked_div(Fixed::from_int(2).ok()?))
                .unwrap_or(bid);
            let bid_qty = ticker
                .best_bid_amount
                .map(|raw| decimal_literal("best_bid_amount", raw))
                .transpose()?
                .and_then(|amount| to_base_units(amount, bid, inverse));
            let ask_qty = ticker
                .best_ask_amount
                .map(|raw| decimal_literal("best_ask_amount", raw))
                .transpose()?
                .and_then(|amount| to_base_units(amount, ask, inverse));

            out.push(Observation {
                instrument: entry.instrument.clone(),
                kind: ObsKind::BookTop,
                price: mid,
                bid: Some(bid),
                ask: Some(ask),
                bid_qty,
                ask_qty,
                depth_notional_1bp: None,
                exchange_time_ns,
                local_recv_ns,
                seq: None,
                book: None,
                funding: None,
            });
            emitted = true;
        }
    }

    let unit = if entry.instrument.market == MarketKind::InversePerp {
        OpenInterestUnit::Quote
    } else {
        OpenInterestUnit::Base
    };
    let funding = Arc::new(FundingInfo {
        open_interest: ticker
            .open_interest
            .map(|raw| decimal_literal("open_interest", raw))
            .transpose()?
            .map(|oi| (oi, unit)),
        ..FundingInfo::new(FundingBasis::EightHours)
    });
    for (field, kind, raw) in [
        ("last_price", ObsKind::Trade, ticker.last_price),
        ("mark_price", ObsKind::MarkPrice, ticker.mark_price),
        ("index_price", ObsKind::IndexPrice, ticker.index_price),
        ("funding_8h", ObsKind::Funding, ticker.funding_8h),
    ] {
        let Some(raw) = raw else { continue };
        out.push(Observation {
            instrument: entry.instrument.clone(),
            kind,
            price: decimal_literal(field, raw)?,
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            depth_notional_1bp: None,
            exchange_time_ns,
            local_recv_ns,
            seq: None,
            book: None,
            funding: (kind == ObsKind::Funding).then(|| Arc::clone(&funding)),
        });
        emitted = true;
    }

    if emitted {
        Ok(())
    } else {
        Err(DecodeError::Control)
    }
}

/// Converts an order size to base units.
///
/// On an inverse contract the amount is quote-currency notional, so dividing by
/// the price recovers base units and puts Deribit on the same footing as every
/// other venue. Returns `None` rather than a wrong number if the division cannot
/// be represented.
fn to_base_units(amount: Fixed, price: Fixed, inverse: bool) -> Option<Fixed> {
    if !inverse {
        return Some(amount);
    }
    if !price.is_positive() {
        return None;
    }
    amount.checked_div(price)
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

    fn map(market: MarketKind, name: &str) -> InstrumentMap {
        let specs = vec![InstrumentSpec::new(name, market, "CRYPTO.BTC/USD").expect("valid")];
        InstrumentMap::new(Venue::Deribit, market, &specs).expect("valid")
    }

    fn decode(payload: &str, market: MarketKind, name: &str) -> Vec<Observation> {
        let mut out = Vec::new();
        decode_payload(payload.as_bytes(), &map(market, name), RECV, &mut out).expect("decodes");
        out
    }

    /// The documented notification shape, wrapped in its JSON-RPC envelope.
    const TICKER: &str = r#"{"jsonrpc":"2.0","method":"subscription","params":{
        "channel":"ticker.BTC-PERPETUAL.100ms","data":{
        "instrument_name":"BTC-PERPETUAL","timestamp":1623060194301,"state":"open",
        "stats":{"volume":7871.02139035,"low":35213.5,"high":36824.5},
        "open_interest":502097590,"best_bid_price":36442.5,"best_bid_amount":5000,
        "best_ask_price":36443,"best_ask_amount":100,"index_price":36441.64,
        "min_price":35898.37,"max_price":36991.72,"mark_price":36446.51,
        "last_price":36457.5,"settlement_price":36169.49,
        "estimated_delivery_price":36441.64,"funding_8h":0.0000211,
        "current_funding":0,"interest_value":1.7362511643080387}}}"#;

    #[test]
    fn a_ticker_yields_book_trade_mark_index_and_funding() {
        let observations = decode(TICKER, MarketKind::InversePerp, "BTC-PERPETUAL");
        let kinds: Vec<_> = observations.iter().map(|o| o.kind).collect();
        assert_eq!(
            kinds,
            [
                ObsKind::BookTop,
                ObsKind::Trade,
                ObsKind::MarkPrice,
                ObsKind::IndexPrice,
                ObsKind::Funding,
            ]
        );
        assert_eq!(observations[0].bid, Some("36442.5".parse().expect("valid")));
        assert_eq!(observations[0].ask, Some("36443".parse().expect("valid")));
        assert_eq!(observations[0].price, "36442.75".parse().expect("valid"));
        assert_eq!(observations[2].price, "36446.51".parse().expect("valid"));
        assert_eq!(observations[4].price, "0.0000211".parse().expect("valid"));
    }

    /// An inverse contract's `best_bid_amount` is USD. Reporting it unconverted
    /// would put a number three orders of magnitude off into a field every other
    /// venue fills with base units.
    #[test]
    fn inverse_contract_sizes_are_converted_to_base_units() {
        let observations = decode(TICKER, MarketKind::InversePerp, "BTC-PERPETUAL");
        // 5000 USD at 36442.5 is about 0.13719 BTC.
        let expected = Fixed::from_int(5000)
            .expect("valid")
            .checked_div("36442.5".parse().expect("valid"))
            .expect("representable");
        assert_eq!(observations[0].bid_qty, Some(expected));
        assert!(
            observations[0].bid_qty < Some(Fixed::from_int(1).expect("valid")),
            "a 5000 USD bid is a fraction of a BTC, not five thousand of them"
        );
    }

    /// The same numbers on a linear contract are already base units and must be
    /// passed through untouched.
    #[test]
    fn linear_contract_sizes_are_passed_through() {
        let linear = TICKER.replace("BTC-PERPETUAL", "BTC_USDC-PERPETUAL");
        let observations = decode(&linear, MarketKind::LinearPerp, "BTC_USDC-PERPETUAL");
        assert_eq!(
            observations[0].bid_qty,
            Some(Fixed::from_int(5000).expect("valid"))
        );
    }

    #[test]
    fn margining_style_is_read_from_the_instrument_name() {
        assert!(is_inverse("BTC-PERPETUAL"));
        assert!(is_inverse("ETH-PERPETUAL"));
        assert!(!is_inverse("BTC_USDC-PERPETUAL"));
        assert!(!is_inverse("BTC_USDT-PERPETUAL"));
    }

    /// The one venue here whose funding needs no interval metadata.
    #[test]
    fn funding_is_the_eight_hour_figure() {
        let observations = decode(TICKER, MarketKind::InversePerp, "BTC-PERPETUAL");
        assert_eq!(observations[4].kind, ObsKind::Funding);
        assert_eq!(
            observations[4].price,
            "0.0000211".parse().expect("valid"),
            "funding_8h, not current_funding, which is 0 here"
        );
    }

    #[test]
    fn bare_json_numbers_keep_every_digit() {
        let precise = TICKER.replace(
            "\"mark_price\":36446.51",
            "\"mark_price\":36446.123456789012",
        );
        let observations = decode(&precise, MarketKind::InversePerp, "BTC-PERPETUAL");
        assert_eq!(
            observations[2].price,
            "36446.123456789012".parse().expect("valid")
        );
    }

    #[test]
    fn the_timestamp_is_read_as_milliseconds() {
        let observations = decode(TICKER, MarketKind::InversePerp, "BTC-PERPETUAL");
        assert_eq!(
            observations[0].exchange_time_ns,
            Some(1_623_060_194_301_000_000)
        );
    }

    #[test]
    fn a_closed_instrument_publishes_nothing() {
        let closed = TICKER.replace(r#""state":"open""#, r#""state":"closed""#);
        let mut out = Vec::new();
        let error = decode_payload(
            closed.as_bytes(),
            &map(MarketKind::InversePerp, "BTC-PERPETUAL"),
            RECV,
            &mut out,
        )
        .expect_err("closed");
        assert!(matches!(error, DecodeError::Halted(_)), "got {error:?}");
        assert!(out.is_empty());
    }

    /// Deribit zeroes an empty side rather than omitting it, so a zero bid must
    /// not become a quote at half the ask.
    #[test]
    fn a_zeroed_side_is_not_a_quote() {
        let empty = TICKER.replace(r#""best_bid_price":36442.5"#, r#""best_bid_price":0"#);
        let observations = decode(&empty, MarketKind::InversePerp, "BTC-PERPETUAL");
        assert!(
            observations.iter().all(|o| o.kind != ObsKind::BookTop),
            "a zero bid must not produce a book observation"
        );
        // The rest of the ticker is still perfectly good.
        assert!(observations.iter().any(|o| o.kind == ObsKind::MarkPrice));
    }

    #[test]
    fn jsonrpc_replies_and_heartbeats_are_benign() {
        let mut out = Vec::new();
        for control in [
            r#"{"jsonrpc":"2.0","id":1,"result":["ticker.BTC-PERPETUAL.100ms"]}"#,
            r#"{"jsonrpc":"2.0","method":"heartbeat","params":{"type":"test_request"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"Invalid params"}}"#,
            // The reply to the keepalive, as Deribit sent it.
            r#"{"jsonrpc":"2.0","id":2,"result":{"version":"1.2.26"},"usIn":1791613428196921,"usOut":1791613428196968,"usDiff":47,"testnet":false}"#,
        ] {
            let error = decode_payload(
                control.as_bytes(),
                &map(MarketKind::InversePerp, "BTC-PERPETUAL"),
                RECV,
                &mut out,
            )
            .expect_err("not market data");
            assert!(error.is_benign(), "got {error:?} for {control}");
        }
        assert!(out.is_empty());
    }

    #[test]
    fn untracked_instruments_are_benign() {
        let other = TICKER.replace("BTC-PERPETUAL", "ETH-PERPETUAL");
        let mut out = Vec::new();
        let error = decode_payload(
            other.as_bytes(),
            &map(MarketKind::InversePerp, "BTC-PERPETUAL"),
            RECV,
            &mut out,
        )
        .expect_err("untracked");
        assert!(error.is_benign());
    }

    #[test]
    fn subscribe_frames_name_the_ticker_channel_and_chunk() {
        let frames = subscribe_frames([("BTC-PERPETUAL", false)].into_iter(), 100);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains(r#""method":"public/subscribe""#));
        assert!(frames[0].contains("ticker.BTC-PERPETUAL.100ms"));
        assert!(!frames[0].contains("book."));

        let many = subscribe_frames(
            [("BTC-PERPETUAL", false), ("ETH-PERPETUAL", false)].into_iter(),
            1,
        );
        assert_eq!(many.len(), 2, "two channels at one per frame");
        // Distinct request ids, so a reply can be attributed.
        assert!(many[0].contains(r#""id":1"#));
        assert!(many[1].contains(r#""id":2"#));
    }

    #[test]
    fn depth_adds_the_grouped_book_channel() {
        let frames = subscribe_frames([("BTC-PERPETUAL", true)].into_iter(), 100);
        assert!(frames[0].contains("book.BTC-PERPETUAL.100ms"));
    }

    /// Recorded from Deribit on 2026-10-06: the subscribe reply, a full
    /// snapshot, and the changes after it.
    const RECORDED_BOOK: &str = include_str!("../../tests/fixtures/deribit-book.jsonl");

    fn book_map() -> InstrumentMap {
        let specs = vec![
            InstrumentSpec::new(
                "BTC-PERPETUAL",
                MarketKind::InversePerp,
                "CRYPTO.BTC/USD.PERP_MARK",
            )
            .expect("valid")
            .with_depth(),
        ];
        InstrumentMap::new(Venue::Deribit, MarketKind::InversePerp, &specs).expect("valid")
    }

    #[test]
    fn a_recorded_book_follows_its_changes_in_base_units() {
        let map = book_map();
        let mut books = Books::default();
        let mut last = None;
        for line in RECORDED_BOOK.lines() {
            let mut out = Vec::new();
            match super::decode(line.as_bytes(), &map, &mut books, RECV, &mut out) {
                Ok(()) => {}
                Err(error) if error.is_benign() => {}
                Err(error) => panic!("{error}: {line}"),
            }
            last = out.pop().or(last);
        }
        let depth = last.expect("a depth observation");
        assert_eq!(depth.kind, ObsKind::Depth);
        // USD amounts become BTC: a level is worth well under 1000 BTC.
        let book = depth.book.as_deref().expect("levels");
        assert!(book.bids[0].qty < "1000".parse().expect("valid"));
        assert!(book.bids[0].price < book.asks[0].price);
    }

    #[test]
    fn a_change_that_skips_one_asks_for_a_resync() {
        let map = book_map();
        let mut books = Books::default();
        let mut lines = RECORDED_BOOK
            .lines()
            .filter(|line| line.contains(r#""type":"#));
        let snapshot = lines.next().expect("a snapshot");
        super::decode(snapshot.as_bytes(), &map, &mut books, RECV, &mut Vec::new()).expect("valid");
        let _skipped = lines.next().expect("a change");
        let after = lines.next().expect("a later change");
        assert!(matches!(
            super::decode(after.as_bytes(), &map, &mut books, RECV, &mut Vec::new()),
            Err(DecodeError::Resync(_))
        ));
    }
}
