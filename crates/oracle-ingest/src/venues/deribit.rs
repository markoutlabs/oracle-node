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

use crate::book::{BookMsg, BookRule, Books, Change, Continuity, Halts};
use crate::clock::millis_to_nanos;
use crate::instrument::InstrumentEntry;
use crate::{DecodeError, InstrumentMap};

use super::{book_top, decimal_literal, observation, parse, to_base_units};

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

/// Each change names the `change_id` of the one before it as `prev_change_id`.
const BOOK_RULE: BookRule = BookRule::new(Continuity::UpdateId);

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

/// Decodes one Deribit payload. The book channel is kept in `books`.
///
/// # Errors
///
/// Returns [`DecodeError`]. Subscribe replies and heartbeats are benign; a
/// book change that does not follow the last one is [`DecodeError::Resync`].
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> = serde_json::from_slice(payload)?;
    // Replies to our own requests carry `id` and `result`, never `method`.
    let (Some("subscription"), Some(params)) = (envelope.method, envelope.params) else {
        return Err(DecodeError::Control);
    };
    let (Some(channel), Some(data)) = (params.channel, params.data) else {
        return Err(DecodeError::Control);
    };
    if channel.starts_with("book.") {
        return decode_book(data, map, books, local_recv_ns, out);
    }
    if channel.starts_with("ticker.") {
        return decode_ticker(data, map, local_recv_ns, out);
    }
    Err(DecodeError::UnhandledStream(channel.to_owned()))
}

fn decode_book(
    data: &RawValue,
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let message: Book<'_> = parse(data).map_err(|e| BOOK_RULE.unparsed(e))?;
    let Some(entry) = map.lookup(message.instrument_name) else {
        return Err(DecodeError::Control);
    };
    let parsed = book_message(&message, entry);
    books
        .keeper
        .apply(BOOK_RULE, entry, parsed, local_recv_ns, out)
}

/// One book message, with an inverse contract's USD sizes in coins.
fn book_message(
    message: &Book<'_>,
    entry: &InstrumentEntry,
) -> Result<BookMsg<'static>, DecodeError> {
    let inverse = entry.instrument.market == MarketKind::InversePerp;
    let change = |(action, price, amount): &(&str, &RawValue, &RawValue)| {
        let price = decimal_literal("book price", price)?;
        if *action == "delete" {
            return Ok(Change::new(price, Fixed::ZERO));
        }
        let amount = decimal_literal("book amount", amount)?;
        let qty = to_base_units(amount, price, inverse)
            .ok_or_else(|| DecodeError::Malformed(format!("amount {amount} at price {price}")))?;
        Ok(Change::new(price, qty))
    };
    Ok(BookMsg {
        snapshot: message.kind == "snapshot",
        prev_id: message.prev_change_id,
        next_id: Some(message.change_id),
        time: message.timestamp.map(millis_to_nanos),
        ..BookMsg::changes(&message.bids, &message.asks, change)?
    })
}

fn decode_ticker(
    data: &RawValue,
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let ticker: Ticker<'_> = parse(data)?;
    let Some(entry) = map.lookup(ticker.instrument_name) else {
        return Err(DecodeError::Control);
    };
    // Deribit keeps publishing a ticker for a closed instrument. The session
    // stops confirming its last values, so the staleness filter sheds them.
    if ticker.state.is_some_and(|state| state != "open") {
        return Err(DecodeError::Suspended(entry.instrument.clone()));
    }
    let exchange_time_ns = ticker.timestamp.map(millis_to_nanos);
    let inverse = entry.instrument.market == MarketKind::InversePerp;
    let before = out.len();

    // Deribit gives an empty side as a null or a zero price. The rest of the
    // ticker stands, and the book stops counting.
    let lost = |error| DecodeError::lost(&entry.instrument, error);
    let price = |raw: Option<&RawValue>, field| {
        raw.map(|raw| decimal_literal(field, raw))
            .transpose()
            .map_err(lost)
    };
    let bid = price(ticker.best_bid_price, "best_bid_price")?;
    let ask = price(ticker.best_ask_price, "best_ask_price")?;
    let size = |raw: Option<&RawValue>, field, price: Option<Fixed>| {
        let amount = raw.map(|raw| decimal_literal(field, raw)).transpose();
        amount.map_err(lost).map(|amount| {
            amount
                .zip(price)
                .and_then(|(amount, price)| to_base_units(amount, price, inverse))
        })
    };
    let bid_qty = size(ticker.best_bid_amount, "best_bid_amount", bid)?;
    let ask_qty = size(ticker.best_ask_amount, "best_ask_amount", ask)?;
    let sizes = (
        bid_qty.unwrap_or(Fixed::ZERO),
        ask_qty.unwrap_or(Fixed::ZERO),
    );
    let top = || Ok(bid.zip(ask).map(|prices| (prices, sizes)));
    let quote = book_top(entry, top, exchange_time_ns, local_recv_ns).map(|top| {
        out.push(Observation {
            bid_qty,
            ask_qty,
            ..top
        });
    });
    let mut halts = Halts::default();
    halts.absorb(&entry.instrument, quote)?;

    let unit = if inverse {
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
            exchange_time_ns,
            funding: (kind == ObsKind::Funding).then(|| Arc::clone(&funding)),
            ..observation(entry, kind, decimal_literal(field, raw)?, local_recv_ns)
        });
    }

    let empty = if out.len() == before {
        Err(DecodeError::Control)
    } else {
        Ok(())
    };
    halts.finish(empty)
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixed payloads; an out-of-range index is a failing test"
)]
mod tests {
    use super::*;
    use crate::testing::{Feed, fixed, instrument, kinds};
    use oracle_types::Venue;

    fn deribit(market: MarketKind, name: &str) -> Feed {
        Feed::venue(decode, Venue::Deribit, market, &[instrument(name, market)])
    }

    /// The inverse BTC perpetual, whose sizes are USD.
    fn inverse() -> Feed {
        deribit(MarketKind::InversePerp, "BTC-PERPETUAL")
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
        let observations = inverse().decoded(TICKER);
        assert_eq!(
            kinds(&observations),
            [
                ObsKind::BookTop,
                ObsKind::Trade,
                ObsKind::MarkPrice,
                ObsKind::IndexPrice,
                ObsKind::Funding,
            ]
        );
        assert_eq!(observations[0].bid, Some(fixed("36442.5")));
        assert_eq!(observations[0].ask, Some(fixed("36443")));
        assert_eq!(observations[0].price, fixed("36442.75"));
        assert_eq!(observations[2].price, fixed("36446.51"));
        assert_eq!(observations[4].price, fixed("0.0000211"));
    }

    /// An inverse contract's `best_bid_amount` is USD. Reporting it unconverted
    /// would put a number three orders of magnitude off into a field every other
    /// venue fills with base units.
    #[test]
    fn inverse_contract_sizes_are_converted_to_base_units() {
        let quote = &inverse().decoded(TICKER)[0];
        // 5000 USD at 36442.5 is about 0.13719 BTC.
        let expected = fixed("5000")
            .checked_div(fixed("36442.5"))
            .expect("representable");
        assert_eq!(quote.bid_qty, Some(expected));
        assert!(
            quote.bid_qty < Some(fixed("1")),
            "a 5000 USD bid is a fraction of a BTC, not five thousand of them"
        );
    }

    /// The same numbers on a linear contract are already base units and must be
    /// passed through untouched.
    #[test]
    fn linear_contract_sizes_are_passed_through() {
        let linear = TICKER.replace("BTC-PERPETUAL", "BTC_USDC-PERPETUAL");
        let quote = &deribit(MarketKind::LinearPerp, "BTC_USDC-PERPETUAL").decoded(linear)[0];
        assert_eq!(quote.bid_qty, Some(fixed("5000")));
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
        let funding = &inverse().decoded(TICKER)[4];
        assert_eq!(funding.kind, ObsKind::Funding);
        assert_eq!(
            funding.price,
            fixed("0.0000211"),
            "funding_8h, not current_funding, which is 0 here"
        );
    }

    #[test]
    fn bare_json_numbers_keep_every_digit() {
        let precise = TICKER.replace(
            "\"mark_price\":36446.51",
            "\"mark_price\":36446.123456789012",
        );
        let mark = &inverse().decoded(precise)[2];
        assert_eq!(mark.price, fixed("36446.123456789012"));
    }

    #[test]
    fn the_timestamp_is_read_as_milliseconds() {
        let quote = &inverse().decoded(TICKER)[0];
        assert_eq!(
            quote.exchange_time_ns,
            Some(millis_to_nanos(1_623_060_194_301))
        );
    }

    #[test]
    fn a_closed_instrument_is_suspended() {
        let closed = TICKER.replace(r#""state":"open""#, r#""state":"closed""#);
        let error = inverse().refused(closed);
        assert!(matches!(error, DecodeError::Suspended(_)), "got {error:?}");
    }

    /// Deribit gives an empty side as a zero or a null price. Neither may
    /// become a quote at half the ask, and the last quote stops counting.
    #[test]
    fn a_zeroed_side_halts_the_book_and_keeps_the_rest() {
        for empty in ["0", "null"] {
            let ticker = TICKER.replace(
                r#""best_bid_price":36442.5"#,
                &format!(r#""best_bid_price":{empty}"#),
            );
            let (observations, halted) = inverse().halted(ticker);
            assert_eq!(halted, ["BTC-PERPETUAL"], "{empty}");
            assert_eq!(
                kinds(&observations),
                [
                    ObsKind::Trade,
                    ObsKind::MarkPrice,
                    ObsKind::IndexPrice,
                    ObsKind::Funding
                ],
                "{empty}"
            );
        }
    }

    #[test]
    fn jsonrpc_replies_and_heartbeats_are_benign() {
        let mut inverse = inverse();
        for control in [
            r#"{"jsonrpc":"2.0","id":1,"result":["ticker.BTC-PERPETUAL.100ms"]}"#,
            r#"{"jsonrpc":"2.0","method":"heartbeat","params":{"type":"test_request"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"Invalid params"}}"#,
            // The reply to the keepalive, as Deribit sent it.
            r#"{"jsonrpc":"2.0","id":2,"result":{"version":"1.2.26"},"usIn":1791613428196921,"usOut":1791613428196968,"usDiff":47,"testnet":false}"#,
        ] {
            let error = inverse.refused(control);
            assert!(error.is_benign(), "got {error:?} for {control}");
        }
    }

    #[test]
    fn untracked_instruments_are_benign() {
        let other = TICKER.replace("BTC-PERPETUAL", "ETH-PERPETUAL");
        assert!(inverse().refused(other).is_benign());
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

    /// The recorded book of the inverse perpetual counts in USD; its levels
    /// reach the book in BTC.
    #[test]
    fn a_recorded_book_follows_its_changes_in_base_units() {
        // Recorded from Deribit on 2026-10-06: a full snapshot and its changes.
        let recorded = include_str!("../../tests/fixtures/deribit-book.jsonl");
        let book = instrument("BTC-PERPETUAL", MarketKind::InversePerp).with_depth();
        let mut feed = Feed::venue(decode, Venue::Deribit, MarketKind::InversePerp, &[book]);
        let depth = feed
            .replay(recorded.lines())
            .pop()
            .expect("a depth observation");
        assert_eq!(depth.kind, ObsKind::Depth);
        let levels = depth.book.as_deref().expect("levels");
        // A level of thousands of USD is well under 1000 BTC.
        assert!(levels.bids[0].qty < fixed("1000"));
        assert!(levels.bids[0].price < levels.asks[0].price);
    }
}
