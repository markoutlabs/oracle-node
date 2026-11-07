//! Kraken v2 public streams.
//!
//! # The precision hazard
//!
//! Kraken v2 sends prices as **bare JSON numbers**, not strings. Deserializing
//! those through `f64` would quietly lose precision on exactly the values that
//! matter, and the loss is silent — the number still looks like a price.
//!
//! Every numeric field here is therefore captured as a `RawValue` and parsed
//! from its **literal characters** into fixed point, so the venue's own digits
//! reach the aggregator unchanged.
//!
//! **Kraken quotes natively in USD.** With Coinbase it is one of only two such
//! venues in scope; see `super::coinbase` for why losing both matters.

use oracle_types::{ObsKind, Observation};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{BookMsg, BookRule, Books, Change, Continuity, Halts, LocalBook, Side};
use crate::{DecodeError, InstrumentMap};

use super::{book_top, decimal_literal, observation, parse, rfc3339_to_unix_nanos};

/// The v2 public endpoint. The protocol differs substantially from v1.
pub const URL: &str = "wss://ws.kraken.com/v2";

/// Book levels kept per side. Kraken stops sending levels that fall out of the
/// subscribed depth, so the local book is cut to it after every update.
pub const BOOK_DEPTH: usize = 100;

/// Levels per side the checksum covers.
const CHECKSUM_LEVELS: usize = 10;

/// Each message carries a checksum of the top ten levels, and nothing else
/// proves the book. So an observation shows only those ten.
const BOOK_RULE: BookRule = BookRule::new(Continuity::Checksum)
    .depth(BOOK_DEPTH)
    .checksum(checksum)
    .shown(CHECKSUM_LEVELS);

/// Builds the subscribe frames for a set of Kraken symbols such as `BTC/USD`,
/// each with whether it wants the book.
#[must_use]
pub fn subscribe_frames<'a>(instruments: impl Iterator<Item = (&'a str, bool)>) -> Vec<String> {
    let instruments: Vec<(&str, bool)> = instruments.collect();
    let mut frames = vec![subscribe_frame(
        instruments.iter().map(|(symbol, _)| *symbol),
    )];
    let books: Vec<&str> = instruments
        .iter()
        .filter(|(_, depth)| *depth)
        .map(|(symbol, _)| *symbol)
        .collect();
    if !books.is_empty() {
        frames.push(
            serde_json::json!({
                "method": "subscribe",
                "params": { "channel": "book", "symbol": books, "depth": BOOK_DEPTH },
            })
            .to_string(),
        );
    }
    frames
}

/// Builds the ticker subscribe frame for a set of Kraken symbols.
///
/// # Why `event_trigger: "bbo"`
///
/// Kraken's ticker defaults to `trades`, pushing only when a trade prints. On a
/// pair that trades every few seconds — which USDT/USD often is — the quote goes
/// stale between prints and the venue silently drops out of the aggregate. The
/// `bbo` trigger pushes on every top-of-book change instead, which is both
/// fresher and what the aggregator actually wants.
#[must_use]
pub fn subscribe_frame<'a>(symbols: impl Iterator<Item = &'a str>) -> String {
    let symbols: Vec<&str> = symbols.collect();
    serde_json::json!({
        "method": "subscribe",
        "params": {
            "channel": "ticker",
            "symbol": symbols,
            "event_trigger": "bbo",
        },
    })
    .to_string()
}

/// Kraken multiplexes several channels over one connection, and each carries a
/// differently-shaped `data`. The channel is therefore read first and the
/// payload deferred, or a `status` message would fail to deserialize as a ticker
/// and be counted as malformed.
#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow, default)]
    channel: Option<&'a str>,
    /// `snapshot` or `update`.
    #[serde(rename = "type", borrow, default)]
    kind: Option<&'a str>,
    #[serde(borrow, default)]
    data: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct Ticker<'a> {
    #[serde(borrow)]
    symbol: &'a str,
    #[serde(borrow, default)]
    bid: Option<&'a RawValue>,
    #[serde(rename = "bid_qty", borrow, default)]
    bid_qty: Option<&'a RawValue>,
    #[serde(borrow, default)]
    ask: Option<&'a RawValue>,
    #[serde(rename = "ask_qty", borrow, default)]
    ask_qty: Option<&'a RawValue>,
    #[serde(borrow, default)]
    last: Option<&'a RawValue>,
    /// RFC 3339, present on snapshots and trade-triggered updates.
    #[serde(borrow, default)]
    timestamp: Option<&'a str>,
}

/// One entry of a `book` message: a snapshot, or the levels that changed.
#[derive(Deserialize)]
struct BookData<'a> {
    #[serde(borrow)]
    symbol: &'a str,
    #[serde(borrow, default)]
    bids: Vec<BookLevel<'a>>,
    #[serde(borrow, default)]
    asks: Vec<BookLevel<'a>>,
    checksum: u32,
    #[serde(borrow, default)]
    timestamp: Option<&'a str>,
}

#[derive(Deserialize)]
struct BookLevel<'a> {
    #[serde(borrow)]
    price: &'a RawValue,
    #[serde(borrow)]
    qty: &'a RawValue,
}

/// Decodes one Kraken v2 payload. The book channel is kept in `books`.
///
/// # Errors
///
/// Returns [`DecodeError`]. Method replies and heartbeats are benign; a book
/// whose checksum fails is [`DecodeError::Resync`].
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> = serde_json::from_slice(payload)?;
    let (Some(channel), Some(data)) = (envelope.channel, envelope.data) else {
        // Subscribe replies carry `method`/`success`; heartbeats carry no data.
        return Err(DecodeError::Control);
    };
    match channel {
        "book" => {
            let snapshot = envelope.kind == Some("snapshot");
            let mut halts = Halts::default();
            for data in parse::<Vec<BookData<'_>>>(data).map_err(|e| BOOK_RULE.unparsed(e))? {
                let Some(entry) = map.lookup(data.symbol) else {
                    continue;
                };
                let parsed = book_message(&data, snapshot);
                let applied = books
                    .keeper
                    .apply(BOOK_RULE, entry, parsed, local_recv_ns, out);
                halts.absorb(&entry.instrument, applied)?;
            }
            halts.finish(Ok(()))
        }
        "ticker" => decode_ticker(data, map, local_recv_ns, out),
        other => Err(DecodeError::UnhandledStream(other.to_owned())),
    }
}

/// One book entry, with the venue's text of each level for the checksum.
fn book_message<'a>(data: &BookData<'a>, snapshot: bool) -> Result<BookMsg<'a>, DecodeError> {
    let change = |level: &BookLevel<'a>| {
        let (price, qty) = (level.price.get(), level.qty.get());
        Ok(Change {
            text: Some((price, qty)),
            ..Change::from(crate::depth::level(price, qty)?)
        })
    };
    Ok(BookMsg {
        snapshot,
        checksum: Some(data.checksum),
        time: data.timestamp.and_then(rfc3339_to_unix_nanos),
        ..BookMsg::changes(&data.bids, &data.asks, change)?
    })
}

/// Kraken's CRC32 over the top ten asks, then the top ten bids: each price and
/// size as sent, without the decimal point and leading zeros.
pub(super) fn checksum(book: &LocalBook) -> Option<u32> {
    let mut text = String::with_capacity(CHECKSUM_LEVELS * 2 * 24);
    for side in [Side::Ask, Side::Bid] {
        for (price, qty) in book.top_text(side, CHECKSUM_LEVELS)? {
            for part in [price, qty] {
                text.extend(part.chars().filter(|c| *c != '.').skip_while(|c| *c == '0'));
            }
        }
    }
    Some(crc32fast::hash(text.as_bytes()))
}

/// A ticker gives the top of book and the last trade of each symbol.
fn decode_ticker(
    data: &RawValue,
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let tickers: Vec<Ticker<'_>> = parse(data)?;
    let before = out.len();
    let mut halts = Halts::default();
    for ticker in tickers {
        let Some(entry) = map.lookup(ticker.symbol) else {
            continue;
        };
        let exchange_time_ns = ticker.timestamp.and_then(rfc3339_to_unix_nanos);
        // An absent or null side is an empty side; the trade still stands.
        let top = || {
            let (Some(bid), Some(bid_qty), Some(ask), Some(ask_qty)) =
                (ticker.bid, ticker.bid_qty, ticker.ask, ticker.ask_qty)
            else {
                return Ok(None);
            };
            Ok(Some((
                (decimal_literal("bid", bid)?, decimal_literal("ask", ask)?),
                (
                    decimal_literal("bid_qty", bid_qty)?,
                    decimal_literal("ask_qty", ask_qty)?,
                ),
            )))
        };
        let quote = book_top(entry, top, exchange_time_ns, local_recv_ns).map(|top| out.push(top));
        halts.absorb(&entry.instrument, quote)?;
        if let Some(last) = ticker.last {
            out.push(Observation {
                exchange_time_ns,
                ..observation(
                    entry,
                    ObsKind::Trade,
                    decimal_literal("last", last)?,
                    local_recv_ns,
                )
            });
        }
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
    use oracle_types::{MarketKind, Venue};

    fn ticker() -> Feed {
        Feed::venue(
            decode,
            Venue::Kraken,
            MarketKind::Spot,
            &[instrument("BTCUSD", MarketKind::Spot)],
        )
    }

    /// Captured from the live v2 feed, including the bare JSON numbers.
    const TICKER: &str = r#"{"channel":"ticker","type":"snapshot","data":[
        {"symbol":"BTCUSD","bid":64312.0,"bid_qty":0.5,"ask":64313.0,"ask_qty":0.25,
         "last":64312.1,"volume":100.0,"vwap":64000.0,"low":62000.0,"high":65000.0,
         "change":100.0,"change_pct":0.15,"trades":43225,
         "timestamp":"2026-08-07T17:06:53.510000Z"}]}"#;

    #[test]
    fn a_ticker_yields_both_a_book_and_a_trade() {
        let observations = ticker().decoded(TICKER);
        assert_eq!(kinds(&observations), [ObsKind::BookTop, ObsKind::Trade]);
        assert_eq!(observations[0].bid, Some(fixed("64312")));
        assert_eq!(observations[0].price, fixed("64312.5"));
        assert_eq!(observations[1].price, fixed("64312.1"));
    }

    /// The reason every field goes through `RawValue`: a double would round this.
    #[test]
    fn bare_json_numbers_keep_every_digit() {
        let precise = r#"{"channel":"ticker","type":"update","data":[
            {"symbol":"BTCUSD","bid":64312.123456789012,"bid_qty":0.000000000001,
             "ask":64313.987654321098,"ask_qty":1.0,"last":64312.5}]}"#;
        let book = &ticker().decoded(precise)[0];
        assert_eq!(book.bid, Some(fixed("64312.123456789012")));
        assert_eq!(book.ask, Some(fixed("64313.987654321098")));
        assert_eq!(book.bid_qty, Some(fixed("0.000000000001")));
    }

    /// Live Kraken sends `status` as the very first frame. Reading the channel
    /// before the payload is what keeps that from counting as malformed.
    #[test]
    fn the_status_frame_kraken_opens_with_is_benign() {
        let status = r#"{"channel":"status","type":"update","data":[{"version":"2.0.10",
            "system":"online","api_version":"v2","connection_id":3720116461514031670}]}"#;
        let error = ticker().refused(status);
        assert!(error.is_benign(), "got {error:?}");
    }

    #[test]
    fn the_ticker_timestamp_is_parsed() {
        let book = &ticker().decoded(TICKER)[0];
        // 2026-08-07T17:06:53.510000Z
        assert_eq!(
            book.exchange_time_ns,
            Some(1_786_122_413 * 1_000_000_000 + 510_000_000)
        );
    }

    #[test]
    fn method_replies_and_heartbeats_are_benign() {
        let mut ticker = ticker();
        for control in [
            r#"{"method":"subscribe","result":{"channel":"ticker","symbol":"BTC/USD"},"success":true,"time_in":"x","time_out":"y"}"#,
            r#"{"channel":"heartbeat"}"#,
            r#"{"channel":"status","type":"update","data":[{"version":"2.0.0"}]}"#,
        ] {
            let error = ticker.refused(control);
            assert!(error.is_benign(), "got {error:?} for {control}");
        }
    }

    #[test]
    fn untracked_symbols_are_benign() {
        assert!(
            ticker()
                .refused(TICKER.replace("BTCUSD", "ETHUSD"))
                .is_benign()
        );
    }

    #[test]
    fn a_ticker_without_its_book_halts_the_quote_and_keeps_the_trade() {
        let partial = r#"{"channel":"ticker","type":"update","data":[
            {"symbol":"BTCUSD","bid":null,"last":64312.1}]}"#;
        let (observations, halted) = ticker().halted(partial);
        assert_eq!(kinds(&observations), [ObsKind::Trade]);
        assert_eq!(halted, ["BTCUSD"]);
    }

    #[test]
    fn the_subscribe_frame_uses_the_v2_shape() {
        let frame = subscribe_frame(["BTC/USD"].into_iter());
        assert!(frame.contains(r#""method":"subscribe""#));
        assert!(frame.contains(r#""channel":"ticker""#));
        assert!(frame.contains("BTC/USD"));
        // Without this the venue pushes only on trades and goes stale between them.
        assert!(frame.contains(r#""event_trigger":"bbo""#));
    }

    #[test]
    fn depth_adds_a_book_subscription_at_the_kept_depth() {
        let frames = subscribe_frames([("BTC/USD", true), ("ETH/USD", false)].into_iter());
        assert_eq!(frames.len(), 2);
        assert!(frames[1].contains(r#""channel":"book""#));
        assert!(frames[1].contains(r#""depth":100"#));
        assert!(!frames[1].contains("ETH/USD"));
        assert_eq!(subscribe_frames([("BTC/USD", false)].into_iter()).len(), 1);
    }
}
