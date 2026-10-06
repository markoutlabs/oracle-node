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

use oracle_types::{Fixed, ObsKind, Observation};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{Books, LocalBook, Side};
use crate::{DecodeError, InstrumentMap};

use super::{decimal_literal, rfc3339_to_unix_nanos};

/// The v2 public endpoint. The protocol differs substantially from v1.
pub const URL: &str = "wss://ws.kraken.com/v2";

/// Book levels kept per side. Kraken stops sending levels that fall out of the
/// subscribed depth, so the local book is cut to it after every update.
pub const BOOK_DEPTH: usize = 100;

/// Levels per side the checksum covers.
const CHECKSUM_LEVELS: usize = 10;

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

/// A `book` message: a snapshot, or the levels that changed.
#[derive(Deserialize)]
struct BookMessage<'a> {
    #[serde(rename = "type", borrow)]
    kind: &'a str,
    #[serde(borrow)]
    data: Vec<BookData<'a>>,
}

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

/// The session's entry point: the book channel is kept in `books`; every other
/// channel goes to [`decode_payload`].
///
/// # Errors
///
/// As [`decode_payload`], and [`DecodeError::Resync`] when a book's checksum
/// fails.
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    if envelope.channel != Some("book") {
        return decode_payload(payload, map, local_recv_ns, out);
    }
    let message: BookMessage<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    for data in message.data {
        let Some(entry) = map.lookup(data.symbol) else {
            continue;
        };
        let book = books.book(data.symbol);
        if message.kind == "snapshot" {
            book.clear();
        }
        for (side, levels) in [(Side::Bid, &data.bids), (Side::Ask, &data.asks)] {
            for level in levels {
                let (price, qty) = (level.price.get(), level.qty.get());
                let parsed = crate::depth::level(price, qty)?;
                book.set_with_text(side, parsed.price, parsed.qty, Some((price, qty)));
            }
        }
        book.truncate(BOOK_DEPTH);
        if checksum(book) != Some(data.checksum) {
            return Err(DecodeError::Resync(format!(
                "{}: checksum mismatch",
                data.symbol
            )));
        }
        books.emit(
            data.symbol,
            entry.instrument.clone(),
            data.timestamp.and_then(rfc3339_to_unix_nanos),
            local_recv_ns,
            out,
        )?;
    }
    Ok(())
}

/// Kraken's CRC32 over the top ten asks, then the top ten bids: each price and
/// size as sent, without the decimal point and leading zeros.
fn checksum(book: &LocalBook) -> Option<u32> {
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

/// Decodes one Kraken v2 payload.
///
/// # Errors
///
/// Returns [`DecodeError`]. Method replies and heartbeats are benign.
pub fn decode_payload(
    payload: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let (Some(channel), Some(data)) = (envelope.channel, envelope.data) else {
        // Subscribe replies carry `method`/`success`; heartbeats carry no data.
        return Err(DecodeError::Control);
    };
    if channel != "ticker" {
        return Err(DecodeError::UnhandledStream(channel.to_owned()));
    }
    let data: Vec<Ticker<'_>> =
        serde_json::from_str(data.get()).map_err(|e| DecodeError::Malformed(e.to_string()))?;

    let mut emitted = false;
    for ticker in data {
        let Some(entry) = map.lookup(ticker.symbol) else {
            continue;
        };
        let exchange_time_ns = ticker.timestamp.and_then(rfc3339_to_unix_nanos);

        if let (Some(bid), Some(bid_qty), Some(ask), Some(ask_qty)) =
            (ticker.bid, ticker.bid_qty, ticker.ask, ticker.ask_qty)
        {
            let bid = decimal_literal("bid", bid)?;
            let ask = decimal_literal("ask", ask)?;
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
                bid_qty: Some(decimal_literal("bid_qty", bid_qty)?),
                ask_qty: Some(decimal_literal("ask_qty", ask_qty)?),
                depth_notional_1bp: None,
                exchange_time_ns,
                local_recv_ns,
                seq: None,
                book: None,
            });
            emitted = true;
        }

        if let Some(last) = ticker.last {
            out.push(Observation {
                instrument: entry.instrument.clone(),
                kind: ObsKind::Trade,
                price: decimal_literal("last", last)?,
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
            emitted = true;
        }
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
    use oracle_types::{MarketKind, Venue};

    const RECV: u64 = 1_754_582_400_500_000_000;

    fn map() -> InstrumentMap {
        let specs =
            vec![InstrumentSpec::new("BTCUSD", MarketKind::Spot, "CRYPTO.BTC/USD").expect("valid")];
        InstrumentMap::new(Venue::Kraken, MarketKind::Spot, &specs).expect("valid")
    }

    fn decode(payload: &str) -> Vec<Observation> {
        let mut out = Vec::new();
        decode_payload(payload.as_bytes(), &map(), RECV, &mut out).expect("decodes");
        out
    }

    /// Captured from the live v2 feed, including the bare JSON numbers.
    const TICKER: &str = r#"{"channel":"ticker","type":"snapshot","data":[
        {"symbol":"BTCUSD","bid":64312.0,"bid_qty":0.5,"ask":64313.0,"ask_qty":0.25,
         "last":64312.1,"volume":100.0,"vwap":64000.0,"low":62000.0,"high":65000.0,
         "change":100.0,"change_pct":0.15,"trades":43225,
         "timestamp":"2026-08-07T17:06:53.510000Z"}]}"#;

    #[test]
    fn a_ticker_yields_both_a_book_and_a_trade() {
        let observations = decode(TICKER);
        assert_eq!(observations.len(), 2);
        let kinds: Vec<_> = observations.iter().map(|o| o.kind).collect();
        assert_eq!(kinds, [ObsKind::BookTop, ObsKind::Trade]);
        assert_eq!(observations[0].bid, Some("64312".parse().expect("valid")));
        assert_eq!(observations[0].price, "64312.5".parse().expect("valid"));
        assert_eq!(observations[1].price, "64312.1".parse().expect("valid"));
    }

    /// The reason every field goes through `RawValue`: a double would round this.
    #[test]
    fn bare_json_numbers_keep_every_digit() {
        let precise = r#"{"channel":"ticker","type":"update","data":[
            {"symbol":"BTCUSD","bid":64312.123456789012,"bid_qty":0.000000000001,
             "ask":64313.987654321098,"ask_qty":1.0,"last":64312.5}]}"#;
        let observations = decode(precise);
        let book = &observations[0];
        assert_eq!(book.bid, Some("64312.123456789012".parse().expect("valid")));
        assert_eq!(book.ask, Some("64313.987654321098".parse().expect("valid")));
        assert_eq!(book.bid_qty, Some("0.000000000001".parse().expect("valid")));
    }

    /// Live Kraken sends `status` as the very first frame. Reading the channel
    /// before the payload is what keeps that from counting as malformed.
    #[test]
    fn the_status_frame_kraken_opens_with_is_benign() {
        let mut out = Vec::new();
        let status = r#"{"channel":"status","type":"update","data":[{"version":"2.0.10",
            "system":"online","api_version":"v2","connection_id":3720116461514031670}]}"#;
        let error =
            decode_payload(status.as_bytes(), &map(), RECV, &mut out).expect_err("not market data");
        assert!(error.is_benign(), "got {error:?}");
    }

    #[test]
    fn the_ticker_timestamp_is_parsed() {
        let observations = decode(TICKER);
        assert_eq!(
            observations[0].exchange_time_ns,
            Some(1_786_122_413 * 1_000_000_000 + 510_000_000)
        );
    }

    #[test]
    fn method_replies_and_heartbeats_are_benign() {
        let mut out = Vec::new();
        for control in [
            r#"{"method":"subscribe","result":{"channel":"ticker","symbol":"BTC/USD"},"success":true,"time_in":"x","time_out":"y"}"#,
            r#"{"channel":"heartbeat"}"#,
            r#"{"channel":"status","type":"update","data":[{"version":"2.0.0"}]}"#,
        ] {
            let error = decode_payload(control.as_bytes(), &map(), RECV, &mut out)
                .expect_err("not market data");
            assert!(error.is_benign(), "got {error:?} for {control}");
        }
        assert!(out.is_empty());
    }

    #[test]
    fn untracked_symbols_are_benign() {
        let other = TICKER.replace("BTCUSD", "ETHUSD");
        let mut out = Vec::new();
        let error =
            decode_payload(other.as_bytes(), &map(), RECV, &mut out).expect_err("untracked");
        assert!(error.is_benign());
    }

    #[test]
    fn a_ticker_missing_the_book_still_yields_the_trade() {
        let partial = r#"{"channel":"ticker","type":"update","data":[
            {"symbol":"BTCUSD","last":64312.1}]}"#;
        let observations = decode(partial);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].kind, ObsKind::Trade);
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

    /// Recorded from Kraken on 2026-10-06 at depth 100: the subscribe reply, the
    /// snapshot, and the updates after it.
    const RECORDED_BOOK: &str = include_str!("../../tests/fixtures/kraken-book.jsonl");

    fn book_map() -> InstrumentMap {
        let specs = vec![
            InstrumentSpec::new("BTC/USD", MarketKind::Spot, "CRYPTO.BTC/USD")
                .expect("valid")
                .with_depth(),
        ];
        InstrumentMap::new(Venue::Kraken, MarketKind::Spot, &specs).expect("valid")
    }

    /// Every real update must keep the book on Kraken's checksum, and each one
    /// emits the book's top levels.
    #[test]
    fn a_recorded_book_keeps_its_checksum() {
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
        assert!(depths >= 25, "{depths}");
        let last = books.book("BTC/USD");
        assert!(last.top(Side::Bid, 1)[0].price < last.top(Side::Ask, 1)[0].price);
    }

    /// One wrong checksum means a missed or misapplied update: nothing the book
    /// says can be trusted until a fresh snapshot.
    #[test]
    fn a_checksum_mismatch_asks_for_a_resync() {
        let map = book_map();
        let mut books = Books::default();
        let mut lines = RECORDED_BOOK
            .lines()
            .filter(|line| line.contains(r#""type":"#));
        let snapshot = lines.next().expect("a snapshot");
        assert!(snapshot.contains(r#""type":"snapshot""#));
        super::decode(snapshot.as_bytes(), &map, &mut books, RECV, &mut Vec::new()).expect("valid");

        let update = lines.next().expect("an update");
        let at = update.find(r#""checksum":"#).expect("a checksum") + 11;
        let end = at
            + update[at..]
                .find(|c: char| !c.is_ascii_digit())
                .expect("digits end");
        let tampered = format!("{}0{}", &update[..at], &update[end..]);
        let mut out = Vec::new();
        assert!(matches!(
            super::decode(tampered.as_bytes(), &map, &mut books, RECV, &mut out),
            Err(DecodeError::Resync(_))
        ));
        assert!(out.is_empty());
    }
}
