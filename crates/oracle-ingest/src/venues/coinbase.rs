//! Coinbase: trades from the Exchange feed, books from Advanced Trade.
//!
//! The Exchange feed's `ticker` gives the trades. Coinbase sends a ticker only
//! on a trade, so its best bid and ask go stale on a quiet coin.
//!
//! Each product's top of book therefore comes from the keyless Advanced Trade
//! `level2` book, which changes with every order. A product that wants depth
//! gets the book's top levels, and any other product gets its best bid and ask.
//!
//! **Coinbase quotes natively in USD.** With Kraken it is one of only two such
//! venues in scope, which makes losing both a distinct failure class rather than
//! just "two of five sources down" — every stablecoin-quoted price then has no
//! peg to convert through.

use oracle_types::{ObsKind, Observation};
use serde::Deserialize;

use crate::book::{Books, Side};
use crate::{DecodeError, InstrumentMap};

use super::{decimal, rfc3339_to_unix_nanos};

/// The public endpoint.
pub const URL: &str = "wss://ws-feed.exchange.coinbase.com";

/// The Advanced Trade endpoint, for the book. The Exchange feed's `level2`
/// needs credentials, and its keyless `level2_batch` numbers nothing, so a
/// missed message could not be detected. Advanced Trade's `level2` is keyless
/// and numbers every message on the connection.
pub const BOOK_URL: &str = "wss://advanced-trade-ws.coinbase.com";

/// The most products on one book connection. Coinbase refuses more than 30
/// with "too many L2 streams requested in a single session".
pub const BOOK_PRODUCTS: usize = 25;

/// Builds the subscribe frames for the book connection: `level2`, and the
/// heartbeats that keep a quiet product's connection open.
#[must_use]
pub fn book_subscribe_frames<'a>(product_ids: impl Iterator<Item = &'a str>) -> Vec<String> {
    let products: Vec<&str> = product_ids.collect();
    ["level2", "heartbeats"]
        .into_iter()
        .map(|channel| {
            serde_json::json!({
                "type": "subscribe",
                "product_ids": products,
                "channel": channel,
            })
            .to_string()
        })
        .collect()
}

/// Builds the subscribe frame for a set of product ids.
#[must_use]
pub fn subscribe_frame<'a>(product_ids: impl Iterator<Item = &'a str>) -> String {
    let products: Vec<&str> = product_ids.collect();
    serde_json::json!({
        "type": "subscribe",
        "product_ids": products,
        "channels": ["ticker"],
    })
    .to_string()
}

#[derive(Deserialize)]
struct Message<'a> {
    #[serde(rename = "type", borrow)]
    kind: &'a str,
    #[serde(rename = "product_id", borrow, default)]
    product_id: Option<&'a str>,
    #[serde(borrow, default)]
    price: Option<&'a str>,
    #[serde(borrow, default)]
    time: Option<&'a str>,
    #[serde(default)]
    sequence: Option<u64>,
}

/// An Advanced Trade message. `events` is read once the channel is known: a
/// heartbeat's events have another shape.
#[derive(Deserialize)]
struct BookEnvelope<'a> {
    #[serde(borrow, default)]
    channel: Option<&'a str>,
    #[serde(default)]
    sequence_num: Option<u64>,
    #[serde(borrow, default)]
    timestamp: Option<&'a str>,
    #[serde(borrow, default)]
    events: Option<&'a serde_json::value::RawValue>,
}

#[derive(Deserialize)]
struct BookEvent<'a> {
    #[serde(rename = "type", borrow)]
    kind: &'a str,
    #[serde(borrow)]
    product_id: &'a str,
    #[serde(borrow, default)]
    updates: Vec<BookUpdate<'a>>,
}

#[derive(Deserialize)]
struct BookUpdate<'a> {
    #[serde(borrow)]
    side: &'a str,
    #[serde(borrow)]
    price_level: &'a str,
    #[serde(borrow)]
    new_quantity: &'a str,
}

/// Decodes one message on the Advanced Trade book connection into `books`.
///
/// # Errors
///
/// Returns [`DecodeError`], and [`DecodeError::Resync`] when a message number
/// is skipped.
pub fn decode_book(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: BookEnvelope<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let Some(sequence) = envelope.sequence_num else {
        // A subscription error carries `type` and `message`, and no number.
        return Err(DecodeError::Malformed(
            String::from_utf8_lossy(payload).into_owned(),
        ));
    };
    if let Some(last) = books.sequence
        && last.checked_add(1) != Some(sequence)
    {
        return Err(DecodeError::Resync(format!(
            "message {sequence} does not follow {last}"
        )));
    }
    books.sequence = Some(sequence);
    let (Some("l2_data"), Some(events)) = (envelope.channel, envelope.events) else {
        return Err(DecodeError::Control);
    };
    let events: Vec<BookEvent<'_>> =
        serde_json::from_str(events.get()).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let exchange_time_ns = envelope.timestamp.and_then(rfc3339_to_unix_nanos);
    for event in events {
        let Some(entry) = map.lookup(event.product_id) else {
            continue;
        };
        let book = books.book(event.product_id);
        if event.kind == "snapshot" {
            book.clear();
        }
        for update in &event.updates {
            let side = match update.side {
                "bid" => Side::Bid,
                "offer" => Side::Ask,
                other => return Err(DecodeError::Malformed(format!("book side `{other}`"))),
            };
            let level = crate::depth::level(update.price_level, update.new_quantity)?;
            book.set(side, level.price, level.qty);
        }
        let emit = if entry.depth {
            Books::emit
        } else {
            Books::emit_top
        };
        emit(
            books,
            event.product_id,
            entry.instrument.clone(),
            exchange_time_ns,
            local_recv_ns,
            out,
        )?;
    }
    Ok(())
}

/// The session's entry point: [`decode_payload`], with the connection's books.
///
/// # Errors
///
/// As [`decode_payload`].
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    _books: &mut crate::book::Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    decode_payload(payload, map, local_recv_ns, out)
}

/// Decodes one Coinbase Exchange payload: a `ticker` yields its trade. Its best
/// bid and ask are left out, because they are only as new as the last trade.
///
/// # Errors
///
/// Returns [`DecodeError`]. Subscription confirmations and heartbeats are benign.
pub fn decode_payload(
    payload: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let message: Message<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;

    if message.kind == "error" {
        // Surfaced as malformed rather than benign: a subscribe that Coinbase
        // rejected is a configuration problem worth seeing in the counters.
        return Err(DecodeError::Malformed(
            "coinbase rejected a request".to_owned(),
        ));
    }
    if message.kind != "ticker" {
        return Err(DecodeError::Control);
    }

    let product_id = message
        .product_id
        .ok_or(DecodeError::MissingField("product_id"))?;
    let entry = map
        .lookup(product_id)
        .ok_or_else(|| DecodeError::UnknownInstrument(product_id.to_owned()))?;
    let Some(price) = message.price else {
        return Err(DecodeError::Control);
    };
    out.push(Observation {
        instrument: entry.instrument.clone(),
        kind: ObsKind::Trade,
        price: decimal("price", price)?,
        bid: None,
        ask: None,
        bid_qty: None,
        ask_qty: None,
        depth_notional_1bp: None,
        exchange_time_ns: message.time.and_then(rfc3339_to_unix_nanos),
        local_recv_ns,
        seq: message.sequence,
        book: None,
        funding: None,
    });
    Ok(())
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
        let specs = vec![
            InstrumentSpec::new("BTC-USD", MarketKind::Spot, "CRYPTO.BTC/USD").expect("valid"),
        ];
        InstrumentMap::new(Venue::Coinbase, MarketKind::Spot, &specs).expect("valid")
    }

    fn decode(payload: &str) -> Vec<Observation> {
        let mut out = Vec::new();
        decode_payload(payload.as_bytes(), &map(), RECV, &mut out).expect("decodes");
        out
    }

    const TICKER: &str = r#"{"type":"ticker","sequence":12345,"product_id":"BTC-USD",
        "price":"64312.10","open_24h":"63000","volume_24h":"100","low_24h":"62000",
        "high_24h":"65000","volume_30d":"3000","best_bid":"64312.00",
        "best_bid_size":"0.50000000","best_ask":"64313.00","best_ask_size":"0.25000000",
        "side":"buy","time":"2026-08-07T16:00:00.123456Z","trade_id":999,
        "last_size":"0.01"}"#;

    /// The ticker's best bid and ask are as old as the last trade, so they must
    /// not reach the book slot: the level2 book gives the top.
    #[test]
    fn a_ticker_yields_only_its_trade() {
        let observations = decode(TICKER);
        assert_eq!(observations.len(), 1);
        let trade = &observations[0];
        assert_eq!(trade.kind, ObsKind::Trade);
        assert_eq!(trade.price, "64312.1".parse().expect("valid"));
        assert_eq!(trade.seq, Some(12_345));
        assert!(trade.bid.is_none());
    }

    #[test]
    fn the_rfc3339_timestamp_is_parsed() {
        let observations = decode(TICKER);
        // 2026-08-07T16:00:00.123456Z
        assert_eq!(
            observations[0].exchange_time_ns,
            Some(1_786_118_400 * 1_000_000_000 + 123_456_000)
        );
    }

    #[test]
    fn a_ticker_without_a_book_still_yields_the_trade() {
        let no_book = r#"{"type":"ticker","product_id":"BTC-USD","price":"64312.10",
            "time":"2026-08-07T16:00:00Z"}"#;
        let observations = decode(no_book);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].kind, ObsKind::Trade);
    }

    #[test]
    fn subscriptions_and_heartbeats_are_benign() {
        let mut out = Vec::new();
        for control in [
            r#"{"type":"subscriptions","channels":[{"name":"ticker","product_ids":["BTC-USD"]}]}"#,
            r#"{"type":"heartbeat","sequence":1,"last_trade_id":1,"product_id":"BTC-USD","time":"2026-08-07T16:00:00Z"}"#,
        ] {
            let error = decode_payload(control.as_bytes(), &map(), RECV, &mut out)
                .expect_err("not market data");
            assert!(error.is_benign(), "got {error:?}");
        }
        assert!(out.is_empty());
    }

    /// A rejected subscribe is a configuration problem, not routine traffic.
    #[test]
    fn an_error_message_is_not_benign() {
        let mut out = Vec::new();
        let error = decode_payload(
            br#"{"type":"error","message":"Failed to subscribe","reason":"nope"}"#,
            &map(),
            RECV,
            &mut out,
        )
        .expect_err("an error");
        assert!(!error.is_benign(), "a rejected subscribe must be visible");
    }

    #[test]
    fn untracked_products_are_benign() {
        let other = TICKER.replace("BTC-USD", "ETH-USD");
        let mut out = Vec::new();
        let error =
            decode_payload(other.as_bytes(), &map(), RECV, &mut out).expect_err("untracked");
        assert!(error.is_benign());
    }

    #[test]
    fn the_subscribe_frame_names_the_ticker_channel() {
        let frame = subscribe_frame(["BTC-USD", "ETH-USD"].into_iter());
        assert!(frame.contains(r#""type":"subscribe""#));
        assert!(frame.contains("BTC-USD"));
        assert!(frame.contains(r#""ticker""#));
    }

    /// Recorded from Coinbase Advanced Trade on 2026-10-06. The snapshot is cut
    /// to its best 200 levels a side; the updates and their numbers are as sent.
    const RECORDED_BOOK: &str = include_str!("../../tests/fixtures/coinbase-level2.jsonl");

    fn book_map() -> InstrumentMap {
        let specs = vec![
            InstrumentSpec::new("BTC-USD", MarketKind::Spot, "CRYPTO.BTC/USD")
                .expect("valid")
                .with_depth(),
        ];
        InstrumentMap::new(Venue::Coinbase, MarketKind::Spot, &specs).expect("valid")
    }

    fn replay(map: &InstrumentMap) -> (Books, Vec<Observation>) {
        let mut books = Books::default();
        let mut all = Vec::new();
        for line in RECORDED_BOOK.lines() {
            let mut out = Vec::new();
            match decode_book(line.as_bytes(), map, &mut books, RECV, &mut out) {
                Ok(()) => {}
                Err(error) if error.is_benign() => {}
                Err(error) => panic!("{error}: {line}"),
            }
            all.extend(out);
        }
        (books, all)
    }

    /// A product without depth still gets its top from the book, on every book
    /// change, so a quiet coin with no trades keeps a live quote.
    #[test]
    fn a_book_without_depth_yields_its_best_bid_and_ask() {
        let (mut books, observations) = replay(&map());
        assert!(observations.len() >= 20, "{}", observations.len());
        assert!(
            observations
                .iter()
                .all(|o| o.kind == ObsKind::BookTop && o.book.is_none())
        );
        let last = observations.last().expect("one");
        let book = books.book("BTC-USD");
        assert_eq!(last.bid, Some(book.top(Side::Bid, 1)[0].price));
        assert_eq!(last.ask, Some(book.top(Side::Ask, 1)[0].price));
        assert_eq!(last.bid_qty, Some(book.top(Side::Bid, 1)[0].qty));
        assert!(last.bid < last.ask);
    }

    #[test]
    fn book_subscriptions_name_level2_and_heartbeats() {
        let frames = book_subscribe_frames(["BTC-USD"].into_iter());
        assert_eq!(frames.len(), 2);
        assert!(frames[0].contains(r#""channel":"level2""#));
        assert!(frames[1].contains(r#""channel":"heartbeats""#));
    }

    #[test]
    fn a_recorded_book_follows_its_message_numbers() {
        let (mut books, observations) = replay(&book_map());
        assert!(observations.len() >= 20, "{}", observations.len());
        assert!(
            observations
                .iter()
                .all(|o| o.kind == ObsKind::Depth && o.book.is_some())
        );
        let book = books.book("BTC-USD");
        assert!(book.top(Side::Bid, 1)[0].price < book.top(Side::Ask, 1)[0].price);
    }

    #[test]
    fn a_skipped_message_asks_for_a_resync() {
        let map = book_map();
        let mut books = Books::default();
        let mut lines = RECORDED_BOOK
            .lines()
            .filter(|line| line.contains("l2_data"));
        let snapshot = lines.next().expect("a snapshot");
        decode_book(snapshot.as_bytes(), &map, &mut books, RECV, &mut Vec::new()).expect("valid");
        let _skipped = lines.next().expect("an update");
        let after = lines.next().expect("a later update");
        assert!(matches!(
            decode_book(after.as_bytes(), &map, &mut books, RECV, &mut Vec::new()),
            Err(DecodeError::Resync(_))
        ));
    }
}
