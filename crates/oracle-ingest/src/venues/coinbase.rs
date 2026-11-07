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

use crate::book::{BookMsg, BookRule, Books, Change, Continuity, Halts};
use crate::{DecodeError, InstrumentMap};

use super::{decimal, observation, parse, rfc3339_to_unix_nanos};

/// The public endpoint.
pub const URL: &str = "wss://ws-feed.exchange.coinbase.com";

/// The Advanced Trade endpoint, for the book. The Exchange feed's `level2`
/// needs credentials, and its keyless `level2_batch` numbers nothing, so a
/// missed message could not be detected. Advanced Trade's `level2` is keyless
/// and numbers every message on the connection.
pub const BOOK_URL: &str = "wss://advanced-trade-ws.coinbase.com";

/// The connection numbers every message, so a book needs no id of its own.
const BOOK_RULE: BookRule = BookRule::new(Continuity::Connection);

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
    let envelope: BookEnvelope<'_> = serde_json::from_slice(payload)?;
    let Some(sequence) = envelope.sequence_num else {
        // A subscription error carries `type` and `message`, and no number.
        return Err(DecodeError::Malformed(
            String::from_utf8_lossy(payload).into_owned(),
        ));
    };
    books.keeper.next_message(sequence)?;
    let (Some("l2_data"), Some(events)) = (envelope.channel, envelope.events) else {
        return Err(DecodeError::Control);
    };
    let events: Vec<BookEvent<'_>> = parse(events).map_err(|e| BOOK_RULE.unparsed(e))?;
    let time = envelope.timestamp.and_then(rfc3339_to_unix_nanos);
    // One product's empty side must not stop the others: the message number
    // has passed already.
    let mut halts = Halts::default();
    for event in events {
        let Some(entry) = map.lookup(event.product_id) else {
            continue;
        };
        let parsed = book_message(&event).map(|message| message.at(time));
        let applied = books
            .keeper
            .apply(BOOK_RULE, entry, parsed, local_recv_ns, out);
        halts.absorb(&entry.instrument, applied)?;
    }
    halts.finish(Ok(()))
}

/// One product's event: a snapshot, or the levels that changed.
fn book_message(event: &BookEvent<'_>) -> Result<BookMsg<'static>, DecodeError> {
    let mut message = BookMsg {
        snapshot: event.kind == "snapshot",
        ..BookMsg::default()
    };
    for update in &event.updates {
        let level = crate::depth::level(update.price_level, update.new_quantity)?;
        match update.side {
            "bid" => message.bids.push(Change::from(level)),
            "offer" => message.asks.push(Change::from(level)),
            other => return Err(DecodeError::Malformed(format!("book side `{other}`"))),
        }
    }
    Ok(message)
}

/// Decodes one Coinbase Exchange payload: a `ticker` yields its trade. Its best
/// bid and ask are left out, because they are only as new as the last trade.
///
/// # Errors
///
/// Returns [`DecodeError`]. Subscription confirmations and heartbeats are benign.
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    _books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let message: Message<'_> = serde_json::from_slice(payload)?;

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
        exchange_time_ns: message.time.and_then(rfc3339_to_unix_nanos),
        seq: message.sequence,
        ..observation(
            entry,
            ObsKind::Trade,
            decimal("price", price)?,
            local_recv_ns,
        )
    });
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixed payloads; an out-of-range index is a failing test"
)]
mod tests {
    use super::*;
    use crate::testing::{Feed, fixed, instrument};
    use oracle_types::{MarketKind, Venue};

    fn btc_usd(depth: bool) -> crate::InstrumentSpec {
        let spec = instrument("BTC-USD", MarketKind::Spot);
        if depth { spec.with_depth() } else { spec }
    }

    fn ticker() -> Feed {
        Feed::venue(decode, Venue::Coinbase, MarketKind::Spot, &[btc_usd(false)])
    }

    fn book(depth: bool) -> Feed {
        Feed::venue(
            decode_book,
            Venue::Coinbase,
            MarketKind::Spot,
            &[btc_usd(depth)],
        )
    }

    const TICKER: &str = r#"{"type":"ticker","sequence":12345,"product_id":"BTC-USD",
        "price":"64312.10","open_24h":"63000","volume_24h":"100","low_24h":"62000",
        "high_24h":"65000","volume_30d":"3000","best_bid":"64312.00",
        "best_bid_size":"0.50000000","best_ask":"64313.00","best_ask_size":"0.25000000",
        "side":"buy","time":"2026-08-07T16:00:00.123456Z","trade_id":999,
        "last_size":"0.01"}"#;

    /// Recorded from Coinbase Advanced Trade on 2026-10-06. The snapshot is cut
    /// to its best 200 levels a side; the updates and their numbers are as sent.
    const RECORDED_BOOK: &str = include_str!("../../tests/fixtures/coinbase-level2.jsonl");

    /// The ticker's best bid and ask are as old as the last trade, so they must
    /// not reach the book slot: the level2 book gives the top.
    #[test]
    fn a_ticker_yields_only_its_trade() {
        let observations = ticker().decoded(TICKER);
        let [trade] = observations.as_slice() else {
            panic!("one observation: {observations:?}");
        };
        assert_eq!(trade.kind, ObsKind::Trade);
        assert_eq!(trade.price, fixed("64312.1"));
        assert_eq!(trade.seq, Some(12_345));
        assert!(trade.bid.is_none());
    }

    #[test]
    fn the_rfc3339_timestamp_is_parsed() {
        let trade = &ticker().decoded(TICKER)[0];
        // 2026-08-07T16:00:00.123456Z
        let stamped = 1_786_118_400 * 1_000_000_000 + 123_456_000;
        assert_eq!(trade.exchange_time_ns, Some(stamped));
    }

    #[test]
    fn a_ticker_without_a_book_still_yields_the_trade() {
        let no_book = r#"{"type":"ticker","product_id":"BTC-USD","price":"64312.10",
            "time":"2026-08-07T16:00:00Z"}"#;
        let observations = ticker().decoded(no_book);
        assert_eq!(
            observations.iter().map(|o| o.kind).collect::<Vec<_>>(),
            [ObsKind::Trade]
        );
    }

    #[test]
    fn subscriptions_and_heartbeats_are_benign() {
        let mut ticker = ticker();
        for control in [
            r#"{"type":"subscriptions","channels":[{"name":"ticker","product_ids":["BTC-USD"]}]}"#,
            r#"{"type":"heartbeat","sequence":1,"last_trade_id":1,"product_id":"BTC-USD","time":"2026-08-07T16:00:00Z"}"#,
        ] {
            let error = ticker.refused(control);
            assert!(error.is_benign(), "got {error:?}");
        }
    }

    /// A rejected subscribe is a configuration problem, not routine traffic.
    #[test]
    fn an_error_message_is_not_benign() {
        let error =
            ticker().refused(r#"{"type":"error","message":"Failed to subscribe","reason":"nope"}"#);
        assert!(!error.is_benign(), "a rejected subscribe must be visible");
    }

    #[test]
    fn untracked_products_are_benign() {
        assert!(
            ticker()
                .refused(TICKER.replace("BTC-USD", "ETH-USD"))
                .is_benign()
        );
    }

    #[test]
    fn the_subscribe_frame_names_the_ticker_channel() {
        let frame = subscribe_frame(["BTC-USD", "ETH-USD"].into_iter());
        assert!(frame.contains(r#""type":"subscribe""#));
        assert!(frame.contains("BTC-USD"));
        assert!(frame.contains(r#""ticker""#));
    }

    /// A product without depth still gets its top from the book, on every book
    /// change, so a quiet coin with no trades keeps a live quote.
    #[test]
    fn a_book_without_depth_yields_its_best_bid_and_ask() {
        let tops = book(false).replay(RECORDED_BOOK.lines());
        let depths = book(true).replay(RECORDED_BOOK.lines());
        assert_eq!(tops.len(), depths.len(), "one top for each book change");
        for (top, depth) in tops.iter().zip(&depths) {
            assert_eq!((top.kind, top.book.as_ref()), (ObsKind::BookTop, None));
            let quote = |o: &Observation| (o.bid, o.ask, o.bid_qty, o.ask_qty);
            assert_eq!(quote(top), quote(depth), "the top is the book's best level");
        }
    }

    /// The side, the price and the new size of one level.
    type Update<'a> = (&'a str, &'a str, &'a str);

    /// One `l2_data` message of `events`, each a type, a product and its updates.
    fn level2(sequence: u64, events: &[(&str, &str, &[Update<'_>])]) -> String {
        let events: Vec<serde_json::Value> = events
            .iter()
            .map(|(kind, product, updates)| {
                let updates: Vec<serde_json::Value> = updates
                    .iter()
                    .map(|(side, price, size)| {
                        serde_json::json!({ "side": side, "price_level": price, "new_quantity": size })
                    })
                    .collect();
                serde_json::json!({ "type": kind, "product_id": product, "updates": updates })
            })
            .collect();
        serde_json::json!({ "channel": "l2_data", "sequence_num": sequence, "events": events })
            .to_string()
    }

    /// One product's empty side must not stop the other product of the same
    /// message, since the message number has passed.
    #[test]
    fn a_halted_product_does_not_stop_the_others_in_its_message() {
        let pairs = [btc_usd(false), instrument("ETH-USD", MarketKind::Spot)];
        let mut feed = Feed::venue(decode_book, Venue::Coinbase, MarketKind::Spot, &pairs);
        let book: &[Update<'_>] = &[("bid", "100", "1"), ("offer", "101", "1")];
        let _ = feed.decoded(level2(
            1,
            &[("snapshot", "BTC-USD", book), ("snapshot", "ETH-USD", book)],
        ));
        let (observations, halted) = feed.halted(level2(
            2,
            &[
                ("update", "BTC-USD", &[("offer", "101", "0")]),
                ("update", "ETH-USD", &[("bid", "100.5", "2")]),
            ],
        ));
        assert_eq!(halted, ["BTC-USD"]);
        let [eth] = observations.as_slice() else {
            panic!("the ETH quote: {observations:?}");
        };
        assert_eq!(
            (&*eth.instrument.symbol, eth.bid),
            ("ETH-USD", Some(fixed("100.5")))
        );
        let next = feed.decoded(level2(
            3,
            &[("update", "ETH-USD", &[("bid", "100.6", "1")])],
        ));
        assert_eq!(next.len(), 1, "the next message follows");
    }

    #[test]
    fn book_subscriptions_name_level2_and_heartbeats() {
        let frames = book_subscribe_frames(["BTC-USD"].into_iter());
        assert_eq!(frames.len(), 2);
        assert!(frames[0].contains(r#""channel":"level2""#));
        assert!(frames[1].contains(r#""channel":"heartbeats""#));
    }
}
