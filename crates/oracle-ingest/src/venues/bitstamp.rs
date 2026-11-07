//! Bitstamp public streams: spot, natively in USD.
//!
//! - **One envelope.** `{"event":"data","channel":"order_book_btcusd","data":{…}}`;
//!   the symbol is the part of the channel after its prefix. A subscription
//!   names one channel.
//! - **Books.** `order_book_{pair}` gives the top 100 levels as a whole
//!   snapshot at each change, so the node keeps no deltas. It is the only
//!   source of the quote, so every market subscribes it.
//! - **Trades.** `live_trades_{pair}`, with the price as the string `price_str`.
//! - **Control.** `bts:subscription_succeeded` and `bts:heartbeat` are benign.
//!   `bts:error` is a refused request, and `bts:request_reconnect` asks for a
//!   new connection before maintenance.
//!
//! Checked against the live socket on 2026-10-28.

use std::time::Duration;

use oracle_types::{ObsKind, Observation};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{BookMsg, BookRule, Books, Change, Continuity};
use crate::{DecodeError, InstrumentMap};

use super::{decimal, integer, observation, parse};

/// The public socket.
pub const URL: &str = "wss://ws.bitstamp.net";

/// The keepalive, which the venue answers with a `bts:heartbeat` event.
pub const KEEPALIVE: &str = r#"{"event":"bts:heartbeat"}"#;

/// How often to send [`KEEPALIVE`].
pub const KEEPALIVE_EVERY: Duration = Duration::from_secs(30);

/// Markets on one connection. Each market takes two channels; 40 channels in
/// one burst all succeeded on 2026-10-28.
pub const MARKETS_PER_CONNECTION: usize = 20;
const _: () = assert!(MARKETS_PER_CONNECTION * 2 <= 40);

const BOOK: &str = "order_book_";

/// Each book message is a whole book.
const BOOK_RULE: BookRule = BookRule::new(Continuity::WholeBook);
const TRADES: &str = "live_trades_";

fn subscribe(channel: &str) -> String {
    serde_json::json!({ "event": "bts:subscribe", "data": { "channel": channel } }).to_string()
}

/// The subscribe frames of a connection: each market's book and trades.
#[must_use]
pub fn frames<'a>(symbols: impl Iterator<Item = &'a str>) -> Vec<String> {
    symbols
        .flat_map(|symbol| {
            [
                subscribe(&format!("{BOOK}{symbol}")),
                subscribe(&format!("{TRADES}{symbol}")),
            ]
        })
        .collect()
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow)]
    event: &'a str,
    #[serde(borrow, default)]
    channel: &'a str,
    #[serde(borrow, default)]
    data: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct Book<'a> {
    #[serde(borrow)]
    bids: Vec<(&'a str, &'a str)>,
    #[serde(borrow)]
    asks: Vec<(&'a str, &'a str)>,
    #[serde(borrow, default)]
    microtimestamp: Option<&'a str>,
}

#[derive(Deserialize)]
struct Trade<'a> {
    #[serde(borrow)]
    price_str: &'a str,
    #[serde(borrow, default)]
    microtimestamp: Option<&'a str>,
}

/// Unix microseconds, in a string, as unix nanoseconds.
fn micros(text: Option<&str>) -> Result<Option<u64>, DecodeError> {
    text.map(|text| integer("microtimestamp", text))
        .transpose()
        .map(|micros| micros.and_then(|micros| micros.checked_mul(1_000)))
}

/// Decodes one payload.
///
/// # Errors
///
/// Returns [`DecodeError`]. Acks and heartbeats are benign; a refused request
/// is not, and a request to reconnect ends the connection.
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> = serde_json::from_slice(payload)?;
    let data = || envelope.data.ok_or(DecodeError::MissingField("data"));
    match envelope.event {
        "data" => {
            let symbol = envelope
                .channel
                .strip_prefix(BOOK)
                .ok_or_else(|| DecodeError::UnhandledStream(envelope.channel.to_owned()))?;
            let entry = map
                .lookup(symbol)
                .ok_or_else(|| DecodeError::UnknownInstrument(symbol.to_owned()))?;
            let parsed = parse::<Book<'_>>(data()?).and_then(|snapshot| {
                let whole = BookMsg::whole(&snapshot.bids, &snapshot.asks, |(price, size)| {
                    Ok(Change::new(
                        decimal("price", price)?,
                        decimal("amount", size)?,
                    ))
                })?;
                Ok(whole.at(micros(snapshot.microtimestamp)?))
            });
            books
                .keeper
                .apply(BOOK_RULE, entry, parsed, local_recv_ns, out)
        }
        "trade" => {
            let symbol = envelope
                .channel
                .strip_prefix(TRADES)
                .ok_or_else(|| DecodeError::UnhandledStream(envelope.channel.to_owned()))?;
            let entry = map
                .lookup(symbol)
                .ok_or_else(|| DecodeError::UnknownInstrument(symbol.to_owned()))?;
            let trade: Trade<'_> = parse(data()?)?;
            out.push(Observation {
                exchange_time_ns: micros(trade.microtimestamp)?,
                ..observation(
                    entry,
                    ObsKind::Trade,
                    decimal("price_str", trade.price_str)?,
                    local_recv_ns,
                )
            });
            Ok(())
        }
        "bts:error" => Err(DecodeError::Malformed(format!(
            "the server refused a request: {}",
            envelope.data.map_or("", RawValue::get)
        ))),
        "bts:request_reconnect" => Err(DecodeError::Resync(
            "the venue asks for a new connection".to_owned(),
        )),
        _ => Err(DecodeError::Control),
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixed-shape fixtures; an out-of-range index is a failing test"
)]
mod tests {
    use super::*;
    use crate::book::DEPTH_LEVELS;
    use crate::testing::{Feed, Replayed, fixed, instrument, of};
    use oracle_types::{MarketKind, Venue};

    /// 2026-10-26, before every recording: a time read in seconds would be far below it.
    const IN_2026_NS: u64 = 1_793_000_000_000_000_000;

    /// Recorded from Bitstamp on 2026-10-28: the acks, a refused channel, the
    /// BTC and USDT books, BTC's trades and a heartbeat.
    const SPOT: &str = include_str!("../../tests/fixtures/bitstamp-spot.jsonl");

    /// BTC with or without its book, and the USDT peg's top.
    fn bitstamp(depth: bool) -> Feed {
        let btc = instrument("btcusd", MarketKind::Spot);
        let pairs = [
            if depth { btc.with_depth() } else { btc },
            instrument("usdtusd", MarketKind::Spot),
        ];
        Feed::venue(decode, Venue::Bitstamp, MarketKind::Spot, &pairs)
    }

    #[test]
    fn a_session_gives_books_and_trades() {
        let Replayed {
            observations: all,
            errors,
        } = bitstamp(true).replay_all(SPOT.lines());
        let [refused] = errors.as_slice() else {
            panic!("only the refused channel is an error: {errors:?}");
        };
        assert!(refused.to_string().contains("Invalid channel"), "{refused}");

        let depth = *of(&all, "btcusd", ObsKind::Depth).last().expect("a book");
        let book = depth.book.as_deref().expect("levels");
        assert_eq!(book.bids.len(), DEPTH_LEVELS);
        assert_eq!(depth.bid, Some(book.bids[0].price));
        // A time in 2026: the microseconds were read, not the seconds.
        assert!(depth.exchange_time_ns.is_some_and(|ns| ns > IN_2026_NS));

        // The USDT book wants no depth, so it gives only its top.
        let peg = of(&all, "usdtusd", ObsKind::BookTop);
        assert!(of(&all, "usdtusd", ObsKind::Depth).is_empty());
        assert!(peg[0].bid < peg[0].ask);
        assert!(peg[0].price > fixed("0.99"));

        let trades = of(&all, "btcusd", ObsKind::Trade);
        assert_eq!(trades.len(), 3);
        assert!(trades.iter().all(|o| o.exchange_time_ns.is_some()));
    }

    #[test]
    fn a_market_without_depth_gives_its_top() {
        let all = bitstamp(false).replay_all(SPOT.lines()).observations;
        assert!(all.iter().all(|o| o.kind != ObsKind::Depth));
        assert!(!of(&all, "btcusd", ObsKind::BookTop).is_empty());
    }

    #[test]
    fn control_events_are_benign_and_a_reconnect_ends_the_connection() {
        let mut feed = bitstamp(true);
        assert!(
            feed.refused(r#"{"event":"bts:heartbeat","channel":"","data":{"status":"success"}}"#)
                .is_benign()
        );
        assert!(matches!(
            feed.refused(r#"{"event":"bts:request_reconnect","channel":"","data":""}"#),
            DecodeError::Resync(_)
        ));
        let untracked =
            r#"{"event":"data","channel":"order_book_ethusd","data":{"bids":[],"asks":[]}}"#;
        assert!(feed.refused(untracked).is_benign());
    }

    #[test]
    fn a_connection_subscribes_each_book_and_its_trades() {
        let frames = frames(["btcusd", "usdtusd"].into_iter());
        assert_eq!(frames.len(), 4);
        let first: serde_json::Value = serde_json::from_str(&frames[0]).expect("JSON");
        assert_eq!(first["event"], "bts:subscribe");
        assert_eq!(first["data"]["channel"], "order_book_btcusd");
        assert!(frames[3].contains("live_trades_usdtusd"));
    }
}
