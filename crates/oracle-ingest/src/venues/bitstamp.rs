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

use crate::book::{Books, Side};
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
            let snapshot: Book<'_> = parse(data()?)?;
            let book = books.book(symbol);
            book.clear();
            for (side, levels) in [(Side::Bid, &snapshot.bids), (Side::Ask, &snapshot.asks)] {
                for (price, size) in levels {
                    book.set(side, decimal("price", price)?, decimal("amount", size)?);
                }
            }
            let emit = if entry.depth {
                Books::emit
            } else {
                Books::emit_top
            };
            emit(
                books,
                symbol,
                entry.instrument.clone(),
                micros(snapshot.microtimestamp)?,
                local_recv_ns,
                out,
            )
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
    use crate::InstrumentSpec;
    use oracle_types::{Fixed, MarketKind, Venue};

    const RECV: u64 = 1_793_212_030_000_000_000;
    /// Recorded from Bitstamp on 2026-10-28: the acks, a refused channel, the
    /// BTC and USDT books, BTC's trades and a heartbeat.
    const SPOT: &str = include_str!("../../tests/fixtures/bitstamp-spot.jsonl");

    fn map(depth: bool) -> InstrumentMap {
        let specs: Vec<InstrumentSpec> = [("btcusd", depth), ("usdtusd", false)]
            .into_iter()
            .map(|(symbol, depth)| {
                let spec =
                    InstrumentSpec::new(symbol, MarketKind::Spot, "CRYPTO.X/USD").expect("valid");
                if depth { spec.with_depth() } else { spec }
            })
            .collect();
        InstrumentMap::new(Venue::Bitstamp, MarketKind::Spot, &specs).expect("valid")
    }

    fn replay(map: &InstrumentMap) -> (Vec<Observation>, Vec<String>) {
        let mut books = Books::default();
        let (mut all, mut errors) = (Vec::new(), Vec::new());
        for line in SPOT.lines() {
            let mut out = Vec::new();
            match decode(line.as_bytes(), map, &mut books, RECV, &mut out) {
                Ok(()) => all.extend(out),
                Err(error) if error.is_benign() => {}
                Err(error) => errors.push(error.to_string()),
            }
        }
        (all, errors)
    }

    #[test]
    fn a_session_gives_books_and_trades() {
        let (all, errors) = replay(&map(true));
        // Only the refused channel is an error.
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("Invalid channel"), "{errors:?}");

        let depth = all
            .iter()
            .rev()
            .find(|o| o.kind == ObsKind::Depth)
            .expect("a book");
        assert_eq!(&*depth.instrument.symbol, "btcusd");
        let book = depth.book.as_deref().expect("levels");
        assert_eq!(book.bids.len(), 50);
        assert!(book.bids[0].price < book.asks[0].price);
        assert_eq!(depth.bid, Some(book.bids[0].price));
        assert!(
            depth
                .exchange_time_ns
                .is_some_and(|ns| ns > 1_793_000_000_000_000_000)
        );

        // The USDT book wants no depth, so it gives only its top.
        let peg = all
            .iter()
            .find(|o| &*o.instrument.symbol == "usdtusd")
            .expect("a quote");
        assert_eq!(peg.kind, ObsKind::BookTop);
        assert!(peg.bid < peg.ask);
        assert!(peg.price > "0.99".parse::<Fixed>().expect("valid"));

        let trades: Vec<_> = all.iter().filter(|o| o.kind == ObsKind::Trade).collect();
        assert_eq!(trades.len(), 3);
        assert!(trades.iter().all(|o| o.exchange_time_ns.is_some()));
    }

    #[test]
    fn a_market_without_depth_gives_its_top() {
        let (all, _) = replay(&map(false));
        assert!(all.iter().all(|o| o.kind != ObsKind::Depth));
        assert!(
            all.iter()
                .any(|o| o.kind == ObsKind::BookTop && &*o.instrument.symbol == "btcusd")
        );
    }

    #[test]
    fn control_events_are_benign_and_a_reconnect_ends_the_connection() {
        let map = map(true);
        let mut books = Books::default();
        let mut out = Vec::new();
        let mut decode_one =
            |payload: &str| decode(payload.as_bytes(), &map, &mut books, RECV, &mut out);
        assert!(
            decode_one(r#"{"event":"bts:heartbeat","channel":"","data":{"status":"success"}}"#)
                .is_err_and(|error| error.is_benign())
        );
        assert!(matches!(
            decode_one(r#"{"event":"bts:request_reconnect","channel":"","data":""}"#),
            Err(DecodeError::Resync(_))
        ));
        assert!(
            decode_one(
                r#"{"event":"data","channel":"order_book_ethusd","data":{"bids":[],"asks":[]}}"#
            )
            .is_err_and(|error| error.is_benign())
        );
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
