//! dYdX v4 public streams, from the indexer: USDC-margined perpetuals.
//!
//! - **One envelope.** `{"type":"channel_batch_data","channel":"v4_orderbook",
//!   "id":"BTC-USD","contents":[…]}`. A subscription names a channel and a market,
//!   and `batched` groups the changes of a moment into one message.
//! - **Books.** `v4_orderbook` gives the whole book at subscribe, as objects,
//!   then changes as `[price, size]` pairs; a size of zero removes a level. The
//!   changes carry no sequence. The indexer's docs warn that a book can cross;
//!   the node then reads it again from a new connection.
//! - **Trades.** `v4_trades`. The message at subscribe holds old trades, so only
//!   the updates count.
//! - **Funding.** `v4_markets` covers every market in one subscription: the
//!   oracle price, which is the venue's mark, the predicted rate of the next hour,
//!   and the open interest in coins. Its updates carry only the fields that
//!   changed. dYdX pays each hour.
//! - **Control.** The venue pings, and the transport answers. It takes 2
//!   subscriptions a second; a burst of 12 succeeded on 2026-10-28.
//!
//! Checked against the live socket on 2026-10-28.

use oracle_types::{Fixed, NANOS_PER_SEC, ObsKind, Observation};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{Books, Side};
use crate::instrument::InstrumentEntry;
use crate::{DecodeError, InstrumentMap};

use super::{decimal, interval_funding, observation, parse, rfc3339_to_unix_nanos};

/// The indexer's socket.
pub const URL: &str = "wss://indexer.dydx.trade/v4/ws";

/// Markets on one connection: each takes a book and its trades, and the
/// connection takes the markets channel once. The venue allows 32
/// subscriptions to one channel.
pub const MARKETS_PER_CONNECTION: usize = 10;
const _: () = assert!(MARKETS_PER_CONNECTION <= 32);

const HOUR_NS: u64 = 3_600 * NANOS_PER_SEC;

/// The full book: deep enough for every impact size.
const BOOK_DEPTH: usize = 1_000;

fn subscribe(channel: &str, id: Option<&str>) -> String {
    let mut frame = serde_json::json!({ "type": "subscribe", "channel": channel, "batched": true });
    if let (Some(id), Some(object)) = (id, frame.as_object_mut()) {
        object.insert("id".to_owned(), id.into());
    }
    frame.to_string()
}

/// The subscribe frames of a connection: each market's book and trades, then
/// the markets channel.
#[must_use]
pub fn frames<'a>(symbols: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = symbols
        .flat_map(|id| {
            [
                subscribe("v4_orderbook", Some(id)),
                subscribe("v4_trades", Some(id)),
            ]
        })
        .collect();
    if !out.is_empty() {
        out.push(subscribe("v4_markets", None));
    }
    out
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(rename = "type", borrow)]
    kind: &'a str,
    #[serde(borrow, default)]
    channel: Option<&'a str>,
    #[serde(borrow, default)]
    id: Option<&'a str>,
    #[serde(borrow, default)]
    contents: Option<&'a RawValue>,
    #[serde(borrow, default)]
    message: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct Level<'a> {
    #[serde(borrow)]
    price: &'a str,
    #[serde(borrow)]
    size: &'a str,
}

#[derive(Deserialize)]
struct Snapshot<'a> {
    #[serde(borrow, default)]
    bids: Vec<Level<'a>>,
    #[serde(borrow, default)]
    asks: Vec<Level<'a>>,
}

#[derive(Deserialize)]
struct Change<'a> {
    #[serde(borrow, default)]
    bids: Vec<(&'a str, &'a str)>,
    #[serde(borrow, default)]
    asks: Vec<(&'a str, &'a str)>,
}

#[derive(Deserialize)]
struct Trades<'a> {
    #[serde(borrow, default)]
    trades: Vec<Trade<'a>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Trade<'a> {
    #[serde(borrow)]
    price: &'a str,
    #[serde(borrow, default)]
    created_at: Option<&'a str>,
}

/// One market's fields in `v4_markets`. An update carries only those that changed.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Market<'a> {
    #[serde(borrow, default)]
    oracle_price: Option<&'a str>,
    #[serde(borrow, default)]
    next_funding_rate: Option<&'a str>,
    #[serde(borrow, default)]
    open_interest: Option<&'a str>,
}

#[derive(Deserialize)]
struct MarketsSnapshot<'a> {
    #[serde(borrow, default)]
    markets: std::collections::HashMap<&'a str, Market<'a>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarketsChange<'a> {
    #[serde(borrow, default)]
    trading: std::collections::HashMap<&'a str, Market<'a>>,
    #[serde(borrow, default)]
    oracle_prices: std::collections::HashMap<&'a str, Market<'a>>,
}

/// The items of a message: one, or a list when batched.
fn items<'a, T: Deserialize<'a>>(raw: &'a RawValue) -> Result<Vec<T>, DecodeError> {
    if raw.get().starts_with('[') {
        parse(raw)
    } else {
        Ok(vec![parse(raw)?])
    }
}

/// Decodes one payload.
///
/// # Errors
///
/// Returns [`DecodeError`]. The welcome and acks are benign; a refused
/// subscription is not, and a crossed book ends the connection.
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> = serde_json::from_slice(payload)?;
    let subscribed = match envelope.kind {
        "error" => {
            return Err(DecodeError::Malformed(format!(
                "the server refused a request: {}",
                envelope.message.map_or("", RawValue::get)
            )));
        }
        "subscribed" => true,
        "channel_data" | "channel_batch_data" => false,
        _ => return Err(DecodeError::Control),
    };
    let contents = envelope
        .contents
        .ok_or(DecodeError::MissingField("contents"))?;
    match envelope.channel.unwrap_or_default() {
        "v4_orderbook" => {
            let (id, entry) = market(map, envelope.id)?;
            let book = books.book(id);
            if subscribed {
                let snapshot: Snapshot<'_> = parse(contents)?;
                book.clear();
                for (side, levels) in [(Side::Bid, &snapshot.bids), (Side::Ask, &snapshot.asks)] {
                    for level in levels {
                        book.set(
                            side,
                            decimal("price", level.price)?,
                            decimal("size", level.size)?,
                        );
                    }
                }
            } else {
                for change in items::<Change<'_>>(contents)? {
                    for (side, levels) in [(Side::Bid, &change.bids), (Side::Ask, &change.asks)] {
                        for (price, size) in levels {
                            book.set(side, decimal("price", price)?, decimal("size", size)?);
                        }
                    }
                }
            }
            book.truncate(BOOK_DEPTH);
            emit(id, entry, books, local_recv_ns, out)
        }
        "v4_trades" if subscribed => Err(DecodeError::Control),
        "v4_trades" => {
            let (_, entry) = market(map, envelope.id)?;
            for batch in items::<Trades<'_>>(contents)? {
                for trade in batch.trades {
                    out.push(Observation {
                        exchange_time_ns: trade.created_at.and_then(rfc3339_to_unix_nanos),
                        ..observation(
                            entry,
                            ObsKind::Trade,
                            decimal("price", trade.price)?,
                            local_recv_ns,
                        )
                    });
                }
            }
            Ok(())
        }
        "v4_markets" => {
            if subscribed {
                let snapshot: MarketsSnapshot<'_> = parse(contents)?;
                for (id, market) in &snapshot.markets {
                    market_fields(id, market, map, books, local_recv_ns, out)?;
                }
            } else {
                for change in items::<MarketsChange<'_>>(contents)? {
                    for (id, market) in change.trading.iter().chain(&change.oracle_prices) {
                        market_fields(id, market, map, books, local_recv_ns, out)?;
                    }
                }
            }
            Ok(())
        }
        other => Err(DecodeError::UnhandledStream(other.to_owned())),
    }
}

/// The market a message names, and its entry.
fn market<'a, 'm>(
    map: &'m InstrumentMap,
    id: Option<&'a str>,
) -> Result<(&'a str, &'m InstrumentEntry), DecodeError> {
    let id = id.ok_or(DecodeError::MissingField("id"))?;
    map.lookup(id)
        .map(|entry| (id, entry))
        .ok_or_else(|| DecodeError::UnknownInstrument(id.to_owned()))
}

/// Emits the book as depth, or only its top for a market that wants none.
fn emit(
    id: &str,
    entry: &InstrumentEntry,
    books: &Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let emit = if entry.depth {
        Books::emit
    } else {
        Books::emit_top
    };
    emit(
        books,
        id,
        entry.instrument.clone(),
        None,
        local_recv_ns,
        out,
    )
}

/// The mark, funding and open interest of one market, where this node reads it.
fn market_fields(
    id: &str,
    market: &Market<'_>,
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    // The channel covers every market; most of them are not ours.
    let Some(entry) = map.lookup(id) else {
        return Ok(());
    };
    if let Some(price) = market.oracle_price {
        out.push(observation(
            entry,
            ObsKind::MarkPrice,
            decimal("oraclePrice", price)?,
            local_recv_ns,
        ));
    }
    if market.next_funding_rate.is_none() && market.open_interest.is_none() {
        return Ok(());
    }
    let parse_field = |field, text: Option<&str>| text.map(|text| decimal(field, text)).transpose();
    let state = books.funding(id);
    let rate: Option<Fixed> =
        parse_field("nextFundingRate", market.next_funding_rate)?.or(state.rate);
    let open_interest = parse_field("openInterest", market.open_interest)?.or(state.open_interest);
    if state.update(rate, open_interest) {
        state.interval_ns = Some(HOUR_NS);
        state.next_funding_time_ns = local_recv_ns
            .checked_div(HOUR_NS)
            .and_then(|hours| hours.checked_add(1))
            .and_then(|hours| hours.checked_mul(HOUR_NS));
        out.extend(interval_funding(entry, state, local_recv_ns));
    }
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixed-shape fixtures; an out-of-range index is a failing test"
)]
mod tests {
    use super::*;
    use crate::InstrumentSpec;
    use oracle_types::{MarketKind, OpenInterestUnit, Venue};

    const RECV: u64 = 1_793_215_700_000_000_000;
    /// Recorded from dYdX on 2026-10-28, batched: ETH's whole book (cut to 30
    /// levels a side) and its changes, the trades at subscribe, the markets of
    /// BTC, ETH and SOL with two updates, and a refused market.
    const SESSION: &str = include_str!("../../tests/fixtures/dydx.jsonl");

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("valid")
    }

    fn map(depth: bool) -> InstrumentMap {
        let specs: Vec<InstrumentSpec> = ["ETH-USD", "BTC-USD"]
            .into_iter()
            .map(|id| {
                let spec =
                    InstrumentSpec::new(id, MarketKind::LinearPerp, "CRYPTO.X/USDT.PERP_MARK")
                        .expect("valid");
                if depth { spec.with_depth() } else { spec }
            })
            .collect();
        InstrumentMap::new(Venue::Dydx, MarketKind::LinearPerp, &specs).expect("valid")
    }

    fn replay(map: &InstrumentMap) -> (Vec<Observation>, Vec<String>) {
        let mut books = Books::default();
        let (mut all, mut errors) = (Vec::new(), Vec::new());
        for line in SESSION.lines() {
            let mut out = Vec::new();
            match decode(line.as_bytes(), map, &mut books, RECV, &mut out) {
                Ok(()) => all.extend(out),
                Err(error) if error.is_benign() => {}
                Err(error) => errors.push(error.to_string()),
            }
        }
        (all, errors)
    }

    fn of<'a>(all: &'a [Observation], id: &str, kind: ObsKind) -> Vec<&'a Observation> {
        all.iter()
            .filter(|o| &*o.instrument.symbol == id && o.kind == kind)
            .collect()
    }

    #[test]
    fn a_session_gives_a_book_marks_and_hourly_funding() {
        let (all, errors) = replay(&map(true));
        // Only the refused market is an error.
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("NOPE-USD"), "{errors:?}");

        // The whole book and its six batches of changes.
        let depth = of(&all, "ETH-USD", ObsKind::Depth);
        assert_eq!(depth.len(), 7);
        let book = depth[6].book.as_deref().expect("levels");
        assert!(book.bids[0].price < book.asks[0].price);
        // The trades at subscribe are old.
        assert!(of(&all, "ETH-USD", ObsKind::Trade).is_empty());

        // The oracle price at subscribe and the update of ETH; SOL is not ours.
        let marks = of(&all, "ETH-USD", ObsKind::MarkPrice);
        assert_eq!(marks[0].price, fixed("2354.882544"));
        assert!(!of(&all, "BTC-USD", ObsKind::MarkPrice).is_empty());
        assert!(all.iter().all(|o| &*o.instrument.symbol != "SOL-USD"));

        let funding = of(&all, "ETH-USD", ObsKind::Funding);
        let info = funding[0].funding.as_deref().expect("funding");
        assert_eq!(info.interval_ns, Some(HOUR_NS));
        assert_eq!(info.next_funding_time_ns, Some(1_793_217_600_000_000_000));
        let (coins, unit) = info.open_interest.expect("open interest");
        assert_eq!(unit, OpenInterestUnit::Base);
        assert!(coins.is_positive());
        // The update of ETH's rate keeps its open interest.
        let last = funding
            .last()
            .and_then(|o| o.funding.as_deref())
            .expect("funding");
        assert_eq!(funding.last().map(|o| o.price), Some(fixed("0.0000200125")));
        assert_eq!(last.open_interest, info.open_interest);
    }

    #[test]
    fn a_market_without_depth_gives_its_top_and_a_trade_update_counts() {
        let map = map(false);
        let (all, _) = replay(&map);
        assert!(of(&all, "ETH-USD", ObsKind::Depth).is_empty());
        assert_eq!(of(&all, "ETH-USD", ObsKind::BookTop).len(), 7);

        // An update has the shape of the trades at subscribe.
        let mut books = Books::default();
        let mut out = Vec::new();
        let update = r#"{"type":"channel_batch_data","channel":"v4_trades","id":"ETH-USD","contents":[{"trades":[{"id":"1","side":"BUY","size":"0.5","price":"2355.1","type":"LIMIT","createdAt":"2026-10-28T19:30:00.000Z"}]}]}"#;
        decode(update.as_bytes(), &map, &mut books, RECV, &mut out).expect("decodes");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].price, fixed("2355.1"));
        assert_eq!(out[0].exchange_time_ns, Some(1_793_215_800_000_000_000));
    }

    #[test]
    fn a_connection_subscribes_each_market_then_the_markets_channel() {
        let frames = frames(["BTC-USD", "ETH-USD"].into_iter());
        assert_eq!(frames.len(), 5);
        let last: serde_json::Value = serde_json::from_str(&frames[4]).expect("JSON");
        assert_eq!(last["channel"], "v4_markets");
        assert!(last.get("id").is_none());
        let first: serde_json::Value = serde_json::from_str(&frames[0]).expect("JSON");
        assert_eq!(first["id"], "BTC-USD");
        assert_eq!(first["batched"], true);
    }
}
