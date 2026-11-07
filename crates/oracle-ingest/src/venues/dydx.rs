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

use crate::book::{BookMsg, BookRule, Books, Change, Continuity};
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

/// The changes carry no sequence, so nothing proves the book.
const BOOK_RULE: BookRule = BookRule::new(Continuity::Unproved).depth(BOOK_DEPTH);

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
struct Changes<'a> {
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
            let (_, entry) = market(map, envelope.id)?;
            let parsed = if subscribed {
                parse::<Snapshot<'_>>(contents).and_then(|snapshot| {
                    BookMsg::whole(&snapshot.bids, &snapshot.asks, |level| {
                        Ok(Change::new(
                            decimal("price", level.price)?,
                            decimal("size", level.size)?,
                        ))
                    })
                })
            } else {
                // A batch is one moment's changes, so they apply as one message.
                items::<Changes<'_>>(contents).and_then(|batch| {
                    let change = |(price, size): &(&str, &str)| {
                        Ok(Change::new(
                            decimal("price", price)?,
                            decimal("size", size)?,
                        ))
                    };
                    let mut message = BookMsg::default();
                    for changes in &batch {
                        let parsed = BookMsg::changes(&changes.bids, &changes.asks, change)?;
                        message.bids.extend(parsed.bids);
                        message.asks.extend(parsed.asks);
                    }
                    Ok(message)
                })
            };
            books
                .keeper
                .apply(BOOK_RULE, entry, parsed, local_recv_ns, out)
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
    let state = books.funding(&entry.instrument);
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
    use crate::testing::{Feed, Replayed, fixed, instrument, of};
    use oracle_types::{MarketKind, OpenInterestUnit, Venue};

    /// Recorded from dYdX on 2026-10-28, batched: ETH's whole book (cut to 30
    /// levels a side) and its changes, the trades at subscribe, the markets of
    /// BTC, ETH and SOL with two updates, and a refused market.
    const SESSION: &str = include_str!("../../tests/fixtures/dydx.jsonl");
    /// Inside the hour of the recording: dYdX pays at each top of the hour after receipt.
    const RECORDED_AT_NS: u64 = 1_793_215_700_000_000_000;

    /// ETH and BTC, each with or without its book.
    fn dydx(depth: bool) -> Feed {
        let markets = ["ETH-USD", "BTC-USD"].map(|id| {
            let spec = instrument(id, MarketKind::LinearPerp);
            if depth { spec.with_depth() } else { spec }
        });
        Feed::venue(decode, Venue::Dydx, MarketKind::LinearPerp, &markets).at(RECORDED_AT_NS)
    }

    #[test]
    fn a_session_gives_a_book_marks_and_hourly_funding() {
        let Replayed {
            observations: all,
            errors,
        } = dydx(true).replay_all(SESSION.lines());
        let [refused] = errors.as_slice() else {
            panic!("only the refused market is an error: {errors:?}");
        };
        assert!(refused.to_string().contains("NOPE-USD"), "{refused}");

        // The whole book and its six batches of changes.
        assert_eq!(of(&all, "ETH-USD", ObsKind::Depth).len(), 7);
        // The trades at subscribe are old.
        assert!(of(&all, "ETH-USD", ObsKind::Trade).is_empty());

        // The oracle price at subscribe and the update of ETH; SOL is not ours.
        assert_eq!(
            of(&all, "ETH-USD", ObsKind::MarkPrice)[0].price,
            fixed("2354.882544")
        );
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
        let last = funding.last().expect("funding");
        assert_eq!(last.price, fixed("0.0000200125"));
        assert_eq!(
            last.funding.as_deref().map(|f| f.open_interest),
            Some(info.open_interest)
        );
    }

    #[test]
    fn a_market_without_depth_gives_its_top_and_a_trade_update_counts() {
        let mut feed = dydx(false);
        let all = feed.replay_all(SESSION.lines()).observations;
        assert!(of(&all, "ETH-USD", ObsKind::Depth).is_empty());
        assert_eq!(of(&all, "ETH-USD", ObsKind::BookTop).len(), 7);

        // An update has the shape of the trades at subscribe.
        let update = r#"{"type":"channel_batch_data","channel":"v4_trades","id":"ETH-USD","contents":[{"trades":[{"id":"1","side":"BUY","size":"0.5","price":"2355.1","type":"LIMIT","createdAt":"2026-10-28T19:30:00.000Z"}]}]}"#;
        let trades = feed.decoded(update);
        let [trade] = trades.as_slice() else {
            panic!("one trade: {trades:?}");
        };
        assert_eq!(trade.price, fixed("2355.1"));
        // 2026-10-28T19:30:00Z
        assert_eq!(trade.exchange_time_ns, Some(1_793_215_800_000_000_000));
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
