//! KuCoin public streams: USDT spot, and the USDT-margined perpetuals.
//!
//! - **A token first.** Each socket opens at an endpoint and with a token that a
//!   REST call gives; [`super::kucoin_connect::KucoinConnector`] does that.
//! - **One envelope.** `{"type":"message","topic":"/market/ticker:BTC-USDT",
//!   "subject":"trade.ticker","data":{…}}`; the symbol is the part of the topic
//!   after the colon, and a subscription takes a list, `:BTC-USDT,ETH-USDT`.
//! - **Spot.** `/market/ticker` gives the quote, about 10 times a second;
//!   `/spotMarket/level2Depth50` gives the book as a whole 50-level snapshot each
//!   time; `/market/match` gives the trades.
//! - **Perpetuals** count in contracts of `multiplier` coins, the source's
//!   `contract_size`. `/contractMarket/tickerV2` gives the quote,
//!   `/contractMarket/level2Depth50` the book, `/contractMarket/execution` the
//!   trades, and `/contract/instrument` the mark and the index each second, as
//!   bare JSON numbers, and the funding rate each minute.
//! - **Funding.** The socket's rate is the venue's estimate for the next payment.
//!   The interval, the next funding time, the last settled rate and the open
//!   interest come only over REST, in the frames that the connector adds. The
//!   interval varies by contract (1, 4 or 8 hours) and the venue changes it.
//!
//! Checked against the live sockets and REST on 2026-10-25.

use std::time::Duration;

use oracle_types::{ObsKind, Observation};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{BookMsg, BookRule, Books, Change, Continuity};
use crate::clock::millis_to_nanos;
use crate::instrument::InstrumentEntry;
use crate::{DecodeError, InstrumentMap};

use super::{
    base_units, book_top, decimal, decimal_literal, integer, interval_funding, observation, parse,
};

pub use super::kucoin_connect::{FUTURES_TOKEN, SPOT_TOKEN, futures_url};

/// The keepalive. The token reply asks for one each 18 s.
pub const KEEPALIVE: &str = r#"{"id":"ping","type":"ping"}"#;

/// How often to send [`KEEPALIVE`].
pub const KEEPALIVE_EVERY: Duration = Duration::from_secs(15);

/// Markets on one connection. A connection takes 300 to 400 topics, and one
/// subscribe message at most 100; a market takes at most four topics.
pub const MARKETS_PER_CONNECTION: usize = 50;
const _: () = assert!(MARKETS_PER_CONNECTION * 4 <= 300 && MARKETS_PER_CONNECTION <= 100);

fn subscribe(id: usize, channel: &str, symbols: &[&str]) -> String {
    serde_json::json!({
        "id": id.to_string(),
        "type": "subscribe",
        "topic": format!("{channel}:{}", symbols.join(",")),
        "privateChannel": false,
        "response": true,
    })
    .to_string()
}

/// One frame per channel: each market's quote and trades, and the book of the
/// markets that want depth.
fn frames<'a>(
    instruments: impl Iterator<Item = (&'a str, bool)>,
    channels: &[&str],
    book: &str,
) -> Vec<String> {
    let instruments: Vec<(&str, bool)> = instruments.collect();
    let all: Vec<&str> = instruments.iter().map(|(symbol, _)| *symbol).collect();
    let depth: Vec<&str> = instruments
        .iter()
        .filter(|(_, depth)| *depth)
        .map(|(symbol, _)| *symbol)
        .collect();
    let mut out: Vec<String> = channels
        .iter()
        .enumerate()
        .map(|(id, channel)| subscribe(id, channel, &all))
        .collect();
    if !depth.is_empty() {
        out.push(subscribe(channels.len(), book, &depth));
    }
    out
}

/// The subscribe frames of a spot connection, each symbol with whether it wants depth.
#[must_use]
pub fn spot_frames<'a>(instruments: impl Iterator<Item = (&'a str, bool)>) -> Vec<String> {
    frames(
        instruments,
        &["/market/ticker", "/market/match"],
        "/spotMarket/level2Depth50",
    )
}

/// The subscribe frames of a futures connection, each symbol with whether it wants depth.
#[must_use]
pub fn futures_frames<'a>(instruments: impl Iterator<Item = (&'a str, bool)>) -> Vec<String> {
    frames(
        instruments,
        &[
            "/contractMarket/tickerV2",
            "/contractMarket/execution",
            "/contract/instrument",
        ],
        "/contractMarket/level2Depth50",
    )
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(rename = "type", borrow)]
    kind: &'a str,
    #[serde(borrow, default)]
    topic: Option<&'a str>,
    #[serde(borrow, default)]
    subject: Option<&'a str>,
    #[serde(borrow, default)]
    data: Option<&'a RawValue>,
    #[serde(borrow, default)]
    error: Option<&'a RawValue>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpotTicker<'a> {
    best_bid: &'a str,
    best_ask: &'a str,
    best_bid_size: &'a str,
    best_ask_size: &'a str,
    time: Option<u64>,
}

#[derive(Deserialize)]
struct SpotMatch<'a> {
    price: &'a str,
    /// Unix nanoseconds, in a string.
    time: Option<&'a str>,
}

#[derive(Deserialize)]
struct Depth<'a> {
    #[serde(borrow)]
    asks: Vec<(&'a RawValue, &'a RawValue)>,
    #[serde(borrow)]
    bids: Vec<(&'a RawValue, &'a RawValue)>,
    /// Unix milliseconds.
    timestamp: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FuturesTicker<'a> {
    best_bid_price: &'a str,
    best_ask_price: &'a str,
    #[serde(borrow)]
    best_bid_size: &'a RawValue,
    #[serde(borrow)]
    best_ask_size: &'a RawValue,
    /// Unix nanoseconds.
    ts: Option<u64>,
}

#[derive(Deserialize)]
struct Execution<'a> {
    price: &'a str,
    /// Unix nanoseconds.
    ts: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarkIndex<'a> {
    #[serde(borrow)]
    mark_price: &'a RawValue,
    #[serde(borrow)]
    index_price: &'a RawValue,
    /// Unix milliseconds.
    timestamp: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FundingRate<'a> {
    #[serde(borrow)]
    funding_rate: &'a RawValue,
}

/// `/api/v1/funding-rate/{symbol}/current`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FundingCurrent<'a> {
    /// The interval, in milliseconds.
    granularity: u64,
    #[serde(borrow)]
    value: &'a RawValue,
    /// The next payment, in unix milliseconds.
    funding_time: u64,
    #[serde(borrow, default)]
    last_time_funding_rate: Option<&'a RawValue>,
    /// The last payment, in unix milliseconds.
    time_point: u64,
}

/// `/api/v1/contracts/{symbol}`: only the open interest, in contracts.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Contract<'a> {
    #[serde(borrow, default)]
    open_interest: Option<&'a str>,
}

fn lost(entry: &InstrumentEntry, error: DecodeError) -> DecodeError {
    DecodeError::lost(&entry.instrument, error)
}

/// Each depth message is a whole book.
const BOOK_RULE: BookRule = BookRule::new(Continuity::WholeBook);

/// Replaces the book with a whole snapshot, and emits it.
fn depth(
    data: &RawValue,
    entry: &InstrumentEntry,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let parsed = parse::<Depth<'_>>(data).and_then(|snapshot| {
        let whole = BookMsg::whole(&snapshot.bids, &snapshot.asks, |(price, size)| {
            let size = base_units(decimal_literal("depth size", size)?, entry.contract_size);
            Ok(Change::new(decimal_literal("depth price", price)?, size))
        })?;
        Ok(whole.at(snapshot.timestamp.map(millis_to_nanos)))
    });
    books
        .keeper
        .apply(BOOK_RULE, entry, parsed, local_recv_ns, out)
}

/// The topic's channel and symbol, and the symbol's entry.
fn route<'a, 'm>(
    topic: Option<&'a str>,
    map: &'m InstrumentMap,
) -> Result<(&'a str, &'a str, &'m InstrumentEntry), DecodeError> {
    let topic = topic.ok_or(DecodeError::MissingField("topic"))?;
    let (channel, symbol) = topic
        .split_once(':')
        .ok_or_else(|| DecodeError::UnhandledStream(topic.to_owned()))?;
    let entry = map
        .lookup(symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(symbol.to_owned()))?;
    Ok((channel, symbol, entry))
}

/// The envelope of a market message, or the error that ends the decode of a
/// control message.
fn envelope(payload: &[u8]) -> Result<Envelope<'_>, DecodeError> {
    let envelope: Envelope<'_> = serde_json::from_slice(payload)?;
    match envelope.kind {
        "message" | "rest" => Ok(envelope),
        "error" => Err(DecodeError::Malformed(format!(
            "the server refused a request: {}",
            envelope.data.map_or("", RawValue::get)
        ))),
        _ => Err(DecodeError::Control),
    }
}

/// Decodes one spot payload.
///
/// # Errors
///
/// Returns [`DecodeError`]. Welcome, ack and pong messages are benign.
pub fn decode_spot(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope = envelope(payload)?;
    let (channel, _, entry) = route(envelope.topic, map)?;
    let data = envelope.data.ok_or(DecodeError::MissingField("data"))?;
    match channel {
        "/market/ticker" => {
            let ticker: SpotTicker<'_> = parse(data).map_err(|e| lost(entry, e))?;
            let top = || {
                Ok(Some((
                    (
                        decimal("bestBid", ticker.best_bid)?,
                        decimal("bestAsk", ticker.best_ask)?,
                    ),
                    (
                        decimal("bestBidSize", ticker.best_bid_size)?,
                        decimal("bestAskSize", ticker.best_ask_size)?,
                    ),
                )))
            };
            let time = ticker.time.map(millis_to_nanos);
            out.push(book_top(entry, top, time, local_recv_ns)?);
            Ok(())
        }
        "/spotMarket/level2Depth50" => depth(data, entry, books, local_recv_ns, out),
        "/market/match" => {
            let trade: SpotMatch<'_> = parse(data)?;
            out.push(Observation {
                exchange_time_ns: trade.time.map(|time| integer("time", time)).transpose()?,
                ..observation(
                    entry,
                    ObsKind::Trade,
                    decimal("price", trade.price)?,
                    local_recv_ns,
                )
            });
            Ok(())
        }
        other => Err(DecodeError::UnhandledStream(other.to_owned())),
    }
}

/// Decodes one futures payload, or one of the REST frames that the connector adds.
///
/// # Errors
///
/// Returns [`DecodeError`]. Welcome, ack and pong messages are benign; a REST
/// read that failed is an error, which the session counts.
pub fn decode_futures(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope = envelope(payload)?;
    let (channel, symbol, entry) = route(envelope.topic, map)?;
    if let Some(error) = envelope.error {
        return Err(DecodeError::Malformed(format!(
            "a KuCoin REST read failed for {symbol}: {}",
            error.get()
        )));
    }
    let data = envelope.data.ok_or(DecodeError::MissingField("data"))?;
    match (channel, envelope.subject.unwrap_or_default()) {
        ("/contractMarket/tickerV2", _) => {
            let ticker: FuturesTicker<'_> = parse(data).map_err(|e| lost(entry, e))?;
            let size = |field, raw| {
                decimal_literal(field, raw).map(|size| base_units(size, entry.contract_size))
            };
            let top = || {
                Ok(Some((
                    (
                        decimal("bestBidPrice", ticker.best_bid_price)?,
                        decimal("bestAskPrice", ticker.best_ask_price)?,
                    ),
                    (
                        size("bestBidSize", ticker.best_bid_size)?,
                        size("bestAskSize", ticker.best_ask_size)?,
                    ),
                )))
            };
            out.push(book_top(entry, top, ticker.ts, local_recv_ns)?);
            Ok(())
        }
        ("/contractMarket/level2Depth50", _) => depth(data, entry, books, local_recv_ns, out),
        ("/contractMarket/execution", _) => {
            let trade: Execution<'_> = parse(data)?;
            out.push(Observation {
                exchange_time_ns: trade.ts,
                ..observation(
                    entry,
                    ObsKind::Trade,
                    decimal("price", trade.price)?,
                    local_recv_ns,
                )
            });
            Ok(())
        }
        ("/contract/instrument", "mark.index.price") => {
            let prices: MarkIndex<'_> = parse(data)?;
            let time = prices.timestamp.map(millis_to_nanos);
            for (kind, raw) in [
                (ObsKind::MarkPrice, prices.mark_price),
                (ObsKind::IndexPrice, prices.index_price),
            ] {
                out.push(Observation {
                    exchange_time_ns: time,
                    ..observation(entry, kind, decimal_literal("price", raw)?, local_recv_ns)
                });
            }
            Ok(())
        }
        ("/contract/instrument", "funding.rate") => {
            let rate: FundingRate<'_> = parse(data)?;
            books.funding(&entry.instrument).rate =
                Some(decimal_literal("fundingRate", rate.funding_rate)?);
            out.extend(interval_funding(
                entry,
                books.funding(&entry.instrument),
                local_recv_ns,
            ));
            Ok(())
        }
        ("/rest", "funding.current") => {
            let current: FundingCurrent<'_> = parse(data)?;
            let state = books.funding(&entry.instrument);
            state.rate = Some(decimal_literal("value", current.value)?);
            state.interval_ns = Some(millis_to_nanos(current.granularity)).filter(|ns| *ns > 0);
            state.next_funding_time_ns = Some(millis_to_nanos(current.funding_time));
            state.settled = match current.last_time_funding_rate {
                Some(rate) => Some((
                    decimal_literal("lastTimeFundingRate", rate)?,
                    millis_to_nanos(current.time_point),
                )),
                None => None,
            };
            out.extend(interval_funding(entry, state, local_recv_ns));
            Ok(())
        }
        ("/rest", "contract") => {
            let contract: Contract<'_> = parse(data)?;
            if let Some(open_interest) = contract.open_interest {
                let contracts = decimal("openInterest", open_interest)?;
                books.funding(&entry.instrument).open_interest =
                    Some(base_units(contracts, entry.contract_size));
            }
            out.extend(interval_funding(
                entry,
                books.funding(&entry.instrument),
                local_recv_ns,
            ));
            Ok(())
        }
        (other, _) => Err(DecodeError::UnhandledStream(other.to_owned())),
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixed-shape fixtures; an out-of-range index is a failing test"
)]
mod tests {
    use super::*;
    use crate::testing::{Feed, Replayed, contracts_of, fixed, instrument, of};
    use oracle_types::{Fixed, MarketKind, OpenInterestUnit, Venue};

    /// Recorded from KuCoin on 2026-10-25: the BTC and ETH spot quotes, BTC's
    /// book and trades.
    const SPOT: &str = include_str!("../../tests/fixtures/kucoin-spot.jsonl");
    /// Recorded from KuCoin on 2026-10-25: the BTC and ETH perpetuals' quotes,
    /// BTC's book, trades, mark, index and funding rate, and the two REST
    /// records of BTC as the connector frames them, then a failed read.
    const FUTURES: &str = include_str!("../../tests/fixtures/kucoin-futures.jsonl");

    fn spot(depth: bool) -> Feed {
        let btc = instrument("BTC-USDT", MarketKind::Spot);
        let pairs = [
            if depth { btc.with_depth() } else { btc },
            instrument("ETH-USDT", MarketKind::Spot),
        ];
        Feed::venue(decode_spot, Venue::Kucoin, MarketKind::Spot, &pairs)
    }

    fn futures() -> Feed {
        let perps = [
            contracts_of(instrument("XBTUSDTM", MarketKind::LinearPerp), "0.001").with_depth(),
            contracts_of(instrument("ETHUSDTM", MarketKind::LinearPerp), "0.01"),
        ];
        Feed::venue(
            decode_futures,
            Venue::Kucoin,
            MarketKind::LinearPerp,
            &perps,
        )
    }

    #[test]
    fn a_spot_session_gives_quotes_trades_and_a_book() {
        let Replayed {
            observations: all,
            errors,
        } = spot(true).replay_all(SPOT.lines());
        assert!(errors.is_empty(), "{errors:?}");
        let top = all
            .iter()
            .find(|o| o.kind == ObsKind::BookTop)
            .expect("a quote");
        assert!(top.bid < top.ask);
        assert!(top.bid_qty.is_some_and(Fixed::is_positive));
        assert!(top.exchange_time_ns.is_some());
        let trade = all
            .iter()
            .find(|o| o.kind == ObsKind::Trade)
            .expect("a trade");
        // A time after 2023: the milliseconds were read, not the seconds.
        assert!(
            trade
                .exchange_time_ns
                .is_some_and(|ns| ns > 1_700_000_000_000_000_000)
        );
        let depth = *of(&all, "BTC-USDT", ObsKind::Depth).last().expect("a book");
        let book = depth.book.as_deref().expect("levels");
        assert_eq!(depth.bid, Some(book.bids[0].price));
        // The 5-level book of ETH is not subscribed by this build.
        assert!(of(&all, "ETH-USDT", ObsKind::Depth).is_empty());
    }

    #[test]
    fn a_futures_session_sizes_in_coins_and_carries_the_rest_funding() {
        let Replayed {
            observations: all,
            errors,
        } = futures().replay_all(FUTURES.lines());
        let [failed] = errors.as_slice() else {
            panic!("only the failed REST read is an error: {errors:?}");
        };
        assert!(failed.to_string().contains("ETHUSDTM"), "{failed}");

        let top = of(&all, "ETHUSDTM", ObsKind::BookTop)[0];
        // 411 contracts of 0.01 ETH.
        assert_eq!(top.bid_qty, Some(fixed("4.11")));
        assert!(top.bid < top.ask);

        let depth = *of(&all, "XBTUSDTM", ObsKind::Depth).last().expect("a book");
        let book = depth.book.as_deref().expect("levels");
        assert!(book.bids[0].price < book.asks[0].price);

        assert_eq!(
            of(&all, "XBTUSDTM", ObsKind::MarkPrice)[0].price,
            fixed("80346.90")
        );
        assert_eq!(
            of(&all, "XBTUSDTM", ObsKind::IndexPrice)[0].price,
            fixed("80379.74")
        );

        let last = *of(&all, "XBTUSDTM", ObsKind::Funding)
            .last()
            .expect("funding");
        assert_eq!(last.price, fixed("0.0001"));
        let info = last.funding.as_deref().expect("info");
        assert_eq!(info.interval_ns, Some(8 * 3_600 * 1_000_000_000));
        assert_eq!(info.next_funding_time_ns, Some(1_792_944_000_000_000_000));
        assert_eq!(
            info.settled,
            Some((fixed("0.000034"), 1_792_915_200_000_000_000))
        );
        let (open_interest, unit) = info.open_interest.expect("open interest");
        assert_eq!(unit, OpenInterestUnit::Base);
        assert!(
            open_interest > fixed("1000") && open_interest < fixed("100000"),
            "{open_interest}"
        );
    }

    #[test]
    fn control_messages_are_benign_and_a_refusal_is_not() {
        let mut spot = spot(false);
        for control in [
            r#"{"id":"capture1","type":"welcome"}"#,
            r#"{"id":"0","type":"ack"}"#,
            r#"{"id":"ping","type":"pong","timestamp":1792936290000000}"#,
            r#"{"type":"message","topic":"/market/ticker:DOGE-USDT","subject":"trade.ticker","data":{}}"#,
        ] {
            let error = spot.refused(control);
            assert!(error.is_benign(), "got {error:?} for {control}");
        }
        let refused = r#"{"id":"1","type":"error","code":404,"data":"topic /market/x:BTC-USDT is not found"}"#;
        assert!(!spot.refused(refused).is_benign());
    }

    #[test]
    fn subscribe_frames_list_the_symbols_and_the_book_only_where_wanted() {
        let frames = futures_frames([("XBTUSDTM", true), ("ETHUSDTM", false)].into_iter());
        assert_eq!(frames.len(), 4, "{frames:?}");
        assert!(frames[0].contains(r#""topic":"/contractMarket/tickerV2:XBTUSDTM,ETHUSDTM""#));
        assert!(frames[3].contains(r#""topic":"/contractMarket/level2Depth50:XBTUSDTM""#));
        let spot = spot_frames([("BTC-USDT", false)].into_iter());
        assert_eq!(spot.len(), 2, "{spot:?}");
        assert!(spot.iter().all(|f| f.contains(r#""type":"subscribe""#)));
    }
}
