//! Bitget public streams (v3): spot, and the USDT-margined and coin-margined
//! perpetuals.
//!
//! - **One envelope.** `{"action":"snapshot","arg":{"instType":"spot",
//!   "topic":"books1","symbol":"BTCUSDT"},"data":[…]}`. One subscribe frame
//!   takes a list of `{instType, topic, symbol}`.
//! - **Books.** `books1` gives the best bid and ask as a whole snapshot at each
//!   change. A market that wants depth takes `books` instead: a snapshot of
//!   1,000 levels, then changes, each naming the `seq` of the last one as `pseq`.
//! - **Trades.** `publicTrade`.
//! - **Perpetuals.** `ticker` gives the mark, the index and the open interest in
//!   coins. `funding-rate` gives the rate, the interval in hours, the next payment
//!   and the last settled rate, at each change and once a minute. A USDT
//!   perpetual counts in coins. A coin-margined one, such as `BTCUSD_CM`, counts
//!   in USD, so its sizes are divided by the price.
//! - **Control.** The keepalive is the text `ping`, and the venue answers `pong`.
//!
//! Checked against the live socket on 2026-10-28.

use std::time::Duration;

use oracle_types::{Fixed, MarketKind, ObsKind, Observation};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{Books, Side};
use crate::clock::millis_to_nanos;
use crate::instrument::InstrumentEntry;
use crate::{DecodeError, InstrumentMap};

use super::{book_top, decimal, integer, interval_funding, observation, parse, to_base_units};

/// The public socket of the unified account.
pub const URL: &str = "wss://ws.bitget.com/v3/ws/public";

/// The keepalive. The venue closes a connection that is quiet for 2 minutes.
pub const KEEPALIVE: &str = "ping";

/// How often to send [`KEEPALIVE`].
pub const KEEPALIVE_EVERY: Duration = Duration::from_secs(25);

/// The venue advises fewer than 50 channels on one connection.
const MAX_CHANNELS: usize = 48;

/// Spot markets on one connection: the book and the trades.
pub const SPOT_MARKETS_PER_CONNECTION: usize = 24;
const _: () = assert!(SPOT_MARKETS_PER_CONNECTION * 2 <= MAX_CHANNELS);

/// Perpetuals on one connection: the book, the trades, the ticker and the funding.
pub const FUTURES_MARKETS_PER_CONNECTION: usize = 12;
const _: () = assert!(FUTURES_MARKETS_PER_CONNECTION * 4 <= MAX_CHANNELS);

/// The full book: deep enough for every impact size, and what the venue keeps.
const BOOK_DEPTH: usize = 1_000;

const fn inst_type(market: MarketKind) -> &'static str {
    match market {
        MarketKind::Spot => "spot",
        MarketKind::LinearPerp => "usdt-futures",
        MarketKind::InversePerp => "coin-futures",
    }
}

/// The one subscribe frame of a connection: each market's book and trades, and
/// a perpetual's ticker and funding.
#[must_use]
pub fn frames<'a>(
    instruments: impl Iterator<Item = (&'a str, bool)>,
    market: MarketKind,
) -> Vec<String> {
    let kind = inst_type(market);
    let args: Vec<serde_json::Value> = instruments
        .flat_map(|(symbol, depth)| {
            let book = if depth { "books" } else { "books1" };
            let perp = market.is_perp();
            [Some(book), Some("publicTrade"), perp.then_some("ticker"), perp.then_some("funding-rate")]
                .into_iter()
                .flatten()
                .map(move |topic| serde_json::json!({ "instType": kind, "topic": topic, "symbol": symbol }))
        })
        .collect();
    if args.is_empty() {
        return Vec::new();
    }
    vec![serde_json::json!({ "op": "subscribe", "args": args }).to_string()]
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow, default)]
    event: Option<&'a str>,
    #[serde(borrow, default)]
    action: Option<&'a str>,
    #[serde(borrow, default)]
    arg: Option<Arg<'a>>,
    #[serde(borrow, default)]
    data: Option<&'a RawValue>,
    #[serde(borrow, default)]
    msg: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct Arg<'a> {
    #[serde(rename = "instType", borrow)]
    inst_type: &'a str,
    #[serde(borrow)]
    topic: &'a str,
    #[serde(borrow)]
    symbol: &'a str,
}

#[derive(Deserialize)]
struct Book<'a> {
    #[serde(borrow)]
    a: Vec<(&'a str, &'a str)>,
    #[serde(borrow)]
    b: Vec<(&'a str, &'a str)>,
    #[serde(default)]
    seq: Option<u64>,
    #[serde(default)]
    pseq: Option<u64>,
    /// Unix milliseconds, in a string.
    #[serde(borrow, default)]
    ts: Option<&'a str>,
}

#[derive(Deserialize)]
struct Trade<'a> {
    #[serde(borrow)]
    p: &'a str,
    /// Unix milliseconds, in a string.
    #[serde(rename = "T", borrow, default)]
    time: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ticker<'a> {
    #[serde(borrow)]
    mark_price: &'a str,
    #[serde(borrow)]
    index_price: &'a str,
    #[serde(borrow, default)]
    open_interest: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Funding<'a> {
    #[serde(borrow)]
    funding_rate: &'a str,
    /// Hours, in a string.
    #[serde(borrow)]
    funding_rate_interval: &'a str,
    /// The next payment, in unix milliseconds, in a string.
    #[serde(borrow)]
    next_update: &'a str,
    #[serde(borrow, default)]
    last_funding_rate: Option<&'a str>,
}

fn millis(field: &'static str, text: Option<&str>) -> Result<Option<u64>, DecodeError> {
    text.filter(|text| !text.is_empty())
        .map(|text| integer(field, text).map(millis_to_nanos))
        .transpose()
}

/// A level's price and its size in coins. A coin-margined size is in USD.
fn level((price, size): (&str, &str), market: MarketKind) -> Result<(Fixed, Fixed), DecodeError> {
    let price = decimal("price", price)?;
    let size = decimal("size", size)?;
    let size = to_base_units(size, price, market == MarketKind::InversePerp)
        .ok_or_else(|| DecodeError::Malformed(format!("size {size} at price {price}")))?;
    Ok((price, size))
}

/// Decodes one payload of any market.
///
/// # Errors
///
/// Returns [`DecodeError`]. Acks and pongs are benign; a refused subscription
/// is not, and a book change that does not follow the last one ends the
/// connection.
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    if payload == b"pong" {
        return Err(DecodeError::Control);
    }
    let envelope: Envelope<'_> = serde_json::from_slice(payload)?;
    match envelope.event {
        Some("error") => {
            return Err(DecodeError::Malformed(format!(
                "the server refused a request: {}",
                envelope.msg.map_or("", RawValue::get)
            )));
        }
        Some(_) => return Err(DecodeError::Control),
        None => {}
    }
    let arg = envelope.arg.ok_or(DecodeError::MissingField("arg"))?;
    let entry = map
        .lookup(arg.symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(arg.symbol.to_owned()))?;
    let market = entry.instrument.market;
    let data = envelope.data.ok_or(DecodeError::MissingField("data"))?;
    match arg.topic {
        "books1" => {
            for book in parse::<Vec<Book<'_>>>(data)? {
                let (Some(bid), Some(ask)) = (book.b.first(), book.a.first()) else {
                    return Err(DecodeError::Control);
                };
                let ((bid, bid_qty), (ask, ask_qty)) = (level(*bid, market)?, level(*ask, market)?);
                out.push(book_top(
                    entry,
                    (bid, ask),
                    (bid_qty, ask_qty),
                    millis("ts", book.ts)?,
                    local_recv_ns,
                )?);
            }
            Ok(())
        }
        "books" => {
            let snapshot = envelope.action == Some("snapshot");
            for change in parse::<Vec<Book<'_>>>(data)? {
                depth(
                    arg.symbol,
                    entry,
                    snapshot,
                    &change,
                    books,
                    local_recv_ns,
                    out,
                )?;
            }
            Ok(())
        }
        // The snapshot at subscribe holds old trades: a price that may be hours old is no news.
        "publicTrade" if envelope.action == Some("snapshot") => Err(DecodeError::Control),
        "publicTrade" => {
            for trade in parse::<Vec<Trade<'_>>>(data)? {
                out.push(Observation {
                    exchange_time_ns: millis("T", trade.time)?,
                    ..observation(entry, ObsKind::Trade, decimal("p", trade.p)?, local_recv_ns)
                });
            }
            Ok(())
        }
        "ticker" => {
            for ticker in parse::<Vec<Ticker<'_>>>(data)? {
                for (kind, price) in [
                    (ObsKind::MarkPrice, ticker.mark_price),
                    (ObsKind::IndexPrice, ticker.index_price),
                ] {
                    out.push(observation(
                        entry,
                        kind,
                        decimal("price", price)?,
                        local_recv_ns,
                    ));
                }
                // The open interest goes out with the next funding message, at most a minute later.
                if let Some(coins) = ticker.open_interest.filter(|text| !text.is_empty()) {
                    books.funding(arg.symbol).open_interest = Some(decimal("openInterest", coins)?);
                }
            }
            Ok(())
        }
        "funding-rate" => {
            for funding in parse::<Vec<Funding<'_>>>(data)? {
                let hours = integer("fundingRateInterval", funding.funding_rate_interval)?;
                let interval_ns = hours.checked_mul(3_600_000_000_000).filter(|ns| *ns > 0);
                let next_ns = millis("nextUpdate", Some(funding.next_update))?;
                let state = books.funding(arg.symbol);
                state.rate = Some(decimal("fundingRate", funding.funding_rate)?);
                state.interval_ns = interval_ns;
                state.next_funding_time_ns = next_ns;
                state.settled = match (funding.last_funding_rate, next_ns, interval_ns) {
                    (Some(rate), Some(next), Some(interval)) if !rate.is_empty() => Some((
                        decimal("lastFundingRate", rate)?,
                        next.saturating_sub(interval),
                    )),
                    _ => None,
                };
                out.extend(interval_funding(entry, state, local_recv_ns));
            }
            Ok(())
        }
        other => Err(DecodeError::UnhandledStream(format!(
            "{}/{other}",
            arg.inst_type
        ))),
    }
}

/// Applies a snapshot or a change of the full book, and emits it.
fn depth(
    symbol: &str,
    entry: &InstrumentEntry,
    snapshot: bool,
    change: &Book<'_>,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let book = books.book(symbol);
    if snapshot {
        book.clear();
    } else if change.pseq != book.last_id {
        return Err(DecodeError::Resync(format!(
            "{symbol}: change follows {:?} but the book is at {:?}",
            change.pseq, book.last_id
        )));
    }
    book.last_id = change.seq;
    for (side, levels) in [(Side::Bid, &change.b), (Side::Ask, &change.a)] {
        for raw in levels {
            let (price, size) = level(*raw, entry.instrument.market)?;
            book.set(side, price, size);
        }
    }
    book.truncate(BOOK_DEPTH);
    books.emit(
        symbol,
        entry.instrument.clone(),
        millis("ts", change.ts)?,
        local_recv_ns,
        out,
    )
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixed-shape fixtures; an out-of-range index is a failing test"
)]
mod tests {
    use super::*;
    use crate::InstrumentSpec;
    use oracle_types::{FundingBasis, OpenInterestUnit, Venue};

    const RECV: u64 = 1_793_213_200_000_000_000;
    /// Recorded from Bitget on 2026-10-28: BTC's top and trades, ETH's full book
    /// (its snapshot cut to 30 levels) and trades, a refused symbol and a pong.
    const SPOT: &str = include_str!("../../tests/fixtures/bitget-spot.jsonl");
    /// Recorded from Bitget on 2026-10-28: BTC's full book (its snapshot cut to
    /// 30 levels), trades, ticker and funding, and ETH's top, ticker and funding.
    const FUTURES: &str = include_str!("../../tests/fixtures/bitget-futures.jsonl");
    /// Recorded from Bitget on 2026-10-28: the coin-margined BTC perpetual.
    const COIN: &str = include_str!("../../tests/fixtures/bitget-coin.jsonl");

    fn map(market: MarketKind, symbols: &[(&str, bool)]) -> InstrumentMap {
        let specs: Vec<InstrumentSpec> = symbols
            .iter()
            .map(|(symbol, depth)| {
                let spec = InstrumentSpec::new(*symbol, market, "CRYPTO.X/USD").expect("valid");
                if *depth { spec.with_depth() } else { spec }
            })
            .collect();
        InstrumentMap::new(Venue::Bitget, market, &specs).expect("valid")
    }

    fn replay(session: &str, map: &InstrumentMap) -> (Vec<Observation>, Vec<String>) {
        let mut books = Books::default();
        let (mut all, mut errors) = (Vec::new(), Vec::new());
        for line in session.lines() {
            let mut out = Vec::new();
            match decode(line.as_bytes(), map, &mut books, RECV, &mut out) {
                Ok(()) => all.extend(out),
                Err(error) if error.is_benign() => {}
                Err(error) => errors.push(error.to_string()),
            }
        }
        (all, errors)
    }

    fn of<'a>(all: &'a [Observation], symbol: &str, kind: ObsKind) -> Vec<&'a Observation> {
        all.iter()
            .filter(|o| &*o.instrument.symbol == symbol && o.kind == kind)
            .collect()
    }

    #[test]
    fn a_spot_session_gives_tops_a_full_book_and_trades() {
        let map = map(MarketKind::Spot, &[("BTCUSDT", false), ("ETHUSDT", true)]);
        let (all, errors) = replay(SPOT, &map);
        // Only the refused symbol is an error.
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("NOPEUSDT"), "{errors:?}");

        let tops = of(&all, "BTCUSDT", ObsKind::BookTop);
        assert_eq!(tops.len(), 3);
        assert!(
            tops.iter()
                .all(|o| o.bid < o.ask && o.exchange_time_ns.is_some())
        );
        // The snapshot and its six changes follow one another.
        let depth = of(&all, "ETHUSDT", ObsKind::Depth);
        assert_eq!(depth.len(), 7);
        let book = depth[6].book.as_deref().expect("levels");
        assert!(book.bids[0].price < book.asks[0].price);
        assert_eq!(of(&all, "ETHUSDT", ObsKind::BookTop).len(), 0);
        assert_eq!(of(&all, "BTCUSDT", ObsKind::Trade).len(), 3);
    }

    #[test]
    fn a_perpetual_session_gives_marks_and_funding_with_its_interval() {
        let map = map(
            MarketKind::LinearPerp,
            &[("BTCUSDT", true), ("ETHUSDT", false)],
        );
        let (all, errors) = replay(FUTURES, &map);
        assert!(errors.is_empty(), "{errors:?}");

        assert_eq!(of(&all, "BTCUSDT", ObsKind::Depth).len(), 7);
        assert_eq!(of(&all, "ETHUSDT", ObsKind::BookTop).len(), 3);
        let mark = of(&all, "BTCUSDT", ObsKind::MarkPrice);
        let index = of(&all, "BTCUSDT", ObsKind::IndexPrice);
        assert_eq!((mark.len(), index.len()), (2, 2));

        let funding = of(&all, "BTCUSDT", ObsKind::Funding);
        let info = funding[0].funding.as_deref().expect("funding");
        assert_eq!(info.basis, FundingBasis::Interval);
        assert_eq!(info.interval_ns, Some(8 * 3_600_000_000_000));
        let next = info.next_funding_time_ns.expect("next");
        let (_, settled_at) = info.settled.expect("settled");
        assert_eq!(next - settled_at, 8 * 3_600_000_000_000);
        // The first funding message came before any ticker; the next one carries its open interest.
        assert!(info.open_interest.is_none());
        let last = funding
            .last()
            .and_then(|o| o.funding.as_deref())
            .expect("funding");
        let (coins, unit) = last.open_interest.expect("open interest");
        assert_eq!(unit, OpenInterestUnit::Base);
        assert!(coins.is_positive());
    }

    #[test]
    fn a_coin_margined_perpetual_sizes_in_coins() {
        let map = map(MarketKind::InversePerp, &[("BTCUSD_CM", false)]);
        let (all, errors) = replay(COIN, &map);
        assert!(errors.is_empty(), "{errors:?}");
        let top = of(&all, "BTCUSD_CM", ObsKind::BookTop)[0];
        let (bid, qty) = (top.bid.expect("bid"), top.bid_qty.expect("size"));
        // A size in USD over a price near 81,000 is well under the USD amount.
        let usd = qty.checked_mul(bid).expect("fits");
        assert!(qty < usd, "{qty} coins at {bid}");
        assert_eq!(of(&all, "BTCUSD_CM", ObsKind::MarkPrice).len(), 2);
        assert_eq!(of(&all, "BTCUSD_CM", ObsKind::Funding).len(), 1);
    }

    #[test]
    fn a_change_that_skips_one_ends_the_connection() {
        let map = map(MarketKind::Spot, &[("ETHUSDT", true)]);
        let mut books = Books::default();
        let mut out = Vec::new();
        let snapshot = r#"{"action":"snapshot","arg":{"instType":"spot","topic":"books","symbol":"ETHUSDT"},"data":[{"a":[["2400","1"]],"b":[["2399","1"]],"seq":10,"pseq":0,"ts":"1"}]}"#;
        let skip = r#"{"action":"update","arg":{"instType":"spot","topic":"books","symbol":"ETHUSDT"},"data":[{"a":[["2401","1"]],"b":[],"seq":12,"pseq":11,"ts":"2"}]}"#;
        assert!(decode(snapshot.as_bytes(), &map, &mut books, RECV, &mut out).is_ok());
        assert!(matches!(
            decode(skip.as_bytes(), &map, &mut books, RECV, &mut out),
            Err(DecodeError::Resync(_))
        ));
    }

    #[test]
    fn one_frame_subscribes_each_market() {
        let spot = frames(
            [("BTCUSDT", false), ("ETHUSDT", true)].into_iter(),
            MarketKind::Spot,
        );
        assert_eq!(spot.len(), 1);
        let value: serde_json::Value = serde_json::from_str(&spot[0]).expect("JSON");
        assert_eq!(value["args"].as_array().map(Vec::len), Some(4));
        assert_eq!(value["args"][2]["topic"], "books");
        let perps = frames([("BTCUSD_CM", false)].into_iter(), MarketKind::InversePerp);
        let value: serde_json::Value = serde_json::from_str(&perps[0]).expect("JSON");
        assert_eq!(value["args"].as_array().map(Vec::len), Some(4));
        assert_eq!(value["args"][3]["instType"], "coin-futures");
        assert_eq!(value["args"][3]["topic"], "funding-rate");
    }

    #[test]
    fn the_trades_at_subscribe_are_old_and_left_out() {
        let map = map(MarketKind::Spot, &[("BTCUSDT", false)]);
        let mut books = Books::default();
        let mut out = Vec::new();
        let old = r#"{"action":"snapshot","arg":{"instType":"spot","topic":"publicTrade","symbol":"BTCUSDT"},"data":[{"p":"80000","v":"1","T":"1"}]}"#;
        assert!(
            decode(old.as_bytes(), &map, &mut books, RECV, &mut out).is_err_and(|e| e.is_benign())
        );
        assert!(out.is_empty());
    }
}
