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

use crate::book::{BookMsg, BookRule, Books, Change, Continuity, Halts};
use crate::clock::millis_to_nanos;
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

/// Each change names the `seq` of the one before it as `pseq`.
const BOOK_RULE: BookRule = BookRule::new(Continuity::UpdateId).depth(BOOK_DEPTH);

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
            let books = parse::<Vec<Book<'_>>>(data)
                .map_err(|e| DecodeError::lost(&entry.instrument, e))?;
            let mut halts = Halts::default();
            for book in books {
                let top = || {
                    let (Some(bid), Some(ask)) = (book.b.first(), book.a.first()) else {
                        return Ok(None);
                    };
                    let ((bid, bid_qty), (ask, ask_qty)) =
                        (level(*bid, market)?, level(*ask, market)?);
                    Ok(Some(((bid, ask), (bid_qty, ask_qty))))
                };
                let time = millis("ts", book.ts)?;
                let quote = book_top(entry, top, time, local_recv_ns).map(|top| out.push(top));
                halts.absorb(&entry.instrument, quote)?;
            }
            halts.finish(Ok(()))
        }
        "books" => {
            let snapshot = envelope.action == Some("snapshot");
            let mut halts = Halts::default();
            for change in parse::<Vec<Book<'_>>>(data).map_err(|e| BOOK_RULE.unparsed(e))? {
                let parsed = book_message(&change, snapshot, market);
                let applied = books
                    .keeper
                    .apply(BOOK_RULE, entry, parsed, local_recv_ns, out);
                halts.absorb(&entry.instrument, applied)?;
            }
            halts.finish(Ok(()))
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
                    books.funding(&entry.instrument).open_interest =
                        Some(decimal("openInterest", coins)?);
                }
            }
            Ok(())
        }
        "funding-rate" => {
            for funding in parse::<Vec<Funding<'_>>>(data)? {
                let hours = integer("fundingRateInterval", funding.funding_rate_interval)?;
                let interval_ns = hours.checked_mul(3_600_000_000_000).filter(|ns| *ns > 0);
                let next_ns = millis("nextUpdate", Some(funding.next_update))?;
                let state = books.funding(&entry.instrument);
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

/// A snapshot or a change of the full book. A change without its ids cannot
/// prove that it follows the last one.
fn book_message(
    change: &Book<'_>,
    snapshot: bool,
    market: MarketKind,
) -> Result<BookMsg<'static>, DecodeError> {
    let seq = change.seq.ok_or(DecodeError::MissingField("seq"))?;
    let pseq = if snapshot {
        change.pseq
    } else {
        Some(change.pseq.ok_or(DecodeError::MissingField("pseq"))?)
    };
    let level = |raw: &(&str, &str)| {
        let (price, size) = level(*raw, market)?;
        Ok(Change::new(price, size))
    };
    Ok(BookMsg {
        snapshot,
        prev_id: pseq,
        next_id: Some(seq),
        time: millis("ts", change.ts)?,
        ..BookMsg::changes(&change.b, &change.a, level)?
    })
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixed-shape fixtures; an out-of-range index is a failing test"
)]
mod tests {
    use super::*;
    use crate::testing::{Feed, Replayed, instrument, of};
    use oracle_types::{FundingBasis, OpenInterestUnit, Venue};

    /// Recorded from Bitget on 2026-10-28: BTC's top and trades, ETH's full book
    /// (its snapshot cut to 30 levels) and trades, a refused symbol and a pong.
    const SPOT: &str = include_str!("../../tests/fixtures/bitget-spot.jsonl");
    /// Recorded from Bitget on 2026-10-28: BTC's full book (its snapshot cut to
    /// 30 levels), trades, ticker and funding, and ETH's top, ticker and funding.
    const FUTURES: &str = include_str!("../../tests/fixtures/bitget-futures.jsonl");
    /// Recorded from Bitget on 2026-10-28: the coin-margined BTC perpetual.
    const COIN: &str = include_str!("../../tests/fixtures/bitget-coin.jsonl");

    const EIGHT_HOURS_NS: u64 = 8 * 3_600_000_000_000;

    /// One connection of `market`, each symbol with whether it wants the book.
    fn bitget(market: MarketKind, symbols: &[(&str, bool)]) -> Feed {
        let specs: Vec<_> = symbols
            .iter()
            .map(|(symbol, depth)| {
                let spec = instrument(symbol, market);
                if *depth { spec.with_depth() } else { spec }
            })
            .collect();
        Feed::venue(decode, Venue::Bitget, market, &specs)
    }

    #[test]
    fn a_spot_session_gives_tops_a_full_book_and_trades() {
        let mut spot = bitget(MarketKind::Spot, &[("BTCUSDT", false), ("ETHUSDT", true)]);
        let Replayed {
            observations: all,
            errors,
        } = spot.replay_all(SPOT.lines());
        let [refused] = errors.as_slice() else {
            panic!("only the refused symbol is an error: {errors:?}");
        };
        assert!(refused.to_string().contains("NOPEUSDT"), "{refused}");

        let tops = of(&all, "BTCUSDT", ObsKind::BookTop);
        assert_eq!(tops.len(), 3);
        assert!(
            tops.iter()
                .all(|o| o.bid < o.ask && o.exchange_time_ns.is_some())
        );
        // The snapshot and its six changes follow one another.
        assert_eq!(of(&all, "ETHUSDT", ObsKind::Depth).len(), 7);
        assert!(of(&all, "ETHUSDT", ObsKind::BookTop).is_empty());
        assert_eq!(of(&all, "BTCUSDT", ObsKind::Trade).len(), 3);
    }

    #[test]
    fn a_perpetual_session_gives_marks_and_funding_with_its_interval() {
        let mut perps = bitget(
            MarketKind::LinearPerp,
            &[("BTCUSDT", true), ("ETHUSDT", false)],
        );
        let Replayed {
            observations: all,
            errors,
        } = perps.replay_all(FUTURES.lines());
        assert!(errors.is_empty(), "{errors:?}");

        assert_eq!(of(&all, "BTCUSDT", ObsKind::Depth).len(), 7);
        assert_eq!(of(&all, "ETHUSDT", ObsKind::BookTop).len(), 3);
        assert_eq!(of(&all, "BTCUSDT", ObsKind::MarkPrice).len(), 2);
        assert_eq!(of(&all, "BTCUSDT", ObsKind::IndexPrice).len(), 2);

        let funding = of(&all, "BTCUSDT", ObsKind::Funding);
        let info = funding[0].funding.as_deref().expect("funding");
        assert_eq!(info.basis, FundingBasis::Interval);
        assert_eq!(info.interval_ns, Some(EIGHT_HOURS_NS));
        let next = info.next_funding_time_ns.expect("next");
        let (_, settled_at) = info.settled.expect("settled");
        assert_eq!(next - settled_at, EIGHT_HOURS_NS);
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
        let mut coin = bitget(MarketKind::InversePerp, &[("BTCUSD_CM", false)]);
        let Replayed {
            observations: all,
            errors,
        } = coin.replay_all(COIN.lines());
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

    /// A venue that leaves out `seq` and `pseq` everywhere would pass a check
    /// of one missing id against another, so a book without them resyncs.
    #[test]
    fn a_book_without_its_ids_resyncs() {
        let mut spot = bitget(MarketKind::Spot, &[("ETHUSDT", true)]);
        let snapshot = SPOT
            .lines()
            .find(|line| {
                line.contains(r#""action":"snapshot""#) && line.contains(r#""topic":"books","#)
            })
            .expect("a book snapshot");
        let without = snapshot
            .replace(r#""seq":"#, r#""a_seq":"#)
            .replace(r#""pseq":"#, r#""a_pseq":"#);
        assert!(matches!(spot.refused(without), DecodeError::Resync(_)));
    }

    #[test]
    fn the_trades_at_subscribe_are_old_and_left_out() {
        let old = r#"{"action":"snapshot","arg":{"instType":"spot","topic":"publicTrade","symbol":"BTCUSDT"},"data":[{"p":"80000","v":"1","T":"1"}]}"#;
        let error = bitget(MarketKind::Spot, &[("BTCUSDT", false)]).refused(old);
        assert!(error.is_benign());
    }
}
