//! Gate public streams: spot, and the USDT-settled perpetuals.
//!
//! - **One envelope.** `{"channel":"spot.book_ticker","event":"update","result":{…}}`.
//!   A subscription names a channel and a list of markets, such as `BTC_USDT`.
//!   Its `time` field is fixed: the venue does not check it.
//! - **Spot.** `spot.book_ticker` gives the quote. A market that wants depth takes
//!   `spot.order_book` instead: a whole 50-level book every 100 ms.
//!   `spot.trades` gives the trades.
//! - **Perpetuals** count in contracts of `quanto_multiplier` coins, the source's
//!   `contract_size`. `futures.book_ticker` gives the quote, `futures.order_book`
//!   a whole 50-level book at each change, and `futures.trades` the trades.
//!   `futures.tickers` gives the mark, the index, the funding rate with its
//!   interval and next payment, and the open interest in contracts.
//! - **Control.** The keepalive is `spot.ping` or `futures.ping`. A subscription
//!   to an unknown market is acknowledged and then stays silent.
//!
//! Checked against the live sockets on 2026-10-28.

use std::time::Duration;

use oracle_types::{ObsKind, Observation};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{BookMsg, BookRule, Books, Change, Continuity};
use crate::clock::millis_to_nanos;
use crate::instrument::InstrumentEntry;
use crate::{DecodeError, InstrumentMap};

use super::{base_units, book_top, decimal, decimal_literal, interval_funding, observation, parse};

/// The spot socket.
pub const SPOT_URL: &str = "wss://api.gateio.ws/ws/v4/";

/// The socket of the USDT-settled perpetuals.
pub const FUTURES_URL: &str = "wss://fx-ws.gateio.ws/v4/ws/usdt";

/// The spot keepalive, answered with `spot.pong`.
pub const SPOT_KEEPALIVE: &str = r#"{"time":1700000000,"channel":"spot.ping"}"#;

/// The futures keepalive, answered with `futures.pong`.
pub const FUTURES_KEEPALIVE: &str = r#"{"time":1700000000,"channel":"futures.ping"}"#;

/// How often to send a keepalive.
pub const KEEPALIVE_EVERY: Duration = Duration::from_secs(15);

/// Markets on one connection. One frame takes the quotes, the trades and the
/// tickers of every market, and each book takes a frame of its own.
pub const MARKETS_PER_CONNECTION: usize = 40;

/// Levels of a whole book.
const BOOK_LEVELS: &str = "50";

fn subscribe(channel: &str, payload: &[&str]) -> String {
    serde_json::json!({
        "time": 1_700_000_000_u64,
        "channel": channel,
        "event": "subscribe",
        "payload": payload,
    })
    .to_string()
}

fn frames<'a>(
    instruments: impl Iterator<Item = (&'a str, bool)>,
    prefix: &str,
    book_interval: &str,
    lists: &[&str],
) -> Vec<String> {
    let instruments: Vec<(&str, bool)> = instruments.collect();
    let all: Vec<&str> = instruments.iter().map(|(symbol, _)| *symbol).collect();
    let quoted: Vec<&str> = instruments
        .iter()
        .filter(|(_, depth)| !depth)
        .map(|(symbol, _)| *symbol)
        .collect();
    let mut out = Vec::new();
    if !quoted.is_empty() {
        out.push(subscribe(&format!("{prefix}.book_ticker"), &quoted));
    }
    for (symbol, _) in instruments.iter().filter(|(_, depth)| *depth) {
        out.push(subscribe(
            &format!("{prefix}.order_book"),
            &[symbol, BOOK_LEVELS, book_interval],
        ));
    }
    if !all.is_empty() {
        for list in lists {
            out.push(subscribe(&format!("{prefix}.{list}"), &all));
        }
    }
    out
}

/// The subscribe frames of a spot connection, each symbol with whether it wants depth.
#[must_use]
pub fn spot_frames<'a>(instruments: impl Iterator<Item = (&'a str, bool)>) -> Vec<String> {
    frames(instruments, "spot", "100ms", &["trades"])
}

/// The subscribe frames of a futures connection, each symbol with whether it wants depth.
#[must_use]
pub fn futures_frames<'a>(instruments: impl Iterator<Item = (&'a str, bool)>) -> Vec<String> {
    frames(instruments, "futures", "0", &["trades", "tickers"])
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow)]
    channel: &'a str,
    #[serde(borrow, default)]
    event: &'a str,
    #[serde(borrow, default)]
    result: Option<&'a RawValue>,
    #[serde(borrow, default)]
    error: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct BookTicker<'a> {
    #[serde(borrow)]
    s: &'a str,
    #[serde(borrow)]
    b: &'a RawValue,
    #[serde(rename = "B", borrow)]
    bid_size: &'a RawValue,
    #[serde(borrow)]
    a: &'a RawValue,
    #[serde(rename = "A", borrow)]
    ask_size: &'a RawValue,
    /// Unix milliseconds.
    #[serde(default)]
    t: Option<u64>,
}

#[derive(Deserialize)]
struct SpotBook<'a> {
    #[serde(borrow)]
    s: &'a str,
    #[serde(borrow)]
    bids: Vec<(&'a str, &'a str)>,
    #[serde(borrow)]
    asks: Vec<(&'a str, &'a str)>,
    #[serde(default)]
    t: Option<u64>,
}

#[derive(Deserialize)]
struct Level<'a> {
    #[serde(borrow)]
    p: &'a str,
    #[serde(borrow)]
    s: &'a RawValue,
}

#[derive(Deserialize)]
struct FuturesBook<'a> {
    #[serde(borrow)]
    contract: &'a str,
    #[serde(borrow)]
    bids: Vec<Level<'a>>,
    #[serde(borrow)]
    asks: Vec<Level<'a>>,
    #[serde(default)]
    t: Option<u64>,
}

#[derive(Deserialize)]
struct SpotTrade<'a> {
    #[serde(borrow)]
    currency_pair: &'a str,
    #[serde(borrow)]
    price: &'a str,
    /// Unix milliseconds with a fraction, such as `1793214164157.247000`.
    #[serde(borrow, default)]
    create_time_ms: Option<&'a str>,
}

#[derive(Deserialize)]
struct FuturesTrade<'a> {
    #[serde(borrow)]
    contract: &'a str,
    #[serde(borrow)]
    price: &'a str,
    #[serde(default)]
    create_time_ms: Option<u64>,
}

#[derive(Deserialize)]
struct Ticker<'a> {
    #[serde(borrow)]
    contract: &'a str,
    #[serde(borrow)]
    mark_price: &'a str,
    #[serde(borrow)]
    index_price: &'a str,
    #[serde(borrow)]
    funding_rate: &'a str,
    /// Seconds.
    #[serde(default)]
    funding_interval: Option<u64>,
    /// Unix seconds.
    #[serde(default)]
    funding_next_apply: Option<u64>,
    /// The open interest, in contracts.
    #[serde(borrow, default)]
    total_size: Option<&'a str>,
}

fn entry<'a>(map: &'a InstrumentMap, symbol: &str) -> Result<&'a InstrumentEntry, DecodeError> {
    map.lookup(symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(symbol.to_owned()))
}

/// Each book message is a whole book.
const BOOK_RULE: BookRule = BookRule::new(Continuity::WholeBook);

/// Decodes one payload of either socket.
///
/// # Errors
///
/// Returns [`DecodeError`]. Acks and pongs are benign; a refused subscription
/// is not.
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> = serde_json::from_slice(payload)?;
    if let Some(error) = envelope.error.filter(|error| error.get() != "null") {
        return Err(DecodeError::Malformed(format!(
            "the server refused a request: {}",
            error.get()
        )));
    }
    if envelope.channel.ends_with(".pong") || !matches!(envelope.event, "update" | "all") {
        return Err(DecodeError::Control);
    }
    let result = envelope.result.ok_or(DecodeError::MissingField("result"))?;
    match envelope.channel {
        "spot.book_ticker" | "futures.book_ticker" => {
            let quote: BookTicker<'_> = parse(result)?;
            let entry = entry(map, quote.s)?;
            let size = |raw| {
                decimal_literal("size", raw).map(|size| base_units(size, entry.contract_size))
            };
            let top = || {
                // An empty side comes as an empty string.
                if [quote.b, quote.a].iter().any(|raw| raw.get() == r#""""#) {
                    return Ok(None);
                }
                Ok(Some((
                    (
                        decimal_literal("b", quote.b)?,
                        decimal_literal("a", quote.a)?,
                    ),
                    (size(quote.bid_size)?, size(quote.ask_size)?),
                )))
            };
            let time = quote.t.map(millis_to_nanos);
            out.push(book_top(entry, top, time, local_recv_ns)?);
            Ok(())
        }
        "spot.order_book" => {
            let book: SpotBook<'_> = parse(result)?;
            let entry = entry(map, book.s)?;
            let parsed = BookMsg::whole(&book.bids, &book.asks, |(price, size)| {
                Ok(Change::new(
                    decimal("price", price)?,
                    decimal("size", size)?,
                ))
            });
            let parsed = parsed.map(|whole| whole.at(book.t.map(millis_to_nanos)));
            books
                .keeper
                .apply(BOOK_RULE, entry, parsed, local_recv_ns, out)
        }
        "futures.order_book" => {
            let book: FuturesBook<'_> = parse(result)?;
            let entry = entry(map, book.contract)?;
            let parsed = BookMsg::whole(&book.bids, &book.asks, |level| {
                let size = decimal_literal("s", level.s)?;
                Ok(Change::new(
                    decimal("p", level.p)?,
                    base_units(size, entry.contract_size),
                ))
            });
            let parsed = parsed.map(|whole| whole.at(book.t.map(millis_to_nanos)));
            books
                .keeper
                .apply(BOOK_RULE, entry, parsed, local_recv_ns, out)
        }
        "spot.trades" => {
            let trade: SpotTrade<'_> = parse(result)?;
            let entry = entry(map, trade.currency_pair)?;
            // A fraction of a millisecond adds nothing to a receipt measured in milliseconds.
            let time_ms = trade
                .create_time_ms
                .and_then(|text| text.split('.').next())
                .and_then(|millis| millis.parse::<u64>().ok());
            out.push(Observation {
                exchange_time_ns: time_ms.map(millis_to_nanos),
                ..observation(
                    entry,
                    ObsKind::Trade,
                    decimal("price", trade.price)?,
                    local_recv_ns,
                )
            });
            Ok(())
        }
        "futures.trades" => {
            for trade in parse::<Vec<FuturesTrade<'_>>>(result)? {
                let entry = entry(map, trade.contract)?;
                out.push(Observation {
                    exchange_time_ns: trade.create_time_ms.map(millis_to_nanos),
                    ..observation(
                        entry,
                        ObsKind::Trade,
                        decimal("price", trade.price)?,
                        local_recv_ns,
                    )
                });
            }
            Ok(())
        }
        "futures.tickers" => {
            for ticker in parse::<Vec<Ticker<'_>>>(result)? {
                let entry = entry(map, ticker.contract)?;
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
                let open_interest = ticker
                    .total_size
                    .map(|contracts| decimal("total_size", contracts))
                    .transpose()?
                    .map(|contracts| base_units(contracts, entry.contract_size));
                let interval_ns = ticker
                    .funding_interval
                    .and_then(|secs| secs.checked_mul(1_000_000_000))
                    .filter(|ns| *ns > 0);
                let next_ns = ticker
                    .funding_next_apply
                    .and_then(|secs| secs.checked_mul(1_000_000_000));
                let state = books.funding(&entry.instrument);
                let moved =
                    state.interval_ns != interval_ns || state.next_funding_time_ns != next_ns;
                state.interval_ns = interval_ns;
                state.next_funding_time_ns = next_ns;
                // The ticker repeats each second: funding goes out only when it changed.
                let rate = decimal("funding_rate", ticker.funding_rate)?;
                if state.update(Some(rate), open_interest) || moved {
                    out.extend(interval_funding(entry, state, local_recv_ns));
                }
            }
            Ok(())
        }
        other => Err(DecodeError::UnhandledStream(other.to_owned())),
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
    use crate::testing::{Feed, Replayed, contracts_of, fixed, instrument, of};
    use oracle_types::{MarketKind, OpenInterestUnit, Venue};

    /// 2026-10-26, before every recording: a time read in seconds would be far below it.
    const IN_2026_NS: u64 = 1_793_000_000_000_000_000;

    /// Recorded from Gate on 2026-10-28: the BTC and ETH quotes, ETH's whole
    /// book, BTC's trades and a pong.
    const SPOT: &str = include_str!("../../tests/fixtures/gate-spot.jsonl");
    /// Recorded from Gate on 2026-10-28: BTC's quote and trades, ETH's whole
    /// book, the tickers of both, and a pong.
    const FUTURES: &str = include_str!("../../tests/fixtures/gate-futures.jsonl");

    /// Contracts of the futures recording, in coins.
    const BTC_CONTRACT: &str = "0.0001";
    const ETH_CONTRACT: &str = "0.01";

    fn spot() -> Feed {
        let pairs = [
            instrument("BTC_USDT", MarketKind::Spot),
            instrument("ETH_USDT", MarketKind::Spot).with_depth(),
        ];
        Feed::venue(decode, Venue::Gate, MarketKind::Spot, &pairs)
    }

    fn futures() -> Feed {
        let perps = [
            contracts_of(instrument("BTC_USDT", MarketKind::LinearPerp), BTC_CONTRACT),
            contracts_of(instrument("ETH_USDT", MarketKind::LinearPerp), ETH_CONTRACT).with_depth(),
        ];
        Feed::venue(decode, Venue::Gate, MarketKind::LinearPerp, &perps)
    }

    #[test]
    fn a_spot_session_gives_quotes_a_whole_book_and_trades() {
        let Replayed {
            observations: all,
            errors,
        } = spot().replay_all(SPOT.lines());
        assert!(errors.is_empty(), "{errors:?}");
        let tops = of(&all, "BTC_USDT", ObsKind::BookTop);
        assert_eq!(tops.len(), 3);
        assert!(
            tops.iter()
                .all(|o| o.bid < o.ask && o.exchange_time_ns.is_some())
        );
        let depth = of(&all, "ETH_USDT", ObsKind::Depth);
        assert_eq!(depth.len(), 2);
        assert_eq!(
            depth[1].book.as_deref().map(|book| book.bids.len()),
            Some(DEPTH_LEVELS)
        );
        let trades = of(&all, "BTC_USDT", ObsKind::Trade);
        assert_eq!(trades.len(), 3);
        // A time in 2026: the milliseconds were read, not the seconds.
        assert!(
            trades
                .iter()
                .all(|o| { o.exchange_time_ns.is_some_and(|ns| ns > IN_2026_NS) })
        );
    }

    #[test]
    fn a_futures_session_sizes_in_coins_and_carries_funding() {
        let Replayed {
            observations: all,
            errors,
        } = futures().replay_all(FUTURES.lines());
        assert!(errors.is_empty(), "{errors:?}");

        let top = of(&all, "BTC_USDT", ObsKind::BookTop)[0];
        let line = FUTURES
            .lines()
            .find(|l| l.contains("futures.book_ticker\",\"event\":\"update"))
            .expect("a quote");
        let quote: serde_json::Value = serde_json::from_str(line).expect("JSON");
        let bid_contracts = quote["result"]["B"]
            .as_u64()
            .expect("contracts")
            .to_string();
        let bid_coins = fixed(&bid_contracts).checked_mul(fixed(BTC_CONTRACT));
        assert_eq!(top.bid_qty, Some(bid_coins.expect("fits")));

        assert_eq!(of(&all, "ETH_USDT", ObsKind::Depth).len(), 2);
        assert_eq!(of(&all, "BTC_USDT", ObsKind::MarkPrice).len(), 2);
        assert_eq!(of(&all, "BTC_USDT", ObsKind::IndexPrice).len(), 2);
        let funding = of(&all, "ETH_USDT", ObsKind::Funding);
        let info = funding[0].funding.as_deref().expect("funding");
        assert_eq!(info.interval_ns, Some(8 * 3_600_000_000_000));
        assert_eq!(info.next_funding_time_ns, Some(1_793_232_000_000_000_000));
        assert_eq!(
            info.open_interest,
            Some((fixed("719893.514"), OpenInterestUnit::Base))
        );
        assert_eq!(of(&all, "BTC_USDT", ObsKind::Trade).len(), 3);
    }

    #[test]
    fn pongs_and_acks_are_benign_and_a_refusal_is_not() {
        let mut spot = spot();
        assert!(
            spot.refused(r#"{"time":1,"channel":"spot.pong","event":"","result":null}"#)
                .is_benign()
        );
        assert!(
            spot.refused(r#"{"time":1,"channel":"spot.trades","event":"subscribe","result":{"status":"success"}}"#)
                .is_benign()
        );
        assert!(
            !spot
                .refused(r#"{"time":1,"channel":"spot.trades","event":"subscribe","error":{"code":2,"message":"bad"},"result":{"status":"fail"}}"#)
                .is_benign()
        );
    }

    #[test]
    fn the_frames_take_lists_and_a_book_each() {
        let spot = spot_frames([("BTC_USDT", false), ("ETH_USDT", true)].into_iter());
        assert_eq!(spot.len(), 3);
        let book: serde_json::Value = serde_json::from_str(&spot[1]).expect("JSON");
        assert_eq!(book["channel"], "spot.order_book");
        assert_eq!(
            book["payload"],
            serde_json::json!(["ETH_USDT", "50", "100ms"])
        );
        let futures = futures_frames([("BTC_USDT", false)].into_iter());
        let channels: Vec<String> = futures
            .iter()
            .map(|frame| {
                serde_json::from_str::<serde_json::Value>(frame).expect("JSON")["channel"]
                    .to_string()
            })
            .collect();
        assert_eq!(
            channels,
            [
                "\"futures.book_ticker\"",
                "\"futures.trades\"",
                "\"futures.tickers\""
            ]
        );
    }
}
