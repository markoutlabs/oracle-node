//! Lighter public streams: USDC-margined perpetuals, named by numeric market ids.
//!
//! - **One envelope.** `{"type":"update/ticker","channel":"ticker:1",…}`; the market
//!   id is the part of the channel after the colon, and the source's symbol, such
//!   as `1` for BTC. A subscription names one channel, `ticker/1`.
//! - **Books.** `ticker` gives the best bid and ask at each change. A market that
//!   wants depth takes `order_book` instead: the whole book, then changes, each
//!   naming the `nonce` of the last one as `begin_nonce`. A size of zero removes
//!   a level.
//! - **Trades.** `trade`. The first message of a subscription holds old trades,
//!   so only the updates count. Liquidations come in their own list and are left out.
//! - **Funding.** `market_stats`, about once a second: the mark, the index, the
//!   rate that accrues now, the last settled rate and when, and the open interest
//!   in USD. The rates are in percent. Lighter pays each hour.
//! - **Control.** The keepalive is `{"type":"ping"}`. The venue takes 200 messages
//!   a minute from one IP, so a connection subscribes once, and to few channels.
//!
//! Checked against the live socket on 2026-10-28.

use std::sync::Arc;
use std::time::Duration;

use oracle_types::{Fixed, FundingBasis, FundingInfo, ObsKind, Observation, OpenInterestUnit};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{Books, Side};
use crate::clock::millis_to_nanos;
use crate::instrument::InstrumentEntry;
use crate::{DecodeError, InstrumentMap};

use super::{book_top, decimal, observation, parse};

/// The public socket.
pub const URL: &str = "wss://mainnet.zklighter.elliot.ai/stream";

/// The keepalive. The venue closes a connection that sends nothing for 2 minutes.
pub const KEEPALIVE: &str = r#"{"type":"ping"}"#;

/// How often to send [`KEEPALIVE`].
pub const KEEPALIVE_EVERY: Duration = Duration::from_secs(60);

/// Markets on one connection: three channels each, inside the 200 messages a
/// minute that one IP may send.
pub const MARKETS_PER_CONNECTION: usize = 60;
const _: () = assert!(MARKETS_PER_CONNECTION * 3 <= 200);

/// Lighter pays funding each hour.
const FUNDING_INTERVAL_NS: u64 = 3_600_000_000_000;

/// The full book: deep enough for every impact size.
const BOOK_DEPTH: usize = 1_000;

fn subscribe(channel: &str) -> String {
    serde_json::json!({ "type": "subscribe", "channel": channel }).to_string()
}

/// The subscribe frames of a connection: each market's book, trades and stats.
#[must_use]
pub fn frames<'a>(instruments: impl Iterator<Item = (&'a str, bool)>) -> Vec<String> {
    instruments
        .flat_map(|(id, depth)| {
            let book = if depth { "order_book" } else { "ticker" };
            [book, "trade", "market_stats"].map(|channel| subscribe(&format!("{channel}/{id}")))
        })
        .collect()
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(rename = "type", borrow, default)]
    kind: Option<&'a str>,
    #[serde(borrow, default)]
    channel: Option<&'a str>,
    #[serde(borrow, default)]
    ticker: Option<&'a RawValue>,
    #[serde(borrow, default)]
    order_book: Option<&'a RawValue>,
    #[serde(borrow, default)]
    trades: Option<&'a RawValue>,
    #[serde(borrow, default)]
    market_stats: Option<&'a RawValue>,
    #[serde(borrow, default)]
    error: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct Level<'a> {
    #[serde(borrow)]
    price: &'a str,
    #[serde(borrow)]
    size: &'a str,
}

#[derive(Deserialize)]
struct Ticker<'a> {
    #[serde(borrow)]
    a: Level<'a>,
    #[serde(borrow)]
    b: Level<'a>,
    /// Unix microseconds.
    #[serde(default)]
    last_updated_at: Option<u64>,
}

#[derive(Deserialize)]
struct Book<'a> {
    #[serde(borrow)]
    asks: Vec<Level<'a>>,
    #[serde(borrow)]
    bids: Vec<Level<'a>>,
    #[serde(default)]
    nonce: Option<u64>,
    #[serde(default)]
    begin_nonce: Option<u64>,
    /// Unix microseconds.
    #[serde(default)]
    last_updated_at: Option<u64>,
}

#[derive(Deserialize)]
struct Trade<'a> {
    #[serde(borrow)]
    price: &'a str,
    /// Unix milliseconds.
    #[serde(default)]
    timestamp: Option<u64>,
}

#[derive(Deserialize)]
struct Stats<'a> {
    #[serde(borrow)]
    mark_price: &'a str,
    #[serde(borrow)]
    index_price: &'a str,
    /// Percent, over the hour that accrues now.
    #[serde(borrow)]
    current_funding_rate: &'a str,
    /// Percent: the last rate settled, at `funding_timestamp`.
    #[serde(borrow, default)]
    funding_rate: Option<&'a str>,
    /// Unix milliseconds of the last payment.
    #[serde(default)]
    funding_timestamp: Option<u64>,
    /// USD, one side.
    #[serde(borrow, default)]
    open_interest: Option<&'a str>,
}

fn micros(time: Option<u64>) -> Option<u64> {
    time.and_then(|micros| micros.checked_mul(1_000))
}

/// A rate in percent as a fraction.
fn percent(field: &'static str, text: &str) -> Result<Fixed, DecodeError> {
    let hundred = Fixed::from_int(100).map_err(|_| DecodeError::Malformed("100".to_owned()))?;
    decimal(field, text)?
        .checked_div(hundred)
        .ok_or_else(|| DecodeError::Malformed(format!("{field} {text}")))
}

/// Decodes one payload.
///
/// # Errors
///
/// Returns [`DecodeError`]. The welcome, acks and pongs are benign; a refused
/// channel is not, and a book change that does not follow the last one ends
/// the connection.
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> = serde_json::from_slice(payload)?;
    if let Some(error) = envelope.error {
        return Err(DecodeError::Malformed(format!(
            "the server refused a request: {}",
            error.get()
        )));
    }
    let (Some(kind), Some(channel)) = (envelope.kind, envelope.channel) else {
        return Err(DecodeError::Control);
    };
    let Some((stage, topic)) = kind.split_once('/') else {
        return Err(DecodeError::Control);
    };
    let id = channel
        .split_once(':')
        .map(|(_, id)| id)
        .ok_or_else(|| DecodeError::UnhandledStream(channel.to_owned()))?;
    let entry = map
        .lookup(id)
        .ok_or_else(|| DecodeError::UnknownInstrument(id.to_owned()))?;
    let missing = || DecodeError::MissingField("data");
    match topic {
        "ticker" => {
            let ticker: Ticker<'_> = parse(envelope.ticker.ok_or_else(missing)?)?;
            out.push(book_top(
                entry,
                (decimal("b", ticker.b.price)?, decimal("a", ticker.a.price)?),
                (decimal("b", ticker.b.size)?, decimal("a", ticker.a.size)?),
                micros(ticker.last_updated_at),
                local_recv_ns,
            )?);
            Ok(())
        }
        "order_book" => {
            let book: Book<'_> = parse(envelope.order_book.ok_or_else(missing)?)?;
            depth(
                id,
                entry,
                stage == "subscribed",
                &book,
                books,
                local_recv_ns,
                out,
            )
        }
        "trade" if stage == "subscribed" => Err(DecodeError::Control),
        "trade" => {
            for trade in parse::<Vec<Trade<'_>>>(envelope.trades.ok_or_else(missing)?)? {
                out.push(Observation {
                    exchange_time_ns: trade.timestamp.map(millis_to_nanos),
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
        "market_stats" => {
            let stats: Stats<'_> = parse(envelope.market_stats.ok_or_else(missing)?)?;
            for (kind, price) in [
                (ObsKind::MarkPrice, stats.mark_price),
                (ObsKind::IndexPrice, stats.index_price),
            ] {
                out.push(observation(
                    entry,
                    kind,
                    decimal("price", price)?,
                    local_recv_ns,
                ));
            }
            let rate = percent("current_funding_rate", stats.current_funding_rate)?;
            let paid_ns = stats.funding_timestamp.map(millis_to_nanos);
            let settled = match (stats.funding_rate, paid_ns) {
                (Some(rate), Some(paid)) => Some((percent("funding_rate", rate)?, paid)),
                _ => None,
            };
            let open_interest = stats
                .open_interest
                .map(|usd| decimal("open_interest", usd))
                .transpose()?;
            let state = books.funding(id);
            // The stats repeat each second: funding goes out only when it changed.
            if state.update(Some(rate), open_interest) || state.settled != settled {
                state.settled = settled;
                let info = FundingInfo {
                    interval_ns: Some(FUNDING_INTERVAL_NS),
                    next_funding_time_ns: paid_ns
                        .and_then(|paid| paid.checked_add(FUNDING_INTERVAL_NS)),
                    settled,
                    open_interest: open_interest.map(|usd| (usd, OpenInterestUnit::Quote)),
                    ..FundingInfo::new(FundingBasis::Interval)
                };
                out.push(Observation {
                    funding: Some(Arc::new(info)),
                    ..observation(entry, ObsKind::Funding, rate, local_recv_ns)
                });
            }
            Ok(())
        }
        other => Err(DecodeError::UnhandledStream(other.to_owned())),
    }
}

/// Applies the whole book or a change of it, and emits it.
fn depth(
    id: &str,
    entry: &InstrumentEntry,
    snapshot: bool,
    change: &Book<'_>,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let book = books.book(id);
    if snapshot {
        book.clear();
    } else if change.begin_nonce != book.last_id {
        return Err(DecodeError::Resync(format!(
            "{id}: change follows {:?} but the book is at {:?}",
            change.begin_nonce, book.last_id
        )));
    }
    book.last_id = change.nonce;
    for (side, levels) in [(Side::Bid, &change.bids), (Side::Ask, &change.asks)] {
        for level in levels {
            book.set(
                side,
                decimal("price", level.price)?,
                decimal("size", level.size)?,
            );
        }
    }
    book.truncate(BOOK_DEPTH);
    books.emit(
        id,
        entry.instrument.clone(),
        micros(change.last_updated_at),
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
    use oracle_types::{MarketKind, Venue};

    const RECV: u64 = 1_793_214_910_000_000_000;
    /// Recorded from Lighter on 2026-10-28: ETH's (`0`) quotes, and BTC's (`1`)
    /// whole book (cut to 30 levels a side) with its changes, trades and stats,
    /// and the refusal of an unknown market.
    const SESSION: &str = include_str!("../../tests/fixtures/lighter.jsonl");

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("valid")
    }

    fn map() -> InstrumentMap {
        let specs: Vec<InstrumentSpec> = [("0", false), ("1", true)]
            .into_iter()
            .map(|(id, depth)| {
                let spec =
                    InstrumentSpec::new(id, MarketKind::LinearPerp, "CRYPTO.X/USDT.PERP_MARK")
                        .expect("valid");
                if depth { spec.with_depth() } else { spec }
            })
            .collect();
        InstrumentMap::new(Venue::Lighter, MarketKind::LinearPerp, &specs).expect("valid")
    }

    fn replay() -> (Vec<Observation>, Vec<String>) {
        let map = map();
        let mut books = Books::default();
        let (mut all, mut errors) = (Vec::new(), Vec::new());
        for line in SESSION.lines() {
            let mut out = Vec::new();
            match decode(line.as_bytes(), &map, &mut books, RECV, &mut out) {
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
    fn a_session_gives_quotes_a_book_trades_and_hourly_funding() {
        let (all, errors) = replay();
        // Only the unknown market is an error.
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("Invalid Channel"), "{errors:?}");

        // The ticker at subscribe and its three updates.
        let tops = of(&all, "0", ObsKind::BookTop);
        assert_eq!(tops.len(), 4);
        assert!(
            tops.iter()
                .all(|o| o.bid < o.ask && o.exchange_time_ns.is_some())
        );
        // The whole book and its six changes follow one another.
        let depth = of(&all, "1", ObsKind::Depth);
        assert_eq!(depth.len(), 7);
        let book = depth[6].book.as_deref().expect("levels");
        assert!(book.bids[0].price < book.asks[0].price);
        // The three trades at subscribe are old; the two updates hold 1 and 4.
        assert_eq!(of(&all, "1", ObsKind::Trade).len(), 5);

        assert_eq!(of(&all, "1", ObsKind::MarkPrice).len(), 2);
        let funding = of(&all, "1", ObsKind::Funding);
        let info = funding[0].funding.as_deref().expect("funding");
        // 0.0012 % an hour, like Hyperliquid's 0.0000125.
        assert_eq!(funding[0].price, fixed("0.000012"));
        assert_eq!(info.interval_ns, Some(FUNDING_INTERVAL_NS));
        let (_, paid) = info.settled.expect("settled");
        assert_eq!(info.next_funding_time_ns, Some(paid + FUNDING_INTERVAL_NS));
        let (usd, unit) = info.open_interest.expect("open interest");
        assert_eq!(unit, OpenInterestUnit::Quote);
        assert!(usd > fixed("1000000"));
    }

    #[test]
    fn a_change_that_skips_one_ends_the_connection() {
        let map = map();
        let mut books = Books::default();
        let mut out = Vec::new();
        let whole = r#"{"type":"subscribed/order_book","channel":"order_book:1","order_book":{"asks":[{"price":"2","size":"1"}],"bids":[{"price":"1","size":"1"}],"nonce":10,"begin_nonce":0}}"#;
        let skip = r#"{"type":"update/order_book","channel":"order_book:1","order_book":{"asks":[],"bids":[{"price":"1","size":"0"}],"nonce":12,"begin_nonce":11}}"#;
        assert!(decode(whole.as_bytes(), &map, &mut books, RECV, &mut out).is_ok());
        assert!(matches!(
            decode(skip.as_bytes(), &map, &mut books, RECV, &mut out),
            Err(DecodeError::Resync(_))
        ));
    }

    #[test]
    fn a_connection_subscribes_three_channels_a_market() {
        let frames = frames([("1", true), ("0", false)].into_iter());
        let channels: Vec<String> = frames
            .iter()
            .map(|frame| {
                serde_json::from_str::<serde_json::Value>(frame).expect("JSON")["channel"]
                    .to_string()
            })
            .collect();
        assert_eq!(
            channels,
            [
                "\"order_book/1\"",
                "\"trade/1\"",
                "\"market_stats/1\"",
                "\"ticker/0\"",
                "\"trade/0\"",
                "\"market_stats/0\""
            ]
        );
    }
}
