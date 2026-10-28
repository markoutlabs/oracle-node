//! Bitfinex v2 public streams: USD and USDt spot, and the USDt-margined
//! perpetuals.
//!
//! - **Arrays, not objects.** A subscription is answered with a `subscribed`
//!   event that names a channel id; every later message is `[id, data]`, so
//!   the decoder keeps the id of each channel in [`Books::channels`].
//! - About 30 channels on one connection: the node splits a venue's markets
//!   over [`MARKETS_PER_CONNECTION`].
//! - Every market takes its book, the source of its quote. The `ticker`
//!   channel is throttled: on 2026-10-25 it sent 2 quotes in 25 s while the
//!   BTC book sent 790 updates.
//! - A perpetual's mark, index, funding and open interest come on its
//!   `status` channel, `deriv:tBTCF0:USTF0`. Funding is paid every 8 hours.
//!   `CURRENT_FUNDING` is the rate set at the last event, so it goes out as
//!   the settled rate. The live rate is the accrued premium beyond the dead
//!   band: on 2026-10-25 at 08:00 UTC, an accrued 0.00060401 less the
//!   `CLAMP_MIN` of 0.0005 became the 0.00010401 that was set. That rule comes
//!   from the data; the docs do not state it.
//! - Bare JSON numbers, like Deribit: each one goes through `RawValue`, so the
//!   venue's own digits reach the aggregator. Checked against the live socket
//!   and the docs on 2026-10-25.

use std::time::Duration;

use oracle_types::{Fixed, NANOS_PER_SEC, ObsKind, Observation};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{Books, Side};
use crate::clock::millis_to_nanos;
use crate::{DecodeError, InstrumentMap};

use super::{decimal_literal, interval_funding, observation};

/// The public endpoint.
pub const URL: &str = "wss://api-pub.bitfinex.com/ws/2";

/// The keepalive; the server also sends a heartbeat on each channel every 15 s.
pub const KEEPALIVE: &str = r#"{"event":"ping","cid":1}"#;

/// How often to send [`KEEPALIVE`].
pub const KEEPALIVE_EVERY: Duration = Duration::from_secs(30);

/// Markets on one connection: at most three channels each, inside the limit of 30.
pub const MARKETS_PER_CONNECTION: usize = 6;
const _: () = assert!(MARKETS_PER_CONNECTION * 3 <= 30);

/// Book levels per side.
const BOOK_LEN: &str = "25";

const EIGHT_HOURS_NS: u64 = 8 * 3_600 * NANOS_PER_SEC;

/// The `status` key of a perpetual.
fn status_key(symbol: &str) -> String {
    format!("deriv:{symbol}")
}

/// Builds the subscribe frames for a set of Bitfinex symbols: the book and the
/// trades of each, and the status channel of a perpetual. Whether a market
/// wants depth only changes what the decoder emits from its book.
#[must_use]
pub fn subscribe_frames<'a>(
    instruments: impl Iterator<Item = (&'a str, bool)>,
    perp: bool,
) -> Vec<String> {
    let mut frames = Vec::new();
    for (symbol, _) in instruments {
        frames.push(
            serde_json::json!({
                "event": "subscribe", "channel": "book", "symbol": symbol,
                "prec": "P0", "freq": "F0", "len": BOOK_LEN,
            })
            .to_string(),
        );
        frames.push(
            serde_json::json!({ "event": "subscribe", "channel": "trades", "symbol": symbol })
                .to_string(),
        );
        if perp {
            frames.push(
                serde_json::json!({ "event": "subscribe", "channel": "status", "key": status_key(symbol) })
                    .to_string(),
            );
        }
    }
    frames
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Event<'a> {
    #[serde(borrow)]
    event: &'a str,
    #[serde(borrow, default)]
    channel: Option<&'a str>,
    #[serde(default)]
    chan_id: Option<u64>,
    #[serde(borrow, default)]
    symbol: Option<&'a str>,
    #[serde(borrow, default)]
    key: Option<&'a str>,
    #[serde(default)]
    code: Option<u64>,
    #[serde(borrow, default)]
    msg: Option<&'a str>,
}

fn number(field: &'static str, raw: Option<&&RawValue>) -> Result<Option<Fixed>, DecodeError> {
    match raw {
        Some(raw) if raw.get() != "null" => decimal_literal(field, raw).map(Some),
        _ => Ok(None),
    }
}

/// The part of `accrued` beyond the dead band of `band` on each side, at most
/// `cap` either way. A missing band or cap counts as none.
fn beyond_band(accrued: Fixed, band: Option<Fixed>, cap: Option<Fixed>) -> Fixed {
    let band = band.unwrap_or(Fixed::ZERO);
    let rate = if accrued > band {
        accrued.checked_sub(band)
    } else if accrued
        .checked_add(band)
        .is_some_and(|sum| sum < Fixed::ZERO)
    {
        accrued.checked_add(band)
    } else {
        Some(Fixed::ZERO)
    }
    .unwrap_or(Fixed::ZERO);
    let Some(floor) = cap.and_then(|cap| Fixed::ZERO.checked_sub(cap)) else {
        return rate;
    };
    match cap {
        Some(cap) if rate > cap => cap,
        Some(_) if rate < floor => floor,
        _ => rate,
    }
}

/// Decodes one Bitfinex payload.
///
/// # Errors
///
/// Returns [`DecodeError`]. Heartbeats, pongs and subscribe replies are
/// benign; an `error` event names a bad subscription and is not. An `info`
/// event that asks for a reconnect is [`DecodeError::Resync`].
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let malformed = |e: serde_json::Error| DecodeError::Malformed(e.to_string());
    if payload.first() == Some(&b'{') {
        let event: Event<'_> = serde_json::from_slice(payload).map_err(malformed)?;
        return match event.event {
            "subscribed" => {
                let (Some(id), Some(channel)) = (event.chan_id, event.channel) else {
                    return Err(DecodeError::MissingField("chanId"));
                };
                let symbol = event
                    .symbol
                    .or_else(|| event.key.and_then(|key| key.strip_prefix("deriv:")))
                    .ok_or(DecodeError::MissingField("symbol"))?;
                books
                    .channels
                    .insert(id, (channel.to_owned(), symbol.to_owned()));
                Err(DecodeError::Control)
            }
            // 20051 restarts the server; 20060 starts maintenance, which leaves the
            // last book standing; 20061 ends it and asks for fresh subscriptions.
            "info" if matches!(event.code, Some(20_051 | 20_060 | 20_061)) => {
                Err(DecodeError::Resync(format!(
                    "the server asks for a reconnect: {}",
                    event.code.unwrap_or(0)
                )))
            }
            "error" => Err(DecodeError::Malformed(format!(
                "the server refused a request: {} {}",
                event.code.unwrap_or(0),
                event.msg.unwrap_or("")
            ))),
            _ => Err(DecodeError::Control),
        };
    }
    let message: Vec<&RawValue> = serde_json::from_slice(payload).map_err(malformed)?;
    let (Some(id), Some(body)) = (message.first(), message.get(1)) else {
        return Err(DecodeError::Malformed("an empty array".to_owned()));
    };
    let id: u64 = serde_json::from_str(id.get()).map_err(malformed)?;
    let Some((channel, symbol)) = books.channels.get(&id).cloned() else {
        return Err(DecodeError::UnhandledStream(format!("channel {id}")));
    };
    let Some(entry) = map.lookup(&symbol).cloned() else {
        return Err(DecodeError::UnknownInstrument(symbol));
    };
    // A heartbeat, or a trade update that repeats an executed trade.
    if body.get() == r#""hb""# || body.get() == r#""tu""# {
        return Err(DecodeError::Control);
    }
    match channel.as_str() {
        "trades" => {
            // `[id, "te", [ID, MTS, AMOUNT, PRICE]]`; the snapshot of past trades is skipped.
            if body.get() != r#""te""# {
                return Err(DecodeError::Control);
            }
            let trade: Vec<&RawValue> = serde_json::from_str(
                message
                    .get(2)
                    .ok_or(DecodeError::MissingField("trade"))?
                    .get(),
            )
            .map_err(malformed)?;
            let price = number("PRICE", trade.get(3))?.ok_or(DecodeError::MissingField("PRICE"))?;
            let time: Option<u64> = trade
                .get(1)
                .and_then(|raw| serde_json::from_str(raw.get()).ok());
            out.push(Observation {
                exchange_time_ns: time.map(millis_to_nanos),
                ..observation(&entry, ObsKind::Trade, price, local_recv_ns)
            });
            Ok(())
        }
        "book" => {
            let levels: Vec<Vec<&RawValue>> = match serde_json::from_str(body.get()) {
                Ok(snapshot) => {
                    books.book(&symbol).clear();
                    snapshot
                }
                Err(_) => vec![serde_json::from_str(body.get()).map_err(malformed)?],
            };
            let book = books.book(&symbol);
            for level in levels {
                let price =
                    number("PRICE", level.first())?.ok_or(DecodeError::MissingField("PRICE"))?;
                let count = number("COUNT", level.get(1))?.unwrap_or(Fixed::ZERO);
                let amount = number("AMOUNT", level.get(2))?.unwrap_or(Fixed::ZERO);
                // A positive amount is a bid, a negative one an ask; a count of 0 removes the level.
                let side = if amount.is_positive() {
                    Side::Bid
                } else {
                    Side::Ask
                };
                let qty = if count.is_positive() {
                    amount.checked_abs().unwrap_or(Fixed::ZERO)
                } else {
                    Fixed::ZERO
                };
                book.set(side, price, qty);
            }
            let emit = if entry.depth {
                Books::emit
            } else {
                Books::emit_top
            };
            emit(
                books,
                &symbol,
                entry.instrument.clone(),
                None,
                local_recv_ns,
                out,
            )
        }
        "status" => {
            let fields: Vec<&RawValue> = serde_json::from_str(body.get()).map_err(malformed)?;
            let mut emitted = false;
            for (field, kind, index) in [
                ("MARK_PRICE", ObsKind::MarkPrice, 14),
                ("SPOT_PRICE", ObsKind::IndexPrice, 3),
            ] {
                if let Some(price) = number(field, fields.get(index))? {
                    out.push(observation(&entry, kind, price, local_recv_ns));
                    emitted = true;
                }
            }
            let accrued = number("NEXT_FUNDING_ACCRUED", fields.get(8))?;
            let band = number("CLAMP_MIN", fields.get(21))?;
            let cap = number("CLAMP_MAX", fields.get(22))?;
            let rate = accrued.map(|accrued| beyond_band(accrued, band, cap));
            let set = number("CURRENT_FUNDING", fields.get(11))?;
            let open_interest = number("OPEN_INTEREST", fields.get(17))?;
            let next_ms: Option<u64> = fields
                .get(7)
                .and_then(|raw| serde_json::from_str(raw.get()).ok());
            let next_ns = next_ms.map(millis_to_nanos);
            let set_at = next_ns.and_then(|next| next.checked_sub(EIGHT_HOURS_NS));
            // The status repeats each second: the rate goes out when it or the open interest changed.
            let last = books.funding(&symbol);
            if last.update(rate, open_interest) {
                last.interval_ns = Some(EIGHT_HOURS_NS);
                last.next_funding_time_ns = next_ns;
                last.settled = set.zip(set_at);
                if let Some(funding) = interval_funding(&entry, last, local_recv_ns) {
                    out.push(funding);
                    emitted = true;
                }
            }
            if emitted {
                Ok(())
            } else {
                Err(DecodeError::Control)
            }
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
    use crate::InstrumentSpec;
    use oracle_types::OpenInterestUnit;
    use oracle_types::{MarketKind, Venue};

    const RECV: u64 = 1_792_928_910_000_000_000;
    /// Recorded from Bitfinex on 2026-10-25: the subscribe replies, then the
    /// first messages of a spot ticker, trades and book, and a perpetual's
    /// ticker and status. The decoder no longer takes the tickers.
    const SESSION: &str = include_str!("../../tests/fixtures/bitfinex-session.jsonl");

    fn maps() -> (InstrumentMap, InstrumentMap) {
        let spot = InstrumentSpec::new("tBTCUSD", MarketKind::Spot, "CRYPTO.BTC/USD")
            .expect("valid")
            .with_depth();
        let perp = InstrumentSpec::new(
            "tBTCF0:USTF0",
            MarketKind::LinearPerp,
            "CRYPTO.BTC/USDT.PERP_MARK",
        )
        .expect("valid");
        (
            InstrumentMap::new(Venue::Bitfinex, MarketKind::Spot, &[spot]).expect("valid"),
            InstrumentMap::new(Venue::Bitfinex, MarketKind::LinearPerp, &[perp]).expect("valid"),
        )
    }

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("valid")
    }

    /// Runs the session through one map, as one connection would.
    fn replay(map: &InstrumentMap) -> Vec<Observation> {
        let mut books = Books::default();
        let mut all = Vec::new();
        for line in SESSION.lines() {
            let mut out = Vec::new();
            match decode(line.as_bytes(), map, &mut books, RECV, &mut out) {
                Ok(()) => all.extend(out),
                Err(error) if error.is_benign() => {}
                Err(error) => panic!("{error}: {line}"),
            }
        }
        all
    }

    #[test]
    fn a_recorded_spot_session_gives_trades_and_a_book_with_its_quote() {
        let (spot, _) = maps();
        let all = replay(&spot);
        assert!(all.iter().any(|o| o.kind == ObsKind::Trade));
        assert!(
            all.iter().all(|o| o.kind != ObsKind::BookTop),
            "no ticker quote"
        );
        let depth = all
            .iter()
            .rev()
            .find(|o| o.kind == ObsKind::Depth)
            .expect("a book");
        let book = depth.book.as_deref().expect("levels");
        assert!(book.bids[0].price < book.asks[0].price);
        assert!(book.bids.iter().all(|level| level.qty.is_positive()));
        assert_eq!(depth.bid, Some(book.bids[0].price));
        assert_eq!(depth.ask, Some(book.asks[0].price));
    }

    /// A market without depth still takes its quote from the book.
    #[test]
    fn a_market_without_depth_gets_its_quote_from_the_book() {
        let spec =
            InstrumentSpec::new("tBTCUSD", MarketKind::Spot, "CRYPTO.BTC/USD").expect("valid");
        let map = InstrumentMap::new(Venue::Bitfinex, MarketKind::Spot, &[spec]).expect("valid");
        let all = replay(&map);
        assert!(all.iter().all(|o| o.kind != ObsKind::Depth));
        let top = all
            .iter()
            .rev()
            .find(|o| o.kind == ObsKind::BookTop)
            .expect("a quote");
        assert!(top.bid < top.ask);
        assert!(top.book.is_none());
    }

    #[test]
    fn a_perpetual_status_gives_mark_index_and_eight_hour_funding() {
        let (_, perp) = maps();
        let all = replay(&perp);
        let mark = all
            .iter()
            .find(|o| o.kind == ObsKind::MarkPrice)
            .expect("a mark");
        assert_eq!(mark.price, fixed("80543.2212"));
        let index = all
            .iter()
            .find(|o| o.kind == ObsKind::IndexPrice)
            .expect("an index");
        assert_eq!(index.price, fixed("80556"));
        let funding: Vec<&Observation> =
            all.iter().filter(|o| o.kind == ObsKind::Funding).collect();
        assert!(!funding.is_empty());
        // Accrued 0.00027518 sits inside the 0.0005 band: nothing would be paid now.
        assert_eq!(funding[0].price, Fixed::ZERO);
        let info = funding[0].funding.as_deref().expect("info");
        assert_eq!(info.interval_ns, Some(EIGHT_HOURS_NS));
        assert_eq!(info.next_funding_time_ns, Some(1_792_944_000_000_000_000));
        // The rate set at 08:00 UTC, eight hours before the next event.
        assert_eq!(
            info.settled,
            Some((fixed("0.00010401"), 1_792_915_200_000_000_000))
        );
        assert_eq!(
            info.open_interest,
            Some((fixed("9254.55332705"), OpenInterestUnit::Base))
        );
        // The spot channels of the session are not this map's.
        assert!(all.iter().all(|o| o.instrument.symbol.contains("F0")));
    }

    /// The 08:00 UTC event of 2026-10-25: 0.00060401 accrued became 0.00010401.
    #[test]
    fn the_live_rate_is_the_accrued_premium_beyond_the_band() {
        let (band, cap) = (Some(fixed("0.0005")), Some(fixed("0.0025")));
        assert_eq!(
            beyond_band(fixed("0.00060401"), band, cap),
            fixed("0.00010401")
        );
        assert_eq!(beyond_band(fixed("-0.0007"), band, cap), fixed("-0.0002"));
        assert_eq!(beyond_band(fixed("0.0003"), band, cap), Fixed::ZERO);
        assert_eq!(beyond_band(fixed("-0.0004"), band, cap), Fixed::ZERO);
        assert_eq!(beyond_band(fixed("0.01"), band, cap), fixed("0.0025"));
        assert_eq!(beyond_band(fixed("-0.01"), band, cap), fixed("-0.0025"));
        assert_eq!(beyond_band(fixed("0.0003"), None, None), fixed("0.0003"));
    }

    #[test]
    fn a_book_update_with_a_count_of_zero_removes_the_level() {
        let (spot, _) = maps();
        let mut books = Books::default();
        let mut out = Vec::new();
        let subscribed =
            r#"{"event":"subscribed","channel":"book","chanId":5,"symbol":"tBTCUSD","prec":"P0"}"#;
        let snapshot = "[5,[[100,1,2],[99,1,3],[101,1,-1],[102,2,-4]]]";
        for line in [subscribed, snapshot, "[5,[100,0,1]]", "[5,[101,0,-1]]"] {
            let _ = decode(line.as_bytes(), &spot, &mut books, RECV, &mut out);
        }
        let book = out.last().and_then(|o| o.book.as_deref()).expect("a book");
        assert_eq!(book.bids[0].price, fixed("99"));
        assert_eq!(book.asks[0].price, fixed("102"));
        assert_eq!(book.asks[0].qty, fixed("4"));
    }

    #[test]
    fn events_heartbeats_and_unknown_channels_are_benign_and_errors_are_not() {
        let (spot, _) = maps();
        let mut books = Books::default();
        let mut out = Vec::new();
        for control in [
            r#"{"event":"info","version":2,"serverId":"x","platform":{"status":1}}"#,
            r#"{"event":"pong","cid":1,"ts":1792928908844}"#,
            r#"{"event":"subscribed","channel":"ticker","chanId":7,"symbol":"tBTCUSD","pair":"BTCUSD"}"#,
            r#"[7,"hb"]"#,
            r#"[8,[1,2,3,4]]"#,
        ] {
            let error = decode(control.as_bytes(), &spot, &mut books, RECV, &mut out)
                .expect_err("not market data");
            assert!(error.is_benign(), "got {error:?} for {control}");
        }
        let limit = r#"{"event":"error","msg":"subscribe: limit","code":10305}"#;
        assert!(
            !decode(limit.as_bytes(), &spot, &mut books, RECV, &mut out)
                .expect_err("an error")
                .is_benign()
        );
        let restart = r#"{"event":"info","code":20051,"msg":"Stopping. Please try to reconnect"}"#;
        assert!(matches!(
            decode(restart.as_bytes(), &spot, &mut books, RECV, &mut out),
            Err(DecodeError::Resync(_))
        ));
    }

    #[test]
    fn subscribe_frames_name_each_channel_and_the_status_key() {
        let frames = subscribe_frames([("tBTCF0:USTF0", true)].into_iter(), true);
        assert_eq!(frames.len(), 3, "{frames:?}");
        assert!(frames.iter().all(|f| !f.contains("ticker")));
        assert!(
            frames
                .iter()
                .any(|f| f.contains(r#""key":"deriv:tBTCF0:USTF0""#))
        );
        assert!(
            frames
                .iter()
                .any(|f| f.contains(r#""channel":"book""#) && f.contains(r#""prec":"P0""#))
        );
        let spot = subscribe_frames([("tBTCUSD", false)].into_iter(), false);
        assert_eq!(spot.len(), 2);
        assert!(spot[0].contains(r#""channel":"book""#));
    }
}
