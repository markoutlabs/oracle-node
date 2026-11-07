//! OKX v5 public streams.
//!
//! - One host serves spot and swaps; the instrument id carries the distinction
//!   (`BTC-USDT` versus `BTC-USDT-SWAP`).
//! - Requires a **plain text** `ping` roughly every 25s, not a JSON frame and not
//!   a WebSocket ping. OKX closes a connection idle for 30s.
//! - Subscription arguments are objects, and the count per request is capped, so
//!   large catalogues need several frames.

use std::sync::Arc;
use std::time::Duration;

use oracle_types::{FundingBasis, FundingInfo, ObsKind, Observation, OpenInterestUnit};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{BookMsg, BookRule, Books, Change, Continuity, Halts, LocalBook, Side};
use crate::clock::millis_to_nanos;
use crate::instrument::InstrumentEntry;
use crate::{DecodeError, InstrumentMap};

use super::{base_units, book_top, decimal, integer, observation, parse};

/// The public endpoint.
pub const URL: &str = "wss://ws.okx.com:8443/ws/v5/public";

/// Keepalive period, comfortably inside the 30s idle limit.
pub const KEEPALIVE: Duration = Duration::from_secs(25);

/// The keepalive payload: plain text, not JSON.
pub const KEEPALIVE_PAYLOAD: &str = "ping";

/// Channels subscribed per instrument.
const SPOT_CHANNELS: [&str; 2] = ["bbo-tbt", "trades"];
const SWAP_CHANNELS: [&str; 5] = [
    "bbo-tbt",
    "trades",
    "mark-price",
    "funding-rate",
    "open-interest",
];
/// The book: a 400-level snapshot, then the changes every 100ms.
const DEPTH_CHANNEL: &str = "books";

/// Levels kept per side, the depth OKX publishes.
pub const BOOK_DEPTH: usize = 400;

/// Levels per side a non-zero checksum covers.
const CHECKSUM_LEVELS: usize = 25;

/// Each update names the `seqId` of the one before it as `prevSeqId`. OKX now
/// sends a zero checksum on the public channel; a non-zero one is checked.
const BOOK_RULE: BookRule = BookRule::new(Continuity::UpdateId)
    .depth(BOOK_DEPTH)
    .checksum(checksum);

/// Returns `true` if an OKX instrument id names a perpetual swap.
#[must_use]
pub fn is_swap(inst_id: &str) -> bool {
    inst_id.ends_with("-SWAP")
}

/// Builds subscribe frames for a set of OKX instrument ids, each with whether
/// it wants the book. A swap's book is in contracts, so it needs the
/// instrument's contract size; the node config refuses one without it.
#[must_use]
pub fn subscribe_frames<'a>(
    instruments: impl Iterator<Item = (&'a str, bool)>,
    chunk: usize,
) -> Vec<String> {
    let mut args: Vec<serde_json::Value> = Vec::new();
    for (inst_id, depth) in instruments {
        let channels: &[&str] = if is_swap(inst_id) {
            &SWAP_CHANNELS
        } else {
            &SPOT_CHANNELS
        };
        let depth = depth.then_some(DEPTH_CHANNEL);
        for channel in channels.iter().copied().chain(depth) {
            args.push(serde_json::json!({ "channel": channel, "instId": inst_id }));
        }
    }
    args.chunks(chunk.max(1))
        .map(|group| serde_json::json!({ "op": "subscribe", "args": group }).to_string())
        .collect()
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow, default)]
    arg: Option<Arg<'a>>,
    /// `snapshot` or `update`, on the book channel.
    #[serde(borrow, default)]
    action: Option<&'a str>,
    #[serde(borrow, default)]
    data: Option<&'a RawValue>,
}

#[derive(Clone, Copy, Deserialize)]
struct Arg<'a> {
    #[serde(borrow)]
    channel: &'a str,
    #[serde(rename = "instId", borrow, default)]
    inst_id: Option<&'a str>,
}

/// `bbo-tbt`: levels are `[price, size, liquidated_orders, order_count]`.
#[derive(Deserialize)]
struct Bbo<'a> {
    #[serde(borrow, default)]
    bids: Vec<Vec<&'a str>>,
    #[serde(borrow, default)]
    asks: Vec<Vec<&'a str>>,
    #[serde(borrow, default)]
    ts: Option<&'a str>,
}

/// One entry of a `books` message: a snapshot, or the levels that changed.
/// Levels are `[price, size, liquidated_orders, order_count]`.
#[derive(Deserialize)]
struct BooksData<'a> {
    #[serde(borrow, default)]
    bids: Vec<Vec<&'a str>>,
    #[serde(borrow, default)]
    asks: Vec<Vec<&'a str>>,
    #[serde(borrow, default)]
    ts: Option<&'a str>,
    /// Zero on the public channel since OKX stopped computing it.
    #[serde(default)]
    checksum: i64,
    #[serde(rename = "seqId")]
    seq_id: i64,
    #[serde(rename = "prevSeqId")]
    prev_seq_id: i64,
}

#[derive(Deserialize)]
struct Trade<'a> {
    #[serde(rename = "instId", borrow)]
    inst_id: &'a str,
    #[serde(borrow)]
    px: &'a str,
    #[serde(borrow, default)]
    ts: Option<&'a str>,
}

#[derive(Deserialize)]
struct MarkPrice<'a> {
    #[serde(rename = "instId", borrow)]
    inst_id: &'a str,
    #[serde(rename = "markPx", borrow)]
    mark_px: &'a str,
    #[serde(borrow, default)]
    ts: Option<&'a str>,
}

/// Times are milliseconds as strings, and an absent value is an empty string.
#[derive(Deserialize)]
struct FundingRate<'a> {
    #[serde(rename = "instId", borrow)]
    inst_id: &'a str,
    #[serde(rename = "fundingRate", borrow)]
    funding_rate: &'a str,
    /// When the current rate is paid: the next settlement.
    #[serde(rename = "fundingTime", borrow, default)]
    funding_time: Option<&'a str>,
    /// The settlement after it. The two give the interval.
    #[serde(rename = "nextFundingTime", borrow, default)]
    next_funding_time: Option<&'a str>,
    #[serde(rename = "nextFundingRate", borrow, default)]
    next_funding_rate: Option<&'a str>,
    /// The rate settled at `prevFundingTime`, final once `settState` is `settled`.
    #[serde(rename = "settFundingRate", borrow, default)]
    settled_rate: Option<&'a str>,
    #[serde(rename = "settState", borrow, default)]
    settled_state: Option<&'a str>,
    #[serde(rename = "prevFundingTime", borrow, default)]
    previous_funding_time: Option<&'a str>,
    #[serde(rename = "ts", borrow, default)]
    ts: Option<&'a str>,
}

/// One `open-interest` entry. `oiCcy` is the open interest in the base
/// currency; `oi` is in contracts.
#[derive(Deserialize)]
struct OpenInterest<'a> {
    #[serde(rename = "instId", borrow)]
    inst_id: &'a str,
    #[serde(rename = "oiCcy", borrow)]
    oi_ccy: &'a str,
    #[serde(borrow, default)]
    ts: Option<&'a str>,
}

/// The funding fields of one `funding-rate` entry.
fn funding_info(funding: &FundingRate<'_>) -> Result<FundingInfo, DecodeError> {
    fn present(value: Option<&str>) -> Option<&str> {
        value.filter(|text| !text.is_empty())
    }
    let millis = |field, value: Option<&str>| {
        present(value)
            .map(|ms| integer(field, ms))
            .transpose()
            .map(|ms| ms.filter(|ms| *ms > 0).map(millis_to_nanos))
    };
    let next = millis("fundingTime", funding.funding_time)?;
    let after = millis("nextFundingTime", funding.next_funding_time)?;
    let settled_time = millis("prevFundingTime", funding.previous_funding_time)?;
    let settled = match (
        funding.settled_state,
        present(funding.settled_rate),
        settled_time,
    ) {
        (Some("settled"), Some(rate), Some(time)) => {
            Some((decimal("settFundingRate", rate)?, time))
        }
        _ => None,
    };
    Ok(FundingInfo {
        predicted: present(funding.next_funding_rate)
            .map(|rate| decimal("nextFundingRate", rate))
            .transpose()?,
        interval_ns: next
            .zip(after)
            .and_then(|(next, after)| after.checked_sub(next))
            .filter(|interval| *interval > 0),
        next_funding_time_ns: next,
        settled,
        ..FundingInfo::new(FundingBasis::Interval)
    })
}

/// OKX sends timestamps as millisecond counts inside strings.
fn stamp(ts: Option<&str>) -> Option<u64> {
    ts?.parse::<u64>().ok().map(millis_to_nanos)
}

fn lookup<'m>(map: &'m InstrumentMap, inst_id: &str) -> Result<&'m InstrumentEntry, DecodeError> {
    map.lookup(inst_id)
        .ok_or_else(|| DecodeError::UnknownInstrument(inst_id.to_owned()))
}

/// Decodes one OKX payload. `books` keeps the funding fields too, because the
/// rate and the open interest come on two channels.
///
/// # Errors
///
/// Returns [`DecodeError`]; subscription events and pongs are benign. A book
/// update that does not follow the last one, or a failed checksum, is [`DecodeError::Resync`].
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    // The keepalive reply is the bare word `pong`, not JSON.
    if payload == b"pong" {
        return Err(DecodeError::Control);
    }
    let envelope: Envelope<'_> = serde_json::from_slice(payload)?;
    let (Some(arg), Some(data)) = (envelope.arg, envelope.data) else {
        // `{"event":"subscribe","arg":{...}}` carries no data.
        return Err(DecodeError::Control);
    };
    let inst_id = || arg.inst_id.ok_or(DecodeError::MissingField("instId"));
    match arg.channel {
        DEPTH_CHANNEL => {
            let entry = lookup(map, inst_id()?)?;
            let snapshot = envelope.action == Some("snapshot");
            match parse::<Vec<BooksData<'_>>>(data) {
                Err(error) => books
                    .keeper
                    .apply(BOOK_RULE, entry, Err(error), local_recv_ns, out),
                Ok(entries) => {
                    let mut halts = Halts::default();
                    for data in &entries {
                        let parsed = book_message(data, snapshot, entry);
                        let applied =
                            books
                                .keeper
                                .apply(BOOK_RULE, entry, parsed, local_recv_ns, out);
                        halts.absorb(&entry.instrument, applied)?;
                    }
                    halts.finish(Ok(()))
                }
            }
        }
        "bbo-tbt" => decode_bbo(data, lookup(map, inst_id()?)?, local_recv_ns, out),
        "trades" => decode_trades(data, map, local_recv_ns, out),
        "mark-price" => decode_mark_price(data, map, local_recv_ns, out),
        "funding-rate" => decode_funding(data, map, books, local_recv_ns, out),
        "open-interest" => decode_open_interest(data, map, books, local_recv_ns, out),
        other => Err(DecodeError::UnhandledStream(other.to_owned())),
    }
}

/// One `books` entry as a book message. A swap's sizes are in contracts.
fn book_message<'a>(
    data: &BooksData<'a>,
    snapshot: bool,
    entry: &InstrumentEntry,
) -> Result<BookMsg<'a>, DecodeError> {
    let change = |level: &Vec<&'a str>| {
        let (Some(price), Some(size)) = (level.first().copied(), level.get(1).copied()) else {
            return Err(DecodeError::MissingField("book level"));
        };
        let parsed = crate::depth::level(price, size)?;
        Ok(Change {
            qty: base_units(parsed.qty, entry.contract_size),
            text: Some((price, size)),
            ..Change::from(parsed)
        })
    };
    let checksum = match data.checksum {
        0 => None,
        sent => Some(signed_crc(i32::try_from(sent).map_err(|_| {
            DecodeError::Malformed(format!("checksum {sent} is not 32 bits"))
        })?)),
    };
    Ok(BookMsg {
        snapshot,
        prev_id: u64::try_from(data.prev_seq_id).ok(),
        next_id: u64::try_from(data.seq_id).ok(),
        checksum,
        time: stamp(data.ts),
        ..BookMsg::changes(&data.bids, &data.asks, change)?
    })
}

/// A CRC32 that the venue sends as a signed number.
const fn signed_crc(sent: i32) -> u32 {
    u32::from_ne_bytes(sent.to_ne_bytes())
}

/// OKX's CRC32 over the top 25 levels interleaved bid then ask, each as
/// `price:size` exactly as sent.
fn checksum(book: &LocalBook) -> Option<u32> {
    let bids = book.top_text(Side::Bid, CHECKSUM_LEVELS)?;
    let asks = book.top_text(Side::Ask, CHECKSUM_LEVELS)?;
    let mut parts = Vec::with_capacity(CHECKSUM_LEVELS * 2);
    for index in 0..bids.len().max(asks.len()) {
        for side in [&bids, &asks] {
            if let Some((price, size)) = side.get(index) {
                parts.push(format!("{price}:{size}"));
            }
        }
    }
    Some(crc32fast::hash(parts.join(":").as_bytes()))
}

fn decode_bbo(
    data: &RawValue,
    entry: &InstrumentEntry,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let entries: Vec<Bbo<'_>> = parse(data).map_err(|e| DecodeError::lost(&entry.instrument, e))?;
    let level = |level: &[&str], side: &'static str| match level {
        [price, size, ..] => Ok((
            decimal(side, price)?,
            base_units(decimal(side, size)?, entry.contract_size),
        )),
        _ => Err(DecodeError::MissingField(side)),
    };
    let mut halts = Halts::default();
    for bbo in &entries {
        let top = || {
            let (Some(bid), Some(ask)) = (bbo.bids.first(), bbo.asks.first()) else {
                return Ok(None);
            };
            let ((bid, bid_qty), (ask, ask_qty)) = (level(bid, "bids")?, level(ask, "asks")?);
            Ok(Some(((bid, ask), (bid_qty, ask_qty))))
        };
        let quote = book_top(entry, top, stamp(bbo.ts), local_recv_ns).map(|top| out.push(top));
        halts.absorb(&entry.instrument, quote)?;
    }
    let empty = if entries.is_empty() {
        Err(DecodeError::Control)
    } else {
        Ok(())
    };
    halts.finish(empty)
}

fn decode_trades(
    data: &RawValue,
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let trades: Vec<Trade<'_>> = parse(data)?;
    let mut emitted = false;
    for trade in trades {
        let Some(entry) = map.lookup(trade.inst_id) else {
            continue;
        };
        out.push(Observation {
            exchange_time_ns: stamp(trade.ts),
            ..observation(
                entry,
                ObsKind::Trade,
                decimal("px", trade.px)?,
                local_recv_ns,
            )
        });
        emitted = true;
    }
    if emitted {
        Ok(())
    } else {
        Err(DecodeError::Control)
    }
}

fn decode_mark_price(
    data: &RawValue,
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let entries: Vec<MarkPrice<'_>> = parse(data)?;
    let mut emitted = false;
    for mark in entries {
        let Some(entry) = map.lookup(mark.inst_id) else {
            continue;
        };
        out.push(Observation {
            exchange_time_ns: stamp(mark.ts),
            ..observation(
                entry,
                ObsKind::MarkPrice,
                decimal("markPx", mark.mark_px)?,
                local_recv_ns,
            )
        });
        emitted = true;
    }
    if emitted {
        Ok(())
    } else {
        Err(DecodeError::Control)
    }
}

fn decode_funding(
    data: &RawValue,
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let entries: Vec<FundingRate<'_>> = parse(data)?;
    let mut emitted = false;
    for funding in entries {
        let Some(entry) = map.lookup(funding.inst_id) else {
            continue;
        };
        let mut info = funding_info(&funding)?;
        let rate = decimal("fundingRate", funding.funding_rate)?;
        let last = books.funding(&entry.instrument);
        last.rate = Some(rate);
        last.interval_ns = info.interval_ns;
        last.next_funding_time_ns = info.next_funding_time_ns;
        last.predicted = info.predicted;
        last.settled = info.settled;
        info.open_interest = last.open_interest.map(|oi| (oi, OpenInterestUnit::Base));
        out.push(funding_observation(
            entry,
            rate,
            info,
            stamp(funding.ts),
            local_recv_ns,
        ));
        emitted = true;
    }
    if emitted {
        Ok(())
    } else {
        Err(DecodeError::Control)
    }
}

/// A new open interest repeats the last funding update with it. Before the
/// first rate there is nothing to repeat, so the value only waits.
fn decode_open_interest(
    data: &RawValue,
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let entries: Vec<OpenInterest<'_>> = parse(data)?;
    let mut emitted = false;
    for interest in entries {
        let Some(entry) = map.lookup(interest.inst_id) else {
            continue;
        };
        let open_interest = decimal("oiCcy", interest.oi_ccy)?;
        let last = books.funding(&entry.instrument);
        last.open_interest = Some(open_interest);
        let Some(rate) = last.rate else {
            continue;
        };
        let info = FundingInfo {
            predicted: last.predicted,
            interval_ns: last.interval_ns,
            next_funding_time_ns: last.next_funding_time_ns,
            settled: last.settled,
            open_interest: Some((open_interest, OpenInterestUnit::Base)),
            ..FundingInfo::new(FundingBasis::Interval)
        };
        out.push(funding_observation(
            entry,
            rate,
            info,
            stamp(interest.ts),
            local_recv_ns,
        ));
        emitted = true;
    }
    if emitted {
        Ok(())
    } else {
        Err(DecodeError::Control)
    }
}

fn funding_observation(
    entry: &InstrumentEntry,
    rate: oracle_types::Fixed,
    info: FundingInfo,
    exchange_time_ns: Option<u64>,
    local_recv_ns: u64,
) -> Observation {
    Observation {
        exchange_time_ns,
        funding: Some(Arc::new(info)),
        ..observation(entry, ObsKind::Funding, rate, local_recv_ns)
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixed payloads; an out-of-range index is a failing test"
)]
mod tests {
    use super::*;
    use crate::testing::{Feed, fixed, instrument, kinds};
    use oracle_types::{MarketKind, Venue};

    fn okx(market: MarketKind, inst_id: &str) -> Feed {
        Feed::venue(decode, Venue::Okx, market, &[instrument(inst_id, market)])
    }

    fn spot() -> Feed {
        okx(MarketKind::Spot, "BTC-USDT")
    }

    fn swap() -> Feed {
        okx(MarketKind::LinearPerp, "BTC-USDT-SWAP")
    }

    const BBO: &str = r#"{"arg":{"channel":"bbo-tbt","instId":"BTC-USDT"},
        "data":[{"asks":[["64313.0","0.25","0","3"]],"bids":[["64312.0","0.50","0","5"]],
        "ts":"1754582400123"}]}"#;

    const TRADES: &str = r#"{"arg":{"channel":"trades","instId":"BTC-USDT"},
        "data":[{"instId":"BTC-USDT","tradeId":"130639474","px":"64312.1","sz":"0.12",
        "side":"buy","ts":"1754582400100"}]}"#;

    const MARK: &str = r#"{"arg":{"channel":"mark-price","instId":"BTC-USDT-SWAP"},
        "data":[{"instType":"SWAP","instId":"BTC-USDT-SWAP","markPx":"64315.0",
        "ts":"1754582400123"}]}"#;

    const FUNDING: &str = r#"{"arg":{"channel":"funding-rate","instId":"BTC-USDT-SWAP"},
        "data":[{"instId":"BTC-USDT-SWAP","fundingRate":"-0.000125",
        "nextFundingRate":"0.0001","ts":"1754582400123"}]}"#;

    const OPEN_INTEREST: &str = r#"{"arg":{"channel":"open-interest","instId":"BTC-USDT-SWAP"},
        "data":[{"instId":"BTC-USDT-SWAP","instType":"SWAP","oi":"3048419.34","oiCcy":"30484.1934",
        "oiUsd":"2455651150.9","ts":"1754582400456"}]}"#;

    #[test]
    fn a_bbo_yields_a_two_sided_quote() {
        let quote = &spot().decoded(BBO)[0];
        assert_eq!(quote.kind, ObsKind::BookTop);
        assert_eq!(quote.bid, Some(fixed("64312")));
        assert_eq!(quote.ask, Some(fixed("64313")));
        assert_eq!(quote.bid_qty, Some(fixed("0.5")));
        assert_eq!(quote.price, fixed("64312.5"));
        assert_eq!(
            quote.exchange_time_ns,
            Some(millis_to_nanos(1_754_582_400_123))
        );
    }

    #[test]
    fn a_trade_decodes() {
        let trade = &spot().decoded(TRADES)[0];
        assert_eq!(trade.kind, ObsKind::Trade);
        assert_eq!(trade.price, fixed("64312.1"));
    }

    #[test]
    fn mark_price_and_funding_decode() {
        let mark = &swap().decoded(MARK)[0];
        assert_eq!(
            (mark.kind, mark.price),
            (ObsKind::MarkPrice, fixed("64315"))
        );
        let funding = &swap().decoded(FUNDING)[0];
        assert_eq!(
            (funding.kind, funding.price),
            (ObsKind::Funding, fixed("-0.000125"))
        );
    }

    #[test]
    fn the_text_pong_is_benign() {
        assert_eq!(spot().refused("pong"), DecodeError::Control);
    }

    #[test]
    fn subscription_events_are_benign() {
        let event = r#"{"event":"subscribe","arg":{"channel":"bbo-tbt","instId":"BTC-USDT"},
            "connId":"abc"}"#;
        assert!(spot().refused(event).is_benign());
    }

    /// The last two-sided quote must stop counting.
    #[test]
    fn a_one_sided_top_of_book_halts_the_quote() {
        let one_sided = r#"{"arg":{"channel":"bbo-tbt","instId":"BTC-USDT"},
            "data":[{"asks":[["64313.0","0.25","0","3"]],"bids":[],"ts":"1"}]}"#;
        assert!(matches!(spot().refused(one_sided), DecodeError::Halted(_)));
    }

    #[test]
    fn swaps_are_distinguished_by_their_instrument_id() {
        assert!(is_swap("BTC-USDT-SWAP"));
        assert!(!is_swap("BTC-USDT"));
    }

    #[test]
    fn swaps_subscribe_to_more_channels_than_spot() {
        let spot = subscribe_frames([("BTC-USDT", false)].into_iter(), 100);
        assert!(!spot[0].contains("mark-price"));
        let swap = subscribe_frames([("BTC-USDT-SWAP", false)].into_iter(), 100);
        assert!(swap[0].contains("mark-price"));
        assert!(swap[0].contains("funding-rate"));
        assert!(swap[0].contains("open-interest"));
    }

    /// The rate and the open interest come on two channels; each funding
    /// update carries the last of both.
    #[test]
    fn the_open_interest_joins_the_funding_update() {
        let mut swap = swap();
        let base = |coins| Some((fixed(coins), OpenInterestUnit::Base));
        assert!(
            swap.refused(OPEN_INTEREST).is_benign(),
            "before the first rate, the open interest only waits"
        );

        let funding = swap.decoded(FUNDING);
        let info = funding[0].funding.as_deref().expect("funding info");
        assert_eq!(info.open_interest, base("30484.1934"));
        assert_eq!(info.predicted, Some(fixed("0.0001")));

        let later = swap.decoded(OPEN_INTEREST.replace("30484.1934", "30500"));
        assert_eq!(kinds(&later), [ObsKind::Funding]);
        assert_eq!(later[0].price, fixed("-0.000125"));
        let info = later[0].funding.as_deref().expect("funding info");
        assert_eq!(info.open_interest, base("30500"));
        assert_eq!(
            info.predicted,
            Some(fixed("0.0001")),
            "the rate's fields stay"
        );
    }

    #[test]
    fn subscribe_frames_are_chunked() {
        let frames = subscribe_frames([("BTC-USDT", false), ("ETH-USDT", false)].into_iter(), 2);
        assert_eq!(frames.len(), 2, "four args at two per frame");
    }

    #[test]
    fn depth_subscribes_the_book_channel() {
        let spot = subscribe_frames([("BTC-USDT", true)].into_iter(), 100);
        assert!(spot[0].contains(r#""channel":"books""#));
        let swap = subscribe_frames([("BTC-USDT-SWAP", false)].into_iter(), 100);
        assert!(!swap[0].contains(r#""channel":"books""#));
    }

    /// A snapshot of a small book with `checksum`.
    fn checked_snapshot(checksum: i64) -> String {
        format!(
            r#"{{"arg":{{"channel":"books","instId":"BTC-USDT"}},"action":"snapshot","data":[{{
            "asks":[["101","3","0","1"]],"bids":[["100.5","1","0","1"],["100","2","0","1"]],
            "ts":"1","checksum":{checksum},"seqId":10,"prevSeqId":-1}}]}}"#
        )
    }

    /// The text is `100.5:1:101:3:100:2`, bid then ask by level. Python's
    /// `zlib.crc32` of it is 3539187920, which is -755779376 as a signed number.
    #[test]
    fn a_non_zero_checksum_is_checked_against_the_book() {
        const CHECKSUM: i64 = -755_779_376;
        let book = instrument("BTC-USDT", MarketKind::Spot).with_depth();
        let mut feed = Feed::venue(decode, Venue::Okx, MarketKind::Spot, &[book]);
        assert_eq!(feed.decoded(checked_snapshot(CHECKSUM)).len(), 1);
        let error = feed.refused(checked_snapshot(CHECKSUM + 1));
        assert!(matches!(error, DecodeError::Resync(_)), "{error:?}");
    }

    /// 50 contracts of 0.01 BTC are half a bitcoin.
    #[test]
    fn swap_sizes_become_base_units() {
        assert_eq!(base_units(fixed("50"), Some(fixed("0.01"))), fixed("0.5"));
        assert_eq!(base_units(fixed("50"), None), fixed("50"));
    }
}
