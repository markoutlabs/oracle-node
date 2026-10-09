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

use oracle_types::{Fixed, FundingBasis, FundingInfo, ObsKind, Observation};
use serde::Deserialize;

use crate::book::{Books, LocalBook, Side};
use crate::clock::millis_to_nanos;
use crate::{DecodeError, InstrumentMap};

use super::{decimal, integer};

/// The public endpoint.
pub const URL: &str = "wss://ws.okx.com:8443/ws/v5/public";

/// Keepalive period, comfortably inside the 30s idle limit.
pub const KEEPALIVE: Duration = Duration::from_secs(25);

/// The keepalive payload: plain text, not JSON.
pub const KEEPALIVE_PAYLOAD: &str = "ping";

/// Channels subscribed per instrument.
const SPOT_CHANNELS: [&str; 2] = ["bbo-tbt", "trades"];
const SWAP_CHANNELS: [&str; 4] = ["bbo-tbt", "trades", "mark-price", "funding-rate"];
/// The book: a 400-level snapshot, then the changes every 100ms.
const DEPTH_CHANNEL: &str = "books";

/// Levels kept per side, the depth OKX publishes.
pub const BOOK_DEPTH: usize = 400;

/// Levels per side a non-zero checksum covers.
const CHECKSUM_LEVELS: usize = 25;

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
    #[serde(borrow, default)]
    data: Option<&'a serde_json::value::RawValue>,
}

#[derive(Deserialize)]
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

/// A `books` message: a snapshot, or the levels that changed.
#[derive(Deserialize)]
struct BooksMessage<'a> {
    #[serde(borrow)]
    arg: Arg<'a>,
    #[serde(borrow)]
    action: &'a str,
    #[serde(borrow)]
    data: Vec<BooksData<'a>>,
}

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

/// A size in base units: contracts times the contract size on a swap, as sent
/// on spot.
fn base_units(size: Fixed, contract_size: Option<Fixed>) -> Fixed {
    contract_size
        .and_then(|contract| size.checked_mul(contract))
        .unwrap_or(size)
}

/// OKX sends timestamps as millisecond counts inside strings.
fn stamp(ts: Option<&str>) -> Option<u64> {
    ts?.parse::<u64>().ok().map(millis_to_nanos)
}

/// The session's entry point: the `books` channel is kept in `books`; every
/// other channel goes to [`decode_payload`].
///
/// # Errors
///
/// As [`decode_payload`], and [`DecodeError::Resync`] when an update does not
/// follow the last one, or a non-zero checksum fails.
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
    let envelope: Envelope<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let is_books = envelope.arg.is_some_and(|arg| arg.channel == DEPTH_CHANNEL);
    if !is_books || envelope.data.is_none() {
        return decode_payload(payload, map, local_recv_ns, out);
    }
    let message: BooksMessage<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let inst_id = message
        .arg
        .inst_id
        .ok_or(DecodeError::MissingField("instId"))?;
    let entry = map
        .lookup(inst_id)
        .ok_or_else(|| DecodeError::UnknownInstrument(inst_id.to_owned()))?;
    for data in message.data {
        let book = books.book(inst_id);
        if message.action == "snapshot" {
            book.clear();
        } else if u64::try_from(data.prev_seq_id).ok() != book.last_id {
            return Err(DecodeError::Resync(format!(
                "{inst_id}: update follows {} but the book is at {:?}",
                data.prev_seq_id, book.last_id
            )));
        }
        book.last_id = u64::try_from(data.seq_id).ok();
        for (side, levels) in [(Side::Bid, &data.bids), (Side::Ask, &data.asks)] {
            for level in levels {
                let (Some(price), Some(size)) = (level.first(), level.get(1)) else {
                    continue;
                };
                let parsed = crate::depth::level(price, size)?;
                let qty = base_units(parsed.qty, entry.contract_size);
                book.set_with_text(side, parsed.price, qty, Some((price, size)));
            }
        }
        book.truncate(BOOK_DEPTH);
        if data.checksum != 0 && checksum(book) != Some(data.checksum) {
            return Err(DecodeError::Resync(format!("{inst_id}: checksum mismatch")));
        }
        books.emit(
            inst_id,
            entry.instrument.clone(),
            stamp(data.ts),
            local_recv_ns,
            out,
        )?;
    }
    Ok(())
}

/// OKX's CRC32, as a signed 32-bit number, over the top 25 levels interleaved
/// bid then ask, each as `price:size` exactly as sent.
fn checksum(book: &LocalBook) -> Option<i64> {
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
    let hash = crc32fast::hash(parts.join(":").as_bytes());
    Some(i64::from(i32::from_ne_bytes(hash.to_ne_bytes())))
}

/// Decodes one OKX payload.
///
/// # Errors
///
/// Returns [`DecodeError`]. Subscription events and pongs are benign.
pub fn decode_payload(
    payload: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    // The keepalive reply is the bare word `pong`, not JSON.
    if payload == b"pong" {
        return Err(DecodeError::Control);
    }
    let envelope: Envelope<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let (Some(arg), Some(data)) = (envelope.arg, envelope.data) else {
        // `{"event":"subscribe","arg":{...}}` carries no data.
        return Err(DecodeError::Control);
    };
    let data = data.get().as_bytes();

    match arg.channel {
        "bbo-tbt" => {
            let inst_id = arg.inst_id.ok_or(DecodeError::MissingField("instId"))?;
            decode_bbo(data, inst_id, map, local_recv_ns, out)
        }
        "trades" => decode_trades(data, map, local_recv_ns, out),
        "mark-price" => decode_mark_price(data, map, local_recv_ns, out),
        "funding-rate" => decode_funding(data, map, local_recv_ns, out),
        other => Err(DecodeError::UnhandledStream(other.to_owned())),
    }
}

fn decode_bbo(
    data: &[u8],
    inst_id: &str,
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let entries: Vec<Bbo<'_>> =
        serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let entry = map
        .lookup(inst_id)
        .ok_or_else(|| DecodeError::UnknownInstrument(inst_id.to_owned()))?;

    let mut emitted = false;
    for bbo in entries {
        // A one-sided top of book is not a quote.
        let (Some(bid_level), Some(ask_level)) = (bbo.bids.first(), bbo.asks.first()) else {
            continue;
        };
        let (Some(bid), Some(bid_qty)) = (bid_level.first(), bid_level.get(1)) else {
            continue;
        };
        let (Some(ask), Some(ask_qty)) = (ask_level.first(), ask_level.get(1)) else {
            continue;
        };
        let bid = decimal("bids", bid)?;
        let ask = decimal("asks", ask)?;
        let mid = bid
            .checked_add(ask)
            .and_then(|sum| sum.checked_div(Fixed::from_int(2).ok()?))
            .unwrap_or(bid);

        out.push(Observation {
            instrument: entry.instrument.clone(),
            kind: ObsKind::BookTop,
            price: mid,
            bid: Some(bid),
            ask: Some(ask),
            bid_qty: Some(base_units(
                decimal("bid_qty", bid_qty)?,
                entry.contract_size,
            )),
            ask_qty: Some(base_units(
                decimal("ask_qty", ask_qty)?,
                entry.contract_size,
            )),
            depth_notional_1bp: None,
            exchange_time_ns: stamp(bbo.ts),
            local_recv_ns,
            seq: None,
            book: None,
            funding: None,
        });
        emitted = true;
    }
    if emitted {
        Ok(())
    } else {
        Err(DecodeError::Control)
    }
}

fn decode_trades(
    data: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let trades: Vec<Trade<'_>> =
        serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let mut emitted = false;
    for trade in trades {
        let Some(entry) = map.lookup(trade.inst_id) else {
            continue;
        };
        out.push(Observation {
            instrument: entry.instrument.clone(),
            kind: ObsKind::Trade,
            price: decimal("px", trade.px)?,
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            depth_notional_1bp: None,
            exchange_time_ns: stamp(trade.ts),
            local_recv_ns,
            seq: None,
            book: None,
            funding: None,
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
    data: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let entries: Vec<MarkPrice<'_>> =
        serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let mut emitted = false;
    for mark in entries {
        let Some(entry) = map.lookup(mark.inst_id) else {
            continue;
        };
        out.push(Observation {
            instrument: entry.instrument.clone(),
            kind: ObsKind::MarkPrice,
            price: decimal("markPx", mark.mark_px)?,
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            depth_notional_1bp: None,
            exchange_time_ns: stamp(mark.ts),
            local_recv_ns,
            seq: None,
            book: None,
            funding: None,
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
    data: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let entries: Vec<FundingRate<'_>> =
        serde_json::from_slice(data).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let mut emitted = false;
    for funding in entries {
        let Some(entry) = map.lookup(funding.inst_id) else {
            continue;
        };
        let info = funding_info(&funding)?;
        out.push(Observation {
            instrument: entry.instrument.clone(),
            kind: ObsKind::Funding,
            price: decimal("fundingRate", funding.funding_rate)?,
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            depth_notional_1bp: None,
            exchange_time_ns: stamp(funding.ts),
            local_recv_ns,
            seq: None,
            book: None,
            funding: Some(Arc::new(info)),
        });
        emitted = true;
    }
    if emitted {
        Ok(())
    } else {
        Err(DecodeError::Control)
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixtures are fixed-shape; an out-of-range index is a failing test, \
              which is exactly what should happen if decoding changed"
)]
mod tests {
    use super::*;
    use crate::InstrumentSpec;
    use oracle_types::{MarketKind, Venue};

    const RECV: u64 = 1_754_582_400_500_000_000;

    fn map(market: MarketKind, inst_id: &str) -> InstrumentMap {
        let specs = vec![InstrumentSpec::new(inst_id, market, "CRYPTO.BTC/USDT").expect("valid")];
        InstrumentMap::new(Venue::Okx, market, &specs).expect("valid")
    }

    fn decode(payload: &str, market: MarketKind, inst_id: &str) -> Vec<Observation> {
        let mut out = Vec::new();
        decode_payload(payload.as_bytes(), &map(market, inst_id), RECV, &mut out).expect("decodes");
        out
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

    #[test]
    fn a_bbo_yields_a_two_sided_quote() {
        let observations = decode(BBO, MarketKind::Spot, "BTC-USDT");
        let obs = observations.first().expect("one observation");
        assert_eq!(obs.kind, ObsKind::BookTop);
        assert_eq!(obs.bid, Some("64312".parse().expect("valid")));
        assert_eq!(obs.ask, Some("64313".parse().expect("valid")));
        assert_eq!(obs.bid_qty, Some("0.5".parse().expect("valid")));
        assert_eq!(obs.price, "64312.5".parse().expect("valid"));
        assert_eq!(obs.exchange_time_ns, Some(1_754_582_400_123_000_000));
    }

    #[test]
    fn a_trade_decodes() {
        let observations = decode(TRADES, MarketKind::Spot, "BTC-USDT");
        let obs = observations.first().expect("one observation");
        assert_eq!(obs.kind, ObsKind::Trade);
        assert_eq!(obs.price, "64312.1".parse().expect("valid"));
    }

    #[test]
    fn mark_price_and_funding_decode() {
        let mark = decode(MARK, MarketKind::LinearPerp, "BTC-USDT-SWAP");
        assert_eq!(mark[0].kind, ObsKind::MarkPrice);
        assert_eq!(mark[0].price, "64315".parse().expect("valid"));

        let funding = decode(FUNDING, MarketKind::LinearPerp, "BTC-USDT-SWAP");
        assert_eq!(funding[0].kind, ObsKind::Funding);
        assert_eq!(funding[0].price, "-0.000125".parse().expect("valid"));
    }

    #[test]
    fn the_text_pong_is_benign() {
        let mut out = Vec::new();
        let error = decode_payload(b"pong", &map(MarketKind::Spot, "BTC-USDT"), RECV, &mut out)
            .expect_err("not market data");
        assert_eq!(error, DecodeError::Control);
    }

    #[test]
    fn subscription_events_are_benign() {
        let mut out = Vec::new();
        let event = r#"{"event":"subscribe","arg":{"channel":"bbo-tbt","instId":"BTC-USDT"},
            "connId":"abc"}"#;
        let error = decode_payload(
            event.as_bytes(),
            &map(MarketKind::Spot, "BTC-USDT"),
            RECV,
            &mut out,
        )
        .expect_err("not market data");
        assert!(error.is_benign());
    }

    #[test]
    fn a_one_sided_book_is_benign_not_a_quote() {
        let one_sided = r#"{"arg":{"channel":"bbo-tbt","instId":"BTC-USDT"},
            "data":[{"asks":[["64313.0","0.25","0","3"]],"bids":[],"ts":"1"}]}"#;
        let mut out = Vec::new();
        let error = decode_payload(
            one_sided.as_bytes(),
            &map(MarketKind::Spot, "BTC-USDT"),
            RECV,
            &mut out,
        )
        .expect_err("not a quote");
        assert!(error.is_benign());
        assert!(out.is_empty());
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

    /// 50 contracts of 0.01 BTC are half a bitcoin.
    #[test]
    fn swap_sizes_become_base_units() {
        let half: Fixed = "0.5".parse().expect("valid");
        let contracts: Fixed = "50".parse().expect("valid");
        let contract: Fixed = "0.01".parse().expect("valid");
        assert_eq!(base_units(contracts, Some(contract)), half);
        assert_eq!(base_units(contracts, None), contracts);
    }

    /// Recorded from OKX on 2026-10-06: the subscribe reply, a 400-level
    /// snapshot, and the updates after it.
    const RECORDED_BOOKS: &str = include_str!("../../tests/fixtures/okx-books.jsonl");

    fn book_map() -> InstrumentMap {
        let specs = vec![
            InstrumentSpec::new("BTC-USDT", MarketKind::Spot, "CRYPTO.BTC/USDT")
                .expect("valid")
                .with_depth(),
        ];
        InstrumentMap::new(Venue::Okx, MarketKind::Spot, &specs).expect("valid")
    }

    #[test]
    fn a_recorded_book_follows_its_sequence() {
        let map = book_map();
        let mut books = Books::default();
        let mut depths = 0;
        for line in RECORDED_BOOKS.lines() {
            let mut out = Vec::new();
            match super::decode(line.as_bytes(), &map, &mut books, RECV, &mut out) {
                Ok(()) => {}
                Err(error) if error.is_benign() => {}
                Err(error) => panic!("{error}: {line}"),
            }
            depths += out.iter().filter(|o| o.kind == ObsKind::Depth).count();
        }
        assert!(depths >= 14, "{depths}");
        let book = books.book("BTC-USDT");
        assert!(book.top(Side::Bid, 1)[0].price < book.top(Side::Ask, 1)[0].price);
        assert_eq!(book.top(Side::Bid, 500).len(), BOOK_DEPTH);
    }

    /// An update that does not follow the last one means a missed message.
    #[test]
    fn a_sequence_gap_asks_for_a_resync() {
        let map = book_map();
        let mut books = Books::default();
        let mut lines = RECORDED_BOOKS
            .lines()
            .filter(|line| line.contains(r#""action":"#));
        let snapshot = lines.next().expect("a snapshot");
        super::decode(snapshot.as_bytes(), &map, &mut books, RECV, &mut Vec::new()).expect("valid");
        let _skipped = lines.next().expect("an update");
        let after = lines.next().expect("a later update");
        assert!(matches!(
            super::decode(after.as_bytes(), &map, &mut books, RECV, &mut Vec::new()),
            Err(DecodeError::Resync(_))
        ));
    }
}
