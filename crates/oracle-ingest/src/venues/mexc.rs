//! MEXC public streams: USDT spot over protobuf, and the USDT-margined
//! perpetuals over JSON.
//!
//! - **Spot** is `wss://wbs-api.mexc.com/ws`, and each push is a protobuf
//!   `PushDataV3ApiWrapper`. The JSON socket refuses every subscription with
//!   "Blocked!". The channels are `spot@public.aggre.bookTicker.v3.api.pb@100ms@BTCUSDT`
//!   for the quote, about 10 a second; `spot@public.aggre.deals.v3.api.pb@100ms@BTCUSDT`
//!   for the trades; and `spot@public.limit.depth.v3.api.pb@BTCUSDT@20` for a whole
//!   20-level book each time. One connection takes at most 30 channels.
//! - **Perpetuals** are `wss://contract.mexc.com/edge`, one subscription per
//!   channel and symbol: `sub.depth.full`, a whole 20-level book each time and the
//!   quote of every market; `sub.deal`; `sub.fair.price`, the mark;
//!   `sub.index.price`; `sub.ticker`, each 3 s, with the funding rate and the open
//!   interest; and `sub.funding.rate`, each minute, with the rate and the next
//!   funding time. Sizes count in contracts of `contractSize` coins, the source's
//!   `contract_size`. Prices are bare JSON numbers.
//! - **Funding.** The interval and the last settled rate come only over REST, in
//!   the frames that [`super::mexc_connect::MexcConnector`] adds.
//!
//! Checked against the live sockets and REST on 2026-10-25.

use std::time::Duration;

use oracle_types::{Fixed, ObsKind, Observation};
use prost::Message as _;
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{Books, Side};
use crate::clock::millis_to_nanos;
use crate::instrument::InstrumentEntry;
use crate::{DecodeError, InstrumentMap};

use super::{base_units, book_top, decimal, decimal_literal, interval_funding, observation, parse};

pub use super::mexc_connect::{FUTURES_URL, futures_url};

/// The spot socket.
pub const SPOT_URL: &str = "wss://wbs-api.mexc.com/ws";

/// The spot keepalive.
pub const SPOT_KEEPALIVE: &str = r#"{"method":"PING"}"#;

/// The futures keepalive.
pub const FUTURES_KEEPALIVE: &str = r#"{"method":"ping"}"#;

/// How often to send a keepalive: both sockets close after a minute without one.
pub const KEEPALIVE_EVERY: Duration = Duration::from_secs(15);

/// Spot markets on one connection: at most three channels each, of 30.
pub const SPOT_MARKETS_PER_CONNECTION: usize = 10;
const _: () = assert!(SPOT_MARKETS_PER_CONNECTION * 3 <= 30);

/// Perpetuals on one connection, six subscriptions each.
pub const FUTURES_MARKETS_PER_CONNECTION: usize = 20;

/// Book levels per side.
const BOOK_LEVELS: u32 = 20;

/// MEXC's spot push messages, from `mexcdevelop/websocket-proto` at commit
/// `0c9c4f3`; only the fields read here.
mod pb {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct PushDataV3ApiWrapper {
        #[prost(string, tag = "1")]
        pub channel: String,
        #[prost(oneof = "Body", tags = "303, 314, 315")]
        pub body: Option<Body>,
        #[prost(string, optional, tag = "3")]
        pub symbol: Option<String>,
        #[prost(int64, optional, tag = "6")]
        pub send_time: Option<i64>,
    }

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "303")]
        LimitDepths(PublicLimitDepthsV3Api),
        #[prost(message, tag = "314")]
        AggreDeals(PublicAggreDealsV3Api),
        #[prost(message, tag = "315")]
        AggreBookTicker(PublicAggreBookTickerV3Api),
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct PublicAggreBookTickerV3Api {
        #[prost(string, tag = "1")]
        pub bid_price: String,
        #[prost(string, tag = "2")]
        pub bid_quantity: String,
        #[prost(string, tag = "3")]
        pub ask_price: String,
        #[prost(string, tag = "4")]
        pub ask_quantity: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct PublicAggreDealsV3Api {
        #[prost(message, repeated, tag = "1")]
        pub deals: Vec<PublicAggreDealsV3ApiItem>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct PublicAggreDealsV3ApiItem {
        #[prost(string, tag = "1")]
        pub price: String,
        #[prost(int64, tag = "4")]
        pub time: i64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct PublicLimitDepthsV3Api {
        #[prost(message, repeated, tag = "1")]
        pub asks: Vec<PublicLimitDepthV3ApiItem>,
        #[prost(message, repeated, tag = "2")]
        pub bids: Vec<PublicLimitDepthV3ApiItem>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct PublicLimitDepthV3ApiItem {
        #[prost(string, tag = "1")]
        pub price: String,
        #[prost(string, tag = "2")]
        pub quantity: String,
    }
}

/// The subscribe frame of a spot connection, each symbol with whether it wants depth.
#[must_use]
pub fn spot_frames<'a>(instruments: impl Iterator<Item = (&'a str, bool)>) -> Vec<String> {
    let mut params = Vec::new();
    for (symbol, depth) in instruments {
        params.push(format!(
            "spot@public.aggre.bookTicker.v3.api.pb@100ms@{symbol}"
        ));
        params.push(format!("spot@public.aggre.deals.v3.api.pb@100ms@{symbol}"));
        if depth {
            params.push(format!(
                "spot@public.limit.depth.v3.api.pb@{symbol}@{BOOK_LEVELS}"
            ));
        }
    }
    vec![serde_json::json!({ "method": "SUBSCRIPTION", "params": params }).to_string()]
}

/// The subscribe frames of a futures connection. Every market takes its book,
/// the source of its quote.
#[must_use]
pub fn futures_frames<'a>(instruments: impl Iterator<Item = (&'a str, bool)>) -> Vec<String> {
    let mut frames = Vec::new();
    for (symbol, _) in instruments {
        frames.push(
            serde_json::json!({
                "method": "sub.depth.full",
                "param": { "symbol": symbol, "limit": BOOK_LEVELS },
            })
            .to_string(),
        );
        for method in [
            "sub.deal",
            "sub.fair.price",
            "sub.index.price",
            "sub.ticker",
            "sub.funding.rate",
        ] {
            frames.push(
                serde_json::json!({ "method": method, "param": { "symbol": symbol } }).to_string(),
            );
        }
    }
    frames
}

fn lookup(map: &InstrumentMap, symbol: &str) -> Result<InstrumentEntry, DecodeError> {
    map.lookup(symbol)
        .cloned()
        .ok_or_else(|| DecodeError::UnknownInstrument(symbol.to_owned()))
}

/// Replaces the book with a whole snapshot, and emits all of it where the
/// market wants depth, or only its top.
fn snapshot<P, Q>(
    levels: [(Side, &[(P, Q)]); 2],
    parse_level: impl Fn(&P, &Q) -> Result<(Fixed, Fixed), DecodeError>,
    symbol: &str,
    entry: &InstrumentEntry,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let book = books.book(symbol);
    book.clear();
    for (side, levels) in levels {
        for (price, size) in levels {
            let (price, size) = parse_level(price, size)?;
            book.set(side, price, base_units(size, entry.contract_size));
        }
    }
    let emit = if entry.depth {
        Books::emit
    } else {
        Books::emit_top
    };
    emit(
        books,
        symbol,
        entry.instrument.clone(),
        None,
        local_recv_ns,
        out,
    )
}

#[derive(Deserialize)]
struct SpotReply<'a> {
    #[serde(default)]
    code: i64,
    #[serde(borrow, default)]
    msg: &'a str,
}

/// Decodes one spot payload: a protobuf push, or a JSON reply.
///
/// # Errors
///
/// Returns [`DecodeError`]. A pong and a subscription reply are benign; a
/// refused subscription is not.
pub fn decode_spot(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    // A push starts with its channel, field 1: byte 0x0a. A reply is JSON.
    if payload.first() == Some(&b'{') {
        let reply: SpotReply<'_> = serde_json::from_slice(payload)?;
        // A refusal can come with code 0: "Not Subscribed successfully! … Blocked!".
        if reply.code != 0 || reply.msg.contains("Not Subscribed") {
            return Err(DecodeError::Malformed(format!(
                "the server refused a request: {}",
                reply.msg
            )));
        }
        return Err(DecodeError::Control);
    }
    let push = pb::PushDataV3ApiWrapper::decode(payload)?;
    let symbol = push
        .symbol
        .as_deref()
        .ok_or(DecodeError::MissingField("symbol"))?;
    let entry = lookup(map, symbol)?;
    let time = push
        .send_time
        .and_then(|ms| u64::try_from(ms).ok())
        .map(millis_to_nanos);
    match push.body {
        Some(pb::Body::AggreBookTicker(ticker)) => {
            let prices = (
                decimal("bidPrice", &ticker.bid_price)?,
                decimal("askPrice", &ticker.ask_price)?,
            );
            let sizes = (
                decimal("bidQuantity", &ticker.bid_quantity)?,
                decimal("askQuantity", &ticker.ask_quantity)?,
            );
            out.push(book_top(&entry, prices, sizes, time, local_recv_ns)?);
            Ok(())
        }
        Some(pb::Body::AggreDeals(deals)) => {
            for deal in deals.deals {
                out.push(Observation {
                    exchange_time_ns: u64::try_from(deal.time).ok().map(millis_to_nanos),
                    ..observation(
                        &entry,
                        ObsKind::Trade,
                        decimal("price", &deal.price)?,
                        local_recv_ns,
                    )
                });
            }
            Ok(())
        }
        Some(pb::Body::LimitDepths(depth)) => {
            let side = |items: &[pb::PublicLimitDepthV3ApiItem]| -> Vec<(String, String)> {
                items
                    .iter()
                    .map(|item| (item.price.clone(), item.quantity.clone()))
                    .collect()
            };
            let (asks, bids) = (side(&depth.asks), side(&depth.bids));
            snapshot(
                [(Side::Ask, &asks), (Side::Bid, &bids)],
                |price, size| Ok((decimal("depth price", price)?, decimal("depth size", size)?)),
                symbol,
                &entry,
                books,
                local_recv_ns,
                out,
            )
        }
        None => Err(DecodeError::UnhandledStream(push.channel)),
    }
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow, default)]
    channel: Option<&'a str>,
    #[serde(borrow, default)]
    symbol: Option<&'a str>,
    #[serde(borrow, default)]
    data: Option<&'a RawValue>,
    /// The connector's REST frames.
    #[serde(rename = "type", borrow, default)]
    kind: Option<&'a str>,
    #[serde(borrow, default)]
    subject: Option<&'a str>,
    #[serde(borrow, default)]
    topic: Option<&'a str>,
    #[serde(borrow, default)]
    error: Option<&'a RawValue>,
}

/// Levels of `[price, contracts, orders]`.
#[derive(Deserialize)]
struct FuturesDepth<'a> {
    #[serde(borrow)]
    asks: Vec<Vec<&'a RawValue>>,
    #[serde(borrow)]
    bids: Vec<Vec<&'a RawValue>>,
}

/// The price and the contracts of each level.
fn pairs<'a>(
    levels: &[Vec<&'a RawValue>],
) -> Result<Vec<(&'a RawValue, &'a RawValue)>, DecodeError> {
    levels
        .iter()
        .map(|level| match level.as_slice() {
            [price, size, ..] => Ok((*price, *size)),
            _ => Err(DecodeError::MissingField("depth level")),
        })
        .collect()
}

/// One trade of `push.deal`: price, volume, side, time.
#[derive(Deserialize)]
struct Deal<'a> {
    #[serde(borrow)]
    p: &'a RawValue,
    t: Option<u64>,
}

#[derive(Deserialize)]
struct Price<'a> {
    #[serde(borrow)]
    price: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ticker<'a> {
    #[serde(borrow)]
    funding_rate: Option<&'a RawValue>,
    /// The open interest, in contracts.
    #[serde(borrow)]
    hold_vol: Option<&'a RawValue>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FundingPush<'a> {
    #[serde(borrow)]
    rate: &'a RawValue,
    next_settle_time: Option<u64>,
}

/// `funding_rate/{symbol}`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FundingCurrent<'a> {
    #[serde(borrow)]
    funding_rate: &'a RawValue,
    /// The interval, in hours.
    collect_cycle: u64,
    next_settle_time: Option<u64>,
}

/// `funding_rate/history`, newest first.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FundingHistory<'a> {
    #[serde(borrow)]
    result_list: Vec<Settled<'a>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settled<'a> {
    #[serde(borrow)]
    funding_rate: &'a RawValue,
    settle_time: u64,
}

const HOUR_NS: u64 = 3_600_000_000_000;

/// Decodes one futures payload, or one of the REST frames that the connector adds.
///
/// # Errors
///
/// Returns [`DecodeError`]. A pong and a subscription reply are benign; a
/// refused subscription and a REST read that failed are not.
pub fn decode_futures(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> = serde_json::from_slice(payload)?;
    if envelope.kind == Some("rest") {
        return rest(&envelope, map, books, local_recv_ns, out);
    }
    let channel = envelope
        .channel
        .ok_or(DecodeError::MissingField("channel"))?;
    if channel == "pong" {
        return Err(DecodeError::Control);
    }
    if channel.starts_with("rs.") {
        let accepted = envelope
            .data
            .is_some_and(|data| data.get() == r#""success""#);
        return Err(if accepted {
            DecodeError::Control
        } else {
            DecodeError::Malformed(format!(
                "the server refused a request: {channel} {}",
                envelope.data.map_or("", RawValue::get)
            ))
        });
    }
    let symbol = envelope.symbol.ok_or(DecodeError::MissingField("symbol"))?;
    let entry = lookup(map, symbol)?;
    let data = envelope.data.ok_or(DecodeError::MissingField("data"))?;
    match channel {
        "push.depth.full" => {
            let depth: FuturesDepth<'_> = parse(data)?;
            let (asks, bids) = (pairs(&depth.asks)?, pairs(&depth.bids)?);
            snapshot(
                [(Side::Ask, &asks), (Side::Bid, &bids)],
                |price, size| {
                    Ok((
                        decimal_literal("depth price", price)?,
                        decimal_literal("depth size", size)?,
                    ))
                },
                symbol,
                &entry,
                books,
                local_recv_ns,
                out,
            )
        }
        "push.deal" => {
            let deals: Vec<Deal<'_>> = parse(data)?;
            for deal in deals {
                out.push(Observation {
                    exchange_time_ns: deal.t.map(millis_to_nanos),
                    ..observation(
                        &entry,
                        ObsKind::Trade,
                        decimal_literal("p", deal.p)?,
                        local_recv_ns,
                    )
                });
            }
            Ok(())
        }
        "push.fair.price" | "push.index.price" => {
            let kind = if channel == "push.fair.price" {
                ObsKind::MarkPrice
            } else {
                ObsKind::IndexPrice
            };
            let price: Price<'_> = parse(data)?;
            out.push(observation(
                &entry,
                kind,
                decimal_literal("price", price.price)?,
                local_recv_ns,
            ));
            Ok(())
        }
        "push.ticker" => {
            let ticker: Ticker<'_> = parse(data)?;
            let state = books.funding(symbol);
            if let Some(rate) = ticker.funding_rate {
                state.rate = Some(decimal_literal("fundingRate", rate)?);
            }
            if let Some(contracts) = ticker.hold_vol {
                let contracts = decimal_literal("holdVol", contracts)?;
                state.open_interest = Some(base_units(contracts, entry.contract_size));
            }
            out.extend(interval_funding(&entry, state, local_recv_ns));
            Ok(())
        }
        "push.funding.rate" => {
            let funding: FundingPush<'_> = parse(data)?;
            let state = books.funding(symbol);
            state.rate = Some(decimal_literal("rate", funding.rate)?);
            if let Some(next) = funding.next_settle_time {
                state.next_funding_time_ns = Some(millis_to_nanos(next));
            }
            out.extend(interval_funding(&entry, state, local_recv_ns));
            Ok(())
        }
        other => Err(DecodeError::UnhandledStream(other.to_owned())),
    }
}

/// A REST record of the connector's.
fn rest(
    envelope: &Envelope<'_>,
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let symbol = envelope
        .topic
        .and_then(|topic| topic.strip_prefix("/rest:"))
        .ok_or(DecodeError::MissingField("topic"))?;
    let entry = lookup(map, symbol)?;
    if let Some(error) = envelope.error {
        return Err(DecodeError::Malformed(format!(
            "a MEXC REST read failed for {symbol}: {}",
            error.get()
        )));
    }
    let data = envelope.data.ok_or(DecodeError::MissingField("data"))?;
    let state = books.funding(symbol);
    match envelope.subject.unwrap_or_default() {
        "funding.current" => {
            let current: FundingCurrent<'_> = parse(data)?;
            state.rate = Some(decimal_literal("fundingRate", current.funding_rate)?);
            state.interval_ns =
                Some(current.collect_cycle.saturating_mul(HOUR_NS)).filter(|ns| *ns > 0);
            if let Some(next) = current.next_settle_time {
                state.next_funding_time_ns = Some(millis_to_nanos(next));
            }
        }
        "funding.last" => {
            let history: FundingHistory<'_> = parse(data)?;
            if let Some(last) = history.result_list.first() {
                state.settled = Some((
                    decimal_literal("fundingRate", last.funding_rate)?,
                    millis_to_nanos(last.settle_time),
                ));
            }
        }
        other => return Err(DecodeError::UnhandledStream(other.to_owned())),
    }
    out.extend(interval_funding(&entry, state, local_recv_ns));
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

    const RECV: u64 = 1_792_940_600_000_000_000;
    /// Recorded from MEXC on 2026-10-25: the subscription reply and a pong as
    /// text (`T`), then pushes of BTC's and ETH's quotes, BTC's trades and BTC's
    /// book as protobuf, in hex (`B`).
    const SPOT: &str = include_str!("../../tests/fixtures/mexc-spot.txt");
    /// Recorded from MEXC on 2026-10-25: the subscription replies, BTC's book,
    /// trades, mark, index, ticker and funding push, ETH's ticker, then BTC's
    /// two REST records as the connector frames them, and a failed read.
    const FUTURES: &str = include_str!("../../tests/fixtures/mexc-futures.jsonl");

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("valid")
    }

    fn spec(symbol: &str, market: MarketKind, depth: bool, size: Option<&str>) -> InstrumentSpec {
        let spec = InstrumentSpec {
            contract_size: size.map(fixed),
            ..InstrumentSpec::new(symbol, market, "CRYPTO.X/USDT").expect("valid")
        };
        if depth { spec.with_depth() } else { spec }
    }

    fn spot_map(depth: bool) -> InstrumentMap {
        let specs = [
            spec("BTCUSDT", MarketKind::Spot, depth, None),
            spec("ETHUSDT", MarketKind::Spot, false, None),
        ];
        InstrumentMap::new(Venue::Mexc, MarketKind::Spot, &specs).expect("valid")
    }

    fn futures_map(depth: bool) -> InstrumentMap {
        let specs = [
            spec("BTC_USDT", MarketKind::LinearPerp, depth, Some("0.0001")),
            spec("ETH_USDT", MarketKind::LinearPerp, false, Some("0.01")),
        ];
        InstrumentMap::new(Venue::Mexc, MarketKind::LinearPerp, &specs).expect("valid")
    }

    /// Runs a session through one map; returns the observations and the errors
    /// that are not benign.
    fn replay(
        lines: impl Iterator<Item = Vec<u8>>,
        map: &InstrumentMap,
        decode: super::super::DecodeFn,
    ) -> (Vec<Observation>, Vec<String>) {
        let mut books = Books::default();
        let (mut all, mut errors) = (Vec::new(), Vec::new());
        for payload in lines {
            let mut out = Vec::new();
            match decode(&payload, map, &mut books, RECV, &mut out) {
                Ok(()) => all.extend(out),
                Err(error) if error.is_benign() => {}
                Err(error) => errors.push(error.to_string()),
            }
        }
        (all, errors)
    }

    fn spot_lines() -> impl Iterator<Item = Vec<u8>> {
        SPOT.lines().map(|line| match line.split_once(' ') {
            Some(("B", body)) => hex::decode(body).expect("hex"),
            Some((_, body)) => body.as_bytes().to_vec(),
            None => Vec::new(),
        })
    }

    #[test]
    fn a_spot_session_gives_quotes_trades_and_a_book_from_protobuf() {
        let (all, errors) = replay(spot_lines(), &spot_map(true), decode_spot);
        assert!(errors.is_empty(), "{errors:?}");
        let top = all
            .iter()
            .find(|o| o.kind == ObsKind::BookTop && &*o.instrument.symbol == "ETHUSDT")
            .expect("a quote");
        assert!(top.bid < top.ask);
        assert!(top.bid_qty.is_some_and(Fixed::is_positive));
        assert!(
            top.exchange_time_ns
                .is_some_and(|ns| ns > 1_700_000_000_000_000_000)
        );
        let trade = all
            .iter()
            .find(|o| o.kind == ObsKind::Trade)
            .expect("a trade");
        assert!(trade.price > fixed("10000"));
        let depth = all
            .iter()
            .rev()
            .find(|o| o.kind == ObsKind::Depth)
            .expect("a book");
        let book = depth.book.as_deref().expect("levels");
        assert_eq!(book.bids.len().min(book.asks.len()), 20);
        assert!(book.bids[0].price < book.asks[0].price);
    }

    #[test]
    fn a_spot_book_without_depth_gives_only_its_top() {
        let (all, _) = replay(spot_lines(), &spot_map(false), decode_spot);
        assert!(all.iter().all(|o| o.kind != ObsKind::Depth));
    }

    #[test]
    fn a_futures_session_sizes_in_coins_and_carries_the_rest_funding() {
        let lines = FUTURES.lines().map(|line| line.as_bytes().to_vec());
        let (all, errors) = replay(lines, &futures_map(true), decode_futures);
        // Only the failed REST read is an error.
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("ETH_USDT"), "{errors:?}");

        let depth = all
            .iter()
            .rev()
            .find(|o| o.kind == ObsKind::Depth)
            .expect("a book");
        let book = depth.book.as_deref().expect("levels");
        assert!(book.bids[0].price < book.asks[0].price);
        assert_eq!(depth.bid, Some(book.bids[0].price));
        assert!(
            book.bids[0].qty < fixed("1000"),
            "contracts of 0.0001 BTC become coins"
        );

        assert!(all.iter().any(|o| o.kind == ObsKind::Trade));
        let mark = all
            .iter()
            .find(|o| o.kind == ObsKind::MarkPrice)
            .expect("a mark");
        assert!(mark.price > fixed("10000"));
        assert!(all.iter().any(|o| o.kind == ObsKind::IndexPrice));

        let funding = all
            .iter()
            .rev()
            .find(|o| o.kind == ObsKind::Funding && &*o.instrument.symbol == "BTC_USDT")
            .expect("funding");
        let info = funding.funding.as_deref().expect("info");
        assert_eq!(info.interval_ns, Some(8 * HOUR_NS));
        assert_eq!(info.next_funding_time_ns, Some(1_792_944_000_000_000_000));
        assert_eq!(
            info.settled,
            Some((fixed("0.00006"), 1_792_915_200_000_000_000))
        );
        let (open_interest, unit) = info.open_interest.expect("open interest");
        assert_eq!(unit, OpenInterestUnit::Base);
        assert!(
            open_interest > fixed("1000") && open_interest < fixed("1000000"),
            "{open_interest}"
        );
    }

    #[test]
    fn replies_are_benign_and_a_refusal_is_not() {
        let (spot, futures) = (spot_map(false), futures_map(false));
        let mut books = Books::default();
        let mut out = Vec::new();
        let replies: [(super::super::DecodeFn, &str, &InstrumentMap); 3] = [
            (decode_spot, r#"{"id":0,"code":0,"msg":"PONG"}"#, &spot),
            (
                decode_futures,
                r#"{"channel":"pong","data":1792940539872,"ts":1792940539872}"#,
                &futures,
            ),
            (
                decode_futures,
                r#"{"channel":"rs.sub.deal","data":"success","ts":1}"#,
                &futures,
            ),
        ];
        for (decode, reply, map) in replies {
            let error =
                decode(reply.as_bytes(), map, &mut books, RECV, &mut out).expect_err("a reply");
            assert!(error.is_benign(), "{error:?} for {reply}");
        }
        let refusals: [(super::super::DecodeFn, &str, &InstrumentMap); 2] = [
            (
                decode_spot,
                r#"{"id":0,"code":0,"msg":"Not Subscribed successfully! [spot@x].  Reason： Blocked! "}"#,
                &spot,
            ),
            (
                decode_futures,
                r#"{"channel":"rs.sub.deal","data":"symbol not exist","ts":1}"#,
                &futures,
            ),
        ];
        for (decode, refusal, map) in refusals {
            let error =
                decode(refusal.as_bytes(), map, &mut books, RECV, &mut out).expect_err("a refusal");
            assert!(!error.is_benign(), "{error:?} for {refusal}");
        }
    }

    #[test]
    fn subscribe_frames_name_each_channel() {
        let spot = spot_frames([("BTCUSDT", true), ("ETHUSDT", false)].into_iter());
        assert_eq!(spot.len(), 1);
        assert!(spot[0].contains("spot@public.limit.depth.v3.api.pb@BTCUSDT@20"));
        assert!(!spot[0].contains("limit.depth.v3.api.pb@ETHUSDT"));
        let futures = futures_frames([("BTC_USDT", false)].into_iter());
        assert_eq!(futures.len(), 6, "{futures:?}");
        assert!(futures[0].contains(r#""method":"sub.depth.full""#));
    }
}
