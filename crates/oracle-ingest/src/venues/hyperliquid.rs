//! Hyperliquid public streams: USDC-quoted perpetuals and spot.
//!
//! - One socket serves both markets. A perpetual is named by its coin, `BTC`;
//!   a spot pair by its index, `@142` for `UBTC/USDC`. The socket refuses the
//!   token names of a pair, so the config names the index.
//! - One subscribe frame per channel and coin. `bbo` is the top of book,
//!   `trades` the prints, `l2Book` a 20-level snapshot on each change, and
//!   `activeAssetCtx` the perpetual's mark, oracle price, funding and open
//!   interest. A spot pair answers that channel with `activeSpotAssetCtx`,
//!   which has nothing this node uses.
//! - Funding is paid each hour, as a rate for that hour. The context carries
//!   no clock, so the next payment is the next top of the hour by our clock.
//! - Every number is a JSON string. Checked against the live socket on
//!   2026-10-25.

use std::time::Duration;

use oracle_types::{Fixed, NANOS_PER_SEC, ObsKind, Observation};
use serde::Deserialize;

use crate::book::{Books, Side};
use crate::clock::millis_to_nanos;
use crate::{DecodeError, InstrumentMap};

use super::{decimal, interval_funding};

/// The production endpoint.
pub const URL: &str = "wss://api.hyperliquid.xyz/ws";

/// The keepalive: the server closes a socket that is quiet for 60 s.
pub const KEEPALIVE: &str = r#"{"method":"ping"}"#;

/// How often to send [`KEEPALIVE`].
pub const KEEPALIVE_EVERY: Duration = Duration::from_secs(30);

const HOUR_NS: u64 = 3_600 * NANOS_PER_SEC;

/// Builds the subscribe frames for a set of coins, each with whether it wants
/// the book. A perpetual also takes its context channel.
#[must_use]
pub fn subscribe_frames<'a>(
    instruments: impl Iterator<Item = (&'a str, bool)>,
    perp: bool,
) -> Vec<String> {
    let mut frames = Vec::new();
    for (coin, depth) in instruments {
        let channels = ["bbo", "trades"]
            .into_iter()
            .chain(perp.then_some("activeAssetCtx"))
            .chain(depth.then_some("l2Book"));
        for channel in channels {
            frames.push(
                serde_json::json!({
                    "method": "subscribe",
                    "subscription": { "type": channel, "coin": coin },
                })
                .to_string(),
            );
        }
    }
    frames
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow)]
    channel: &'a str,
    #[serde(borrow, default)]
    data: Option<&'a serde_json::value::RawValue>,
}

#[derive(Deserialize)]
struct Level<'a> {
    #[serde(borrow)]
    px: &'a str,
    #[serde(borrow)]
    sz: &'a str,
}

#[derive(Deserialize)]
struct Bbo<'a> {
    #[serde(borrow)]
    coin: &'a str,
    /// Milliseconds.
    time: u64,
    #[serde(borrow)]
    bbo: (Option<Level<'a>>, Option<Level<'a>>),
}

#[derive(Deserialize)]
struct Trade<'a> {
    #[serde(borrow)]
    coin: &'a str,
    #[serde(borrow)]
    px: &'a str,
    /// Milliseconds.
    time: u64,
}

#[derive(Deserialize)]
struct Book<'a> {
    #[serde(borrow)]
    coin: &'a str,
    /// Milliseconds.
    time: u64,
    #[serde(borrow)]
    levels: (Vec<Level<'a>>, Vec<Level<'a>>),
}

#[derive(Deserialize)]
struct AssetCtx<'a> {
    #[serde(borrow)]
    coin: &'a str,
    #[serde(borrow)]
    ctx: Ctx<'a>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ctx<'a> {
    #[serde(borrow, default)]
    funding: Option<&'a str>,
    #[serde(borrow, default)]
    open_interest: Option<&'a str>,
    #[serde(borrow, default)]
    mark_px: Option<&'a str>,
    #[serde(borrow, default)]
    oracle_px: Option<&'a str>,
}

/// Decodes one Hyperliquid payload.
///
/// # Errors
///
/// Returns [`DecodeError`]. Subscribe replies, pongs and spot contexts are
/// benign; an `error` channel is not, because it names a bad subscription.
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let data = match (envelope.channel, envelope.data) {
        ("error", data) => {
            return Err(DecodeError::Malformed(format!(
                "the server refused a request: {}",
                data.map_or("", |raw| raw.get())
            )));
        }
        ("bbo" | "trades" | "l2Book" | "activeAssetCtx", Some(data)) => data,
        ("subscriptionResponse" | "pong" | "activeSpotAssetCtx", _) => {
            return Err(DecodeError::Control);
        }
        (channel, _) => return Err(DecodeError::UnhandledStream(channel.to_owned())),
    };
    let parse = |error: serde_json::Error| DecodeError::Malformed(error.to_string());
    match envelope.channel {
        "bbo" => {
            let bbo: Bbo<'_> = serde_json::from_str(data.get()).map_err(parse)?;
            let Some(entry) = map.lookup(bbo.coin) else {
                return Err(DecodeError::UnknownInstrument(bbo.coin.to_owned()));
            };
            let (Some(bid), Some(ask)) = bbo.bbo else {
                // One side is empty: no quote.
                return Err(DecodeError::Control);
            };
            let (bid_px, ask_px) = (decimal("bid px", bid.px)?, decimal("ask px", ask.px)?);
            let mid = bid_px
                .checked_add(ask_px)
                .and_then(|sum| sum.checked_div(Fixed::from_int(2).ok()?))
                .unwrap_or(bid_px);
            out.push(Observation {
                instrument: entry.instrument.clone(),
                kind: ObsKind::BookTop,
                price: mid,
                bid: Some(bid_px),
                ask: Some(ask_px),
                bid_qty: Some(decimal("bid sz", bid.sz)?),
                ask_qty: Some(decimal("ask sz", ask.sz)?),
                depth_notional_1bp: None,
                exchange_time_ns: Some(millis_to_nanos(bbo.time)),
                local_recv_ns,
                seq: None,
                book: None,
                funding: None,
            });
            Ok(())
        }
        "trades" => {
            let trades: Vec<Trade<'_>> = serde_json::from_str(data.get()).map_err(parse)?;
            let mut emitted = false;
            for trade in trades {
                let Some(entry) = map.lookup(trade.coin) else {
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
                    exchange_time_ns: Some(millis_to_nanos(trade.time)),
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
        "l2Book" => {
            let message: Book<'_> = serde_json::from_str(data.get()).map_err(parse)?;
            let Some(entry) = map.lookup(message.coin) else {
                return Err(DecodeError::UnknownInstrument(message.coin.to_owned()));
            };
            // Each message is a whole snapshot, so nothing can be missed.
            let book = books.book(message.coin);
            book.clear();
            book.last_id = Some(message.time);
            for (side, levels) in [
                (Side::Bid, &message.levels.0),
                (Side::Ask, &message.levels.1),
            ] {
                for level in levels {
                    book.set(side, decimal("px", level.px)?, decimal("sz", level.sz)?);
                }
            }
            books.emit(
                message.coin,
                entry.instrument.clone(),
                Some(millis_to_nanos(message.time)),
                local_recv_ns,
                out,
            )
        }
        _ => {
            let message: AssetCtx<'_> = serde_json::from_str(data.get()).map_err(parse)?;
            let Some(entry) = map.lookup(message.coin) else {
                return Err(DecodeError::UnknownInstrument(message.coin.to_owned()));
            };
            let ctx = message.ctx;
            let mut emitted = false;
            for (field, kind, raw) in [
                ("markPx", ObsKind::MarkPrice, ctx.mark_px),
                ("oraclePx", ObsKind::IndexPrice, ctx.oracle_px),
            ] {
                let Some(raw) = raw else { continue };
                out.push(Observation {
                    instrument: entry.instrument.clone(),
                    kind,
                    price: decimal(field, raw)?,
                    bid: None,
                    ask: None,
                    bid_qty: None,
                    ask_qty: None,
                    depth_notional_1bp: None,
                    exchange_time_ns: None,
                    local_recv_ns,
                    seq: None,
                    book: None,
                    funding: None,
                });
                emitted = true;
            }
            let rate = ctx.funding.map(|raw| decimal("funding", raw)).transpose()?;
            let open_interest = ctx
                .open_interest
                .map(|raw| decimal("openInterest", raw))
                .transpose()?;
            // The context repeats each second; the rate goes out when it or the
            // open interest changed.
            let last = books.funding(message.coin);
            if last.update(rate, open_interest) {
                last.interval_ns = Some(HOUR_NS);
                last.next_funding_time_ns = local_recv_ns
                    .checked_div(HOUR_NS)
                    .and_then(|hours| hours.checked_add(1))
                    .and_then(|hours| hours.checked_mul(HOUR_NS));
                if let Some(funding) = interval_funding(entry, last, local_recv_ns) {
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
    use oracle_types::{FundingBasis, OpenInterestUnit};
    use oracle_types::{MarketKind, Venue};

    /// 2026-10-25 07:29:54 UTC, inside the hour of the fixtures.
    const RECV: u64 = 1_792_913_394_000_000_000;
    const ASSET_CTX: &str = include_str!("../../tests/fixtures/funding/hyperliquid-asset-ctx.json");
    const BBO: &str = include_str!("../../tests/fixtures/funding/hyperliquid-bbo.json");
    const SPOT_BBO: &str = include_str!("../../tests/fixtures/funding/hyperliquid-bbo-spot.json");
    const BOOK: &str = include_str!("../../tests/fixtures/hyperliquid-book.json");

    fn map(market: MarketKind, coin: &str, depth: bool) -> InstrumentMap {
        let spec = InstrumentSpec::new(coin, market, "CRYPTO.BTC/USDC").expect("valid");
        let spec = if depth { spec.with_depth() } else { spec };
        InstrumentMap::new(Venue::Hyperliquid, market, &[spec]).expect("valid")
    }

    fn decoded(payload: &str, map: &InstrumentMap, books: &mut Books) -> Vec<Observation> {
        let mut out = Vec::new();
        decode(payload.as_bytes(), map, books, RECV, &mut out).expect("decodes");
        out
    }

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("valid")
    }

    #[test]
    fn the_top_of_book_is_a_quote_with_its_sizes() {
        let perp = map(MarketKind::LinearPerp, "BTC", false);
        let out = decoded(BBO, &perp, &mut Books::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, ObsKind::BookTop);
        assert_eq!(out[0].bid, Some(fixed("80560.0")));
        assert_eq!(out[0].ask, Some(fixed("80561.0")));
        assert_eq!(out[0].price, fixed("80560.5"));
        assert_eq!(out[0].bid_qty, Some(fixed("0.98523")));
        assert_eq!(out[0].exchange_time_ns, Some(1_792_913_436_085_000_000));

        // A spot pair is named by its index.
        let spot = map(MarketKind::Spot, "@142", false);
        let out = decoded(SPOT_BBO, &spot, &mut Books::default());
        assert_eq!(out[0].bid, Some(fixed("80501.0")));
        assert_eq!(&*out[0].instrument.symbol, "@142");
    }

    #[test]
    fn the_context_gives_mark_index_and_hourly_funding_with_open_interest() {
        let perp = map(MarketKind::LinearPerp, "BTC", false);
        let mut books = Books::default();
        let out = decoded(ASSET_CTX, &perp, &mut books);
        let kinds: Vec<_> = out.iter().map(|o| o.kind).collect();
        assert_eq!(
            kinds,
            [ObsKind::MarkPrice, ObsKind::IndexPrice, ObsKind::Funding]
        );
        assert_eq!(out[0].price, fixed("80560.0"));
        assert_eq!(out[1].price, fixed("80595.3"));
        assert_eq!(out[2].price, fixed("0.0000091007"));
        let info = out[2].funding.as_deref().expect("info");
        assert_eq!(info.basis, FundingBasis::Interval);
        assert_eq!(info.interval_ns, Some(HOUR_NS));
        // The next top of the hour after RECV: 08:00:00 UTC.
        assert_eq!(info.next_funding_time_ns, Some(1_792_915_200_000_000_000));
        assert_eq!(
            info.open_interest,
            Some((fixed("42690.39078"), OpenInterestUnit::Base))
        );

        // The same context again: the prices, but no second funding observation.
        let again = decoded(ASSET_CTX, &perp, &mut books);
        assert!(again.iter().all(|o| o.kind != ObsKind::Funding));
    }

    #[test]
    fn a_book_message_is_a_whole_snapshot() {
        let perp = map(MarketKind::LinearPerp, "BTC", true);
        let mut books = Books::default();
        let out = decoded(BOOK, &perp, &mut books);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, ObsKind::Depth);
        let book = out[0].book.as_deref().expect("levels");
        assert!(book.bids[0].price < book.asks[0].price);
        assert_eq!(book.bids[0].price, fixed("80560.0"));
        assert_eq!(out[0].seq, Some(1_792_913_435_816));

        // A later snapshot replaces the first, levels and all.
        let moved = BOOK.replace(r#""px":"80560.0""#, r#""px":"80559.5""#);
        let out = decoded(&moved, &perp, &mut books);
        let book = out[0].book.as_deref().expect("levels");
        assert_eq!(book.bids[0].price, fixed("80559.5"));
        assert!(
            book.bids
                .iter()
                .all(|level| level.price != fixed("80560.0"))
        );
    }

    #[test]
    fn trades_are_prints_of_tracked_coins_only() {
        let perp = map(MarketKind::LinearPerp, "BTC", false);
        let trades = r#"{"channel":"trades","data":[
            {"coin":"BTC","side":"A","px":"80564.0","sz":"0.001","time":1792913373012,"hash":"0x0","tid":1,"users":["0xa","0xb"]},
            {"coin":"ETH","side":"B","px":"2344.4","sz":"1","time":1792913373013,"hash":"0x0","tid":2,"users":["0xa","0xb"]}]}"#;
        let out = decoded(trades, &perp, &mut Books::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, ObsKind::Trade);
        assert_eq!(out[0].price, fixed("80564.0"));
    }

    #[test]
    fn replies_pongs_and_spot_contexts_are_benign_and_errors_are_not() {
        let perp = map(MarketKind::LinearPerp, "BTC", false);
        let mut out = Vec::new();
        for control in [
            r#"{"channel":"subscriptionResponse","data":{"method":"subscribe","subscription":{"type":"bbo","coin":"BTC"}}}"#,
            r#"{"channel":"pong"}"#,
            r#"{"channel":"activeSpotAssetCtx","data":{"coin":"@142","ctx":{"markPx":"80506.0"}}}"#,
            r#"{"channel":"bbo","data":{"coin":"ETH","time":1,"bbo":[{"px":"1","sz":"1","n":1},{"px":"2","sz":"1","n":1}]}}"#,
            r#"{"channel":"bbo","data":{"coin":"BTC","time":1,"bbo":[null,{"px":"2","sz":"1","n":1}]}}"#,
        ] {
            let error = decode(
                control.as_bytes(),
                &perp,
                &mut Books::default(),
                RECV,
                &mut out,
            )
            .expect_err("not market data");
            assert!(error.is_benign(), "got {error:?} for {control}");
        }
        assert!(out.is_empty());
        let refused =
            r#"{"channel":"error","data":"Error parsing JSON into valid websocket request"}"#;
        let error = decode(
            refused.as_bytes(),
            &perp,
            &mut Books::default(),
            RECV,
            &mut out,
        )
        .expect_err("an error");
        assert!(!error.is_benign());
    }

    #[test]
    fn subscribe_frames_name_each_channel_once() {
        let frames = subscribe_frames([("BTC", true), ("ETH", false)].into_iter(), true);
        assert_eq!(frames.len(), 7, "{frames:?}");
        assert!(frames[0].contains(r#""type":"bbo""#) && frames[0].contains(r#""coin":"BTC""#));
        assert!(
            frames
                .iter()
                .any(|f| f.contains("activeAssetCtx") && f.contains("BTC"))
        );
        assert!(
            frames
                .iter()
                .any(|f| f.contains("l2Book") && f.contains("BTC"))
        );
        assert!(
            !frames
                .iter()
                .any(|f| f.contains("l2Book") && f.contains("ETH"))
        );

        let spot = subscribe_frames([("@142", false)].into_iter(), false);
        assert_eq!(spot.len(), 2);
        assert!(!spot.iter().any(|f| f.contains("activeAssetCtx")));
    }
}
