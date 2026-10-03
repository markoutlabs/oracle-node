//! Kraken Futures v1 public streams.
//!
//! Shares a brand with [`super::kraken`] and nothing else. Different host,
//! different envelope (`feed` rather than `channel`, `event` rather than
//! `method`), different field names. It is a separate protocol and therefore a
//! separate decoder, selected per connection rather than per venue.
//!
//! # The same precision hazard as spot
//!
//! Kraken Futures sends prices as **bare JSON numbers**. Routing those through
//! `f64` would silently round exactly the values that matter, so every numeric
//! field is captured as a `RawValue` and parsed from its literal characters.
//!
//! # Funding is hourly here
//!
//! `relative_funding_rate` is a fraction over Kraken's **one-hour** funding
//! interval, not eight. It is emitted raw, as [`ObsKind::Funding`] is defined —
//! a fraction over the venue's own interval. Averaging it against an 8h venue
//! without scaling would be off by 8×; see SPEC.md §13, open question 3.

use oracle_types::{Fixed, ObsKind, Observation};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::clock::millis_to_nanos;
use crate::{DecodeError, InstrumentMap};

use super::decimal_literal;

/// The public endpoint.
pub const URL: &str = "wss://futures.kraken.com/ws/v1";

/// Builds the subscribe frame for a set of Kraken Futures product ids.
///
/// Product ids are `PF_XBTUSD` for multi-collateral (linear) perpetuals and
/// `PI_XBTUSD` for inverse ones — note Kraken's `XBT`, not `BTC`.
#[must_use]
pub fn subscribe_frame<'a>(product_ids: impl Iterator<Item = &'a str>) -> String {
    let products: Vec<&str> = product_ids.collect();
    serde_json::json!({
        "event": "subscribe",
        "feed": "ticker",
        "product_ids": products,
    })
    .to_string()
}

/// The feed is read first and the payload deferred, so that an `event` frame —
/// `info`, `subscribed`, `alert` — cannot fail to deserialize as a ticker and be
/// counted as malformed.
#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow, default)]
    feed: Option<&'a str>,
    #[serde(borrow, default)]
    event: Option<&'a str>,
}

#[derive(Deserialize)]
struct Ticker<'a> {
    #[serde(rename = "product_id", borrow)]
    product_id: &'a str,
    #[serde(borrow, default)]
    bid: Option<&'a RawValue>,
    #[serde(rename = "bid_size", borrow, default)]
    bid_size: Option<&'a RawValue>,
    #[serde(borrow, default)]
    ask: Option<&'a RawValue>,
    #[serde(rename = "ask_size", borrow, default)]
    ask_size: Option<&'a RawValue>,
    #[serde(borrow, default)]
    last: Option<&'a RawValue>,
    #[serde(rename = "markPrice", borrow, default)]
    mark_price: Option<&'a RawValue>,
    #[serde(borrow, default)]
    index: Option<&'a RawValue>,
    /// The fractional funding rate, over Kraken's own interval.
    ///
    /// Deliberately not `funding_rate`, which is an absolute figure in price
    /// units — averaging that against another venue's fraction would be
    /// meaningless rather than merely mis-scaled.
    #[serde(rename = "relative_funding_rate", borrow, default)]
    relative_funding_rate: Option<&'a RawValue>,
    /// Milliseconds.
    #[serde(default)]
    time: Option<u64>,
    /// Kraken flags halted contracts rather than dropping them from the feed.
    #[serde(default)]
    suspended: Option<bool>,
}

/// Decodes one Kraken Futures payload.
///
/// # Errors
///
/// Returns [`DecodeError`]. Subscription acknowledgements, `info` frames and
/// heartbeats are benign.
pub fn decode_payload(
    payload: &[u8],
    map: &InstrumentMap,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let envelope: Envelope<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    if envelope.event.is_some() {
        // `{"event":"info","version":1}`, `{"event":"subscribed",...}`, alerts.
        return Err(DecodeError::Control);
    }
    let Some(feed) = envelope.feed else {
        return Err(DecodeError::Control);
    };
    // `ticker_snapshot` is the initial burst and carries the same shape.
    if feed != "ticker" && feed != "ticker_snapshot" {
        return Err(DecodeError::UnhandledStream(feed.to_owned()));
    }

    let ticker: Ticker<'_> =
        serde_json::from_slice(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let Some(entry) = map.lookup(ticker.product_id) else {
        return Err(DecodeError::Control);
    };
    // A suspended contract still publishes a stale-looking book. Dropping it
    // here means the staleness filter sheds it rather than the aggregator
    // pricing off a market nobody can trade.
    if ticker.suspended == Some(true) {
        return Err(DecodeError::Control);
    }
    let exchange_time_ns = ticker.time.map(millis_to_nanos);

    let mut emitted = false;
    if let (Some(bid), Some(bid_size), Some(ask), Some(ask_size)) =
        (ticker.bid, ticker.bid_size, ticker.ask, ticker.ask_size)
    {
        let bid = decimal_literal("bid", bid)?;
        let ask = decimal_literal("ask", ask)?;
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
            bid_qty: Some(decimal_literal("bid_size", bid_size)?),
            ask_qty: Some(decimal_literal("ask_size", ask_size)?),
            depth_notional_1bp: None,
            exchange_time_ns,
            local_recv_ns,
            seq: None,
        });
        emitted = true;
    }

    for (field, kind, raw) in [
        ("last", ObsKind::Trade, ticker.last),
        ("markPrice", ObsKind::MarkPrice, ticker.mark_price),
        ("index", ObsKind::IndexPrice, ticker.index),
        (
            "relative_funding_rate",
            ObsKind::Funding,
            ticker.relative_funding_rate,
        ),
    ] {
        let Some(raw) = raw else { continue };
        out.push(Observation {
            instrument: entry.instrument.clone(),
            kind,
            price: decimal_literal(field, raw)?,
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            depth_notional_1bp: None,
            exchange_time_ns,
            local_recv_ns,
            seq: None,
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

    fn map() -> InstrumentMap {
        let specs = vec![
            InstrumentSpec::new("PF_XBTUSD", MarketKind::LinearPerp, "CRYPTO.BTC/USD")
                .expect("valid"),
        ];
        InstrumentMap::new(Venue::Kraken, MarketKind::LinearPerp, &specs).expect("valid")
    }

    fn decode(payload: &str) -> Vec<Observation> {
        let mut out = Vec::new();
        decode_payload(payload.as_bytes(), &map(), RECV, &mut out).expect("decodes");
        out
    }

    /// The shape Kraken documents, bare numbers and all.
    const TICKER: &str = r#"{"time":1676393235406,"product_id":"PF_XBTUSD",
        "funding_rate":-6.2604214e-11,"funding_rate_prediction":-3.65989977e-10,
        "relative_funding_rate":-0.000001380384722222,
        "relative_funding_rate_prediction":-8.047629166667e-6,
        "next_funding_rate_time":1676394000000,"feed":"ticker","bid":21978.5,"ask":21987.0,
        "bid_size":2536.0,"ask_size":13948.0,"volume":31403908.0,"dtm":0,"leverage":"50x",
        "index":21984.54,"premium":-0.0,"last":21983.5,"change":1.99,"suspended":false,
        "tag":"perpetual","pair":"XBT:USD","openInterest":30072580.0,
        "markPrice":21979.68641534714,"maturityTime":0,"post_only":false,
        "volumeQuote":31403908.0,"open":21968.5,"high":22123.0,"low":21456.0}"#;

    #[test]
    fn a_ticker_yields_book_trade_mark_index_and_funding() {
        let observations = decode(TICKER);
        let kinds: Vec<_> = observations.iter().map(|o| o.kind).collect();
        assert_eq!(
            kinds,
            [
                ObsKind::BookTop,
                ObsKind::Trade,
                ObsKind::MarkPrice,
                ObsKind::IndexPrice,
                ObsKind::Funding,
            ]
        );
        assert_eq!(observations[0].bid, Some("21978.5".parse().expect("valid")));
        assert_eq!(observations[0].ask, Some("21987".parse().expect("valid")));
        assert_eq!(
            observations[0].price,
            "21982.75".parse().expect("valid"),
            "the mid of the two sides"
        );
        assert_eq!(observations[1].price, "21983.5".parse().expect("valid"));
        assert_eq!(observations[3].price, "21984.54".parse().expect("valid"));
    }

    /// The reason every field goes through `RawValue`: a double would round the
    /// mark price's last digits away.
    #[test]
    fn bare_json_numbers_keep_every_digit() {
        let observations = decode(TICKER);
        assert_eq!(
            observations[2].price,
            "21979.68641534714".parse().expect("valid"),
            "the mark price must survive with every digit the venue sent"
        );
    }

    /// `relative_funding_rate` is the fraction; `funding_rate` is an absolute
    /// figure in price units. Picking the wrong one would put a number three
    /// orders of magnitude off into a funding feed.
    #[test]
    fn funding_uses_the_relative_rate_not_the_absolute_one() {
        let observations = decode(TICKER);
        assert_eq!(
            observations[4].price,
            "-0.000001380384722222".parse().expect("valid")
        );
    }

    #[test]
    fn the_timestamp_is_read_as_milliseconds() {
        let observations = decode(TICKER);
        assert_eq!(
            observations[0].exchange_time_ns,
            Some(1_676_393_235_406_000_000)
        );
    }

    #[test]
    fn a_suspended_contract_publishes_nothing() {
        let suspended = TICKER.replace(r#""suspended":false"#, r#""suspended":true"#);
        let mut out = Vec::new();
        let error =
            decode_payload(suspended.as_bytes(), &map(), RECV, &mut out).expect_err("suspended");
        assert!(error.is_benign(), "got {error:?}");
        assert!(
            out.is_empty(),
            "a market nobody can trade must not reach the aggregator"
        );
    }

    #[test]
    fn event_frames_and_heartbeats_are_benign() {
        let mut out = Vec::new();
        for control in [
            r#"{"event":"info","version":1}"#,
            r#"{"event":"subscribed","feed":"ticker","product_ids":["PF_XBTUSD"]}"#,
            r#"{"event":"alert","message":"some notice"}"#,
            r#"{"feed":"heartbeat","time":1676393235406}"#,
        ] {
            let error = decode_payload(control.as_bytes(), &map(), RECV, &mut out)
                .expect_err("not market data");
            assert!(error.is_benign(), "got {error:?} for {control}");
        }
        assert!(out.is_empty());
    }

    #[test]
    fn untracked_products_are_benign() {
        let other = TICKER.replace("PF_XBTUSD", "PF_ETHUSD");
        let mut out = Vec::new();
        let error =
            decode_payload(other.as_bytes(), &map(), RECV, &mut out).expect_err("untracked");
        assert!(error.is_benign());
    }

    /// Kraken sends every field on every update, but a partial frame must still
    /// yield what it does carry rather than nothing.
    #[test]
    fn a_ticker_missing_the_book_still_yields_the_mark() {
        let partial = r#"{"feed":"ticker","product_id":"PF_XBTUSD","markPrice":21979.5}"#;
        let observations = decode(partial);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].kind, ObsKind::MarkPrice);
    }

    #[test]
    fn the_subscribe_frame_uses_the_futures_shape() {
        let frame = subscribe_frame(["PF_XBTUSD"].into_iter());
        assert!(frame.contains(r#""event":"subscribe""#));
        assert!(frame.contains(r#""feed":"ticker""#));
        assert!(frame.contains("PF_XBTUSD"));
    }
}
