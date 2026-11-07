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

use std::sync::Arc;

use oracle_types::{
    FundingBasis, FundingInfo, NANOS_PER_SEC, ObsKind, Observation, OpenInterestUnit,
};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{Books, Halts};
use crate::clock::millis_to_nanos;
use crate::{DecodeError, InstrumentMap};

use super::{book_top, decimal_literal, observation};

/// Kraken Futures pays funding every hour.
const FUNDING_INTERVAL_NS: u64 = 3_600 * NANOS_PER_SEC;

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

/// A ticker, or an `event` frame — `info`, `subscribed`, `alert`. Every field
/// is optional, so one parse reads either, and an event cannot count as a
/// malformed ticker.
#[derive(Deserialize)]
struct Ticker<'a> {
    #[serde(borrow, default)]
    feed: Option<&'a str>,
    #[serde(borrow, default)]
    event: Option<&'a str>,
    #[serde(rename = "product_id", borrow, default)]
    product_id: Option<&'a str>,
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
    #[serde(rename = "relative_funding_rate_prediction", borrow, default)]
    relative_funding_rate_prediction: Option<&'a RawValue>,
    /// Milliseconds.
    #[serde(rename = "next_funding_rate_time", default)]
    next_funding_rate_time: Option<u64>,
    /// In contracts.
    #[serde(rename = "openInterest", borrow, default)]
    open_interest: Option<&'a RawValue>,
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
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    _books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let ticker: Ticker<'_> = serde_json::from_slice(payload)?;
    let (None, Some(feed)) = (ticker.event, ticker.feed) else {
        // `{"event":"info","version":1}`, `{"event":"subscribed",...}`, alerts.
        return Err(DecodeError::Control);
    };
    // `ticker_snapshot` is the initial burst and carries the same shape.
    if feed != "ticker" && feed != "ticker_snapshot" {
        return Err(DecodeError::UnhandledStream(feed.to_owned()));
    }
    let product_id = ticker
        .product_id
        .ok_or(DecodeError::MissingField("product_id"))?;
    let Some(entry) = map.lookup(product_id) else {
        return Err(DecodeError::Control);
    };
    // A suspended contract still publishes a stale-looking book. The session
    // stops confirming its last values, so the staleness filter sheds them.
    if ticker.suspended == Some(true) {
        return Err(DecodeError::Suspended(entry.instrument.clone()));
    }
    let exchange_time_ns = ticker.time.map(millis_to_nanos);
    let before = out.len();

    // An absent, null or zero side has no quote: the rest of the ticker
    // stands, and the book stops counting.
    let top = || {
        let (Some(bid), Some(bid_size), Some(ask), Some(ask_size)) =
            (ticker.bid, ticker.bid_size, ticker.ask, ticker.ask_size)
        else {
            return Ok(None);
        };
        Ok(Some((
            (decimal_literal("bid", bid)?, decimal_literal("ask", ask)?),
            (
                decimal_literal("bid_size", bid_size)?,
                decimal_literal("ask_size", ask_size)?,
            ),
        )))
    };
    let quote = book_top(entry, top, exchange_time_ns, local_recv_ns).map(|top| out.push(top));
    let mut halts = Halts::default();
    halts.absorb(&entry.instrument, quote)?;

    let funding = ticker
        .relative_funding_rate
        .map(|_| -> Result<FundingInfo, DecodeError> {
            Ok(FundingInfo {
                predicted: ticker
                    .relative_funding_rate_prediction
                    .map(|raw| decimal_literal("relative_funding_rate_prediction", raw))
                    .transpose()?,
                interval_ns: Some(FUNDING_INTERVAL_NS),
                next_funding_time_ns: ticker
                    .next_funding_rate_time
                    .filter(|ms| *ms > 0)
                    .map(millis_to_nanos),
                open_interest: ticker
                    .open_interest
                    .map(|raw| decimal_literal("openInterest", raw))
                    .transpose()?
                    .map(|oi| (oi, OpenInterestUnit::Contracts)),
                ..FundingInfo::new(FundingBasis::Interval)
            })
        })
        .transpose()?
        .map(Arc::new);
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
            exchange_time_ns,
            funding: (kind == ObsKind::Funding)
                .then(|| funding.clone())
                .flatten(),
            ..observation(entry, kind, decimal_literal(field, raw)?, local_recv_ns)
        });
    }

    let empty = if out.len() == before {
        Err(DecodeError::Control)
    } else {
        Ok(())
    };
    halts.finish(empty)
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixtures are fixed-shape; an out-of-range index is a failing test, \
              which is exactly what should happen if decoding changed"
)]
mod tests {
    use super::*;
    use crate::testing::{Feed, fixed, instrument, kinds};
    use oracle_types::{MarketKind, Venue};

    fn ticker() -> Feed {
        let perp = instrument("PF_XBTUSD", MarketKind::LinearPerp);
        Feed::venue(decode, Venue::Kraken, MarketKind::LinearPerp, &[perp])
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
        let observations = ticker().decoded(TICKER);
        assert_eq!(
            kinds(&observations),
            [
                ObsKind::BookTop,
                ObsKind::Trade,
                ObsKind::MarkPrice,
                ObsKind::IndexPrice,
                ObsKind::Funding,
            ]
        );
        assert_eq!(observations[0].bid, Some(fixed("21978.5")));
        assert_eq!(observations[0].ask, Some(fixed("21987")));
        assert_eq!(
            observations[0].price,
            fixed("21982.75"),
            "the mid of the two sides"
        );
        assert_eq!(observations[1].price, fixed("21983.5"));
        assert_eq!(observations[3].price, fixed("21984.54"));
    }

    /// The reason every field goes through `RawValue`: a double would round the
    /// mark price's last digits away.
    #[test]
    fn bare_json_numbers_keep_every_digit() {
        let observations = ticker().decoded(TICKER);
        assert_eq!(
            observations[2].price,
            fixed("21979.68641534714"),
            "the mark price must survive with every digit the venue sent"
        );
    }

    /// `relative_funding_rate` is the fraction; `funding_rate` is an absolute
    /// figure in price units. Picking the wrong one would put a number three
    /// orders of magnitude off into a funding feed.
    #[test]
    fn funding_uses_the_relative_rate_not_the_absolute_one() {
        let observations = ticker().decoded(TICKER);
        assert_eq!(observations[4].price, fixed("-0.000001380384722222"));
    }

    #[test]
    fn the_timestamp_is_read_as_milliseconds() {
        let observations = ticker().decoded(TICKER);
        assert_eq!(
            observations[0].exchange_time_ns,
            Some(1_676_393_235_406_000_000)
        );
    }

    #[test]
    fn a_suspended_contract_publishes_nothing() {
        let suspended = TICKER.replace(r#""suspended":false"#, r#""suspended":true"#);
        // A market nobody can trade must not reach the aggregator.
        let error = ticker().refused(suspended);
        assert!(matches!(error, DecodeError::Suspended(_)), "got {error:?}");
    }

    #[test]
    fn event_frames_and_heartbeats_are_benign() {
        let mut ticker = ticker();
        for control in [
            r#"{"event":"info","version":1}"#,
            r#"{"event":"subscribed","feed":"ticker","product_ids":["PF_XBTUSD"]}"#,
            r#"{"event":"alert","message":"some notice"}"#,
            r#"{"feed":"heartbeat","time":1676393235406}"#,
        ] {
            let error = ticker.refused(control);
            assert!(error.is_benign(), "got {error:?} for {control}");
        }
    }

    #[test]
    fn untracked_products_are_benign() {
        let other = TICKER.replace("PF_XBTUSD", "PF_ETHUSD");
        assert!(ticker().refused(other).is_benign());
    }

    /// Kraken sends every field on every update, but a partial frame must still
    /// yield what it does carry rather than nothing.
    #[test]
    fn a_ticker_without_its_book_halts_the_quote_and_keeps_the_mark() {
        let partial = r#"{"feed":"ticker","product_id":"PF_XBTUSD","markPrice":21979.5}"#;
        let (observations, halted) = ticker().halted(partial);
        assert_eq!(kinds(&observations), [ObsKind::MarkPrice]);
        assert_eq!(halted, ["PF_XBTUSD"]);
    }

    #[test]
    fn the_subscribe_frame_uses_the_futures_shape() {
        let frame = subscribe_frame(["PF_XBTUSD"].into_iter());
        assert!(frame.contains(r#""event":"subscribe""#));
        assert!(frame.contains(r#""feed":"ticker""#));
        assert!(frame.contains("PF_XBTUSD"));
    }
}
