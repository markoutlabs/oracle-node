//! Shared machinery for the venues that subscribe over the socket.
//!
//! Binance encodes its subscription in the URL. Every other venue in scope sends
//! a subscribe frame after connecting and needs an application-level keepalive —
//! a WebSocket ping is not enough, and they drop connections that only answer
//! protocol pings.
//!
//! What actually differs per venue is small: how to name a subscription, what
//! keepalive to send, and how to decode a payload. Everything else — connect,
//! reconnect, backoff, staleness, invalidation — is [`crate::Session`].

pub mod adapter;
pub mod bitfinex;
pub mod bitget;
pub mod bitstamp;
pub mod bybit;
pub mod coinbase;
pub mod deribit;
pub mod dydx;
pub mod gate;
pub mod hyperliquid;
pub mod kraken;
pub mod kraken_futures;
pub mod kucoin;
pub mod kucoin_connect;
pub mod lighter;
pub mod mexc;
pub mod mexc_connect;
pub mod okx;
pub mod rest_frames;

pub use adapter::{DecodeFn, VenueAdapter, VenueHandler, VenueSpec};

use std::sync::Arc;

use oracle_types::{Fixed, FundingBasis, FundingInfo, ObsKind, Observation, OpenInterestUnit};

use crate::DecodeError;
use crate::book::LastFunding;
use crate::instrument::InstrumentEntry;

/// An observation of `kind` at `price`, with nothing else set.
pub(crate) fn observation(
    entry: &InstrumentEntry,
    kind: ObsKind,
    price: Fixed,
    local_recv_ns: u64,
) -> Observation {
    Observation {
        instrument: entry.instrument.clone(),
        kind,
        price,
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
    }
}

/// A JSON value parsed from its raw text.
pub(crate) fn parse<'a, T: serde::Deserialize<'a>>(
    raw: &'a serde_json::value::RawValue,
) -> Result<T, DecodeError> {
    Ok(serde_json::from_str(raw.get())?)
}

/// The mid of a quote, or the bid when the sum overflows.
pub(crate) fn mid(bid: Fixed, ask: Fixed) -> Fixed {
    bid.checked_add(ask)
        .and_then(|sum| sum.checked_div(Fixed::from_int(2).ok()?))
        .unwrap_or(bid)
}

/// A size in coins: contracts times the contract size, where the venue counts
/// in contracts.
pub(crate) fn base_units(size: Fixed, contract_size: Option<Fixed>) -> Fixed {
    contract_size
        .and_then(|contract| size.checked_mul(contract))
        .unwrap_or(size)
}

/// Converts an order size to base units.
///
/// On an inverse contract the amount is quote-currency notional, so dividing by
/// the price recovers base units and puts an inverse perpetual on the same
/// footing as every other market. Returns `None` rather than a wrong number if the division cannot
/// be represented.
pub(crate) fn to_base_units(amount: Fixed, price: Fixed, inverse: bool) -> Option<Fixed> {
    if !inverse {
        return Some(amount);
    }
    if !price.is_positive() {
        return None;
    }
    amount.checked_div(price)
}

/// A best bid and ask as a book top, priced at the mid. A side at zero or
/// below is an empty book, not a quote.
pub(crate) fn book_top(
    entry: &InstrumentEntry,
    (bid, ask): (Fixed, Fixed),
    (bid_qty, ask_qty): (Fixed, Fixed),
    exchange_time_ns: Option<u64>,
    local_recv_ns: u64,
) -> Result<Observation, DecodeError> {
    if !bid.is_positive() || !ask.is_positive() {
        return Err(DecodeError::Control);
    }
    Ok(Observation {
        bid: Some(bid),
        ask: Some(ask),
        bid_qty: Some(bid_qty),
        ask_qty: Some(ask_qty),
        exchange_time_ns,
        ..observation(entry, ObsKind::BookTop, mid(bid, ask), local_recv_ns)
    })
}

/// The funding state of a venue that pays over its own interval, once a rate
/// is known. The open interest is in coins.
pub(crate) fn interval_funding(
    entry: &InstrumentEntry,
    state: &LastFunding,
    local_recv_ns: u64,
) -> Option<Observation> {
    let rate = state.rate?;
    let info = FundingInfo {
        interval_ns: state.interval_ns,
        next_funding_time_ns: state.next_funding_time_ns,
        settled: state.settled,
        open_interest: state
            .open_interest
            .map(|coins| (coins, OpenInterestUnit::Base)),
        ..FundingInfo::new(FundingBasis::Interval)
    };
    Some(Observation {
        funding: Some(Arc::new(info)),
        ..observation(entry, ObsKind::Funding, rate, local_recv_ns)
    })
}

/// Parses a decimal that arrived as a JSON string.
pub(crate) fn decimal(field: &'static str, value: &str) -> Result<Fixed, DecodeError> {
    value.parse().map_err(|_| DecodeError::BadDecimal {
        field,
        value: value.to_owned(),
    })
}

/// Parses a whole number that arrived as a JSON string, such as a time in
/// milliseconds.
pub(crate) fn integer(field: &'static str, value: &str) -> Result<u64, DecodeError> {
    value.parse().map_err(|_| DecodeError::BadDecimal {
        field,
        value: value.to_owned(),
    })
}

/// Parses a decimal that arrived as a bare JSON number.
///
/// Takes the **raw literal text** rather than a parsed `f64`. Kraken v2 sends
/// prices as JSON numbers, and routing those through a double would quietly lose
/// precision on exactly the values that matter. `serde_json::value::RawValue`
/// hands back the original characters, so the fixed-point parser sees what the
/// venue actually wrote.
pub(crate) fn decimal_literal(
    field: &'static str,
    raw: &serde_json::value::RawValue,
) -> Result<Fixed, DecodeError> {
    decimal(field, raw.get().trim_matches('"'))
}

/// Converts an RFC 3339 timestamp to unix nanoseconds.
///
/// Coinbase stamps `2026-08-07T16:00:00.123456Z`. The only consumer is a
/// diagnostic field: staleness is measured with our own clock, never the
/// venue's.
///
/// Returns `None` for anything that is not RFC 3339 or is before the epoch,
/// which is the right outcome — a wrong timestamp in a lag metric is worse than
/// a missing one.
pub(crate) fn rfc3339_to_unix_nanos(text: &str) -> Option<u64> {
    let parsed =
        time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).ok()?;
    u64::try_from(parsed.unix_timestamp_nanos()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_parses_the_shapes_coinbase_sends() {
        // The epoch itself.
        assert_eq!(rfc3339_to_unix_nanos("1970-01-01T00:00:00Z"), Some(0));
        // A whole second, cross-checked against a known unix timestamp.
        assert_eq!(
            rfc3339_to_unix_nanos("2026-08-07T00:00:00Z"),
            Some(1_786_060_800 * 1_000_000_000)
        );
        // Microsecond precision, as Coinbase actually stamps it.
        assert_eq!(
            rfc3339_to_unix_nanos("2026-08-07T00:00:00.123456Z"),
            Some(1_786_060_800 * 1_000_000_000 + 123_456_000)
        );
        // Millisecond precision.
        assert_eq!(
            rfc3339_to_unix_nanos("2026-08-07T00:00:00.5Z"),
            Some(1_786_060_800 * 1_000_000_000 + 500_000_000)
        );
    }

    #[test]
    fn rfc3339_handles_leap_years_and_month_boundaries() {
        // 2024 is a leap year; 29 February must exist.
        let leap = rfc3339_to_unix_nanos("2024-02-29T00:00:00Z").expect("valid date");
        let march = rfc3339_to_unix_nanos("2024-03-01T00:00:00Z").expect("valid date");
        assert_eq!(march - leap, 86_400 * 1_000_000_000);

        // 2100 is not a leap year, which the naive rule gets wrong.
        let feb28 = rfc3339_to_unix_nanos("2100-02-28T00:00:00Z").expect("valid date");
        let mar01 = rfc3339_to_unix_nanos("2100-03-01T00:00:00Z").expect("valid date");
        assert_eq!(mar01 - feb28, 86_400 * 1_000_000_000);
    }

    #[test]
    fn rfc3339_refuses_what_it_cannot_read() {
        // A wrong timestamp in a lag metric is worse than a missing one.
        for bad in [
            "",
            "not a timestamp",
            "2026-08-07",
            "2026/08/07T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-08-00T00:00:00Z",
            "2026-02-31T00:00:00Z",
            "2026-08-07T25:00:00Z",
            "2026-08-07T00:00:00Zjunk",
            "1969-12-31T23:59:59Z",
        ] {
            assert_eq!(rfc3339_to_unix_nanos(bad), None, "should refuse {bad:?}");
        }
    }

    #[test]
    fn rfc3339_applies_utc_offsets() {
        let utc = rfc3339_to_unix_nanos("2026-08-07T00:00:00Z").expect("valid");
        assert_eq!(
            rfc3339_to_unix_nanos("2026-08-07T02:00:00+02:00"),
            Some(utc)
        );
        assert_eq!(
            rfc3339_to_unix_nanos("2026-08-06T19:30:00-04:30"),
            Some(utc)
        );
    }

    #[test]
    fn json_numbers_keep_their_literal_precision() {
        // Kraken sends bare numbers. The literal text must reach the parser.
        let raw: Box<serde_json::value::RawValue> =
            serde_json::from_str("64312.123456789012").expect("valid json");
        assert_eq!(
            decimal_literal("bid", &raw).expect("parses").to_string(),
            "64312.123456789012"
        );
    }

    #[test]
    fn quoted_and_bare_numbers_both_parse() {
        let quoted: Box<serde_json::value::RawValue> =
            serde_json::from_str("\"1.5\"").expect("valid json");
        assert_eq!(
            decimal_literal("p", &quoted).expect("parses").to_string(),
            "1.5"
        );
    }

    #[test]
    fn bad_decimals_name_the_offending_value() {
        assert_eq!(
            decimal("bid", "oops"),
            Err(DecodeError::BadDecimal {
                field: "bid",
                value: "oops".to_owned()
            })
        );
    }
}
