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
pub mod bybit;
pub mod coinbase;
pub mod kraken;
pub mod okx;

pub use adapter::{DecodeFn, VenueAdapter, VenueHandler, VenueSpec};

use oracle_types::Fixed;

use crate::DecodeError;

/// Parses a decimal that arrived as a JSON string.
pub(crate) fn decimal(field: &'static str, value: &str) -> Result<Fixed, DecodeError> {
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
/// Coinbase stamps `2026-08-07T16:00:00.123456Z`. Implemented here rather than
/// pulling in a date library, because the only consumer is a diagnostic field:
/// staleness is measured with our own clock, never the venue's.
///
/// Returns `None` for anything it does not fully understand, which is the right
/// outcome — a wrong timestamp in a lag metric is worse than a missing one.
pub(crate) fn rfc3339_to_unix_nanos(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes.get(4) != Some(&b'-') || bytes.get(10) != Some(&b'T') {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> { text.get(range)?.parse().ok() };
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;

    // Fractional seconds, if present, to nanosecond resolution.
    let mut nanos = 0_u64;
    if bytes.get(19) == Some(&b'.') {
        let digits: String = text
            .get(20..)?
            .chars()
            .take_while(char::is_ascii_digit)
            .take(9)
            .collect();
        let scale = 9_u32.checked_sub(u32::try_from(digits.len()).ok()?)?;
        nanos = digits.parse::<u64>().ok()?.checked_mul(10_u64.pow(scale))?;
    }

    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    u64::try_from(seconds)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(nanos)
}

/// Days since the unix epoch, by Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_shift = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_shift + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
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
        ] {
            assert_eq!(rfc3339_to_unix_nanos(bad), None, "should refuse {bad:?}");
        }
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
