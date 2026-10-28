//! Transforms that turn a clean recording into an attack (SPEC §10).
//!
//! Each function rewrites the frames of one venue connection, identified by its
//! host, and leaves everything else byte for byte. Replaying the result through
//! [`crate::run`] and comparing with the clean replay is the adversarial suite:
//! one venue lies, and the aggregator must degrade or halt rather than publish a
//! confidently wrong price.
//!
//! Prices are rewritten inside the venue JSON wherever a venue puts them: Binance
//! `b`/`a`/`p` strings, Bybit `b`/`a` level arrays and `p` prints, OKX
//! `bids`/`asks` level arrays and `px` prints. Quantities are left alone. The
//! arithmetic is fixed point, so a transform is exact and reproducible.

use oracle_ingest::Record;
use oracle_types::Fixed;
use serde_json::Value;

/// Host of Binance spot streams.
pub const BINANCE_SPOT: &str = "stream.binance.com";
/// Host of Bybit spot streams.
pub const BYBIT_SPOT: &str = "stream.bybit.com";
/// Host of OKX public streams.
pub const OKX: &str = "ws.okx.com";

/// Multiplies every price one venue sends in `[from_ns, until_ns)` by `factor`.
///
/// A factor of `1.10` from some instant onward is a ten percent jump on one
/// venue; `1.50` over a short window is a spoofed print.
#[must_use]
pub fn scale_prices(
    records: &[Record],
    host: &str,
    factor: Fixed,
    from_ns: u64,
    until_ns: u64,
) -> Vec<Record> {
    rewrite(records, host, from_ns, until_ns, |value, _| {
        map_prices(value, &|price| price.checked_mul(factor));
    })
}

/// Drifts one venue's prices away linearly: `bps_per_second` basis points for
/// every second since `from_ns`. Slow enough to stay inside the outlier band
/// for a while, which is the point.
#[must_use]
pub fn drift_prices(
    records: &[Record],
    host: &str,
    bps_per_second: i64,
    from_ns: u64,
) -> Vec<Record> {
    let per_second = Fixed::from_int(bps_per_second)
        .ok()
        .and_then(|bps| bps.checked_div(Fixed::from_int(10_000).ok()?));
    rewrite(records, host, from_ns, u64::MAX, |value, t| {
        let Some(per_second) = per_second else {
            return;
        };
        // Nanoseconds are 1000 raw units at the 1e-12 scale, so this is exact.
        let elapsed_s =
            Fixed::from_raw(i128::from(t.saturating_sub(from_ns)).saturating_mul(1_000));
        let Some(factor) = per_second
            .checked_mul(elapsed_s)
            .and_then(|growth| Fixed::ONE.checked_add(growth))
        else {
            return;
        };
        map_prices(value, &|price| price.checked_mul(factor));
    })
}

/// Crosses one venue's book from `from_ns`: every ask is set below its bid.
///
/// A crossed book is a broken venue, not a price. The quote derivation drops
/// it and falls through to the venue's prints.
#[must_use]
pub fn cross_book(records: &[Record], host: &str, from_ns: u64) -> Vec<Record> {
    let below = "0.999".parse::<Fixed>().ok();
    rewrite(records, host, from_ns, u64::MAX, |value, _| {
        if let Some(below) = below {
            cross(value, below);
        }
    })
}

/// Drops every frame one venue sends from `from_ns`, as if it went silent on a
/// connection that stays open. Staleness has to shed it.
#[must_use]
pub fn silence(records: &[Record], host: &str, from_ns: u64) -> Vec<Record> {
    records
        .iter()
        .filter(|record| {
            !(record.url().contains(host)
                && record.time_ns() >= from_ns
                && matches!(
                    record,
                    Record::Text { .. } | Record::Rest { .. } | Record::Binary { .. }
                ))
        })
        .cloned()
        .collect()
}

/// Freezes one venue from `from_ns`: every later frame repeats the last frame
/// it sent before, at its original time. The venue looks alive and is not.
#[must_use]
pub fn freeze(records: &[Record], host: &str, from_ns: u64) -> Vec<Record> {
    let last = records
        .iter()
        .filter(|record| record.url().contains(host) && record.time_ns() < from_ns)
        .filter_map(|record| match record {
            Record::Text { text, .. } => Some(text.clone()),
            _ => None,
        })
        .next_back();
    let Some(last) = last else {
        return records.to_vec();
    };
    records
        .iter()
        .map(|record| match record {
            Record::Text { t, url, .. } if url.contains(host) && *t >= from_ns => Record::Text {
                t: *t,
                url: url.clone(),
                text: last.clone(),
            },
            other => other.clone(),
        })
        .collect()
}

/// Applies `edit` to the parsed JSON of every text frame on `host` in range.
fn rewrite(
    records: &[Record],
    host: &str,
    from_ns: u64,
    until_ns: u64,
    edit: impl Fn(&mut Value, u64),
) -> Vec<Record> {
    records
        .iter()
        .map(|record| match record {
            Record::Text { t, url, text }
                if url.contains(host) && *t >= from_ns && *t < until_ns =>
            {
                let Ok(mut value) = serde_json::from_str::<Value>(text) else {
                    return record.clone();
                };
                edit(&mut value, *t);
                Record::Text {
                    t: *t,
                    url: url.clone(),
                    text: value.to_string(),
                }
            }
            other => other.clone(),
        })
        .collect()
}

/// Rewrites every price-bearing field in a venue message.
fn map_prices(value: &mut Value, f: &dyn Fn(Fixed) -> Option<Fixed>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                match (key.as_str(), &mut *child) {
                    // Binance book top and prints, Bybit prints, OKX prints.
                    ("b" | "a" | "p" | "px", Value::String(text)) => {
                        if let Some(scaled) = scale_decimal(text, f) {
                            *text = scaled;
                        }
                    }
                    // Bybit and OKX levels: `[[price, qty, ...], ...]`.
                    ("b" | "a" | "bids" | "asks", Value::Array(levels)) => {
                        for level in levels.iter_mut() {
                            if let Some(Value::String(text)) =
                                level.as_array_mut().and_then(|l| l.first_mut())
                                && let Some(scaled) = scale_decimal(text, f)
                            {
                                *text = scaled;
                            }
                        }
                    }
                    _ => map_prices(child, f),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                map_prices(item, f);
            }
        }
        _ => {}
    }
}

/// Sets every ask to `below` times its bid.
fn cross(value: &mut Value, below: Fixed) {
    match value {
        Value::Object(map) => {
            let bid = map
                .get("b")
                .and_then(first_price)
                .or_else(|| map.get("bids").and_then(first_price));
            if let Some(bid) = bid
                && let Some(crossed) = bid.checked_mul(below)
            {
                for key in ["a", "asks"] {
                    match map.get_mut(key) {
                        Some(Value::String(text)) => *text = crossed.to_string(),
                        Some(Value::Array(levels)) => {
                            if let Some(Value::String(text)) = levels
                                .first_mut()
                                .and_then(|l| l.as_array_mut())
                                .and_then(|l| l.first_mut())
                            {
                                *text = crossed.to_string();
                            }
                        }
                        _ => {}
                    }
                }
            }
            for child in map.values_mut() {
                cross(child, below);
            }
        }
        Value::Array(items) => {
            for item in items {
                cross(item, below);
            }
        }
        _ => {}
    }
}

/// The price in a `"123.4"` string or a `[["123.4", ...], ...]` level list.
fn first_price(value: &Value) -> Option<Fixed> {
    match value {
        Value::String(text) => text.parse().ok(),
        Value::Array(levels) => levels.first()?.as_array()?.first()?.as_str()?.parse().ok(),
        _ => None,
    }
}

fn scale_decimal(text: &str, f: &dyn Fn(Fixed) -> Option<Fixed>) -> Option<String> {
    let price: Fixed = text.parse().ok()?;
    f(price).map(|scaled| scaled.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(t: u64, host: &str, text: &str) -> Record {
        Record::Text {
            t,
            url: format!("wss://{host}/x"),
            text: text.to_owned(),
        }
    }

    #[test]
    fn scaling_touches_prices_on_every_venue_shape_and_nothing_else() {
        let records = vec![
            text(
                10,
                BINANCE_SPOT,
                r#"{"data":{"b":"100","B":"2","a":"101","A":"3"}}"#,
            ),
            text(10, BINANCE_SPOT, r#"{"data":{"p":"100.5","q":"7"}}"#),
            text(
                10,
                BYBIT_SPOT,
                r#"{"data":{"b":[["100","2"]],"a":[["101","3"]]}}"#,
            ),
            text(10, BYBIT_SPOT, r#"{"data":[{"p":"100.5","v":"7"}]}"#),
            text(
                10,
                OKX,
                r#"{"data":[{"bids":[["100","2","0","1"]],"asks":[["101","3","0","1"]]}]}"#,
            ),
            text(10, OKX, r#"{"data":[{"px":"100.5","sz":"7"}]}"#),
            text(5, BINANCE_SPOT, r#"{"data":{"b":"100","a":"101"}}"#),
        ];
        let two = Fixed::from_int(2).expect("fits");
        let mut out = Vec::new();
        for host in [BINANCE_SPOT, BYBIT_SPOT, OKX] {
            out = scale_prices(
                if out.is_empty() { &records } else { &out },
                host,
                two,
                10,
                u64::MAX,
            );
        }
        let texts: Vec<&str> = out
            .iter()
            .filter_map(|r| match r {
                Record::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            texts,
            [
                r#"{"data":{"A":"3","B":"2","a":"202","b":"200"}}"#,
                r#"{"data":{"p":"201","q":"7"}}"#,
                r#"{"data":{"a":[["202","3"]],"b":[["200","2"]]}}"#,
                r#"{"data":[{"p":"201","v":"7"}]}"#,
                r#"{"data":[{"asks":[["202","3","0","1"]],"bids":[["200","2","0","1"]]}]}"#,
                r#"{"data":[{"px":"201","sz":"7"}]}"#,
                // Before `from_ns`: untouched, not even re-serialised.
                r#"{"data":{"b":"100","a":"101"}}"#,
            ]
        );
    }

    #[test]
    fn crossing_puts_every_ask_below_its_bid() {
        let records = vec![
            text(10, BINANCE_SPOT, r#"{"data":{"b":"100","a":"101"}}"#),
            text(
                10,
                OKX,
                r#"{"data":[{"bids":[["100","2"]],"asks":[["101","3"]]}]}"#,
            ),
        ];
        let out = cross_book(&cross_book(&records, BINANCE_SPOT, 0), OKX, 0);
        let texts: Vec<&str> = out
            .iter()
            .filter_map(|r| match r {
                Record::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            texts,
            [
                r#"{"data":{"a":"99.9","b":"100"}}"#,
                r#"{"data":[{"asks":[["99.9","3"]],"bids":[["100","2"]]}]}"#,
            ]
        );
    }

    #[test]
    fn silence_and_freeze_keep_the_connection_and_change_the_frames() {
        let records = vec![
            Record::Connect {
                t: 1,
                url: "wss://stream.binance.com/x".to_owned(),
            },
            text(2, BINANCE_SPOT, "first"),
            text(3, BINANCE_SPOT, "second"),
            text(4, BINANCE_SPOT, "third"),
            text(4, OKX, "okx"),
        ];
        let silent = silence(&records, BINANCE_SPOT, 3);
        assert_eq!(silent.len(), 3);
        let frozen = freeze(&records, BINANCE_SPOT, 3);
        let texts: Vec<String> = frozen
            .iter()
            .filter_map(|r| match r {
                Record::Text { text, url, .. } if url.contains(BINANCE_SPOT) => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(texts, ["first", "first", "first"]);
    }

    #[test]
    fn drift_grows_with_time() {
        let records = vec![
            text(0, BINANCE_SPOT, r#"{"data":{"b":"10000","a":"10000"}}"#),
            text(
                1_000_000_000,
                BINANCE_SPOT,
                r#"{"data":{"b":"10000","a":"10000"}}"#,
            ),
            text(
                2_000_000_000,
                BINANCE_SPOT,
                r#"{"data":{"b":"10000","a":"10000"}}"#,
            ),
        ];
        let out = drift_prices(&records, BINANCE_SPOT, 50, 0);
        let prices: Vec<String> = out
            .iter()
            .filter_map(|r| match r {
                Record::Text { text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect();
        let bids: Vec<bool> = prices
            .iter()
            .zip([r#""b":"10000""#, r#""b":"10050""#, r#""b":"10100""#])
            .map(|(text, want)| text.contains(want))
            .collect();
        assert_eq!(bids, [true, true, true], "{prices:?}");
    }
}
