//! The logical price update: the unit that gets signed.
//!
//! The byte encoding lives in `oracle-wire`. This crate holds only the shape,
//! so that nothing here depends on a cryptographic library.

use crate::{FeedId, Fixed, FixedError, Flags, VenueSet};

/// One node's signed assertion about one feed at one instant.
///
/// # Field semantics that are easy to get wrong
///
/// - `observation_time_ns` is the freshest market data that fed this price;
///   `publish_time_ns` is when the node signed it. Staleness checks want the
///   former, replay checks want the latter.
/// - `seq` is monotonic per `(node, feed)` and never reused. It is the only
///   defence against a relay replaying an old, perfectly-valid signature.
/// - `num_sources` and `sources` are **claims**. Nothing binds them to reality;
///   a node that never connected to an exchange can sign whatever it likes. The
///   defence against a lying node is the median across nodes, not the signature.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct PriceUpdate {
    /// The feed this update is for.
    pub feed_id: FeedId,

    /// Status bits.
    pub flags: Flags,

    /// Price mantissa, to be read at `expo`.
    #[cfg_attr(feature = "serde", serde(with = "num_str"))]
    pub price: i64,

    /// Confidence half-width mantissa, at the same `expo` as `price`.
    #[cfg_attr(feature = "serde", serde(with = "num_str"))]
    pub conf: u64,

    /// Decimal exponent applied to both `price` and `conf`.
    pub expo: i32,

    /// When the node signed this update, in unix nanoseconds.
    #[cfg_attr(feature = "serde", serde(with = "num_str"))]
    pub publish_time_ns: u64,

    /// The newest contributing observation's receipt time, in unix nanoseconds.
    #[cfg_attr(feature = "serde", serde(with = "num_str"))]
    pub observation_time_ns: u64,

    /// This node's previous `publish_time_ns` for this feed, or `0` if none.
    #[cfg_attr(feature = "serde", serde(with = "num_str"))]
    pub prev_publish_time_ns: u64,

    /// Monotonic sequence number for this `(node, feed)` pair.
    #[cfg_attr(feature = "serde", serde(with = "num_str"))]
    pub seq: u64,

    /// Number of venues claimed to have contributed.
    pub num_sources: u32,

    /// Which venues are claimed to have contributed.
    pub sources: VenueSet,
}

impl PriceUpdate {
    /// Returns the price as a [`Fixed`].
    ///
    /// # Errors
    ///
    /// Returns [`FixedError`] if the mantissa and exponent do not fit the
    /// internal fixed-point range.
    pub fn price_fixed(&self) -> Result<Fixed, FixedError> {
        Fixed::from_scaled(self.price, self.expo)
    }

    /// Returns the confidence half-width as a [`Fixed`].
    ///
    /// # Errors
    ///
    /// Returns [`FixedError`] if the mantissa and exponent do not fit the
    /// internal fixed-point range.
    pub fn conf_fixed(&self) -> Result<Fixed, FixedError> {
        let mantissa = i64::try_from(self.conf).map_err(|_| FixedError::Overflow)?;
        Fixed::from_scaled(mantissa, self.expo)
    }

    /// Returns the confidence as a fraction of the price, in basis points.
    ///
    /// Returns `None` if the price is zero or the conversion overflows. This is
    /// the number to alert on: it is how the oracle says "I am unsure" without
    /// going dark.
    #[must_use]
    pub fn conf_bps(&self) -> Option<Fixed> {
        let price = self.price_fixed().ok()?.checked_abs()?;
        self.conf_fixed().ok()?.to_bps_of(price)
    }

    /// Returns how stale the underlying market data is, in nanoseconds.
    ///
    /// Measured from `observation_time_ns`, not `publish_time_ns`: a node can
    /// sign a fresh envelope around stale data.
    #[must_use]
    pub const fn observation_age_ns(&self, now_ns: u64) -> u64 {
        now_ns.saturating_sub(self.observation_time_ns)
    }

    /// Returns `true` if this update may be used for settlement.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.flags.is_usable()
    }

    /// Returns `true` if `num_sources` agrees with the `sources` bitmap.
    ///
    /// A producer must maintain this. It is deliberately **not** enforced when
    /// decoding: a future revision may carry more than 32 venues, at which point
    /// `num_sources` legitimately exceeds the bitmap's population count, and a
    /// v1 verifier that rejected such updates would fail on valid data.
    #[must_use]
    pub const fn sources_consistent(&self) -> bool {
        self.num_sources == self.sources.len()
    }

    /// Returns `true` if the timestamps are internally coherent.
    ///
    /// Data cannot be observed after it was published, and a node's previous
    /// publish cannot be in this update's future.
    #[must_use]
    pub const fn timestamps_coherent(&self) -> bool {
        self.observation_time_ns <= self.publish_time_ns
            && self.prev_publish_time_ns <= self.publish_time_ns
    }
}

/// Serializes 64-bit integers as JSON strings.
///
/// JSON numbers are IEEE-754 doubles in most consumers. A nanosecond unix
/// timestamp is around `1.75e18`, far past the `2^53` limit where doubles stop
/// being exact — a JavaScript client parsing `publish_time_ns` as a number gets
/// a silently wrong value and a broken replay check. Strings avoid the entire
/// class of problem, so every 64-bit field crosses as one.
#[cfg(feature = "serde")]
mod num_str {
    use core::fmt::Display;
    use core::str::FromStr;
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(super) fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Display,
        S: Serializer,
    {
        serializer.collect_str(value)
    }

    pub(super) fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Venue;

    fn sample() -> PriceUpdate {
        PriceUpdate {
            feed_id: FeedId::from_bytes([0x11; 32]),
            flags: Flags::NONE,
            price: 6_431_250_000_000,
            conf: 3_200_000,
            expo: -8,
            publish_time_ns: 1_754_582_400_123_456_789,
            observation_time_ns: 1_754_582_400_121_000_000,
            prev_publish_time_ns: 1_754_582_399_123_456_789,
            seq: 918_273,
            num_sources: 3,
            sources: [Venue::Binance, Venue::Coinbase, Venue::Kraken]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn price_and_conf_convert_to_fixed() {
        let update = sample();
        assert_eq!(
            update.price_fixed().expect("in range").to_string(),
            "64312.5"
        );
        assert_eq!(update.conf_fixed().expect("in range").to_string(), "0.032");
    }

    #[test]
    fn conf_bps_is_a_fraction_of_price() {
        let update = sample();
        // 0.032 / 64312.5 = 4.976e-7 -> 0.004976 bps
        let bps = update.conf_bps().expect("nonzero price");
        assert!(bps.is_positive());
        assert!(bps < "0.01".parse().expect("valid"), "got {bps}");
    }

    #[test]
    fn observation_age_uses_observation_time() {
        let update = sample();
        let now = update.publish_time_ns;
        assert_eq!(update.observation_age_ns(now), 2_456_789);
        assert_eq!(update.observation_age_ns(0), 0);
    }

    #[test]
    fn source_count_consistency_is_checkable() {
        let mut update = sample();
        assert!(update.sources_consistent());
        update.num_sources = 5;
        assert!(!update.sources_consistent());
    }

    #[test]
    fn timestamp_coherence_is_checkable() {
        let mut update = sample();
        assert!(update.timestamps_coherent());
        update.observation_time_ns = update.publish_time_ns + 1;
        assert!(!update.timestamps_coherent());
    }

    #[test]
    fn halted_updates_are_not_usable() {
        let mut update = sample();
        assert!(update.is_usable());
        update.flags = Flags::HALTED;
        assert!(!update.is_usable());
        // Degraded is still usable; the widened conf is the signal.
        update.flags = Flags::DEGRADED;
        assert!(update.is_usable());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn json_encodes_64_bit_fields_as_strings() {
        let update = sample();
        let json = serde_json::to_value(update).expect("serializes");
        let field = |name: &str| json.get(name).cloned().unwrap_or(serde_json::Value::Null);
        assert!(
            field("publish_time_ns").is_string(),
            "timestamps must not be JSON numbers"
        );
        assert!(field("price").is_string());
        assert!(field("conf").is_string());
        assert!(field("seq").is_string());
        assert_eq!(field("publish_time_ns"), "1754582400123456789");
        // Small fields stay numeric: they are exact as doubles.
        assert!(field("expo").is_number());
        assert!(field("num_sources").is_number());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn json_round_trips_without_precision_loss() {
        let update = sample();
        let json = serde_json::to_string(&update).expect("serializes");
        let back: PriceUpdate = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, update);
        assert_eq!(back.publish_time_ns, 1_754_582_400_123_456_789);
    }
}
