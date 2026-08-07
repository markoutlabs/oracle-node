//! Deterministic fixed-point arithmetic.
//!
//! Every price in this system is an [`Fixed`]: an `i128` mantissa at a fixed
//! scale of `10^-12`. There is no floating point anywhere in the pricing path.
//!
//! That is a deliberate constraint, not an aesthetic one. Aggregation must be a
//! pure function of its inputs so that a recorded observation set replays to a
//! bit-identical published price months later, during an incident review, on a
//! different machine. Floating point makes that reproducibility conditional on
//! evaluation order and compiler flags, which is exactly the kind of "it only
//! happens in production" the design is trying to eliminate.

use core::fmt;
use core::ops::Neg;
use core::str::FromStr;

/// Decimal exponent of the internal scale: values are stored as `mantissa * 10^-12`.
pub const SCALE_EXPO: i32 = -12;

/// Internal scale factor, `10^12`.
pub const SCALE: i128 = 1_000_000_000_000;

/// Longest input accepted by [`Fixed::from_str`], in significant digits.
///
/// Bounds parsing work on adversarial exchange payloads. Any real quote is far
/// under this.
const MAX_INPUT_DIGITS: usize = 48;

/// Errors from fixed-point construction, parsing, and arithmetic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FixedError {
    /// The value cannot be represented at the requested scale.
    #[error("fixed-point overflow")]
    Overflow,

    /// A divisor was zero.
    #[error("division by zero")]
    DivideByZero,

    /// The decimal exponent is outside the supported range.
    #[error("exponent {0} out of range")]
    ExponentOutOfRange(i32),

    /// The input string was not a valid decimal number.
    #[error("invalid decimal `{0}`")]
    InvalidDecimal(String),

    /// The value is negative where a non-negative value was required.
    #[error("value is negative")]
    Negative,
}

/// Powers of ten representable in `i128`. `10^38 < i128::MAX`.
#[expect(
    clippy::indexing_slicing,
    reason = "const evaluation with a literal bound; an out-of-range index is a compile error"
)]
const POW10: [i128; 39] = {
    let mut table = [1_i128; 39];
    let mut i = 1;
    while i < 39 {
        table[i] = table[i - 1] * 10;
        i += 1;
    }
    table
};

/// Returns `10^n`, or `None` if it does not fit in `i128`.
#[inline]
fn pow10(n: u32) -> Option<i128> {
    usize::try_from(n).ok().and_then(|n| POW10.get(n)).copied()
}

/// Divides, rounding halves away from zero.
///
/// Round-half-away-from-zero is chosen over banker's rounding because it is the
/// rule a human checking the arithmetic by hand will assume, and over truncation
/// because truncation introduces a systematic downward bias in prices.
#[inline]
fn div_round(num: i128, den: i128) -> Option<i128> {
    if den == 0 {
        return None;
    }
    let quot = num.checked_div(den)?;
    let rem = num % den;
    if rem == 0 {
        return Some(quot);
    }
    // Widened to u128 so the doubling cannot overflow for any i128 divisor.
    let round_up = rem.unsigned_abs() * 2 >= den.unsigned_abs();
    if !round_up {
        return Some(quot);
    }
    // `num` and `den` signs determine which way "away from zero" points.
    if (num < 0) == (den < 0) {
        quot.checked_add(1)
    } else {
        quot.checked_sub(1)
    }
}

/// A signed decimal fixed-point number with 12 fractional digits.
///
/// # Examples
///
/// ```
/// use oracle_types::Fixed;
///
/// let price: Fixed = "64312.5".parse()?;
/// assert_eq!(price.to_string(), "64312.5");
///
/// // Convert to the wire representation: mantissa at exponent -8.
/// assert_eq!(price.to_scaled(-8)?, 6_431_250_000_000);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct Fixed(i128);

impl Fixed {
    /// Zero.
    pub const ZERO: Self = Self(0);

    /// One.
    pub const ONE: Self = Self(SCALE);

    /// The largest representable value.
    pub const MAX: Self = Self(i128::MAX);

    /// The smallest representable value.
    pub const MIN: Self = Self(i128::MIN);

    /// Wraps a raw mantissa already at scale `10^-12`.
    #[inline]
    #[must_use]
    pub const fn from_raw(raw: i128) -> Self {
        Self(raw)
    }

    /// Returns the raw mantissa at scale `10^-12`.
    #[inline]
    #[must_use]
    pub const fn raw(self) -> i128 {
        self.0
    }

    /// Builds a value from a whole number.
    ///
    /// # Errors
    ///
    /// Returns [`FixedError::Overflow`] if the scaled value exceeds `i128`.
    pub fn from_int(value: i64) -> Result<Self, FixedError> {
        i128::from(value)
            .checked_mul(SCALE)
            .map(Self)
            .ok_or(FixedError::Overflow)
    }

    /// Builds a value from a mantissa and decimal exponent, as they appear on the wire.
    ///
    /// # Errors
    ///
    /// Returns [`FixedError::ExponentOutOfRange`] if `expo` cannot be applied, or
    /// [`FixedError::Overflow`] if the result does not fit.
    pub fn from_scaled(mantissa: i64, expo: i32) -> Result<Self, FixedError> {
        let shift = expo
            .checked_sub(SCALE_EXPO)
            .ok_or(FixedError::ExponentOutOfRange(expo))?;
        let mantissa = i128::from(mantissa);
        if shift >= 0 {
            let factor = u32::try_from(shift)
                .ok()
                .and_then(pow10)
                .ok_or(FixedError::ExponentOutOfRange(expo))?;
            mantissa
                .checked_mul(factor)
                .map(Self)
                .ok_or(FixedError::Overflow)
        } else {
            let divisor = shift
                .checked_neg()
                .and_then(|s| u32::try_from(s).ok())
                .and_then(pow10)
                .ok_or(FixedError::ExponentOutOfRange(expo))?;
            div_round(mantissa, divisor)
                .map(Self)
                .ok_or(FixedError::Overflow)
        }
    }

    /// Converts to a mantissa at the given decimal exponent, rounding halves away from zero.
    ///
    /// This is the conversion applied exactly once, at publish time, when an
    /// internally-computed price becomes a signed wire value.
    ///
    /// # Errors
    ///
    /// Returns [`FixedError::Overflow`] if the result does not fit in `i64`, or
    /// [`FixedError::ExponentOutOfRange`] if `expo` cannot be applied.
    pub fn to_scaled(self, expo: i32) -> Result<i64, FixedError> {
        let shift = expo
            .checked_sub(SCALE_EXPO)
            .ok_or(FixedError::ExponentOutOfRange(expo))?;
        let scaled = if shift >= 0 {
            let divisor = u32::try_from(shift)
                .ok()
                .and_then(pow10)
                .ok_or(FixedError::ExponentOutOfRange(expo))?;
            div_round(self.0, divisor).ok_or(FixedError::Overflow)?
        } else {
            let factor = shift
                .checked_neg()
                .and_then(|s| u32::try_from(s).ok())
                .and_then(pow10)
                .ok_or(FixedError::ExponentOutOfRange(expo))?;
            self.0.checked_mul(factor).ok_or(FixedError::Overflow)?
        };
        i64::try_from(scaled).map_err(|_| FixedError::Overflow)
    }

    /// Converts to an unsigned mantissa at the given decimal exponent.
    ///
    /// Used for confidence intervals, which are magnitudes and must never be negative.
    ///
    /// # Errors
    ///
    /// Returns [`FixedError::Negative`] if the value is below zero, and otherwise
    /// the same errors as [`Fixed::to_scaled`].
    pub fn to_scaled_unsigned(self, expo: i32) -> Result<u64, FixedError> {
        if self.0 < 0 {
            return Err(FixedError::Negative);
        }
        let scaled = self.to_scaled(expo)?;
        u64::try_from(scaled).map_err(|_| FixedError::Overflow)
    }

    /// Returns the absolute value, or `None` on `MIN`.
    #[inline]
    #[must_use]
    pub const fn checked_abs(self) -> Option<Self> {
        match self.0.checked_abs() {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Returns `-1`, `0`, or `1` matching the sign of the value.
    #[inline]
    #[must_use]
    pub const fn signum(self) -> i32 {
        if self.0 < 0 {
            -1
        } else if self.0 > 0 {
            1
        } else {
            0
        }
    }

    /// Returns `true` if the value is greater than zero.
    #[inline]
    #[must_use]
    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }

    /// Returns `true` if the value is exactly zero.
    #[inline]
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Adds, returning `None` on overflow.
    #[inline]
    #[must_use]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Subtracts, returning `None` on overflow.
    #[inline]
    #[must_use]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Multiplies, rounding halves away from zero.
    ///
    /// Returns `None` if the intermediate product overflows `i128`. With both
    /// operands under `10^19` in magnitude — every realistic price and weight —
    /// it cannot.
    #[inline]
    #[must_use]
    pub fn checked_mul(self, rhs: Self) -> Option<Self> {
        let product = self.0.checked_mul(rhs.0)?;
        div_round(product, SCALE).map(Self)
    }

    /// Divides, rounding halves away from zero.
    ///
    /// Returns `None` on division by zero or overflow.
    #[inline]
    #[must_use]
    pub fn checked_div(self, rhs: Self) -> Option<Self> {
        if rhs.0 == 0 {
            return None;
        }
        let numerator = self.0.checked_mul(SCALE)?;
        div_round(numerator, rhs.0).map(Self)
    }

    /// Saturating addition.
    #[inline]
    #[must_use]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Saturating subtraction.
    #[inline]
    #[must_use]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    /// Returns the square root, or `None` for negative values.
    ///
    /// `sqrt(m / S) = sqrt(m · S) / S`, so the mantissa is scaled up once before
    /// the integer root. Exact and deterministic — no floating point, and no
    /// dependence on the host's libm.
    #[inline]
    #[must_use]
    pub fn sqrt(self) -> Option<Self> {
        if self.0 < 0 {
            return None;
        }
        let radicand = self.0.checked_mul(SCALE)?;
        Some(Self(radicand.isqrt()))
    }

    /// Returns this value as a fraction of `reference`, in basis points.
    ///
    /// Returns `None` if `reference` is zero or the computation overflows.
    /// The result carries the sign of `self / reference`.
    #[inline]
    #[must_use]
    pub fn to_bps_of(self, reference: Self) -> Option<Self> {
        let ratio = self.checked_div(reference)?;
        ratio.checked_mul(Self(10_000 * SCALE))
    }
}

impl Neg for Fixed {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Self(self.0.wrapping_neg())
    }
}

impl fmt::Display for Fixed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let magnitude = self.0.unsigned_abs();
        // `SCALE` is positive, so this cast is exact.
        let scale = SCALE.unsigned_abs();
        let whole = magnitude / scale;
        let frac = magnitude % scale;

        if self.0 < 0 {
            f.write_str("-")?;
        }
        if frac == 0 {
            return write!(f, "{whole}");
        }
        // 12 fractional digits, trailing zeros trimmed.
        let mut digits = format!("{frac:012}");
        while digits.ends_with('0') {
            digits.pop();
        }
        write!(f, "{whole}.{digits}")
    }
}

impl fmt::Debug for Fixed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fixed({self})")
    }
}

impl FromStr for Fixed {
    type Err = FixedError;

    /// Parses a decimal, with optional sign and optional `e`/`E` exponent.
    ///
    /// Accepts the shapes exchanges actually emit: `"64312.50"`, `"0.00001234"`,
    /// `"-0.0001"`, `"1.234E-5"`. Digits beyond the 12th fractional place are
    /// rounded, not truncated.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || FixedError::InvalidDecimal(s.to_owned());
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(invalid());
        }

        let (negative, rest) = match trimmed.as_bytes().first() {
            Some(b'-') => (true, trimmed.get(1..).ok_or_else(invalid)?),
            Some(b'+') => (false, trimmed.get(1..).ok_or_else(invalid)?),
            _ => (false, trimmed),
        };

        // Split off a scientific-notation exponent, if present.
        let (mantissa_str, exponent) = match rest.find(['e', 'E']) {
            Some(idx) => {
                let (head, tail) = rest.split_at(idx);
                let exp_str = tail.get(1..).ok_or_else(invalid)?;
                let exp: i32 = exp_str.parse().map_err(|_| invalid())?;
                (head, exp)
            }
            None => (rest, 0),
        };

        let (int_part, frac_part) = match mantissa_str.split_once('.') {
            Some((int_part, frac_part)) => (int_part, frac_part),
            None => (mantissa_str, ""),
        };
        if int_part.is_empty() && frac_part.is_empty() {
            return Err(invalid());
        }
        if int_part.len() + frac_part.len() > MAX_INPUT_DIGITS {
            return Err(FixedError::Overflow);
        }

        let mut digits: i128 = 0;
        for byte in int_part.bytes().chain(frac_part.bytes()) {
            if !byte.is_ascii_digit() {
                return Err(invalid());
            }
            let digit = i128::from(byte - b'0');
            digits = digits
                .checked_mul(10)
                .and_then(|d| d.checked_add(digit))
                .ok_or(FixedError::Overflow)?;
        }

        // The value is `digits * 10^(exponent - frac_len)`; store it at 10^-12.
        let frac_len = i32::try_from(frac_part.len()).map_err(|_| FixedError::Overflow)?;
        let shift = exponent
            .checked_sub(frac_len)
            .and_then(|e| e.checked_sub(SCALE_EXPO))
            .ok_or(FixedError::ExponentOutOfRange(exponent))?;

        let raw = if shift >= 0 {
            let factor = u32::try_from(shift)
                .ok()
                .and_then(pow10)
                .ok_or(FixedError::Overflow)?;
            digits.checked_mul(factor).ok_or(FixedError::Overflow)?
        } else {
            let divisor = shift
                .checked_neg()
                .and_then(|s| u32::try_from(s).ok())
                .and_then(pow10)
                .ok_or(FixedError::Overflow)?;
            div_round(digits, divisor).ok_or(FixedError::Overflow)?
        };

        Ok(Self(if negative { -raw } else { raw }))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Fixed {
    /// Serializes as a decimal **string**.
    ///
    /// Never as a number: JSON numbers are `f64` in most consumers, and an
    /// `i128` mantissa does not survive that round trip.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Fixed {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_renders_plain_decimals() {
        let cases = [
            ("0", "0"),
            ("1", "1"),
            ("64312.5", "64312.5"),
            ("64312.50", "64312.5"),
            ("-0.0001", "-0.0001"),
            ("0.000000000001", "0.000000000001"),
            ("+7.25", "7.25"),
        ];
        for (input, expected) in cases {
            let parsed: Fixed = input.parse().expect("valid decimal");
            assert_eq!(parsed.to_string(), expected, "input {input}");
        }
    }

    #[test]
    fn parses_scientific_notation() {
        assert_eq!(
            "1.234E-5".parse::<Fixed>().expect("valid"),
            "0.00001234".parse().expect("valid")
        );
        assert_eq!(
            "5e3".parse::<Fixed>().expect("valid"),
            Fixed::from_int(5000).expect("in range")
        );
    }

    #[test]
    fn rounds_excess_precision_half_away_from_zero() {
        // 13 fractional digits: the last is dropped with rounding, not truncation.
        assert_eq!(
            "0.0000000000005".parse::<Fixed>().expect("valid"),
            Fixed::from_raw(1)
        );
        assert_eq!(
            "-0.0000000000005".parse::<Fixed>().expect("valid"),
            Fixed::from_raw(-1)
        );
        assert_eq!(
            "0.0000000000004".parse::<Fixed>().expect("valid"),
            Fixed::from_raw(0)
        );
    }

    #[test]
    fn rejects_malformed_input() {
        for input in ["", "  ", "abc", "1.2.3", "1,5", "--1", "1e", "0x10"] {
            assert!(input.parse::<Fixed>().is_err(), "should reject {input:?}");
        }
    }

    #[test]
    fn scaled_conversion_round_trips_at_wire_exponent() {
        let price: Fixed = "64312.5".parse().expect("valid");
        let mantissa = price.to_scaled(-8).expect("in range");
        assert_eq!(mantissa, 6_431_250_000_000);
        assert_eq!(Fixed::from_scaled(mantissa, -8).expect("in range"), price);
    }

    #[test]
    fn scaled_conversion_rounds_rather_than_truncates() {
        // 1.005 at exponent -2 is exactly halfway; round away from zero.
        let value: Fixed = "1.005".parse().expect("valid");
        assert_eq!(value.to_scaled(-2).expect("in range"), 101);
        let negative: Fixed = "-1.005".parse().expect("valid");
        assert_eq!(negative.to_scaled(-2).expect("in range"), -101);
    }

    #[test]
    fn unsigned_conversion_rejects_negatives() {
        let negative: Fixed = "-1".parse().expect("valid");
        assert_eq!(negative.to_scaled_unsigned(-8), Err(FixedError::Negative));
    }

    #[test]
    fn arithmetic_is_checked() {
        let two = Fixed::from_int(2).expect("in range");
        let three = Fixed::from_int(3).expect("in range");
        assert_eq!(
            two.checked_add(three),
            Some(Fixed::from_int(5).expect("in range"))
        );
        assert_eq!(
            two.checked_mul(three),
            Some(Fixed::from_int(6).expect("in range"))
        );
        assert_eq!(Fixed::MAX.checked_add(Fixed::ONE), None);
        assert_eq!(two.checked_div(Fixed::ZERO), None);
    }

    #[test]
    fn division_rounds_deterministically() {
        let one = Fixed::ONE;
        let three = Fixed::from_int(3).expect("in range");
        // 1/3 = 0.333333333333 (12 digits, rounded down at the 13th)
        assert_eq!(
            one.checked_div(three).expect("in range").to_string(),
            "0.333333333333"
        );
        // 2/3 = 0.666666666667 (rounded up)
        let two = Fixed::from_int(2).expect("in range");
        assert_eq!(
            two.checked_div(three).expect("in range").to_string(),
            "0.666666666667"
        );
    }

    #[test]
    fn square_roots_are_exact_where_they_can_be() {
        assert_eq!(
            Fixed::from_int(4).expect("in range").sqrt(),
            Fixed::from_int(2).ok()
        );
        assert_eq!(
            Fixed::from_int(9).expect("in range").sqrt(),
            Fixed::from_int(3).ok()
        );
        assert_eq!(Fixed::ZERO.sqrt(), Some(Fixed::ZERO));
        assert_eq!(Fixed::ONE.sqrt(), Some(Fixed::ONE));
        // sqrt(2) to twelve places, truncated by the integer root.
        assert_eq!(
            Fixed::from_int(2)
                .expect("in range")
                .sqrt()
                .expect("non-negative")
                .to_string(),
            "1.414213562373"
        );
        assert_eq!(Fixed::from_int(-1).expect("in range").sqrt(), None);
    }

    #[test]
    fn bps_of_reference() {
        let diff: Fixed = "6.43125".parse().expect("valid");
        let reference: Fixed = "64312.5".parse().expect("valid");
        assert_eq!(
            diff.to_bps_of(reference).expect("in range").to_string(),
            "1"
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_uses_strings_not_json_numbers() {
        let value: Fixed = "64312.5".parse().expect("valid");
        let json = serde_json::to_string(&value).expect("serializes");
        assert_eq!(json, "\"64312.5\"");
        let back: Fixed = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, value);
    }

    proptest::proptest! {
        #[test]
        fn display_parse_round_trips(raw in i128::MIN / 2..i128::MAX / 2) {
            let value = Fixed::from_raw(raw);
            let parsed: Fixed = value.to_string().parse().expect("display output is parseable");
            proptest::prop_assert_eq!(parsed, value);
        }

        #[test]
        fn scaled_round_trip_is_lossless_within_range(mantissa in -1_000_000_000_000_i64..1_000_000_000_000_i64) {
            let value = Fixed::from_scaled(mantissa, -8).expect("in range");
            proptest::prop_assert_eq!(value.to_scaled(-8).expect("in range"), mantissa);
        }

        #[test]
        fn sqrt_squared_is_close_to_the_input(raw in 0i128..1_000_000_000_000_000) {
            let value = Fixed::from_raw(raw);
            let root = value.sqrt().expect("non-negative");
            let squared = root.checked_mul(root).expect("in range");
            // Truncation loses at most one unit in the last place of the root,
            // so the square is within 2*root+1 raw units below the input.
            let tolerance = Fixed::from_raw(root.raw().saturating_mul(2).saturating_add(1));
            proptest::prop_assert!(squared <= value);
            proptest::prop_assert!(value.checked_sub(squared).expect("in range") <= tolerance);
        }

        #[test]
        fn addition_is_commutative(a in -1_000_000_i128..1_000_000, b in -1_000_000_i128..1_000_000) {
            let (a, b) = (Fixed::from_raw(a), Fixed::from_raw(b));
            proptest::prop_assert_eq!(a.checked_add(b), b.checked_add(a));
        }
    }
}
