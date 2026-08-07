//! Robust statistics over fixed-point samples.
//!
//! Everything here is a pure function on exact `i128` fixed-point. No floating
//! point, so a recorded observation set replays to a bit-identical price.
//!
//! # Why medians rather than means
//!
//! A single venue printing an absurd value moves a mean without limit. It cannot
//! move a median past the neighbouring sample, whatever weight it carries. That
//! is precisely the attack the aggregator exists to survive, so every central
//! estimate here is a median and the property tests assert the bound directly.

use oracle_types::Fixed;

/// Scale factor converting a MAD into a standard-deviation estimate for a
/// normal distribution: `1 / Φ⁻¹(0.75) ≈ 1.4826`.
pub const MAD_TO_SIGMA: Fixed = Fixed::from_raw(1_482_602_218_506);

/// Returns the median.
///
/// Even-length input averages the two central samples. That is the conventional
/// definition and avoids the low bias that picking the lower of the two would
/// introduce with exactly two venues — the common case early in a deployment.
///
/// Sorts `values` in place.
#[must_use]
pub fn median(values: &mut [Fixed]) -> Option<Fixed> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        return values.get(mid).copied();
    }
    let (low, high) = (values.get(mid - 1)?, values.get(mid)?);
    Some(Fixed::from_raw(midpoint(low.raw(), high.raw())))
}

/// Returns `(a + b) / 2` without overflowing, rounding toward negative infinity.
///
/// `(a + b)` overflows for large same-signed operands, and halving a [`Fixed`]
/// through division would scale the mantissa up by `SCALE` first and overflow
/// even sooner. Working on the raw mantissas avoids both.
const fn midpoint(a: i128, b: i128) -> i128 {
    (a / 2) + (b / 2) + ((a % 2) + (b % 2)) / 2
}

/// Returns the weighted median.
///
/// The smallest sample whose cumulative weight reaches half the total. When the
/// cumulative weight lands exactly on half, the two straddling samples are
/// averaged, so equal weights reproduce [`median`] exactly.
///
/// Non-positive weights are ignored.
#[must_use]
pub fn weighted_median(samples: &[(Fixed, Fixed)]) -> Option<Fixed> {
    let mut samples: Vec<(Fixed, Fixed)> = samples
        .iter()
        .copied()
        .filter(|(_, weight)| weight.is_positive())
        .collect();
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    let mut total = Fixed::ZERO;
    for (_, weight) in &samples {
        total = total.checked_add(*weight)?;
    }
    let two = Fixed::from_int(2).ok()?;
    let half = total.checked_div(two)?;

    let mut cumulative = Fixed::ZERO;
    for (index, (value, weight)) in samples.iter().enumerate() {
        cumulative = cumulative.checked_add(*weight)?;
        if cumulative == half {
            // Exactly on the boundary: average with the next distinct sample,
            // mirroring the even-length unweighted case.
            return match samples.get(index + 1) {
                Some((next, _)) => value.checked_div(two)?.checked_add(next.checked_div(two)?),
                None => Some(*value),
            };
        }
        if cumulative > half {
            return Some(*value);
        }
    }
    samples.last().map(|(value, _)| *value)
}

/// Returns the median absolute deviation from `center`.
#[must_use]
pub fn mad(values: &[Fixed], center: Fixed) -> Option<Fixed> {
    let mut deviations: Vec<Fixed> = values
        .iter()
        .filter_map(|value| value.checked_sub(center)?.checked_abs())
        .collect();
    median(&mut deviations)
}

/// Returns the weighted median absolute deviation from `center`.
#[must_use]
pub fn weighted_mad(samples: &[(Fixed, Fixed)], center: Fixed) -> Option<Fixed> {
    let deviations: Vec<(Fixed, Fixed)> = samples
        .iter()
        .filter_map(|(value, weight)| Some((value.checked_sub(center)?.checked_abs()?, *weight)))
        .collect();
    weighted_median(&deviations)
}

/// Returns the weighted arithmetic mean.
///
/// Used only for averaging half-spreads, where there is no adversary to resist
/// and the mean is the right summary.
#[must_use]
pub fn weighted_mean(samples: &[(Fixed, Fixed)]) -> Option<Fixed> {
    let mut numerator = Fixed::ZERO;
    let mut denominator = Fixed::ZERO;
    for (value, weight) in samples {
        if !weight.is_positive() {
            continue;
        }
        numerator = numerator.checked_add(value.checked_mul(*weight)?)?;
        denominator = denominator.checked_add(*weight)?;
    }
    if !denominator.is_positive() {
        return None;
    }
    numerator.checked_div(denominator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("valid decimal")
    }

    fn fixeds(values: &[&str]) -> Vec<Fixed> {
        values.iter().copied().map(fixed).collect()
    }

    #[test]
    fn median_of_odd_and_even_lengths() {
        assert_eq!(median(&mut fixeds(&["3", "1", "2"])), Some(fixed("2")));
        assert_eq!(
            median(&mut fixeds(&["4", "1", "3", "2"])),
            Some(fixed("2.5"))
        );
        assert_eq!(median(&mut fixeds(&["7"])), Some(fixed("7")));
        assert_eq!(median(&mut []), None);
    }

    #[test]
    fn median_does_not_overflow_near_the_limits() {
        let mut values = vec![Fixed::MAX, Fixed::MAX];
        assert_eq!(median(&mut values), Some(Fixed::MAX));
    }

    #[test]
    fn weighted_median_with_equal_weights_matches_the_plain_median() {
        for values in [
            vec!["3", "1", "2"],
            vec!["4", "1", "3", "2"],
            vec!["10", "10", "20"],
            vec!["5"],
        ] {
            let plain = median(&mut fixeds(&values));
            let weighted: Vec<(Fixed, Fixed)> = fixeds(&values)
                .into_iter()
                .map(|v| (v, Fixed::ONE))
                .collect();
            assert_eq!(weighted_median(&weighted), plain, "mismatch for {values:?}");
        }
    }

    #[test]
    fn weight_shifts_the_median_toward_the_heavy_sample() {
        let samples = vec![(fixed("100"), Fixed::ONE), (fixed("200"), fixed("10"))];
        assert_eq!(weighted_median(&samples), Some(fixed("200")));
    }

    #[test]
    fn non_positive_weights_are_ignored() {
        let samples = vec![
            (fixed("100"), Fixed::ONE),
            (fixed("999999"), Fixed::ZERO),
            (fixed("-999999"), fixed("-5")),
            (fixed("102"), Fixed::ONE),
        ];
        assert_eq!(weighted_median(&samples), Some(fixed("101")));
    }

    /// An extreme sample at ordinary weight cannot move the median far.
    #[test]
    fn an_extreme_sample_at_ordinary_weight_barely_moves_the_median() {
        let honest = fixeds(&["100", "100.5", "101", "101.5"]);
        let baseline = median(&mut honest.clone()).expect("non-empty");

        for absurd in ["0.0001", "1000000", "-1000000"] {
            let mut samples: Vec<(Fixed, Fixed)> =
                honest.iter().map(|v| (*v, Fixed::ONE)).collect();
            samples.push((fixed(absurd), Fixed::ONE));
            let poisoned = weighted_median(&samples).expect("non-empty");
            let drift = poisoned.checked_sub(baseline).expect("in range");
            assert!(
                drift.checked_abs().expect("in range") <= fixed("0.5"),
                "{absurd} moved the median by {drift}"
            );
        }
    }

    /// **A weighted median offers no protection against weight itself.**
    ///
    /// Give one sample more than half the total weight and it *is* the answer,
    /// however absurd its value. This is the definition of the estimator, not a
    /// defect in it — but it matters here because the weight inputs (spread,
    /// freshness) are things a manipulating venue controls directly.
    ///
    /// Two things stand between that and the published price, and both live
    /// upstream in `aggregate`: outlier rejection runs first and is deliberately
    /// **unweighted**, and surviving weights are then capped relative to the
    /// median weight. This test exists to document why those are load-bearing.
    #[test]
    fn a_dominant_weight_captures_the_weighted_median() {
        let mut samples: Vec<(Fixed, Fixed)> = fixeds(&["100", "100.5", "101", "101.5"])
            .into_iter()
            .map(|v| (v, Fixed::ONE))
            .collect();
        samples.push((fixed("0.0001"), fixed("40")));
        assert_eq!(weighted_median(&samples), Some(fixed("0.0001")));
    }

    #[test]
    fn mad_measures_spread_not_center() {
        let values = fixeds(&["100", "101", "102", "103"]);
        let center = median(&mut values.clone()).expect("non-empty");
        assert_eq!(center, fixed("101.5"));
        assert_eq!(mad(&values, center), Some(fixed("1")));
        // Identical samples have zero deviation.
        assert_eq!(
            mad(&fixeds(&["5", "5", "5"]), fixed("5")),
            Some(Fixed::ZERO)
        );
    }

    #[test]
    fn weighted_mad_respects_weights() {
        let samples = vec![
            (fixed("100"), Fixed::ONE),
            (fixed("100"), Fixed::ONE),
            (fixed("120"), fixed("0.01")),
        ];
        // The far sample is nearly weightless, so the deviation stays near zero.
        assert_eq!(weighted_mad(&samples, fixed("100")), Some(Fixed::ZERO));
    }

    #[test]
    fn weighted_mean_is_a_mean() {
        let samples = vec![(fixed("100"), Fixed::ONE), (fixed("200"), fixed("3"))];
        assert_eq!(weighted_mean(&samples), Some(fixed("175")));
        assert_eq!(weighted_mean(&[]), None);
        assert_eq!(weighted_mean(&[(fixed("1"), Fixed::ZERO)]), None);
    }

    #[test]
    fn mad_to_sigma_constant() {
        // 1.4826 to twelve places, the standard normal-consistency factor.
        assert_eq!(MAD_TO_SIGMA.to_string(), "1.482602218506");
    }

    prop_compose! {
        fn sample_set()(values in prop::collection::vec(-1_000_000i128..1_000_000, 1..12))
            -> Vec<Fixed> {
            values.into_iter().map(Fixed::from_raw).collect()
        }
    }

    proptest! {
        #[test]
        fn median_lies_within_the_sample_range(values in sample_set()) {
            let result = median(&mut values.clone()).expect("non-empty");
            let low = values.iter().copied().min().expect("non-empty");
            let high = values.iter().copied().max().expect("non-empty");
            prop_assert!(result >= low && result <= high);
        }

        #[test]
        fn weighted_median_is_within_the_sample_range(values in sample_set()) {
            let samples: Vec<(Fixed, Fixed)> =
                values.iter().map(|v| (*v, Fixed::ONE)).collect();
            let result = weighted_median(&samples).expect("non-empty");
            let low = values.iter().copied().min().expect("non-empty");
            let high = values.iter().copied().max().expect("non-empty");
            prop_assert!(result >= low && result <= high);
        }

        #[test]
        fn median_is_order_independent(values in sample_set()) {
            let forward = median(&mut values.clone());
            let mut reversed = values.clone();
            reversed.reverse();
            prop_assert_eq!(forward, median(&mut reversed));
        }

        #[test]
        fn mad_is_never_negative(values in sample_set(), center in -1_000_000i128..1_000_000) {
            let result = mad(&values, Fixed::from_raw(center)).expect("non-empty");
            prop_assert!(result >= Fixed::ZERO);
        }

        /// Scaling every weight by the same positive factor must not change the
        /// answer — otherwise the weight units would leak into the price.
        #[test]
        fn weighted_median_is_scale_invariant_in_weights(
            values in sample_set(),
            scale in 1i128..1_000,
        ) {
            let unit: Vec<(Fixed, Fixed)> = values.iter().map(|v| (*v, Fixed::ONE)).collect();
            let scale = Fixed::from_int(i64::try_from(scale).unwrap_or(1)).expect("in range");
            let scaled: Vec<(Fixed, Fixed)> = values.iter().map(|v| (*v, scale)).collect();
            prop_assert_eq!(weighted_median(&unit), weighted_median(&scaled));
        }
    }
}
