//! The aggregation pipeline: quotes in, one price and confidence out.
//!
//! A pure function of `(config, quotes, reference, last_price)`. No clock, no
//! I/O, no async, no interior state. Every production incident becomes a unit
//! test by construction.
//!
//! # The governing bias
//!
//! **Degrade loudly, halt rarely, never silently narrow.** An oracle that goes
//! dark breaks its consumers; one that publishes a confident wrong number
//! liquidates them. Widening the confidence interval is the pressure-release
//! valve, and almost every failure path here reaches for it before it reaches
//! for a halt.

use oracle_types::{Fixed, Flags, VenueSet};

use crate::config::FeedConfig;
use crate::quote::{self, SourceQuote};
use crate::stats::{self, MAD_TO_SIGMA};

/// Basis points in one whole unit.
const BPS_PER_UNIT: Fixed = Fixed::from_raw(10_000 * 1_000_000_000_000);

/// Why an aggregation degraded or halted.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Reasons(u16);

impl Reasons {
    /// No concerns.
    pub const NONE: Self = Self(0);
    /// Fewer live sources than the feed requires.
    pub const INSUFFICIENT_SOURCES: Self = Self(1 << 0);
    /// Sources disagree and none can be dropped: rejection would breach the
    /// quorum, or two sources differ beyond the outlier floor with no majority to
    /// say which is wrong.
    pub const OUTLIER_PRESSURE: Self = Self(1 << 1);
    /// The price jumped without enough venues corroborating it.
    pub const UNCORROBORATED_JUMP: Self = Self(1 << 2);
    /// The price left the sanity band around its reference.
    pub const SANITY_BAND: Self = Self(1 << 3);
    /// At least one venue had no usable book and fell back to a trade print.
    pub const TRADE_FALLBACK: Self = Self(1 << 4);
    /// At least one source was converted through a peg feed.
    pub const SYNTHETIC_QUOTE: Self = Self(1 << 5);
    /// The peg feed needed for conversion was missing or unusable.
    pub const PEG_UNAVAILABLE: Self = Self(1 << 6);
    /// The peg feed is live but its own confidence is too wide to lean on.
    pub const PEG_UNCERTAIN: Self = Self(1 << 7);

    /// Returns the raw bits, for metrics labels.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns `true` if every reason in `other` is present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns `true` if no reasons are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns these reasons as publishable status flags.
    ///
    /// [`Reasons::TRADE_FALLBACK`] alone does not degrade a feed: a venue falling
    /// back to its last trade is normal on a thin instrument, and treating it as
    /// a fault would keep half the catalogue permanently degraded. It is recorded
    /// for metrics, and its effect on the price shows up as a wider confidence
    /// interval through the missing spread term.
    #[must_use]
    pub const fn to_flags(self) -> Flags {
        let mut bits = 0_u16;
        if self.contains(Self::SYNTHETIC_QUOTE) {
            bits |= Flags::SYNTHETIC_QUOTE.bits();
        }
        if self.0 & (Self::OUTLIER_PRESSURE.0 | Self::UNCORROBORATED_JUMP.0 | Self::PEG_UNCERTAIN.0)
            != 0
        {
            bits |= Flags::DEGRADED.bits();
        }
        match Flags::from_bits(bits) {
            Some(flags) => flags,
            None => Flags::NONE,
        }
    }
}

impl core::ops::BitOr for Reasons {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for Reasons {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl core::fmt::Debug for Reasons {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_empty() {
            return f.write_str("Reasons(NONE)");
        }
        let mut set = f.debug_set();
        for (reason, name) in [
            (Self::INSUFFICIENT_SOURCES, "INSUFFICIENT_SOURCES"),
            (Self::OUTLIER_PRESSURE, "OUTLIER_PRESSURE"),
            (Self::UNCORROBORATED_JUMP, "UNCORROBORATED_JUMP"),
            (Self::SANITY_BAND, "SANITY_BAND"),
            (Self::TRADE_FALLBACK, "TRADE_FALLBACK"),
            (Self::SYNTHETIC_QUOTE, "SYNTHETIC_QUOTE"),
            (Self::PEG_UNAVAILABLE, "PEG_UNAVAILABLE"),
            (Self::PEG_UNCERTAIN, "PEG_UNCERTAIN"),
        ] {
            if self.contains(reason) {
                set.entry(&name);
            }
        }
        set.finish()
    }
}

/// A formed price.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aggregation {
    /// The aggregate price.
    pub price: Fixed,
    /// Symmetric confidence half-width, in price units.
    pub conf: Fixed,
    /// Status flags to publish.
    pub flags: Flags,
    /// Why it degraded, if it did.
    pub reasons: Reasons,
    /// Which venues contributed after filtering.
    pub sources: VenueSet,
    /// How many venues contributed.
    pub num_sources: u32,
    /// How many quotes outlier rejection dropped.
    pub rejected: u32,
    /// Freshest contributing observation, on our clock.
    pub observation_time_ns: u64,
}

/// The result of trying to form a price.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A price was formed.
    Priced(Box<Aggregation>),
    /// No usable price. The caller republishes its last good value, flagged
    /// [`Flags::HALTED`], so consumers have something to render but nothing to
    /// settle against.
    Halted {
        /// Why.
        reasons: Reasons,
        /// How many sources survived filtering.
        live: u32,
    },
}

/// A peg feed's current reading, for converting stablecoin-quoted sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peg {
    /// The peg's price, such as USDT measured in USD.
    pub price: Fixed,
    /// The peg's own confidence half-width.
    pub conf: Fixed,
}

impl Peg {
    /// Returns the peg's confidence as a fraction of its price, in basis points.
    #[must_use]
    pub fn conf_bps(&self) -> Option<Fixed> {
        self.conf.to_bps_of(self.price.checked_abs()?)
    }
}

/// Converts stablecoin-quoted prices into the feed's quote asset.
///
/// Returns `false` if the peg is unusable, in which case the caller must halt
/// rather than publish unconverted prices under a `/USD` symbol.
fn apply_peg(quotes: &mut [SourceQuote], peg: Peg) -> bool {
    if !peg.price.is_positive() {
        return false;
    }
    for quote in quotes {
        if !quote.converted {
            continue;
        }
        let Some(price) = quote.price.checked_mul(peg.price) else {
            return false;
        };
        quote.price = price;
        // The spread is quoted in the same asset, so it converts too.
        quote.half_spread = quote.half_spread.and_then(|s| s.checked_mul(peg.price));
    }
    true
}

/// Widens a confidence to absorb the peg's own uncertainty.
///
/// Relative errors add in quadrature: `rel² = rel_price² + rel_peg²`.
///
/// Applied to the whole aggregate even when only some sources were converted.
/// That is deliberately conservative — the alternative is tracking per-source
/// uncertainty through the median, and erring wide is the right direction for a
/// number consumers use to decide whether to trust the price.
fn widen_for_peg(price: Fixed, conf: Fixed, peg: Peg) -> Option<Fixed> {
    let magnitude = price.checked_abs()?;
    if !magnitude.is_positive() {
        return Some(conf);
    }
    let rel_price = conf.checked_div(magnitude)?;
    let rel_peg = peg.conf.checked_div(peg.price.checked_abs()?)?;
    let sum = rel_price
        .checked_mul(rel_price)?
        .checked_add(rel_peg.checked_mul(rel_peg)?)?;
    let combined = sum.sqrt()?;
    magnitude.checked_mul(combined)
}

/// Aggregates one feed's quotes.
///
/// `reference` is the slow EMA used for the sanity band, and `last_price` is this
/// node's previous publication, used for jump detection. Both are `None` on the
/// first tick, which disables the checks that need history rather than failing.
#[must_use]
pub fn aggregate(
    config: &FeedConfig,
    mut quotes: Vec<SourceQuote>,
    reference: Option<Fixed>,
    last_price: Option<Fixed>,
    peg: Option<Peg>,
) -> Outcome {
    let mut reasons = Reasons::NONE;
    if quotes.iter().any(|quote| !quote.from_book) {
        reasons |= Reasons::TRADE_FALLBACK;
    }

    // Convert stablecoin-quoted sources before anything else looks at a price.
    // Outlier rejection and the sanity band must both see the converted values,
    // or a depeg would read as every USDT venue disagreeing with the USD ones.
    let mut applied_peg = None;
    if config.needs_conversion() {
        let Some(conversion) = config.quote_conversion else {
            return Outcome::Halted {
                reasons: reasons | Reasons::PEG_UNAVAILABLE,
                live: 0,
            };
        };
        let live = u32::try_from(quotes.len()).unwrap_or(u32::MAX);
        // No peg means no honest way to state these prices in the quote asset.
        // Publishing them unconverted would be wrong by whatever the peg has
        // drifted, which is exactly the error nobody would notice.
        let Some(peg) = peg else {
            return Outcome::Halted {
                reasons: reasons | Reasons::PEG_UNAVAILABLE,
                live,
            };
        };
        if !apply_peg(&mut quotes, peg) {
            return Outcome::Halted {
                reasons: reasons | Reasons::PEG_UNAVAILABLE,
                live,
            };
        }
        reasons |= Reasons::SYNTHETIC_QUOTE;
        if peg
            .conf_bps()
            .is_none_or(|bps| bps > conversion.max_peg_conf_bps)
        {
            reasons |= Reasons::PEG_UNCERTAIN;
        }
        applied_peg = Some(peg);
    }

    let live = u32::try_from(quotes.len()).unwrap_or(u32::MAX);
    if live < config.min_sources {
        return Outcome::Halted {
            reasons: reasons | Reasons::INSUFFICIENT_SOURCES,
            live,
        };
    }

    // Outlier rejection, but never below quorum. A wide honest price beats a
    // narrow one derived from whichever quote happened to survive.
    let rejected = match reject_outliers(config, &mut quotes) {
        Some(rejected) => rejected,
        None => {
            reasons |= Reasons::OUTLIER_PRESSURE;
            0
        }
    };

    // Depth compares like with like: a source without a book would read as
    // shallow, so depth weighs in only when every source has one.
    if quotes.iter().all(|quote| quote.depth_notional.is_some()) {
        for quote in &mut quotes {
            if let Some(factor) = quote::depth_factor(config, quote.depth_notional)
                && let Some(weight) = quote.weight.checked_mul(factor)
            {
                quote.weight = weight;
            }
        }
    }

    cap_weights(config, &mut quotes);

    let samples: Vec<(Fixed, Fixed)> = quotes
        .iter()
        .map(|quote| (quote.price, quote.weight))
        .collect();
    // Weights come from spread and freshness, which a venue controls. When the
    // sources disagree and none can be dropped, they must not pick the winner.
    let price = if reasons.contains(Reasons::OUTLIER_PRESSURE) {
        contested_price(&quotes, last_price)
    } else {
        stats::weighted_median(&samples)
    };
    let Some(price) = price else {
        return Outcome::Halted {
            reasons: reasons | Reasons::INSUFFICIENT_SOURCES,
            live,
        };
    };

    // The sanity band catches the failure nothing else can: every venue agreeing,
    // and all of them wrong. A bad instrument mapping, a redenomination, a stock
    // split. Halting is right here — there is no price to widen around.
    if config.sanity_band_enabled()
        && let Some(reference) = reference
        && reference.is_positive()
        && !within_band(price, reference, config)
    {
        return Outcome::Halted {
            reasons: reasons | Reasons::SANITY_BAND,
            live,
        };
    }

    let mut conf = confidence(config, &samples, &quotes, price).unwrap_or(Fixed::ZERO);

    // The peg's uncertainty is part of this price's uncertainty.
    if let Some(peg) = applied_peg
        && let Some(widened) = widen_for_peg(price, conf, peg)
    {
        conf = conf.max(widened);
    }

    // When rejection was blocked by the quorum, the sample set knowingly still
    // contains an outlier — and the MAD, being robust, ignores it. Widening to
    // cover the worst retained quote is the whole point of degrading rather than
    // halting: publish the price, but say plainly how wrong it could be.
    if reasons.contains(Reasons::OUTLIER_PRESSURE)
        && let Some(worst) = quotes
            .iter()
            .filter_map(|quote| quote.price.checked_sub(price)?.checked_abs())
            .max()
    {
        conf = conf.max(worst);
    }

    // A jump only counts as corroborated when enough venues individually moved.
    // If the median jumped because coverage is thin and one venue ran, say so and
    // widen to cover the distance rather than publishing a confident new level.
    if let Some(last) = last_price
        && last.is_positive()
        && let Some(delta) = price.checked_sub(last)
        && let Some(delta_bps) = delta.checked_abs().and_then(|d| d.to_bps_of(last))
        && delta_bps >= config.jump_bps
    {
        let movers = quotes
            .iter()
            .filter(|quote| moved_by(quote.price, last, config.jump_bps))
            .count();
        if u32::try_from(movers).unwrap_or(u32::MAX) < config.jump_corroboration {
            reasons |= Reasons::UNCORROBORATED_JUMP;
            if let Some(distance) = delta.checked_abs() {
                conf = conf.max(distance);
            }
        }
    }

    let sources: VenueSet = quotes.iter().map(|quote| quote.venue).collect();
    let observation_time_ns = quotes
        .iter()
        .map(|quote| quote.observation_time_ns)
        .max()
        .unwrap_or(0);

    Outcome::Priced(Box::new(Aggregation {
        price,
        conf,
        flags: reasons.to_flags(),
        reasons,
        sources,
        num_sources: sources.len(),
        rejected,
        observation_time_ns,
    }))
}

/// Clamps every weight to a multiple of the median weight.
///
/// Weights derive from spread and freshness, both of which a manipulating venue
/// controls. Without a ceiling, quoting an implausibly tight book would buy
/// majority weight and therefore the weighted median outright.
///
/// Relative to the median rather than to a share of the total, because a share
/// target is infeasible for small source counts: with two venues neither can
/// hold under half.
fn cap_weights(config: &FeedConfig, quotes: &mut [SourceQuote]) {
    if !config.weight_cap_multiple.is_positive() {
        return;
    }
    let mut weights: Vec<Fixed> = quotes.iter().map(|quote| quote.weight).collect();
    let Some(median_weight) = stats::median(&mut weights) else {
        return;
    };
    let Some(cap) = median_weight.checked_mul(config.weight_cap_multiple) else {
        return;
    };
    if !cap.is_positive() {
        return;
    }
    for quote in quotes {
        quote.weight = quote.weight.min(cap);
    }
}

/// The price when the sources disagree and none can be dropped.
///
/// Two sources leave no majority, so the one nearer the last published price
/// stands: one moved venue widens the confidence but cannot move the price. A
/// midpoint would hand it half the move, and can land on a level nobody quoted.
fn contested_price(quotes: &[SourceQuote], last_price: Option<Fixed>) -> Option<Fixed> {
    if let ([first, second], Some(last)) = (quotes, last_price) {
        let distance =
            |quote: &SourceQuote| quote.price.checked_sub(last).and_then(Fixed::checked_abs);
        return Some(if distance(first) <= distance(second) {
            first.price
        } else {
            second.price
        });
    }
    stats::median(&mut quotes.iter().map(|quote| quote.price).collect::<Vec<_>>())
}

/// Drops quotes far from the median, returning how many were dropped.
///
/// Returns `None` if rejection would breach the quorum, in which case nothing is
/// dropped and the caller degrades instead.
fn reject_outliers(config: &FeedConfig, quotes: &mut Vec<SourceQuote>) -> Option<u32> {
    let values: Vec<Fixed> = quotes.iter().map(|quote| quote.price).collect();
    let center = stats::median(&mut values.clone())?;
    let sigma = stats::mad(&values, center)?.checked_mul(MAD_TO_SIGMA)?;

    // The floor matters: when venues agree to within a hair the MAD collapses to
    // zero, and a pure MAD test would then reject good quotes over rounding noise.
    let floor = center
        .checked_abs()?
        .checked_mul(config.outlier_floor_bps)?
        .checked_div(BPS_PER_UNIT)?;
    let threshold = sigma.checked_mul(config.mad_k)?.max(floor);

    // Two quotes sit equally far from their midpoint, so the test above can
    // never reject either: a gap past the floor is a disagreement nobody can
    // settle.
    if let [first, second] = quotes.as_slice()
        && first
            .price
            .checked_sub(second.price)
            .and_then(Fixed::checked_abs)
            .is_some_and(|gap| gap > floor)
    {
        return None;
    }

    let survivors: Vec<SourceQuote> = quotes
        .iter()
        .filter(|quote| {
            quote
                .price
                .checked_sub(center)
                .and_then(Fixed::checked_abs)
                .is_some_and(|distance| distance <= threshold)
        })
        .copied()
        .collect();

    let survivor_count = u32::try_from(survivors.len()).unwrap_or(u32::MAX);
    if survivor_count < config.min_sources {
        return None;
    }
    let rejected = u32::try_from(quotes.len().saturating_sub(survivors.len())).unwrap_or(u32::MAX);
    *quotes = survivors;
    Some(rejected)
}

/// Computes the published confidence half-width.
///
/// The widest of three floors: how much the venues disagree, how tight the books
/// actually are, and an absolute minimum. You cannot trade inside the spread, so
/// claiming precision below it would be a lie regardless of how well the venues
/// agree.
fn confidence(
    config: &FeedConfig,
    samples: &[(Fixed, Fixed)],
    quotes: &[SourceQuote],
    price: Fixed,
) -> Option<Fixed> {
    // Unweighted as well: a source holding over half the weight makes the
    // weighted MAD zero however far the others are.
    let values: Vec<Fixed> = samples.iter().map(|(value, _)| *value).collect();
    let dispersion = stats::weighted_mad(samples, price)
        .max(stats::mad(&values, price))
        .and_then(|mad| mad.checked_mul(MAD_TO_SIGMA))
        .unwrap_or(Fixed::ZERO);

    let spreads: Vec<(Fixed, Fixed)> = quotes
        .iter()
        .filter_map(|quote| Some((quote.half_spread?, quote.weight)))
        .collect();
    let spread = stats::weighted_mean(&spreads).unwrap_or(Fixed::ZERO);

    let floor = price
        .checked_abs()?
        .checked_mul(config.min_conf_bps)?
        .checked_div(BPS_PER_UNIT)?;

    Some(dispersion.max(spread).max(floor))
}

/// Returns `true` if `price` sits inside the configured band around `reference`.
fn within_band(price: Fixed, reference: Fixed, config: &FeedConfig) -> bool {
    let (Some(low), Some(high)) = (
        reference.checked_mul(config.sanity_band.0),
        reference.checked_mul(config.sanity_band.1),
    ) else {
        // If the bounds cannot be computed, do not halt on a arithmetic failure.
        return true;
    };
    price >= low && price <= high
}

/// Returns `true` if `price` differs from `reference` by at least `threshold_bps`.
fn moved_by(price: Fixed, reference: Fixed, threshold_bps: Fixed) -> bool {
    price
        .checked_sub(reference)
        .and_then(Fixed::checked_abs)
        .and_then(|delta| delta.to_bps_of(reference))
        .is_some_and(|bps| bps >= threshold_bps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SourceConfig;
    use oracle_types::{FeedId, InstrumentId, MarketKind, ObsKind, Symbol, Venue};

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("valid decimal")
    }

    fn config(venues: &[Venue]) -> FeedConfig {
        let symbol: Symbol = "CRYPTO.BTC/USDT".parse().expect("valid");
        let sources = venues
            .iter()
            .map(|venue| {
                SourceConfig::new(
                    InstrumentId::new(*venue, MarketKind::Spot, "BTCUSDT"),
                    vec![ObsKind::BookTop, ObsKind::Trade],
                )
            })
            .collect();
        FeedConfig::spot(symbol, FeedId::from_bytes([1; 32]), sources)
    }

    fn quote(venue: Venue, price: &str) -> SourceQuote {
        SourceQuote {
            venue,
            price: fixed(price),
            half_spread: Some(fixed("0.01")),
            weight: Fixed::ONE,
            observation_time_ns: 1_000,
            from_book: true,
            converted: false,
            depth_notional: None,
        }
    }

    fn priced(outcome: Outcome) -> Aggregation {
        match outcome {
            Outcome::Priced(aggregation) => *aggregation,
            Outcome::Halted { reasons, live } => {
                panic!("expected a price, halted with {reasons:?} and {live} live sources")
            }
        }
    }

    const ALL: [Venue; 5] = [
        Venue::Binance,
        Venue::Bybit,
        Venue::Okx,
        Venue::Coinbase,
        Venue::Kraken,
    ];

    #[test]
    fn agreeing_venues_produce_a_tight_price() {
        let config = config(&ALL);
        let quotes = vec![
            quote(Venue::Binance, "100.00"),
            quote(Venue::Bybit, "100.01"),
            quote(Venue::Okx, "100.02"),
            quote(Venue::Coinbase, "99.99"),
            quote(Venue::Kraken, "100.00"),
        ];
        let result = priced(aggregate(&config, quotes, None, None, None));
        assert_eq!(result.price, fixed("100"));
        assert_eq!(result.num_sources, 5);
        assert_eq!(result.rejected, 0);
        assert!(result.flags.is_none());
        assert!(result.conf.is_positive(), "confidence must never be zero");
    }

    /// Two sources leave no majority to say which is wrong, whatever their
    /// weights: the fresher one must not simply win.
    #[test]
    fn two_sources_apart_beyond_the_floor_degrade_and_keep_the_last_level() {
        let config = config(&[Venue::Binance, Venue::Okx]);
        let mut heavy = quote(Venue::Okx, "102.5");
        heavy.weight = fixed("3");
        let quotes = vec![quote(Venue::Binance, "100"), heavy];

        let result = priced(aggregate(
            &config,
            quotes.clone(),
            None,
            Some(fixed("100.01")),
            None,
        ));
        assert!(result.reasons.contains(Reasons::OUTLIER_PRESSURE));
        assert!(result.flags.is_degraded());
        assert_eq!(result.price, fixed("100"), "the moved venue cannot move it");
        assert!(
            result.conf >= fixed("2.5"),
            "covers the other: {}",
            result.conf
        );

        // With nothing published yet there is no level to keep.
        let result = priced(aggregate(&config, quotes, None, None, None));
        assert_eq!(result.price, fixed("101.25"));

        // Inside the floor, two sources are just two sources.
        let quotes = vec![quote(Venue::Binance, "100"), quote(Venue::Okx, "100.05")];
        let result = priced(aggregate(&config, quotes, None, None, None));
        assert!(result.flags.is_none());
    }

    /// A source with most of the weight made the weighted MAD zero, and the
    /// confidence fell to its floor while the others disagreed.
    #[test]
    fn a_heavy_source_does_not_hide_disagreement() {
        let config = config(&[Venue::Binance, Venue::Bybit, Venue::Okx]);
        let mut heavy = quote(Venue::Binance, "100");
        heavy.weight = fixed("3");
        let quotes = vec![
            heavy,
            quote(Venue::Bybit, "100.06"),
            quote(Venue::Okx, "100.08"),
        ];
        let result = priced(aggregate(&config, quotes, None, None, None));
        assert_eq!(result.rejected, 0, "all inside the 10bp floor");
        assert!(result.conf >= fixed("0.08"), "{}", result.conf);
    }

    /// A deep venue counts for more, but only when every venue reports depth:
    /// a venue without a book is not a shallow one.
    #[test]
    fn depth_weighs_in_only_when_every_source_has_it() {
        let config = config(&[Venue::Binance, Venue::Bybit, Venue::Okx]);
        let with_depth = |venue, price, depth: &str| SourceQuote {
            depth_notional: Some(fixed(depth)),
            ..quote(venue, price)
        };
        let quotes = vec![
            with_depth(Venue::Binance, "100", "1000000"),
            with_depth(Venue::Bybit, "100.05", "10000"),
            with_depth(Venue::Okx, "100.06", "10000"),
        ];
        let result = priced(aggregate(&config, quotes.clone(), None, None, None));
        assert_eq!(result.price, fixed("100"), "the deep venue leads");

        let mut partial = quotes;
        if let Some(okx) = partial.get_mut(2) {
            okx.depth_notional = None;
        }
        let result = priced(aggregate(&config, partial, None, None, None));
        assert_eq!(result.price, fixed("100.05"), "no depth factor for anyone");
    }

    #[test]
    fn confidence_is_at_least_the_half_spread() {
        let config = config(&ALL);
        let mut quotes = vec![
            quote(Venue::Binance, "100"),
            quote(Venue::Bybit, "100"),
            quote(Venue::Okx, "100"),
        ];
        // Perfect agreement drives dispersion to zero, so the spread must floor it.
        for quote in &mut quotes {
            quote.half_spread = Some(fixed("0.5"));
        }
        let result = priced(aggregate(&config, quotes, None, None, None));
        assert_eq!(result.conf, fixed("0.5"));
    }

    #[test]
    fn confidence_has_an_absolute_floor() {
        let config = config(&ALL);
        let mut quotes = vec![
            quote(Venue::Binance, "100"),
            quote(Venue::Bybit, "100"),
            quote(Venue::Okx, "100"),
        ];
        for quote in &mut quotes {
            quote.half_spread = None;
        }
        let result = priced(aggregate(&config, quotes, None, None, None));
        // 1bp of 100.
        assert_eq!(result.conf, fixed("0.01"));
    }

    #[test]
    fn disagreement_widens_the_confidence() {
        let config = config(&ALL);
        let tight = priced(aggregate(
            &config,
            vec![
                quote(Venue::Binance, "100"),
                quote(Venue::Bybit, "100.01"),
                quote(Venue::Okx, "100.02"),
            ],
            None,
            None,
            None,
        ));
        let loose = priced(aggregate(
            &config,
            vec![
                quote(Venue::Binance, "100"),
                quote(Venue::Bybit, "100.5"),
                quote(Venue::Okx, "101"),
            ],
            None,
            None,
            None,
        ));
        assert!(
            loose.conf > tight.conf,
            "{} should exceed {}",
            loose.conf,
            tight.conf
        );
    }

    #[test]
    fn a_single_manipulated_venue_is_rejected() {
        let config = config(&ALL);
        let quotes = vec![
            quote(Venue::Binance, "100.00"),
            quote(Venue::Bybit, "100.01"),
            quote(Venue::Okx, "100.02"),
            quote(Venue::Coinbase, "99.99"),
            // Ten percent off.
            quote(Venue::Kraken, "110.00"),
        ];
        let result = priced(aggregate(&config, quotes, None, None, None));
        assert_eq!(result.rejected, 1);
        assert_eq!(result.num_sources, 4);
        assert!(!result.sources.contains(Venue::Kraken));
        assert_eq!(result.price, fixed("100.005"));
    }

    #[test]
    fn rejection_stops_at_the_quorum_and_degrades_instead() {
        let mut config = config(&ALL);
        config.min_sources = 3;
        // Two venues agree tightly and one is far out. Rejecting the outlier
        // would leave two, one short of the quorum.
        let quotes = vec![
            quote(Venue::Binance, "100"),
            quote(Venue::Bybit, "100.01"),
            quote(Venue::Okx, "200"),
        ];
        let result = priced(aggregate(&config, quotes, None, None, None));
        assert_eq!(result.rejected, 0, "nothing may be dropped below quorum");
        assert!(result.reasons.contains(Reasons::OUTLIER_PRESSURE));
        assert!(result.flags.is_degraded());
        // The retained outlier sits ~100 away, and the published band must say so
        // rather than reporting the robust MAD of the samples we could not drop.
        assert!(
            result.conf > fixed("99"),
            "a retained outlier must widen the band, got {}",
            result.conf
        );
    }

    #[test]
    fn too_few_live_sources_halts() {
        let mut config = config(&ALL);
        config.min_sources = 3;
        let outcome = aggregate(
            &config,
            vec![quote(Venue::Binance, "100")],
            None,
            None,
            None,
        );
        match outcome {
            Outcome::Halted { reasons, live } => {
                assert!(reasons.contains(Reasons::INSUFFICIENT_SOURCES));
                assert_eq!(live, 1);
            }
            Outcome::Priced(_) => panic!("must halt below quorum"),
        }
    }

    #[test]
    fn an_uncorroborated_jump_degrades_and_widens() {
        let mut config = config(&ALL);
        config.min_sources = 1;
        // One venue moves 5%, past the 300bp jump threshold, and no other venue
        // is there to corroborate it.
        let quotes = vec![quote(Venue::Binance, "105")];
        let result = priced(aggregate(&config, quotes, None, Some(fixed("100")), None));
        assert!(result.reasons.contains(Reasons::UNCORROBORATED_JUMP));
        assert!(result.flags.is_degraded());
        assert!(
            result.conf >= fixed("5"),
            "confidence {} must cover the distance moved",
            result.conf
        );

        // Two venues where one runs 10%: no majority, so the price stays at the
        // last level, degraded, with a confidence that covers the runner.
        config.min_sources = 2;
        let quotes = vec![quote(Venue::Binance, "110"), quote(Venue::Bybit, "100")];
        let result = priced(aggregate(&config, quotes, None, Some(fixed("100")), None));
        assert_eq!(result.price, fixed("100"));
        assert!(result.flags.is_degraded());
        assert!(result.conf >= fixed("10"), "{}", result.conf);
    }

    #[test]
    fn a_corroborated_jump_publishes_cleanly() {
        let config = config(&ALL);
        // Everyone moved together: a real move, not a manipulation.
        let quotes = vec![
            quote(Venue::Binance, "105"),
            quote(Venue::Bybit, "105.01"),
            quote(Venue::Okx, "104.99"),
        ];
        let result = priced(aggregate(&config, quotes, None, Some(fixed("100")), None));
        assert!(!result.reasons.contains(Reasons::UNCORROBORATED_JUMP));
        assert!(result.flags.is_none());
    }

    #[test]
    fn leaving_the_sanity_band_halts() {
        let config = config(&ALL);
        let quotes = vec![
            quote(Venue::Binance, "10"),
            quote(Venue::Bybit, "10"),
            quote(Venue::Okx, "10"),
        ];
        // Every venue agrees, and all of them are wrong: the reference says 100.
        let outcome = aggregate(&config, quotes, Some(fixed("100")), None, None);
        match outcome {
            Outcome::Halted { reasons, .. } => {
                assert!(reasons.contains(Reasons::SANITY_BAND));
            }
            Outcome::Priced(_) => panic!("a tenfold dislocation must halt"),
        }
    }

    #[test]
    fn the_sanity_band_permits_ordinary_moves() {
        let config = config(&ALL);
        let quotes = vec![
            quote(Venue::Binance, "130"),
            quote(Venue::Bybit, "130"),
            quote(Venue::Okx, "130"),
        ];
        let result = priced(aggregate(&config, quotes, Some(fixed("100")), None, None));
        assert_eq!(result.price, fixed("130"));
    }

    #[test]
    fn a_trade_fallback_is_recorded_but_does_not_degrade() {
        let config = config(&ALL);
        let mut quotes = vec![
            quote(Venue::Binance, "100"),
            quote(Venue::Bybit, "100"),
            quote(Venue::Okx, "100"),
        ];
        if let Some(quote) = quotes.first_mut() {
            quote.from_book = false;
            quote.half_spread = None;
        }
        let result = priced(aggregate(&config, quotes, None, None, None));
        assert!(result.reasons.contains(Reasons::TRADE_FALLBACK));
        assert!(
            !result.flags.is_degraded(),
            "a thin instrument is not a fault"
        );
    }

    #[test]
    fn weight_cannot_drag_the_price_past_the_neighbouring_quote() {
        let config = config(&ALL);
        let mut quotes = vec![
            quote(Venue::Binance, "100.00"),
            quote(Venue::Bybit, "100.01"),
            quote(Venue::Okx, "100.02"),
            quote(Venue::Coinbase, "100.03"),
        ];
        // A compromised venue claiming enormous weight and an absurd price.
        let mut attacker = quote(Venue::Kraken, "100.015");
        attacker.weight = fixed("1000000");
        quotes.push(attacker);

        let result = priced(aggregate(&config, quotes, None, None, None));
        assert!(
            result.price >= fixed("100.00") && result.price <= fixed("100.03"),
            "price {} escaped the honest range",
            result.price
        );
    }

    /// Weight is attacker-controllable, so it must not be able to buy the price.
    #[test]
    fn an_inflated_weight_is_capped_to_a_multiple_of_the_median() {
        let config = config(&ALL);
        let mut quotes = vec![
            quote(Venue::Binance, "100.00"),
            quote(Venue::Bybit, "100.01"),
            quote(Venue::Okx, "100.02"),
            quote(Venue::Coinbase, "100.03"),
        ];
        // Inside the outlier band, so rejection does not catch it — but claiming
        // a million times everyone else's weight.
        let mut attacker = quote(Venue::Kraken, "100.04");
        attacker.weight = fixed("1000000");
        quotes.push(attacker);

        let result = priced(aggregate(&config, quotes, None, None, None));
        // Without the cap the attacker's own quote would be the answer. With it,
        // they buy influence but not the price.
        assert!(
            result.price < fixed("100.04"),
            "an inflated weight captured the median: {}",
            result.price
        );
        assert_eq!(result.price, fixed("100.03"));
    }

    #[test]
    fn reasons_debug_lists_what_fired() {
        assert_eq!(format!("{:?}", Reasons::NONE), "Reasons(NONE)");
        let reasons = Reasons::OUTLIER_PRESSURE | Reasons::SANITY_BAND;
        assert_eq!(
            format!("{reasons:?}"),
            r#"{"OUTLIER_PRESSURE", "SANITY_BAND"}"#
        );
    }
}
