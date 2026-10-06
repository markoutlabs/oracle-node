//! Aggregation configuration.
//!
//! Every constant here is a policy decision with a cost on both sides, so each
//! carries the reasoning rather than just a number. They are starting points fit
//! by judgement, not by data; SPEC.md §13 open question 4 is the standing note
//! that they should be re-fit against recorded dislocations before they ossify.

use std::time::Duration;

use oracle_types::{FeedId, Fixed, InstrumentId, ObsKind, Symbol, Venue};

/// How one venue contributes to one feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceConfig {
    /// The venue instrument to read.
    pub instrument: InstrumentId,

    /// Which observation kinds feed this source, in preference order.
    ///
    /// A spot price feed lists `[BookTop, Trade]`: the book is pushed on every
    /// change and is harder to manipulate than a print, but on a venue whose book
    /// has gone one-sided the last trade is better than nothing — and is flagged
    /// when used.
    pub kinds: Vec<ObsKind>,

    /// Static trust weight for this venue, before liquidity and freshness.
    pub weight: Fixed,

    /// This source is quoted in the feed's peg asset and must be converted.
    ///
    /// Binance, Bybit, and OKX quote in USDT. Publishing those as `/USD` without
    /// conversion is a lie that costs money the day the peg breaks — and it is a
    /// silent lie, because on any ordinary day the two are indistinguishable.
    pub convert_quote: bool,
}

impl SourceConfig {
    /// Builds a source with unit weight.
    #[must_use]
    pub fn new(instrument: InstrumentId, kinds: Vec<ObsKind>) -> Self {
        Self {
            instrument,
            kinds,
            weight: Fixed::ONE,
            convert_quote: false,
        }
    }

    /// Sets the static trust weight.
    #[must_use]
    pub const fn with_weight(mut self, weight: Fixed) -> Self {
        self.weight = weight;
        self
    }

    /// Marks this source as needing conversion through the feed's peg.
    #[must_use]
    pub const fn converted(mut self) -> Self {
        self.convert_quote = true;
        self
    }
}

/// How to convert stablecoin-quoted sources into the feed's quote asset.
///
/// The peg is a feed like any other, priced from venues that quote it natively.
/// Its uncertainty propagates into every price that passes through it, so a
/// wobbling peg widens the whole catalogue rather than silently mispricing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuoteConversion {
    /// The peg feed, such as `CRYPTO.USDT/USD`.
    pub peg_feed: FeedId,

    /// Peg confidence above which dependent feeds degrade, in basis points.
    ///
    /// A depeg then shows up as confidence widening across the board — which is
    /// the honest signal — rather than as a uniform, invisible mispricing.
    pub max_peg_conf_bps: Fixed,
}

/// Per-feed aggregation and publication policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedConfig {
    /// The canonical symbol.
    pub symbol: Symbol,
    /// The derived feed id.
    pub feed_id: FeedId,
    /// Publication exponent.
    pub expo: i32,
    /// Contributing venues.
    pub sources: Vec<SourceConfig>,

    /// Peg conversion for sources marked [`SourceConfig::convert_quote`].
    pub quote_conversion: Option<QuoteConversion>,

    /// Fewest surviving venues required to publish a usable price.
    ///
    /// Below this the feed halts. Two is the floor at which disagreement is even
    /// detectable; three is right for anything load-bearing.
    pub min_sources: u32,

    /// Drop an observation older than this, measured on our receipt clock.
    pub max_age: Duration,

    /// Half-life of the sanity-band reference EMA.
    pub ema_half_life: Duration,

    /// Freshness weighting time constant: weight is `tau / (tau + age)`.
    ///
    /// A hyperbolic decay rather than the exponential the spec sketches. It is
    /// monotone, lands in `(0, 1]`, needs no transcendental function, and is
    /// therefore exactly reproducible on replay — which an `exp` over fixed-point
    /// would not be.
    pub recency_tau: Duration,

    /// Reference notional for depth weighting: `sqrt(depth / reference)`, capped.
    ///
    /// Inert until a depth stream exists — `bookTicker` is top-of-book only, so
    /// `depth_notional_1bp` is currently always absent and every source gets the
    /// neutral factor. Wired now so adding depth is a config change, not a
    /// rewrite.
    pub depth_reference: Fixed,

    /// Ceiling on the depth factor, so one deep venue cannot dominate.
    pub depth_cap: Fixed,

    /// Ceiling on any one source's weight, as a multiple of the median weight.
    ///
    /// The weight inputs — spread and freshness — are things a manipulating venue
    /// controls directly, and a weighted median offers no protection against
    /// weight itself: a sample holding more than half the total *is* the answer.
    /// Capping relative to the median means a venue quoting an implausibly tight
    /// book buys influence sub-linearly instead of buying the price.
    ///
    /// This is defence in depth. The primary filter is outlier rejection, which
    /// runs first and is deliberately unweighted.
    pub weight_cap_multiple: Fixed,

    /// MAD multiplier for outlier rejection.
    pub mad_k: Fixed,

    /// Floor under the outlier threshold, in basis points of the median.
    ///
    /// Without it, venues agreeing to within a hair drive the MAD to zero and a
    /// pure MAD test rejects perfectly good quotes over rounding noise.
    pub outlier_floor_bps: Fixed,

    /// Floor under the published confidence, in basis points of price.
    ///
    /// Never claim more precision than the mechanism can support.
    pub min_conf_bps: Fixed,

    /// A move at least this large, in basis points, is treated as a jump.
    pub jump_bps: Fixed,

    /// Venues that must corroborate a jump for it to publish without degrading.
    pub jump_corroboration: u32,

    /// Sanity band around the reference EMA, as `(low, high)` multipliers.
    ///
    /// Outside this the feed halts and a human is paged. It catches the class of
    /// failure where every venue agrees and all of them are wrong — a bad
    /// instrument mapping, a stock split, a redenomination.
    pub sanity_band: (Fixed, Fixed),

    /// Publish when the price has moved at least this far, in basis points.
    pub deviation_bps: Fixed,

    /// Publish at least this often, even when nothing moves.
    pub heartbeat: Duration,

    /// Never publish more often than this.
    ///
    /// Applied before every other trigger, because it is what bounds signing cost
    /// and subscriber bandwidth under volatility — precisely when both are under
    /// the most stress.
    pub min_interval: Duration,
}

impl FeedConfig {
    /// Builds a spot price feed with the defaults from SPEC.md §5.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the symbol's feed id cannot be derived.
    #[must_use]
    pub fn spot(symbol: Symbol, feed_id: FeedId, sources: Vec<SourceConfig>) -> Self {
        Self {
            expo: symbol.expo(),
            symbol,
            feed_id,
            sources,
            quote_conversion: None,
            min_sources: 2,
            max_age: Duration::from_millis(2_000),
            ema_half_life: Duration::from_secs(300),
            recency_tau: Duration::from_millis(500),
            depth_reference: Fixed::from_raw(100_000 * 1_000_000_000_000),
            depth_cap: Fixed::from_raw(2 * 1_000_000_000_000),
            weight_cap_multiple: Fixed::from_raw(3 * 1_000_000_000_000),
            mad_k: Fixed::from_raw(4 * 1_000_000_000_000),
            outlier_floor_bps: Fixed::from_raw(10 * 1_000_000_000_000),
            min_conf_bps: Fixed::ONE,
            jump_bps: Fixed::from_raw(300 * 1_000_000_000_000),
            jump_corroboration: 2,
            sanity_band: (
                Fixed::from_raw(500_000_000_000),
                Fixed::from_raw(2_000_000_000_000),
            ),
            // One confidence floor: a smaller move is inside our own uncertainty.
            deviation_bps: Fixed::ONE,
            heartbeat: Duration::from_millis(1_000),
            min_interval: Duration::from_millis(50),
        }
    }

    /// Builds a feed for a slow-moving quantity: funding rates and open interest.
    ///
    /// These genuinely update on the order of minutes, so the spot staleness
    /// threshold would halt them permanently.
    #[must_use]
    pub fn slow(symbol: Symbol, feed_id: FeedId, sources: Vec<SourceConfig>) -> Self {
        Self {
            max_age: Duration::from_secs(90),
            heartbeat: Duration::from_secs(10),
            min_interval: Duration::from_secs(1),
            min_sources: 1,
            // A funding rate crosses zero routinely, so a multiplicative band
            // around an EMA is meaningless. Disable it.
            sanity_band: (Fixed::ZERO, Fixed::ZERO),
            ..Self::spot(symbol, feed_id, sources)
        }
    }

    /// Returns `true` if any source needs peg conversion.
    #[must_use]
    pub fn needs_conversion(&self) -> bool {
        self.quote_conversion.is_some() && self.sources.iter().any(|source| source.convert_quote)
    }

    /// Sets the peg conversion.
    #[must_use]
    pub const fn with_conversion(mut self, conversion: QuoteConversion) -> Self {
        self.quote_conversion = Some(conversion);
        self
    }

    /// Returns `true` if the sanity band is active.
    #[must_use]
    pub fn sanity_band_enabled(&self) -> bool {
        self.sanity_band.0.is_positive() && self.sanity_band.1.is_positive()
    }

    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for a feed that could never publish: no sources,
    /// a quorum it cannot reach, a heartbeat below the rate cap, or an inverted
    /// sanity band.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.sources.is_empty() {
            return Err(ConfigError::NoSources {
                symbol: self.symbol.to_string(),
            });
        }
        let available = u32::try_from(self.sources.len()).unwrap_or(u32::MAX);
        if self.min_sources > available {
            return Err(ConfigError::UnreachableQuorum {
                symbol: self.symbol.to_string(),
                required: self.min_sources,
                available,
            });
        }
        if self.min_sources == 0 {
            return Err(ConfigError::Invalid {
                symbol: self.symbol.to_string(),
                reason: "min_sources must be at least 1".to_owned(),
            });
        }
        if self.min_interval.is_zero() {
            return Err(ConfigError::Invalid {
                symbol: self.symbol.to_string(),
                reason: "min_interval must be above zero: it bounds signing under volatility"
                    .to_owned(),
            });
        }
        if self.deviation_bps < Fixed::ZERO {
            return Err(ConfigError::Invalid {
                symbol: self.symbol.to_string(),
                reason: "deviation_bps must not be negative".to_owned(),
            });
        }
        if self.heartbeat < self.min_interval {
            return Err(ConfigError::Invalid {
                symbol: self.symbol.to_string(),
                reason: "heartbeat is below min_interval, so it could never fire".to_owned(),
            });
        }
        if self.sanity_band_enabled() && self.sanity_band.0 >= self.sanity_band.1 {
            return Err(ConfigError::Invalid {
                symbol: self.symbol.to_string(),
                reason: "sanity band low bound is not below the high bound".to_owned(),
            });
        }
        if self.sources.iter().any(|source| source.convert_quote) && self.quote_conversion.is_none()
        {
            return Err(ConfigError::Invalid {
                symbol: self.symbol.to_string(),
                reason: "a source is marked for conversion but no peg feed is configured"
                    .to_owned(),
            });
        }
        if let Some(conversion) = &self.quote_conversion
            && conversion.peg_feed == self.feed_id
        {
            return Err(ConfigError::Invalid {
                symbol: self.symbol.to_string(),
                reason: "a feed cannot be its own peg".to_owned(),
            });
        }
        for source in &self.sources {
            if source.kinds.is_empty() {
                return Err(ConfigError::Invalid {
                    symbol: self.symbol.to_string(),
                    reason: format!("source {} lists no observation kinds", source.instrument),
                });
            }
            if !source.weight.is_positive() {
                return Err(ConfigError::Invalid {
                    symbol: self.symbol.to_string(),
                    reason: format!("source {} has a non-positive weight", source.instrument),
                });
            }
        }
        Ok(())
    }

    /// Returns the venues that contribute to this feed.
    pub fn venues(&self) -> impl Iterator<Item = Venue> + '_ {
        self.sources.iter().map(|source| source.instrument.venue)
    }
}

/// A configuration that could never produce a price.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A feed listed no sources.
    #[error("feed `{symbol}` has no sources")]
    NoSources {
        /// The feed.
        symbol: String,
    },

    /// A feed required more sources than it has.
    #[error("feed `{symbol}` requires {required} sources but only {available} are configured")]
    UnreachableQuorum {
        /// The feed.
        symbol: String,
        /// Sources demanded.
        required: u32,
        /// Sources available.
        available: u32,
    },

    /// Some other invariant was violated.
    #[error("feed `{symbol}`: {reason}")]
    Invalid {
        /// The feed.
        symbol: String,
        /// What was wrong.
        reason: String,
    },

    /// Two feeds declared the same id.
    #[error("duplicate feed id for `{symbol}`")]
    DuplicateFeed {
        /// The feed.
        symbol: String,
    },

    /// A feed names a peg that this node does not price.
    #[error("feed `{symbol}` needs peg {peg}, which is not a configured feed")]
    PegNotFound {
        /// The dependent feed.
        symbol: String,
        /// The peg it asked for.
        peg: String,
    },

    /// A peg feed itself needs conversion.
    ///
    /// Refused rather than resolved: chained pegs would need cycle detection and
    /// an evaluation order, and every extra hop multiplies another uncertainty
    /// into every downstream price.
    #[error("feed `{symbol}` names peg `{peg}`, which itself needs conversion")]
    ChainedPeg {
        /// The dependent feed.
        symbol: String,
        /// The peg it asked for.
        peg: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_types::MarketKind;

    fn symbol() -> Symbol {
        "CRYPTO.BTC/USDT".parse().expect("valid")
    }

    fn source(venue: Venue) -> SourceConfig {
        SourceConfig::new(
            InstrumentId::new(venue, MarketKind::Spot, "BTCUSDT"),
            vec![ObsKind::BookTop, ObsKind::Trade],
        )
    }

    fn config() -> FeedConfig {
        FeedConfig::spot(
            symbol(),
            FeedId::from_bytes([1; 32]),
            vec![source(Venue::Binance), source(Venue::Coinbase)],
        )
    }

    #[test]
    fn spot_defaults_validate() {
        assert_eq!(config().validate(), Ok(()));
    }

    #[test]
    fn spot_defaults_match_the_specification() {
        let config = config();
        assert_eq!(config.max_age, Duration::from_millis(2_000));
        assert_eq!(config.deviation_bps.to_string(), "1");
        assert_eq!(config.heartbeat, Duration::from_millis(1_000));
        assert_eq!(config.min_interval, Duration::from_millis(50));
        assert_eq!(config.mad_k.to_string(), "4");
        assert_eq!(config.weight_cap_multiple.to_string(), "3");
        assert_eq!(config.outlier_floor_bps.to_string(), "10");
        assert_eq!(config.jump_bps.to_string(), "300");
        assert_eq!(config.expo, -8);
    }

    #[test]
    fn slow_feeds_relax_staleness_and_drop_the_sanity_band() {
        let funding: Symbol = "CRYPTO.BTC/USDT.FUNDING_8H".parse().expect("valid");
        let config = FeedConfig::slow(
            funding,
            FeedId::from_bytes([2; 32]),
            vec![SourceConfig::new(
                InstrumentId::new(Venue::Binance, MarketKind::LinearPerp, "BTCUSDT"),
                vec![ObsKind::Funding],
            )],
        );
        assert_eq!(config.max_age, Duration::from_secs(90));
        assert_eq!(config.expo, -9, "funding publishes at a finer exponent");
        // A rate that crosses zero cannot be bounded by a multiplicative band.
        assert!(!config.sanity_band_enabled());
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn a_quorum_larger_than_the_source_list_is_rejected() {
        let mut config = config();
        config.min_sources = 5;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnreachableQuorum {
                required: 5,
                available: 2,
                ..
            })
        ));
    }

    #[test]
    fn feeds_that_could_never_publish_are_rejected() {
        let mut empty = config();
        empty.sources.clear();
        assert!(matches!(
            empty.validate(),
            Err(ConfigError::NoSources { .. })
        ));

        let mut zero_quorum = config();
        zero_quorum.min_sources = 0;
        assert!(matches!(
            zero_quorum.validate(),
            Err(ConfigError::Invalid { .. })
        ));

        let mut fast_heartbeat = config();
        fast_heartbeat.heartbeat = Duration::from_millis(10);
        fast_heartbeat.min_interval = Duration::from_millis(50);
        assert!(matches!(
            fast_heartbeat.validate(),
            Err(ConfigError::Invalid { .. })
        ));

        let mut inverted = config();
        inverted.sanity_band = (Fixed::from_int(2).expect("in range"), Fixed::ONE);
        assert!(matches!(
            inverted.validate(),
            Err(ConfigError::Invalid { .. })
        ));

        let mut kindless = config();
        if let Some(source) = kindless.sources.first_mut() {
            source.kinds.clear();
        }
        assert!(matches!(
            kindless.validate(),
            Err(ConfigError::Invalid { .. })
        ));

        let mut weightless = config();
        if let Some(source) = weightless.sources.first_mut() {
            source.weight = Fixed::ZERO;
        }
        assert!(matches!(
            weightless.validate(),
            Err(ConfigError::Invalid { .. })
        ));
    }
}
