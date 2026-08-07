//! Turning one venue's observations into one weighted quote.

use oracle_types::{Fixed, Observation, Venue};

use crate::config::{FeedConfig, SourceConfig};

/// One venue's contribution to a feed, after normalization and weighting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceQuote {
    /// Which venue.
    pub venue: Venue,
    /// The venue's price for this feed.
    pub price: Fixed,
    /// Half the bid-ask spread, when the quote came from a book.
    pub half_spread: Option<Fixed>,
    /// Aggregation weight, after trust, liquidity, freshness, and spread.
    pub weight: Fixed,
    /// Our receipt time for the underlying observation.
    pub observation_time_ns: u64,
    /// `true` if this came from a two-sided book rather than a trade print.
    pub from_book: bool,
}

/// Derives a quote from the freshest usable observation for one source.
///
/// Kinds are tried in the configured preference order. An observation is usable
/// when it is inside `max_age` on **our** clock and, for a book, not crossed.
///
/// # Why the microprice
///
/// On a balanced book it equals the mid. On a one-sided one it leans toward the
/// thin side, which is where the next print is more likely to land — the mid
/// quietly becomes fiction exactly when a venue is under stress, which is the
/// moment the number matters most.
#[must_use]
pub fn derive(
    source: &SourceConfig,
    config: &FeedConfig,
    latest: &[Option<Observation>],
    now_ns: u64,
) -> Option<SourceQuote> {
    let max_age_ns = u64::try_from(config.max_age.as_nanos()).unwrap_or(u64::MAX);

    for kind in &source.kinds {
        let Some(Some(observation)) = latest.get(kind.index()) else {
            continue;
        };
        if observation.is_stale(now_ns, max_age_ns) {
            continue;
        }

        let (price, half_spread, from_book) = if kind.has_book() {
            if observation.is_crossed() {
                // A crossed top-of-book means the venue's feed is inconsistent.
                // Drop it; never repair it.
                continue;
            }
            let Some(price) = observation.microprice().or_else(|| observation.mid()) else {
                continue;
            };
            let half_spread = observation
                .spread()
                .and_then(|spread| spread.checked_div(Fixed::from_int(2).ok()?));
            (price, half_spread, true)
        } else {
            (observation.price, None, false)
        };

        if !price.is_positive() && kind.has_book() {
            // A non-positive book price is nonsense. Non-book kinds may legitimately
            // be zero or negative — funding rates cross zero constantly.
            continue;
        }

        return Some(SourceQuote {
            venue: observation.venue(),
            price,
            half_spread,
            weight: weight_for(source, config, observation, price, now_ns)?,
            observation_time_ns: observation.local_recv_ns,
            from_book,
        });
    }
    None
}

/// Computes the aggregation weight for one observation.
///
/// `trust × depth × recency × spread`, all bounded in `(0, 1]` except trust.
fn weight_for(
    source: &SourceConfig,
    config: &FeedConfig,
    observation: &Observation,
    price: Fixed,
    now_ns: u64,
) -> Option<Fixed> {
    let mut weight = source.weight;

    // Freshness: tau / (tau + age). Hyperbolic rather than exponential so it is
    // exactly reproducible in fixed point — see FeedConfig::recency_tau.
    let tau_ns = u64::try_from(config.recency_tau.as_nanos())
        .unwrap_or(u64::MAX)
        .max(1);
    let age_ns = observation.age_ns(now_ns);
    let tau = Fixed::from_raw(i128::from(tau_ns));
    let age = Fixed::from_raw(i128::from(age_ns));
    let recency = tau.checked_div(tau.checked_add(age)?)?;
    weight = weight.checked_mul(recency)?;

    // Tighter books count for more. Aggressive by design: a venue quoting five
    // basis points wide is not offering the same information as one quoting a
    // tenth of that.
    if let Some(spread_bps) = observation.spread().and_then(|s| s.to_bps_of(price)) {
        let one = Fixed::ONE;
        let denominator = one.checked_add(spread_bps.checked_abs()?)?;
        weight = weight.checked_mul(one.checked_div(denominator)?)?;
    }

    // Liquidity, sub-linearly. Inert until a depth stream exists: `bookTicker`
    // is top-of-book only, so this is currently always the neutral factor.
    if let Some(depth) = observation.depth_notional_1bp
        && config.depth_reference.is_positive()
    {
        let ratio = depth.checked_div(config.depth_reference)?;
        let factor = ratio.sqrt()?.min(config.depth_cap);
        if factor.is_positive() {
            weight = weight.checked_mul(factor)?;
        }
    }

    Some(weight)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SourceConfig;
    use oracle_types::{FeedId, InstrumentId, MarketKind, ObsKind, Symbol};

    const NOW: u64 = 10_000_000_000;

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("valid decimal")
    }

    fn instrument() -> InstrumentId {
        InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT")
    }

    fn config() -> FeedConfig {
        let symbol: Symbol = "CRYPTO.BTC/USDT".parse().expect("valid");
        FeedConfig::spot(
            symbol,
            FeedId::from_bytes([1; 32]),
            vec![SourceConfig::new(
                instrument(),
                vec![ObsKind::BookTop, ObsKind::Trade],
            )],
        )
    }

    fn source() -> SourceConfig {
        SourceConfig::new(instrument(), vec![ObsKind::BookTop, ObsKind::Trade])
    }

    fn slots() -> Vec<Option<Observation>> {
        vec![None; ObsKind::COUNT]
    }

    fn book(bid: &str, ask: &str, bid_qty: &str, ask_qty: &str, age_ns: u64) -> Observation {
        Observation {
            instrument: instrument(),
            kind: ObsKind::BookTop,
            price: fixed(bid),
            bid: Some(fixed(bid)),
            ask: Some(fixed(ask)),
            bid_qty: Some(fixed(bid_qty)),
            ask_qty: Some(fixed(ask_qty)),
            depth_notional_1bp: None,
            exchange_time_ns: None,
            local_recv_ns: NOW - age_ns,
            seq: None,
        }
    }

    fn trade(price: &str, age_ns: u64) -> Observation {
        Observation {
            instrument: instrument(),
            kind: ObsKind::Trade,
            price: fixed(price),
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            depth_notional_1bp: None,
            exchange_time_ns: None,
            local_recv_ns: NOW - age_ns,
            seq: None,
        }
    }

    fn put(slots: &mut [Option<Observation>], observation: Observation) {
        if let Some(slot) = slots.get_mut(observation.kind.index()) {
            *slot = Some(observation);
        }
    }

    #[test]
    fn a_balanced_book_yields_the_mid() {
        let mut slots = slots();
        put(&mut slots, book("100", "102", "5", "5", 0));
        let quote = derive(&source(), &config(), &slots, NOW).expect("usable");
        assert_eq!(quote.price, fixed("101"));
        assert_eq!(quote.half_spread, Some(fixed("1")));
        assert!(quote.from_book);
    }

    #[test]
    fn an_unbalanced_book_leans_toward_the_thin_side() {
        let mut slots = slots();
        put(&mut slots, book("100", "102", "9", "1", 0));
        let quote = derive(&source(), &config(), &slots, NOW).expect("usable");
        assert_eq!(quote.price, fixed("101.8"));
    }

    #[test]
    fn a_stale_book_falls_through_to_a_fresh_trade() {
        let mut slots = slots();
        // Book is three seconds old; the 2s threshold rejects it.
        put(&mut slots, book("100", "102", "5", "5", 3_000_000_000));
        put(&mut slots, trade("101.5", 0));
        let quote = derive(&source(), &config(), &slots, NOW).expect("usable");
        assert_eq!(quote.price, fixed("101.5"));
        assert!(
            !quote.from_book,
            "the fallback must be visible to the caller"
        );
        assert_eq!(quote.half_spread, None);
    }

    #[test]
    fn everything_stale_yields_nothing() {
        let mut slots = slots();
        put(&mut slots, book("100", "102", "5", "5", 3_000_000_000));
        put(&mut slots, trade("101.5", 3_000_000_000));
        assert_eq!(derive(&source(), &config(), &slots, NOW), None);
    }

    #[test]
    fn a_crossed_book_is_dropped_not_repaired() {
        let mut slots = slots();
        put(&mut slots, book("102", "100", "5", "5", 0));
        put(&mut slots, trade("101", 0));
        let quote = derive(&source(), &config(), &slots, NOW).expect("falls back");
        assert_eq!(
            quote.price,
            fixed("101"),
            "must fall through, not average the crossed book"
        );
        assert!(!quote.from_book);
    }

    #[test]
    fn fresher_observations_weigh_more() {
        let mut fresh = slots();
        put(&mut fresh, book("99.999", "100.001", "5", "5", 0));
        let mut old = slots();
        put(&mut old, book("99.999", "100.001", "5", "5", 1_000_000_000));

        let fresh = derive(&source(), &config(), &fresh, NOW).expect("usable");
        let old = derive(&source(), &config(), &old, NOW).expect("usable");
        // tau = 500ms, so a one-second-old quote carries a third of the weight.
        let ratio = fresh.weight.checked_div(old.weight).expect("in range");
        let error = ratio
            .checked_sub(fixed("3"))
            .and_then(Fixed::checked_abs)
            .expect("in range");
        assert!(error <= fixed("0.000000001"), "ratio was {ratio}");
    }

    /// The spread penalty is severe by design, and worth seeing plainly: a book
    /// two percent wide is worth a fraction of a percent of a tight one.
    #[test]
    fn the_spread_penalty_is_steep() {
        let mut tight = slots();
        put(&mut tight, book("99.999", "100.001", "5", "5", 0));
        let mut wide = slots();
        put(&mut wide, book("99", "101", "5", "5", 0));
        let tight = derive(&source(), &config(), &tight, NOW).expect("usable");
        let wide = derive(&source(), &config(), &wide, NOW).expect("usable");
        // A book 0.2bp wide already gives up a sixth of its weight; one 200bp
        // wide keeps half a percent. Relative ordering is what matters, but the
        // steepness is worth seeing.
        assert_eq!(tight.weight.to_string(), "0.833333333333");
        assert_eq!(wide.weight.to_string(), "0.004975124378");
    }

    #[test]
    fn tighter_books_weigh_more() {
        let mut tight = slots();
        put(&mut tight, book("99.99", "100.01", "5", "5", 0));
        let mut wide = slots();
        put(&mut wide, book("99", "101", "5", "5", 0));

        let tight = derive(&source(), &config(), &tight, NOW).expect("usable");
        let wide = derive(&source(), &config(), &wide, NOW).expect("usable");
        assert!(
            tight.weight > wide.weight,
            "{} should exceed {}",
            tight.weight,
            wide.weight
        );
    }

    #[test]
    fn static_trust_scales_the_weight() {
        let mut slots = slots();
        put(&mut slots, book("100", "102", "5", "5", 0));
        let trusted = source().with_weight(fixed("3"));
        let plain = derive(&source(), &config(), &slots, NOW).expect("usable");
        let boosted = derive(&trusted, &config(), &slots, NOW).expect("usable");
        assert_eq!(
            boosted.weight,
            plain.weight.checked_mul(fixed("3")).expect("in range")
        );
    }

    #[test]
    fn depth_weighting_is_neutral_when_depth_is_absent() {
        // bookTicker carries no depth, so every source currently gets the
        // neutral factor rather than a silently-zero weight.
        let mut slots = slots();
        put(&mut slots, book("100", "102", "5", "5", 0));
        let quote = derive(&source(), &config(), &slots, NOW).expect("usable");
        assert!(quote.weight.is_positive());
    }

    #[test]
    fn depth_weighting_applies_sub_linearly_when_present() {
        let mut shallow = slots();
        let mut deep = slots();
        let mut a = book("100", "102", "5", "5", 0);
        let mut b = book("100", "102", "5", "5", 0);
        a.depth_notional_1bp = Some(fixed("25000"));
        b.depth_notional_1bp = Some(fixed("100000"));
        put(&mut shallow, a);
        put(&mut deep, b);

        let shallow = derive(&source(), &config(), &shallow, NOW).expect("usable");
        let deep = derive(&source(), &config(), &deep, NOW).expect("usable");
        // Four times the depth for twice the weight: sqrt, not linear. Exact to
        // within the last place of the fixed-point scale.
        let ratio = deep.weight.checked_div(shallow.weight).expect("in range");
        let error = ratio
            .checked_sub(fixed("2"))
            .and_then(Fixed::checked_abs)
            .expect("in range");
        assert!(error <= fixed("0.000000001"), "ratio was {ratio}");
    }

    #[test]
    fn non_book_kinds_may_be_zero_or_negative() {
        let funding_source = SourceConfig::new(instrument(), vec![ObsKind::Funding]);
        let mut slots = slots();
        let mut observation = trade("-0.000125", 0);
        observation.kind = ObsKind::Funding;
        put(&mut slots, observation);
        let quote = derive(&funding_source, &config(), &slots, NOW).expect("usable");
        assert_eq!(quote.price, fixed("-0.000125"));
    }
}
