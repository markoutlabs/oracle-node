//! Turning one venue's observations into one weighted quote.

use oracle_types::{Fixed, ObsKind, Observation, Venue};

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
    /// `true` if this price is quoted in the peg asset and needs conversion.
    pub converted: bool,
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

    // Depth replaces a top-of-book price, never a venue's mark or index.
    if let Some(notional) = config.impact_notional
        && source.kinds.contains(&ObsKind::BookTop)
        && let Some(quote) = from_depth(source, config, latest, notional, now_ns, max_age_ns)
    {
        return Some(quote);
    }

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
            weight: weight_for(
                source,
                config,
                observation.age_ns(now_ns),
                observation.spread().and_then(|s| s.to_bps_of(price)),
                observation.depth_notional_1bp,
            )?,
            observation_time_ns: observation.local_recv_ns,
            from_book,
            converted: source.convert_quote,
        });
    }
    None
}

/// The latest observation of `kind` if it is fresh and not crossed.
fn usable(
    latest: &[Option<Observation>],
    kind: ObsKind,
    now_ns: u64,
    max_age_ns: u64,
) -> Option<&Observation> {
    latest
        .get(kind.index())?
        .as_ref()
        .filter(|observation| !observation.is_stale(now_ns, max_age_ns))
        .filter(|observation| !observation.is_crossed())
}

/// The impact mid for `notional` from the latest depth snapshot, moved by how
/// far the live top of book has moved since.
///
/// Depth sets the level, so one large order at the top cannot lean it. The top
/// sets the timing, so the price does not wait for the next snapshot; a fake
/// top order moves it only until that snapshot shows the order.
fn from_depth(
    source: &SourceConfig,
    config: &FeedConfig,
    latest: &[Option<Observation>],
    notional: Fixed,
    now_ns: u64,
    max_age_ns: u64,
) -> Option<SourceQuote> {
    let depth = usable(latest, ObsKind::Depth, now_ns, max_age_ns)?;
    let book = depth.book.as_deref()?;
    let impact = book.impact(notional)?;
    if impact.bid > impact.ask {
        return None;
    }
    let mut price = impact.mid()?;
    let (mut received_ns, mut age_ns) = (depth.local_recv_ns, depth.age_ns(now_ns));
    if let Some(top) = usable(latest, ObsKind::BookTop, now_ns, max_age_ns)
        && top.local_recv_ns > depth.local_recv_ns
        && let (Some(now), Some(then)) = (top.mid(), depth.mid())
    {
        price = price.checked_add(now.checked_sub(then)?)?;
        (received_ns, age_ns) = (top.local_recv_ns, top.age_ns(now_ns));
    }
    if !price.is_positive() {
        return None;
    }
    let spread = impact.ask.checked_sub(impact.bid)?;
    Some(SourceQuote {
        venue: depth.venue(),
        price,
        half_spread: spread.checked_div(Fixed::from_int(2).ok()?),
        // No depth factor yet: until every venue sends depth, weighting only some
        // by it tilts the median toward them.
        weight: weight_for(source, config, age_ns, spread.to_bps_of(price), None)?,
        observation_time_ns: received_ns,
        from_book: true,
        converted: source.convert_quote,
    })
}

/// Computes the aggregation weight for one quote.
///
/// `trust × depth × recency × spread`, all bounded in `(0, 1]` except trust.
fn weight_for(
    source: &SourceConfig,
    config: &FeedConfig,
    age_ns: u64,
    spread_bps: Option<Fixed>,
    depth_notional: Option<Fixed>,
) -> Option<Fixed> {
    let mut weight = source.weight;

    // Freshness: tau / (tau + age). Hyperbolic rather than exponential so it is
    // exactly reproducible in fixed point — see FeedConfig::recency_tau.
    let tau_ns = u64::try_from(config.recency_tau.as_nanos())
        .unwrap_or(u64::MAX)
        .max(1);
    let tau = Fixed::from_raw(i128::from(tau_ns));
    let age = Fixed::from_raw(i128::from(age_ns));
    let recency = tau.checked_div(tau.checked_add(age)?)?;
    weight = weight.checked_mul(recency)?;

    // Tighter books count for more. Aggressive by design: a venue quoting five
    // basis points wide is not offering the same information as one quoting a
    // tenth of that.
    if let Some(spread_bps) = spread_bps {
        let one = Fixed::ONE;
        let denominator = one.checked_add(spread_bps.checked_abs()?)?;
        weight = weight.checked_mul(one.checked_div(denominator)?)?;
    }

    // Liquidity, sub-linearly. Only a depth snapshot carries it; a venue priced
    // from its top of book gets the neutral factor.
    if let Some(depth) = depth_notional
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
            book: None,
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
            book: None,
        }
    }

    fn depth(bids: &[(&str, &str)], asks: &[(&str, &str)], age_ns: u64) -> Observation {
        let levels = |pairs: &[(&str, &str)]| -> Vec<oracle_types::Level> {
            pairs
                .iter()
                .map(|(price, qty)| oracle_types::Level {
                    price: fixed(price),
                    qty: fixed(qty),
                })
                .collect()
        };
        let (bids, asks) = (levels(bids), levels(asks));
        let (best_bid, best_ask) = (bids.first().copied(), asks.first().copied());
        Observation {
            kind: ObsKind::Depth,
            bid: best_bid.map(|level| level.price),
            ask: best_ask.map(|level| level.price),
            bid_qty: best_bid.map(|level| level.qty),
            ask_qty: best_ask.map(|level| level.qty),
            book: Some(std::sync::Arc::new(oracle_types::BookDepth { bids, asks })),
            ..trade("0", age_ns)
        }
    }

    fn with_impact(notional: &str) -> FeedConfig {
        let mut config = config();
        config.impact_notional = Some(fixed(notional));
        config
    }

    /// A huge bid at the top leans the microprice; the impact price for the
    /// configured notional does not move.
    #[test]
    fn depth_prices_ignore_a_size_spoof_at_the_top() {
        let mut slots = slots();
        put(
            &mut slots,
            depth(&[("100", "1000")], &[("101", "1"), ("102", "100")], 10),
        );
        put(&mut slots, book("100", "101", "1000", "1", 20));
        let micro = derive(&source(), &config(), &slots, NOW).expect("a quote");
        assert!(
            micro.price > fixed("100.9"),
            "the spoof leans it: {}",
            micro.price
        );

        let quote = derive(&source(), &with_impact("50"), &slots, NOW).expect("a quote");
        assert_eq!(quote.price, fixed("100.5"));
        assert_eq!(quote.half_spread, Some(fixed("0.5")));
    }

    /// Between snapshots the price follows the live top, so it is not as old as
    /// the snapshot.
    #[test]
    fn a_newer_top_moves_the_depth_price_by_its_own_move() {
        let mut slots = slots();
        put(&mut slots, depth(&[("100", "10")], &[("101", "10")], 80));
        put(&mut slots, book("100.4", "101.4", "1", "1", 5));
        let quote = derive(&source(), &with_impact("50"), &slots, NOW).expect("a quote");
        assert_eq!(quote.price, fixed("100.9"));
        assert_eq!(quote.observation_time_ns, NOW - 5);

        // A top older than the snapshot adds nothing.
        put(&mut slots, book("100.4", "101.4", "1", "1", 90));
        let quote = derive(&source(), &with_impact("50"), &slots, NOW).expect("a quote");
        assert_eq!(quote.price, fixed("100.5"));
    }

    #[test]
    fn a_source_that_reads_no_book_ignores_depth() {
        let mark_only = SourceConfig::new(instrument(), vec![ObsKind::MarkPrice]);
        let mut slots = slots();
        put(&mut slots, depth(&[("100", "10")], &[("101", "10")], 10));
        put(
            &mut slots,
            Observation {
                kind: ObsKind::MarkPrice,
                ..trade("100.7", 10)
            },
        );
        let quote = derive(&mark_only, &with_impact("50"), &slots, NOW).expect("a quote");
        assert_eq!(quote.price, fixed("100.7"));
    }

    #[test]
    fn a_stale_snapshot_falls_back_to_the_top_of_book() {
        let mut slots = slots();
        put(
            &mut slots,
            depth(&[("100", "10")], &[("101", "10")], 3_000_000_000),
        );
        put(&mut slots, book("100", "102", "1", "1", 10));
        let quote = derive(&source(), &with_impact("50"), &slots, NOW).expect("a quote");
        assert_eq!(quote.price, fixed("101"));
    }

    /// A thin book reaches deeper for the notional, so its impact spread is
    /// wider, and it counts for less.
    #[test]
    fn a_thin_book_weighs_less_through_its_impact_spread() {
        let thin = {
            let mut slots = slots();
            put(
                &mut slots,
                depth(
                    &[("99.99", "0.1"), ("99.5", "10")],
                    &[("100.01", "0.1"), ("100.5", "10")],
                    10,
                ),
            );
            derive(&source(), &with_impact("50"), &slots, NOW).expect("a quote")
        };
        let deep = {
            let mut slots = slots();
            put(
                &mut slots,
                depth(&[("99.99", "100")], &[("100.01", "100")], 10),
            );
            derive(&source(), &with_impact("50"), &slots, NOW).expect("a quote")
        };
        assert!(
            deep.weight > thin.weight,
            "{} vs {}",
            deep.weight,
            thin.weight
        );
        assert!(thin.half_spread > deep.half_spread);
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
