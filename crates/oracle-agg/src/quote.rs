//! Turning one venue's observations into one weighted quote.

use oracle_types::{Fixed, ObsKind, Observation, SourceStatus, Venue};

use crate::config::{FeedConfig, SourceConfig};

/// One venue's contribution to a feed, after normalization and weighting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceQuote {
    /// The source's position in the feed's configuration.
    pub source: usize,
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
    /// Notional resting within one basis point of the mid, from the venue's
    /// book. Weighs in only when every source has it.
    pub depth_notional: Option<Fixed>,
}

/// When the venue last confirmed an observation: its receipt, or a later sign
/// that the connection carrying this kind was alive. A venue sends on change,
/// so on a live connection the value has not changed. A trade is an event, not
/// a state: only its receipt counts.
fn confirmed_ns(observation: &Observation, alive: &[u64]) -> u64 {
    if observation.kind == ObsKind::Trade {
        return observation.local_recv_ns;
    }
    alive
        .get(observation.kind.index())
        .copied()
        .unwrap_or(0)
        .max(observation.local_recv_ns)
}

/// The two staleness limits of a feed, in nanoseconds.
#[derive(Clone, Copy)]
struct Limits {
    max_age_ns: u64,
    max_unchanged_ns: u64,
}

impl Limits {
    fn of(config: &FeedConfig) -> Self {
        let ns =
            |duration: std::time::Duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        Self {
            max_age_ns: ns(config.max_age),
            max_unchanged_ns: ns(config.max_unchanged),
        }
    }

    /// The age to weigh: time since the venue last confirmed the value.
    fn age_ns(observation: &Observation, alive: &[u64], now_ns: u64) -> u64 {
        now_ns.saturating_sub(confirmed_ns(observation, alive))
    }

    fn is_stale(self, observation: &Observation, alive: &[u64], now_ns: u64) -> bool {
        Self::age_ns(observation, alive, now_ns) > self.max_age_ns
            || observation.age_ns(now_ns) > self.max_unchanged_ns
    }
}

/// Derives a quote from the freshest usable observation for one source.
///
/// Kinds are tried in the configured preference order. An observation is usable
/// when the venue confirmed it within `max_age` on **our** clock, it changed
/// within `max_unchanged` and, for a book, it is not crossed. `alive` holds,
/// for each kind, when the connection carrying it last received anything.
///
/// # Why the microprice
///
/// On a balanced book it equals the mid. On a one-sided one it leans toward the
/// thin side, which is where the next print is more likely to land — the mid
/// quietly becomes fiction exactly when a venue is under stress, which is the
/// moment the number matters most.
///
/// # Errors
///
/// With no usable kind, returns why, for the venue report: crossed, invalid,
/// stale or no data, in that order.
pub fn derive(
    index: usize,
    source: &SourceConfig,
    config: &FeedConfig,
    latest: &[Option<Observation>],
    alive: &[u64],
    now_ns: u64,
) -> Result<SourceQuote, SourceStatus> {
    let limits = Limits::of(config);

    // Depth replaces a top-of-book price, never a venue's mark or index.
    if let Some(notional) = config.impact_notional
        && source.kinds.contains(&ObsKind::BookTop)
        && let Some(quote) = from_depth(index, source, config, latest, alive, notional, now_ns)
    {
        return Ok(quote);
    }

    let mut status = SourceStatus::NoData;
    for kind in &source.kinds {
        let Some(Some(observation)) = latest.get(kind.index()) else {
            continue;
        };
        if limits.is_stale(observation, alive, now_ns) {
            status = worse(status, SourceStatus::Stale);
            continue;
        }

        let (price, half_spread, from_book) = if kind.has_book() {
            if observation.is_crossed() {
                // A crossed top-of-book means the venue's feed is inconsistent.
                // Drop it; never repair it.
                status = worse(status, SourceStatus::Crossed);
                continue;
            }
            let Some(price) = observation.microprice().or_else(|| observation.mid()) else {
                status = worse(status, SourceStatus::Invalid);
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
            status = worse(status, SourceStatus::Invalid);
            continue;
        }

        return Ok(SourceQuote {
            source: index,
            venue: observation.venue(),
            price,
            half_spread,
            weight: weight_for(
                source,
                observation.spread().and_then(|s| s.to_bps_of(price)),
            )
            .ok_or(SourceStatus::Invalid)?,
            observation_time_ns: observation.local_recv_ns,
            from_book,
            converted: source.convert_quote,
            depth_notional: observation.depth_notional_1bp,
        });
    }
    Err(status)
}

/// The more specific of two reasons a source has no quote.
fn worse(current: SourceStatus, found: SourceStatus) -> SourceStatus {
    let rank = |status| match status {
        SourceStatus::Crossed => 3,
        SourceStatus::Invalid => 2,
        SourceStatus::Stale => 1,
        _ => 0,
    };
    if rank(found) > rank(current) {
        found
    } else {
        current
    }
}

/// The latest observation of `kind` if it is fresh and not crossed.
fn usable<'a>(
    latest: &'a [Option<Observation>],
    alive: &[u64],
    kind: ObsKind,
    now_ns: u64,
    limits: Limits,
) -> Option<&'a Observation> {
    latest
        .get(kind.index())?
        .as_ref()
        .filter(|observation| !limits.is_stale(observation, alive, now_ns))
        .filter(|observation| !observation.is_crossed())
}

/// The impact mid for `notional` from the latest depth snapshot, moved by how
/// far the live top of book has moved since.
///
/// Depth sets the level, so one large order at the top cannot lean it. The top
/// sets the timing, so the price does not wait for the next snapshot; a fake
/// top order moves it only until that snapshot shows the order.
fn from_depth(
    index: usize,
    source: &SourceConfig,
    config: &FeedConfig,
    latest: &[Option<Observation>],
    alive: &[u64],
    notional: Fixed,
    now_ns: u64,
) -> Option<SourceQuote> {
    let limits = Limits::of(config);
    let depth = usable(latest, alive, ObsKind::Depth, now_ns, limits)?;
    let book = depth.book.as_deref()?;
    let impact = book.impact(notional)?;
    if impact.bid > impact.ask {
        return None;
    }
    let mut price = impact.mid()?;
    let mut received_ns = depth.local_recv_ns;
    if let Some(top) = usable(latest, alive, ObsKind::BookTop, now_ns, limits)
        && top.local_recv_ns > depth.local_recv_ns
        && let (Some(now), Some(then)) = (top.mid(), depth.mid())
    {
        price = price.checked_add(now.checked_sub(then)?)?;
        received_ns = top.local_recv_ns;
    }
    if !price.is_positive() {
        return None;
    }
    let spread = impact.ask.checked_sub(impact.bid)?;
    Some(SourceQuote {
        source: index,
        venue: depth.venue(),
        price,
        half_spread: spread.checked_div(Fixed::from_int(2).ok()?),
        weight: weight_for(source, spread.to_bps_of(price))?,
        observation_time_ns: received_ns,
        from_book: true,
        converted: source.convert_quote,
        depth_notional: book.notional_within_bps(Fixed::ONE),
    })
}

/// Computes the aggregation weight for one quote, before depth.
///
/// `trust × spread`. Depth is applied across all quotes at once; see
/// [`depth_factor`]. Age has no weight: every quote here is confirmed within
/// `max_age` (SPEC §5.5).
fn weight_for(source: &SourceConfig, spread_bps: Option<Fixed>) -> Option<Fixed> {
    let mut weight = source.weight;

    // Tighter books count for more. Aggressive by design: a venue quoting five
    // basis points wide is not offering the same information as one quoting a
    // tenth of that.
    if let Some(spread_bps) = spread_bps {
        let one = Fixed::ONE;
        let denominator = one.checked_add(spread_bps.checked_abs()?)?;
        weight = weight.checked_mul(one.checked_div(denominator)?)?;
    }

    Some(weight)
}

/// Liquidity, sub-linearly: `sqrt(depth / reference)`, capped. `None` when
/// there is no depth or no reference.
pub(crate) fn depth_factor(config: &FeedConfig, depth: Option<Fixed>) -> Option<Fixed> {
    let depth = depth?;
    if !config.depth_reference.is_positive() {
        return None;
    }
    let factor = depth
        .checked_div(config.depth_reference)?
        .sqrt()?
        .min(config.depth_cap);
    factor.is_positive().then_some(factor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SourceConfig;
    use oracle_types::{FeedId, InstrumentId, MarketKind, ObsKind, Symbol};

    const NOW: u64 = 1_000_000_000_000;
    /// No liveness: only receipts count, as before connection liveness.
    const NO_ALIVE: [u64; ObsKind::COUNT] = [0; ObsKind::COUNT];

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
            funding: None,
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
            funding: None,
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
        let micro = derive(0, &source(), &config(), &slots, &NO_ALIVE, NOW).expect("a quote");
        assert!(
            micro.price > fixed("100.9"),
            "the spoof leans it: {}",
            micro.price
        );

        let quote =
            derive(0, &source(), &with_impact("50"), &slots, &NO_ALIVE, NOW).expect("a quote");
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
        let quote =
            derive(0, &source(), &with_impact("50"), &slots, &NO_ALIVE, NOW).expect("a quote");
        assert_eq!(quote.price, fixed("100.9"));
        assert_eq!(quote.observation_time_ns, NOW - 5);

        // A top older than the snapshot adds nothing.
        put(&mut slots, book("100.4", "101.4", "1", "1", 90));
        let quote =
            derive(0, &source(), &with_impact("50"), &slots, &NO_ALIVE, NOW).expect("a quote");
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
        let quote =
            derive(0, &mark_only, &with_impact("50"), &slots, &NO_ALIVE, NOW).expect("a quote");
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
        let quote =
            derive(0, &source(), &with_impact("50"), &slots, &NO_ALIVE, NOW).expect("a quote");
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
            derive(0, &source(), &with_impact("50"), &slots, &NO_ALIVE, NOW).expect("a quote")
        };
        let deep = {
            let mut slots = slots();
            put(
                &mut slots,
                depth(&[("99.99", "100")], &[("100.01", "100")], 10),
            );
            derive(0, &source(), &with_impact("50"), &slots, &NO_ALIVE, NOW).expect("a quote")
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

    const SECOND: u64 = 1_000_000_000;

    /// Each kind's connection was alive `ago` before now.
    fn alive(ago: u64) -> [u64; ObsKind::COUNT] {
        [NOW - ago; ObsKind::COUNT]
    }

    /// The venue sends on change: a book unchanged for 10 s on a connection that
    /// received data 100 ms ago is the current book, and weighs as fresh.
    #[test]
    fn a_quiet_value_on_a_live_connection_stays_current() {
        let mut quiet = slots();
        put(&mut quiet, book("100", "102", "5", "5", 10 * SECOND));
        let quote =
            derive(0, &source(), &config(), &quiet, &alive(SECOND / 10), NOW).expect("current");
        assert_eq!(quote.price, fixed("101"));

        let mut fresh = slots();
        put(&mut fresh, book("100", "102", "5", "5", SECOND / 10));
        let fresh = derive(0, &source(), &config(), &fresh, &NO_ALIVE, NOW).expect("fresh");
        assert_eq!(quote.weight, fresh.weight, "the same weight");

        // Without the live connection, the same book is stale, as before.
        assert_eq!(
            derive(0, &source(), &config(), &quiet, &NO_ALIVE, NOW),
            Err(SourceStatus::Stale)
        );
    }

    /// A connection that received nothing for longer than `max_age` proves
    /// nothing: its values go stale.
    /// Age gives no weight. A weight that fell with age pulsed with the 1 s
    /// probe, and with two sources the heavier one took the whole price.
    #[test]
    fn a_quote_weighs_the_same_at_any_age_within_the_limit() {
        let weight_at = |age_ns| {
            let mut slots = slots();
            put(&mut slots, book("100", "102", "5", "5", age_ns));
            derive(0, &source(), &config(), &slots, &NO_ALIVE, NOW)
                .expect("current")
                .weight
        };
        assert_eq!(weight_at(0), weight_at(3 * SECOND / 2));
    }

    #[test]
    fn a_silent_connection_makes_its_values_stale() {
        let mut slots = slots();
        put(&mut slots, book("100", "102", "5", "5", 3 * SECOND));
        assert_eq!(
            derive(0, &source(), &config(), &slots, &alive(3 * SECOND), NOW),
            Err(SourceStatus::Stale)
        );
    }

    /// One instrument can freeze inside a live venue feed. Past `max_unchanged`
    /// its value is stale, however alive the connection is.
    #[test]
    fn a_value_unchanged_past_the_cap_is_stale() {
        let mut slots = slots();
        let past_cap = u64::try_from(config().max_unchanged.as_nanos()).expect("fits") + SECOND;
        put(&mut slots, book("100", "102", "5", "5", past_cap));
        assert_eq!(
            derive(0, &source(), &config(), &slots, &alive(0), NOW),
            Err(SourceStatus::Stale)
        );
    }

    /// A trade is an event, not a state: an old print is not the current price,
    /// whatever the connection does.
    #[test]
    fn a_trade_is_not_kept_current_by_liveness() {
        let mut slots = slots();
        put(&mut slots, trade("100", 10 * SECOND));
        assert_eq!(
            derive(0, &source(), &config(), &slots, &alive(0), NOW),
            Err(SourceStatus::Stale)
        );
    }

    #[test]
    fn a_balanced_book_yields_the_mid() {
        let mut slots = slots();
        put(&mut slots, book("100", "102", "5", "5", 0));
        let quote = derive(0, &source(), &config(), &slots, &NO_ALIVE, NOW).expect("usable");
        assert_eq!(quote.price, fixed("101"));
        assert_eq!(quote.half_spread, Some(fixed("1")));
        assert!(quote.from_book);
    }

    #[test]
    fn an_unbalanced_book_leans_toward_the_thin_side() {
        let mut slots = slots();
        put(&mut slots, book("100", "102", "9", "1", 0));
        let quote = derive(0, &source(), &config(), &slots, &NO_ALIVE, NOW).expect("usable");
        assert_eq!(quote.price, fixed("101.8"));
    }

    #[test]
    fn a_stale_book_falls_through_to_a_fresh_trade() {
        let mut slots = slots();
        // Book is three seconds old; the 2s threshold rejects it.
        put(&mut slots, book("100", "102", "5", "5", 3_000_000_000));
        put(&mut slots, trade("101.5", 0));
        let quote = derive(0, &source(), &config(), &slots, &NO_ALIVE, NOW).expect("usable");
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
        assert_eq!(
            derive(0, &source(), &config(), &slots, &NO_ALIVE, NOW),
            Err(SourceStatus::Stale)
        );
    }

    #[test]
    fn no_observation_at_all_is_no_data() {
        assert_eq!(
            derive(0, &source(), &config(), &slots(), &NO_ALIVE, NOW),
            Err(SourceStatus::NoData)
        );
    }

    #[test]
    fn a_crossed_book_outranks_a_stale_trade() {
        let mut slots = slots();
        put(&mut slots, book("102", "100", "5", "5", 0));
        put(&mut slots, trade("101.5", 3_000_000_000));
        assert_eq!(
            derive(0, &source(), &config(), &slots, &NO_ALIVE, NOW),
            Err(SourceStatus::Crossed)
        );
    }

    #[test]
    fn a_crossed_book_is_dropped_not_repaired() {
        let mut slots = slots();
        put(&mut slots, book("102", "100", "5", "5", 0));
        put(&mut slots, trade("101", 0));
        let quote = derive(0, &source(), &config(), &slots, &NO_ALIVE, NOW).expect("falls back");
        assert_eq!(
            quote.price,
            fixed("101"),
            "must fall through, not average the crossed book"
        );
        assert!(!quote.from_book);
    }

    /// The spread penalty is severe by design, and worth seeing plainly: a book
    /// two percent wide is worth a fraction of a percent of a tight one.
    #[test]
    fn the_spread_penalty_is_steep() {
        let mut tight = slots();
        put(&mut tight, book("99.999", "100.001", "5", "5", 0));
        let mut wide = slots();
        put(&mut wide, book("99", "101", "5", "5", 0));
        let tight = derive(0, &source(), &config(), &tight, &NO_ALIVE, NOW).expect("usable");
        let wide = derive(0, &source(), &config(), &wide, &NO_ALIVE, NOW).expect("usable");
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

        let tight = derive(0, &source(), &config(), &tight, &NO_ALIVE, NOW).expect("usable");
        let wide = derive(0, &source(), &config(), &wide, &NO_ALIVE, NOW).expect("usable");
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
        let plain = derive(0, &source(), &config(), &slots, &NO_ALIVE, NOW).expect("usable");
        let boosted = derive(0, &trusted, &config(), &slots, &NO_ALIVE, NOW).expect("usable");
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
        let quote = derive(0, &source(), &config(), &slots, &NO_ALIVE, NOW).expect("usable");
        assert!(quote.weight.is_positive());
    }

    #[test]
    fn the_depth_factor_is_sub_linear_and_capped() {
        let config = config();
        let factor = |depth: &str| depth_factor(&config, Some(fixed(depth))).expect("a factor");
        // Four times the depth for twice the factor: sqrt, not linear.
        let ratio = factor("100000")
            .checked_div(factor("25000"))
            .expect("in range");
        let error = ratio
            .checked_sub(fixed("2"))
            .and_then(Fixed::checked_abs)
            .expect("in range");
        assert!(error <= fixed("0.000000001"), "ratio was {ratio}");
        assert_eq!(factor("100000000"), config.depth_cap);
        assert_eq!(depth_factor(&config, None), None);
    }

    #[test]
    fn non_book_kinds_may_be_zero_or_negative() {
        let funding_source = SourceConfig::new(instrument(), vec![ObsKind::Funding]);
        let mut slots = slots();
        let mut observation = trade("-0.000125", 0);
        observation.kind = ObsKind::Funding;
        put(&mut slots, observation);
        let quote = derive(0, &funding_source, &config(), &slots, &NO_ALIVE, NOW).expect("usable");
        assert_eq!(quote.price, fixed("-0.000125"));
    }
}
