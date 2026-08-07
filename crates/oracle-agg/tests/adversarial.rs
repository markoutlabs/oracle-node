//! Adversarial replay: manipulated venues driven through the full aggregator.
//!
//! Each scenario replays a scripted observation sequence and asserts the same
//! contract: **the aggregator either prices honestly, or degrades loudly, or
//! halts — but it never publishes a confidently wrong number.**
//!
//! These run against [`Aggregator`] rather than the pure aggregation function, so
//! they cover routing, per-venue state, staleness, invalidation, and the
//! publication policy together. That is where the interesting mistakes hide: the
//! individual pieces are easy to get right in isolation.

use std::time::Duration;

use oracle_agg::config::SourceConfig;
use oracle_agg::{Aggregator, FeedConfig};
use oracle_types::{
    FeedId, Fixed, InstrumentId, MarketKind, ObsKind, Observation, PriceUpdate, Symbol, Venue,
};

const SECOND: u64 = 1_000_000_000;
const START: u64 = 1_754_582_400 * SECOND;

/// The five venues from SPEC.md §4.2.
const VENUES: [Venue; 5] = [
    Venue::Binance,
    Venue::Bybit,
    Venue::Okx,
    Venue::Coinbase,
    Venue::Kraken,
];

fn fixed(text: &str) -> Fixed {
    text.parse().expect("valid decimal")
}

fn feed_id() -> FeedId {
    FeedId::from_bytes([7; 32])
}

fn instrument(venue: Venue) -> InstrumentId {
    InstrumentId::new(venue, MarketKind::Spot, "BTCUSDT")
}

fn config(venues: &[Venue], min_sources: u32) -> FeedConfig {
    let symbol: Symbol = "CRYPTO.BTC/USDT".parse().expect("valid");
    let sources = venues
        .iter()
        .map(|venue| SourceConfig::new(instrument(*venue), vec![ObsKind::BookTop, ObsKind::Trade]))
        .collect();
    let mut config = FeedConfig::spot(symbol, feed_id(), sources);
    config.min_sources = min_sources;
    config
}

/// A two-sided book one basis point wide around `mid`.
fn book(venue: Venue, mid: &str, recv_ns: u64) -> Observation {
    let mid = fixed(mid);
    let half = mid.checked_mul(fixed("0.00005")).expect("in range");
    quote_book(
        venue,
        mid.checked_sub(half).expect("in range"),
        mid.checked_add(half).expect("in range"),
        recv_ns,
    )
}

fn quote_book(venue: Venue, bid: Fixed, ask: Fixed, recv_ns: u64) -> Observation {
    Observation {
        instrument: instrument(venue),
        kind: ObsKind::BookTop,
        price: bid,
        bid: Some(bid),
        ask: Some(ask),
        bid_qty: Some(Fixed::ONE),
        ask_qty: Some(Fixed::ONE),
        depth_notional_1bp: None,
        exchange_time_ns: None,
        local_recv_ns: recv_ns,
        seq: None,
    }
}

/// Feeds every venue the same honest mid, then polls.
fn honest_tick(
    aggregator: &mut Aggregator,
    venues: &[Venue],
    mid: &str,
    at_ns: u64,
) -> Option<PriceUpdate> {
    for venue in venues {
        aggregator.observe(&book(*venue, mid, at_ns));
    }
    aggregator.poll(feed_id(), at_ns).expect("no config error")
}

/// Warms the feed up with a few honest ticks and returns the last published price.
fn warm_up(aggregator: &mut Aggregator, venues: &[Venue], mid: &str) -> PriceUpdate {
    let mut last = None;
    for tick in 0..4_u64 {
        if let Some(update) = honest_tick(aggregator, venues, mid, START + tick * SECOND) {
            last = Some(update);
        }
    }
    last.expect("warm-up must publish")
}

fn price_of(update: &PriceUpdate) -> Fixed {
    update.price_fixed().expect("representable")
}

fn conf_of(update: &PriceUpdate) -> Fixed {
    update.conf_fixed().expect("representable")
}

// ---------------------------------------------------------------- scenarios

/// One venue prints ten percent off. The honest majority must absorb it.
#[test]
fn a_single_spoofed_venue_is_rejected() {
    let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
    let baseline = warm_up(&mut aggregator, &VENUES, "64000");

    let at = START + 10 * SECOND;
    for venue in [Venue::Binance, Venue::Bybit, Venue::Okx, Venue::Coinbase] {
        aggregator.observe(&book(venue, "64000", at));
    }
    aggregator.observe(&book(Venue::Kraken, "70400", at));

    let update = aggregator
        .poll(feed_id(), at)
        .expect("no error")
        .expect("publishes");
    assert!(update.is_usable());
    assert!(
        !update.sources.contains(Venue::Kraken),
        "the spoofer must be dropped"
    );
    assert_eq!(update.num_sources, 4);
    assert_eq!(
        price_of(&update),
        price_of(&baseline),
        "the price must not move at all"
    );
}

/// A venue stops updating. It must age out rather than pin a stale price.
#[test]
fn a_frozen_venue_ages_out() {
    let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
    warm_up(&mut aggregator, &VENUES, "64000");

    // Everyone but Kraken keeps quoting while the market moves up one percent.
    let live: Vec<Venue> = VENUES.into_iter().filter(|v| *v != Venue::Kraken).collect();
    let at = START + 10 * SECOND;
    let update = honest_tick(&mut aggregator, &live, "64640", at).expect("publishes");

    assert!(
        !update.sources.contains(Venue::Kraken),
        "a frozen venue must not linger"
    );
    assert_eq!(update.num_sources, 4);
    assert_eq!(price_of(&update), fixed("64640"));
}

/// Losing quorum halts, and the carried price is explicitly unusable.
#[test]
fn losing_quorum_halts_rather_than_guessing() {
    let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
    let baseline = warm_up(&mut aggregator, &VENUES, "64000");

    // Only two venues remain live, one short of the quorum.
    let at = START + 10 * SECOND;
    for venue in [Venue::Binance, Venue::Bybit] {
        aggregator.observe(&book(venue, "64000", at));
    }
    let update = aggregator
        .poll(feed_id(), at)
        .expect("no error")
        .expect("halt publishes");

    assert!(update.flags.is_halted());
    assert!(!update.is_usable(), "a halted price must never settle");
    assert_eq!(
        price_of(&update),
        price_of(&baseline),
        "the last good price is carried"
    );
    assert_eq!(update.num_sources, 0, "a halt claims no sources");
}

/// A book that has gone one-sided must not be priced off a fictional mid.
#[test]
fn a_one_sided_book_is_priced_by_the_microprice_not_the_mid() {
    let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
    warm_up(&mut aggregator, &VENUES, "64000");

    let at = START + 10 * SECOND;
    for venue in [Venue::Binance, Venue::Bybit, Venue::Okx, Venue::Coinbase] {
        aggregator.observe(&book(venue, "64000", at));
    }
    // Kraken's offer has been swept: a sliver left at a much higher price.
    let mut lopsided = quote_book(Venue::Kraken, fixed("63996.8"), fixed("64100"), at);
    lopsided.bid_qty = Some(fixed("50"));
    lopsided.ask_qty = Some(fixed("0.01"));
    aggregator.observe(&lopsided);

    let update = aggregator
        .poll(feed_id(), at)
        .expect("no error")
        .expect("publishes");
    // The wide book earns almost no weight, so it cannot drag the price.
    assert!(update.is_usable());
    let drift = price_of(&update)
        .checked_sub(fixed("64000"))
        .and_then(Fixed::checked_abs)
        .expect("in range");
    assert!(
        drift < fixed("1"),
        "a one-sided book moved the price by {drift}"
    );
}

/// A crossed book is inconsistent venue data. Drop it; never repair it.
#[test]
fn a_crossed_book_is_discarded() {
    let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
    warm_up(&mut aggregator, &VENUES, "64000");

    let at = START + 10 * SECOND;
    for venue in [Venue::Binance, Venue::Bybit, Venue::Okx, Venue::Coinbase] {
        aggregator.observe(&book(venue, "64000", at));
    }
    aggregator.observe(&quote_book(
        Venue::Kraken,
        fixed("64100"),
        fixed("63900"),
        at,
    ));

    let update = aggregator
        .poll(feed_id(), at)
        .expect("no error")
        .expect("publishes");
    assert!(!update.sources.contains(Venue::Kraken));
    assert_eq!(price_of(&update), fixed("64000"));
}

/// A sudden move only one venue makes must degrade and widen, not publish a
/// confident new level.
#[test]
fn an_uncorroborated_jump_degrades_and_widens() {
    let mut aggregator =
        Aggregator::new(vec![config(&[Venue::Binance, Venue::Bybit], 2)]).expect("valid config");
    let baseline = warm_up(&mut aggregator, &[Venue::Binance, Venue::Bybit], "64000");

    // Binance runs ten percent; Bybit does not move.
    let at = START + 10 * SECOND;
    aggregator.observe(&book(Venue::Binance, "70400", at));
    aggregator.observe(&book(Venue::Bybit, "64000", at));

    let update = aggregator
        .poll(feed_id(), at)
        .expect("no error")
        .expect("publishes");
    assert!(
        update.flags.is_degraded(),
        "an uncorroborated jump must be flagged"
    );
    assert!(
        update.is_usable(),
        "degraded is still usable — that is the point"
    );

    let moved = price_of(&update)
        .checked_sub(price_of(&baseline))
        .expect("in range");
    assert!(
        conf_of(&update) >= moved.checked_abs().expect("in range"),
        "the band must cover the distance moved: conf {} vs move {moved}",
        conf_of(&update)
    );
}

/// The same move, made by everyone, is a real move and must publish cleanly.
#[test]
fn a_corroborated_jump_publishes_without_degrading() {
    let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
    warm_up(&mut aggregator, &VENUES, "64000");

    let at = START + 10 * SECOND;
    let update = honest_tick(&mut aggregator, &VENUES, "70400", at).expect("publishes");
    assert!(update.flags.is_none(), "a market-wide move is not a fault");
    assert_eq!(price_of(&update), fixed("70400"));
}

/// Every venue agreeing on a wrong price is the one failure no filter catches.
/// The sanity band exists for exactly this.
#[test]
fn a_market_wide_dislocation_trips_the_sanity_band() {
    let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
    warm_up(&mut aggregator, &VENUES, "64000");

    // A tenfold collapse everyone agrees on: a redenomination, or a mapping bug.
    let at = START + 10 * SECOND;
    let update = honest_tick(&mut aggregator, &VENUES, "6400", at).expect("publishes");
    assert!(
        update.flags.is_halted(),
        "unanimous nonsense must halt, not publish"
    );
    assert!(!update.is_usable());
}

/// A slow drift by one venue must never accumulate into the published price.
#[test]
fn a_slow_drifting_venue_never_moves_the_price() {
    let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
    warm_up(&mut aggregator, &VENUES, "64000");

    let honest: Vec<Venue> = VENUES.into_iter().filter(|v| *v != Venue::Kraken).collect();
    let mut last = None;
    // Kraken walks up 0.5% per tick for twenty ticks: a ten percent divergence.
    for tick in 1..=20_u64 {
        let at = START + (10 + tick) * SECOND;
        for venue in &honest {
            aggregator.observe(&book(*venue, "64000", at));
        }
        let drifted = fixed("64000")
            .checked_mul(
                Fixed::ONE
                    .checked_add(
                        fixed("0.005")
                            .checked_mul(Fixed::from_raw(i128::from(tick) * 1_000_000_000_000))
                            .expect("in range"),
                    )
                    .expect("in range"),
            )
            .expect("in range");
        aggregator.observe(&quote_book(
            Venue::Kraken,
            drifted,
            drifted.checked_mul(fixed("1.0001")).expect("in range"),
            at,
        ));
        if let Some(update) = aggregator.poll(feed_id(), at).expect("no error") {
            last = Some(update);
        }
    }

    let update = last.expect("publishes");
    assert!(update.is_usable());
    assert_eq!(
        price_of(&update),
        fixed("64000"),
        "a drifting venue must be rejected, not averaged in"
    );
}

/// A venue quoting an implausibly tight book is buying weight. It must not be
/// able to buy the price.
#[test]
fn an_implausibly_tight_book_cannot_capture_the_price() {
    let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
    warm_up(&mut aggregator, &VENUES, "64000");

    let at = START + 10 * SECOND;
    for venue in [Venue::Binance, Venue::Bybit, Venue::Okx, Venue::Coinbase] {
        aggregator.observe(&book(venue, "64000", at));
    }
    // Inside the outlier band so rejection will not catch it, but quoting a
    // spread a thousand times tighter than anyone else to maximise its weight.
    aggregator.observe(&quote_book(
        Venue::Kraken,
        fixed("64031.9999"),
        fixed("64032.0001"),
        at,
    ));

    let update = aggregator
        .poll(feed_id(), at)
        .expect("no error")
        .expect("publishes");
    let drift = price_of(&update)
        .checked_sub(fixed("64000"))
        .and_then(Fixed::checked_abs)
        .expect("in range");
    assert!(
        drift < fixed("32"),
        "a tight-book attacker pulled the price {drift} toward its own quote"
    );
}

/// A disconnect must invalidate immediately, even mid-second, because the venue
/// may have moved while we were blind.
#[test]
fn a_disconnect_invalidates_faster_than_the_staleness_filter() {
    let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
    warm_up(&mut aggregator, &VENUES, "64000");

    let at = START + 10 * SECOND;
    for venue in VENUES {
        aggregator.observe(&book(venue, "64000", at));
    }
    // Binance drops. Its book is milliseconds old and would sail through the
    // two-second staleness filter, but it must not survive the gap.
    aggregator.invalidate(Venue::Binance, MarketKind::Spot);

    let update = aggregator
        .poll(feed_id(), at + 10_000_000)
        .expect("no error")
        .expect("publishes");
    assert!(!update.sources.contains(Venue::Binance));
    assert_eq!(update.num_sources, 4);
}

/// Replaying the same inputs twice must produce byte-identical outputs. This is
/// what makes an incident reviewable months later.
#[test]
fn replay_is_deterministic() {
    fn run() -> Vec<PriceUpdate> {
        let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
        let mut updates = Vec::new();
        for tick in 0..40_u64 {
            let at = START + tick * 250_000_000;
            // A deterministic sawtooth, plus one venue misbehaving periodically.
            let mid = format!("{}", 64_000 + (tick % 7) * 3);
            for venue in VENUES {
                if venue == Venue::Kraken && tick % 5 == 0 {
                    aggregator.observe(&book(venue, "70000", at));
                } else {
                    aggregator.observe(&book(venue, &mid, at));
                }
            }
            if let Some(update) = aggregator.poll(feed_id(), at).expect("no error") {
                updates.push(update);
            }
        }
        updates
    }

    let first = run();
    assert!(first.len() > 5, "the scenario must actually publish");
    assert_eq!(
        first,
        run(),
        "identical inputs must replay to identical outputs"
    );
}

/// Confidence must never be zero, whatever the inputs. A zero band claims
/// perfect knowledge.
#[test]
fn confidence_is_never_zero() {
    let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
    let mut checked = 0;
    for tick in 0..20_u64 {
        let at = START + tick * SECOND;
        // Every venue in perfect agreement, the case most likely to collapse the
        // dispersion estimate to nothing.
        if let Some(update) = honest_tick(&mut aggregator, &VENUES, "64000", at) {
            assert!(
                conf_of(&update).is_positive(),
                "confidence collapsed to zero"
            );
            checked += 1;
        }
    }
    assert!(checked > 5);
}

/// Under sustained volatility the rate cap must hold, because that is when
/// signing cost and subscriber bandwidth are under the most stress.
#[test]
fn the_rate_cap_holds_under_volatility() {
    let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
    let mut publish_times = Vec::new();

    // Ten milliseconds per tick, with the price moving hard every tick.
    for tick in 0..500_u64 {
        let at = START + tick * 10_000_000;
        let mid = format!("{}", 64_000 + (tick % 50) * 20);
        for venue in VENUES {
            aggregator.observe(&book(venue, &mid, at));
        }
        if let Some(update) = aggregator.poll(feed_id(), at).expect("no error") {
            publish_times.push(update.publish_time_ns);
        }
    }

    assert!(publish_times.len() > 10, "the feed must still publish");
    let min_interval = u64::try_from(Duration::from_millis(50).as_nanos()).expect("fits");
    for window in publish_times.windows(2) {
        let (Some(previous), Some(next)) = (window.first(), window.get(1)) else {
            continue;
        };
        let gap = next.saturating_sub(*previous);
        assert!(
            gap >= min_interval,
            "published {gap}ns apart, inside the 50ms cap"
        );
    }
}

/// Sequence numbers are the consumer's only defence against a replayed update,
/// so they must be strictly monotonic across every transition.
#[test]
fn sequence_numbers_survive_halts_and_recoveries() {
    let mut aggregator = Aggregator::new(vec![config(&VENUES, 3)]).expect("valid config");
    let mut seqs = Vec::new();

    for cycle in 0..3_u64 {
        let base = START + cycle * 60 * SECOND;
        // Healthy.
        for tick in 0..4_u64 {
            if let Some(update) =
                honest_tick(&mut aggregator, &VENUES, "64000", base + tick * SECOND)
            {
                seqs.push(update.seq);
            }
        }
        // Everything goes away and the feed halts.
        for tick in 4..8_u64 {
            if let Some(update) = aggregator
                .poll(feed_id(), base + tick * SECOND)
                .expect("no error")
            {
                seqs.push(update.seq);
            }
        }
    }

    assert!(seqs.len() > 10);
    assert!(
        seqs.windows(2)
            .all(|w| matches!((w.first(), w.get(1)), (Some(a), Some(b)) if b > a)),
        "sequence numbers repeated: {seqs:?}"
    );
}
