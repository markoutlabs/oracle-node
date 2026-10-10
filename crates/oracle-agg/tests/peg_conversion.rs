//! Stablecoin quote conversion, driven through the full aggregator.
//!
//! Binance, Bybit, and OKX quote in USDT; Coinbase and Kraken quote in USD.
//! Publishing the former as `/USD` without conversion is a lie that costs money
//! the day the peg breaks — and a *silent* one, because on an ordinary day the
//! two are indistinguishable to a few basis points.
//!
//! The contract these tests hold the aggregator to: a depeg must surface as
//! confidence widening across every dependent feed, never as a uniform
//! mispricing, and never as a peg-quoted price published under a USD symbol.
//! Without a peg, the converted sources drop out and the native ones price the
//! feed, degraded, while they meet its quorum.

use oracle_agg::aggregate::Reasons;
use oracle_agg::config::{QuoteConversion, SourceConfig};
use oracle_agg::{Aggregator, FeedConfig};
use oracle_types::{
    FeedId, Fixed, InstrumentId, MarketKind, ObsKind, Observation, PriceUpdate, SourceStatus,
    Symbol, Venue,
};
use oracle_wire::feed_id;

const SECOND: u64 = 1_000_000_000;
const START: u64 = 1_754_582_400 * SECOND;

/// Venues quoting in USDT.
const STABLE_VENUES: [Venue; 3] = [Venue::Binance, Venue::Bybit, Venue::Okx];
/// Venues quoting natively in USD. Losing both is a distinct failure class.
const USD_VENUES: [Venue; 2] = [Venue::Coinbase, Venue::Kraken];

fn fixed(text: &str) -> Fixed {
    text.parse().expect("valid decimal")
}

fn symbol(text: &str) -> Symbol {
    text.parse().expect("valid symbol")
}

fn peg_symbol() -> Symbol {
    symbol("CRYPTO.USDT/USD")
}

fn btc_symbol() -> Symbol {
    symbol("CRYPTO.BTC/USD")
}

fn instrument(venue: Venue, venue_symbol: &str) -> InstrumentId {
    InstrumentId::new(venue, MarketKind::Spot, venue_symbol)
}

/// The peg feed: USDT priced in USD, from venues that quote it natively.
fn peg_feed() -> FeedConfig {
    let sources = USD_VENUES
        .iter()
        .map(|venue| {
            SourceConfig::new(
                instrument(*venue, "USDT-USD"),
                vec![ObsKind::BookTop, ObsKind::Trade],
            )
        })
        .collect();
    let mut config = FeedConfig::spot(peg_symbol(), feed_id(&peg_symbol()), sources);
    config.min_sources = 1;
    // A peg trading at 1.0 has no meaningful multiplicative band around an EMA.
    config.sanity_band = (fixed("0.5"), fixed("2"));
    config
}

/// A BTC/USD feed mixing native-USD venues with USDT-quoted ones, which needs
/// three sources: more than the native venues alone.
fn btc_feed(max_peg_conf_bps: &str) -> FeedConfig {
    btc_feed_needing(max_peg_conf_bps, 3)
}

fn btc_feed_needing(max_peg_conf_bps: &str, min_sources: u32) -> FeedConfig {
    let mut sources: Vec<SourceConfig> = USD_VENUES
        .iter()
        .map(|venue| {
            SourceConfig::new(
                instrument(*venue, "BTC-USD"),
                vec![ObsKind::BookTop, ObsKind::Trade],
            )
        })
        .collect();
    sources.extend(STABLE_VENUES.iter().map(|venue| {
        SourceConfig::new(
            instrument(*venue, "BTCUSDT"),
            vec![ObsKind::BookTop, ObsKind::Trade],
        )
        .converted()
    }));

    let mut config = FeedConfig::spot(btc_symbol(), feed_id(&btc_symbol()), sources);
    config.min_sources = min_sources;
    config.with_conversion(QuoteConversion {
        peg_feed: feed_id(&peg_symbol()),
        max_peg_conf_bps: fixed(max_peg_conf_bps),
    })
}

fn aggregator(max_peg_conf_bps: &str) -> Aggregator {
    Aggregator::new(vec![btc_feed(max_peg_conf_bps), peg_feed()]).expect("valid config")
}

/// A book `width` wide, as a fraction of mid.
fn book(venue: Venue, venue_symbol: &str, mid: Fixed, width: &str, at: u64) -> Observation {
    let half = mid.checked_mul(fixed(width)).expect("in range");
    Observation {
        instrument: instrument(venue, venue_symbol),
        kind: ObsKind::BookTop,
        price: mid,
        bid: Some(mid.checked_sub(half).expect("in range")),
        ask: Some(mid.checked_add(half).expect("in range")),
        bid_qty: Some(Fixed::ONE),
        ask_qty: Some(Fixed::ONE),
        depth_notional_1bp: None,
        exchange_time_ns: None,
        local_recv_ns: at,
        seq: None,
        book: None,
        funding: None,
    }
}

/// Feeds one tick: the peg at `peg_mid`, BTC at `usd_mid` on USD venues and
/// `usdt_mid` on USDT venues.
fn tick(
    aggregator: &mut Aggregator,
    at: u64,
    peg_mid: &str,
    peg_width: &str,
    usd_mid: &str,
    usdt_mid: &str,
) -> Vec<PriceUpdate> {
    for venue in USD_VENUES {
        aggregator.observe(&book(venue, "USDT-USD", fixed(peg_mid), peg_width, at));
        aggregator.observe(&book(venue, "BTC-USD", fixed(usd_mid), "0.00005", at));
    }
    for venue in STABLE_VENUES {
        aggregator.observe(&book(venue, "BTCUSDT", fixed(usdt_mid), "0.00005", at));
    }
    aggregator.poll_all(at).0
}

fn find(updates: &[PriceUpdate], symbol: &Symbol) -> Option<PriceUpdate> {
    let id = feed_id(symbol);
    updates.iter().find(|update| update.feed_id == id).copied()
}

fn price_of(update: &PriceUpdate) -> Fixed {
    update.price_fixed().expect("representable")
}

fn conf_of(update: &PriceUpdate) -> Fixed {
    update.conf_fixed().expect("representable")
}

// ------------------------------------------------------------------- tests

/// With the peg at par, converted and native prices agree and nothing degrades.
#[test]
fn at_par_the_converted_and_native_prices_agree() {
    let mut aggregator = aggregator("50");
    let updates = tick(&mut aggregator, START, "1", "0.00005", "64000", "64000");

    let btc = find(&updates, &btc_symbol()).expect("btc publishes");
    assert_eq!(price_of(&btc), fixed("64000"));
    assert_eq!(btc.num_sources, 5, "all five venues contribute");
    assert!(btc.is_usable());
    // Conversion happened, and the flag says so even though nothing is wrong.
    assert!(btc.flags.is_synthetic_quote());
    assert!(!btc.flags.is_degraded());
}

/// The whole point. USDT at 0.97 means a USDT-quoted 64000 is 62080 in USD, and
/// publishing 64000 under a `/USD` symbol would be wrong by three percent.
#[test]
fn a_depeg_moves_converted_sources_onto_the_usd_scale() {
    let mut aggregator = aggregator("500");
    // USD venues price BTC at 62080; USDT venues still show 64000 in their own
    // unit, because USDT is what fell.
    let updates = tick(&mut aggregator, START, "0.97", "0.00005", "62080", "64000");

    let btc = find(&updates, &btc_symbol()).expect("btc publishes");
    // 64000 * 0.97 = 62080, matching the native-USD venues exactly.
    assert_eq!(
        price_of(&btc),
        fixed("62080"),
        "converted sources must land on the USD scale"
    );
    assert_eq!(
        btc.num_sources, 5,
        "conversion must not orphan the USDT venues"
    );
}

/// Without conversion the USDT venues would look like outliers and be rejected,
/// throwing away most of the depth at exactly the wrong moment.
#[test]
fn conversion_keeps_usdt_venues_from_looking_like_outliers() {
    let mut unconverted = {
        let mut config = btc_feed("50");
        config.quote_conversion = None;
        for source in &mut config.sources {
            source.convert_quote = false;
        }
        Aggregator::new(vec![config, peg_feed()]).expect("valid config")
    };
    let updates = tick(&mut unconverted, START, "0.97", "0.00005", "62080", "64000");
    let btc = find(&updates, &btc_symbol()).expect("btc publishes");
    assert!(
        btc.num_sources < 5,
        "unconverted, the USDT venues should be rejected as outliers"
    );

    let mut converted = aggregator("500");
    let updates = tick(&mut converted, START, "0.97", "0.00005", "62080", "64000");
    let btc = find(&updates, &btc_symbol()).expect("btc publishes");
    assert_eq!(btc.num_sources, 5, "converted, every venue survives");
}

/// A wobbling peg must widen every dependent feed. That is the honest signal.
#[test]
fn peg_uncertainty_widens_dependent_feeds() {
    let mut steady = aggregator("500");
    let steady_btc = find(
        &tick(&mut steady, START, "1", "0.000005", "64000", "64000"),
        &btc_symbol(),
    )
    .expect("publishes");

    let mut wobbling = aggregator("500");
    // The peg's own book is a hundred times wider, so its confidence is wider.
    let wobbling_btc = find(
        &tick(&mut wobbling, START, "1", "0.0005", "64000", "64000"),
        &btc_symbol(),
    )
    .expect("publishes");

    assert!(
        conf_of(&wobbling_btc) > conf_of(&steady_btc),
        "a wobbling peg must widen dependents: {} vs {}",
        conf_of(&wobbling_btc),
        conf_of(&steady_btc)
    );
}

/// Past the configured threshold, widening is not enough — say so explicitly.
#[test]
fn an_uncertain_peg_degrades_dependent_feeds() {
    // Threshold of 1bp against a peg quoting a 10bp-wide book.
    let mut aggregator = aggregator("1");
    let updates = tick(&mut aggregator, START, "1", "0.0005", "64000", "64000");

    let btc = find(&updates, &btc_symbol()).expect("btc publishes");
    assert!(
        btc.flags.is_degraded(),
        "an uncertain peg must degrade its dependents"
    );
    assert!(btc.is_usable(), "but degraded is still usable");

    let peg = find(&updates, &peg_symbol()).expect("peg publishes");
    assert!(
        !peg.flags.is_degraded(),
        "the peg itself is fine; it is just imprecise"
    );
}

/// No peg means no honest way to state the USDT prices in USD. The two native
/// venues alone are below this feed's quorum of three.
#[test]
fn losing_the_peg_halts_dependent_feeds_rather_than_publishing_usdt_as_usd() {
    let mut aggregator = aggregator("50");
    let at = START;

    // BTC quotes arrive from every venue, but nothing prices USDT/USD.
    for venue in USD_VENUES {
        aggregator.observe(&book(venue, "BTC-USD", fixed("64000"), "0.00005", at));
    }
    for venue in STABLE_VENUES {
        aggregator.observe(&book(venue, "BTCUSDT", fixed("64000"), "0.00005", at));
    }
    let updates = aggregator.poll_all(at).0;

    assert!(
        find(&updates, &btc_symbol()).is_none(),
        "with no peg and no history there is nothing honest to publish"
    );
}

/// Once the peg goes away mid-flight, a feed whose native venues are below its
/// quorum halts rather than drifting.
#[test]
fn the_peg_going_away_halts_an_established_feed() {
    let mut aggregator = aggregator("50");
    let established = find(
        &tick(&mut aggregator, START, "1", "0.00005", "64000", "64000"),
        &btc_symbol(),
    )
    .expect("publishes");
    assert!(established.is_usable());

    // Three seconds on, only BTC quotes arrive: the peg's sources go stale.
    let later = START + 3 * SECOND;
    for venue in USD_VENUES {
        aggregator.observe(&book(venue, "BTC-USD", fixed("64000"), "0.00005", later));
    }
    for venue in STABLE_VENUES {
        aggregator.observe(&book(venue, "BTCUSDT", fixed("64000"), "0.00005", later));
    }
    let updates = aggregator.poll_all(later).0;

    let btc = find(&updates, &btc_symbol()).expect("btc publishes a halt");
    assert!(
        btc.flags.is_halted(),
        "a stale peg must halt its dependents"
    );
    assert!(!btc.is_usable());
}

/// Without a peg, the native venues still price a feed whose quorum they meet.
/// The USDT venues quote 10 % higher here: any of them in the price would show.
#[test]
fn losing_the_peg_leaves_the_native_sources_and_degrades() {
    let mut aggregator =
        Aggregator::new(vec![btc_feed_needing("50", 2), peg_feed()]).expect("valid config");
    let established = find(
        &tick(&mut aggregator, START, "1", "0.00005", "64000", "64000"),
        &btc_symbol(),
    )
    .expect("publishes");
    assert_eq!(established.num_sources, 5);

    // Three seconds on, the peg's sources are stale; only BTC quotes arrive.
    let later = START + 3 * SECOND;
    for venue in USD_VENUES {
        aggregator.observe(&book(venue, "BTC-USD", fixed("64000"), "0.00005", later));
    }
    for venue in STABLE_VENUES {
        aggregator.observe(&book(venue, "BTCUSDT", fixed("70400"), "0.00005", later));
    }
    let updates = aggregator.poll_all(later).0;

    let btc = find(&updates, &btc_symbol()).expect("btc publishes");
    assert_eq!(price_of(&btc), fixed("64000"), "the native venues only");
    assert_eq!(btc.num_sources, 2);
    assert!(btc.is_usable() && btc.flags.is_degraded());
    assert!(!btc.flags.is_synthetic_quote(), "nothing was converted");
    let stats = aggregator
        .stats(feed_id(&btc_symbol()))
        .expect("known feed");
    assert!(stats.last_reasons.contains(Reasons::PEG_UNAVAILABLE));

    // The venue report says why the USDT venues are out.
    let reports = aggregator.poll_venues(later, |feed| feed == feed_id(&btc_symbol()));
    let report = reports.first().expect("a report");
    for entry in &report.entries {
        let expected = if STABLE_VENUES.contains(&entry.venue) {
            SourceStatus::PegUnavailable
        } else {
            SourceStatus::Used
        };
        assert_eq!(entry.status, expected, "{:?}", entry.venue);
    }
}

/// The peg must be evaluated before its dependents, in the same tick.
#[test]
fn a_dependent_feed_converts_against_the_current_tick_not_the_previous_one() {
    let mut aggregator = aggregator("500");
    // The very first tick, with no prior state at all: the peg must already be
    // readable by the BTC feed or conversion would be a tick behind forever.
    let updates = tick(&mut aggregator, START, "0.97", "0.00005", "62080", "64000");
    let btc = find(&updates, &btc_symbol()).expect("btc publishes on the first tick");
    assert_eq!(price_of(&btc), fixed("62080"));
}

/// Configuration mistakes that would produce quiet mispricing are refused.
#[test]
fn peg_misconfiguration_is_refused_at_construction() {
    // A peg this node does not price.
    let orphan = btc_feed("50");
    assert!(
        Aggregator::new(vec![orphan]).is_err(),
        "a missing peg must be refused"
    );

    // A feed that is its own peg.
    let mut self_peg = btc_feed("50");
    self_peg.quote_conversion = Some(QuoteConversion {
        peg_feed: feed_id(&btc_symbol()),
        max_peg_conf_bps: fixed("50"),
    });
    assert!(
        self_peg.validate().is_err(),
        "a self-referential peg must be refused"
    );

    // A source marked for conversion with no peg configured at all.
    let mut no_conversion = btc_feed("50");
    no_conversion.quote_conversion = None;
    assert!(
        no_conversion.validate().is_err(),
        "converting with no peg configured must be refused"
    );

    // A peg that itself needs conversion.
    let mut chained = peg_feed();
    for source in &mut chained.sources {
        source.convert_quote = true;
    }
    chained.quote_conversion = Some(QuoteConversion {
        peg_feed: FeedId::from_bytes([0xEE; 32]),
        max_peg_conf_bps: fixed("50"),
    });
    let mut dependent = btc_feed("50");
    dependent.quote_conversion = Some(QuoteConversion {
        peg_feed: feed_id(&peg_symbol()),
        max_peg_conf_bps: fixed("50"),
    });
    assert!(
        Aggregator::new(vec![dependent, chained]).is_err(),
        "a chained peg must be refused rather than resolved"
    );
}

/// A feed with no converted sources is untouched by any of this.
#[test]
fn feeds_without_converted_sources_are_unaffected() {
    let mut aggregator = aggregator("50");
    let updates = tick(&mut aggregator, START, "1", "0.00005", "64000", "64000");
    let peg = find(&updates, &peg_symbol()).expect("peg publishes");
    assert!(
        !peg.flags.is_synthetic_quote(),
        "the peg itself is natively quoted"
    );
    assert_eq!(price_of(&peg), fixed("1"));
}

/// Reasons are surfaced for metrics, not only folded into flags.
#[test]
fn peg_concerns_are_reported_for_metrics() {
    let mut aggregator = aggregator("1");
    let _ = tick(&mut aggregator, START, "1", "0.0005", "64000", "64000");
    let stats = aggregator
        .stats(feed_id(&btc_symbol()))
        .expect("known feed");
    assert!(stats.last_reasons.contains(Reasons::SYNTHETIC_QUOTE));
    assert!(stats.last_reasons.contains(Reasons::PEG_UNCERTAIN));
}

/// Only the peg's sources changed, yet every feed converted through it moved.
#[test]
fn a_peg_move_reaches_its_dependents_without_their_own_input() {
    let mut aggregator = aggregator("50");
    let first = tick(&mut aggregator, START, "1", "0.00005", "100000", "100000");
    assert!(find(&first, &btc_symbol()).is_some());

    let later = START + SECOND / 2;
    for venue in USD_VENUES {
        aggregator.observe(&book(venue, "USDT-USD", fixed("1.0003"), "0.00005", later));
    }
    let updates = aggregator.poll_changed(later).0;
    assert!(find(&updates, &peg_symbol()).is_some(), "{updates:?}");
    assert!(find(&updates, &btc_symbol()).is_some(), "{updates:?}");
}
