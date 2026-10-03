//! The adversarial replay suite (SPEC §10): one venue lies, and the aggregator
//! must degrade or halt rather than publish a confidently wrong price.
//!
//! Every test replays the same twelve-second recording twice: clean, and with
//! one venue's frames rewritten. The published prices are then compared tick
//! by tick. "Never confidently wrong" is a bound, in basis points, on how far
//! the attacked replay may stray from the clean one, plus the counters that
//! show the defence fired.
//!
//! These are the regression suite for §5.4 and §5.7. A change to the outlier
//! or circuit-breaker constants has to keep them green.

use std::path::Path;

use oracle_agg::FeedStats;
use oracle_ingest::Record;
use oracle_ingest::record::read_records;
use oracle_node::NodeConfig;
use oracle_replay::Outcome;
use oracle_replay::adversarial::{
    BINANCE_SPOT, BYBIT_SPOT, OKX, cross_book, drift_prices, freeze, scale_prices, silence,
};
use oracle_types::{Fixed, NANOS_PER_SEC, PriceUpdate};
use oracle_wire::{Signer, feed_id};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn records() -> Vec<Record> {
    let file =
        std::fs::File::open(Path::new(FIXTURES).join("btc-usdt-12s.jsonl")).expect("fixture");
    read_records(std::io::BufReader::new(file)).expect("parses")
}

fn start_ns(records: &[Record]) -> u64 {
    records.first().expect("non-empty").time_ns()
}

/// The end of the recording. The replay's final tick lands exactly here, after
/// every connection has closed and every venue has been invalidated, so it is
/// always a halt with zero sources. It is an artefact of the recording ending,
/// not of the attack, and the checks below stop just before it.
fn end_ns(records: &[Record]) -> u64 {
    records.last().expect("non-empty").time_ns()
}

async fn replay(records: Vec<Record>) -> Outcome {
    let resolved = NodeConfig::load(&Path::new(FIXTURES).join("btc-usdt.toml"))
        .expect("loads")
        .resolve()
        .expect("resolves");
    let signer = Signer::from_secret_bytes([0x5E; 32]).expect("valid key");
    oracle_replay::run(resolved, records, signer, false)
        .await
        .expect("replays")
}

fn btc_usdt() -> oracle_types::FeedId {
    feed_id(&"CRYPTO.BTC/USDT".parse().expect("valid symbol"))
}

fn stats(outcome: &Outcome) -> FeedStats {
    outcome
        .feeds
        .iter()
        .find(|(id, _)| *id == btc_usdt())
        .map(|(_, stats)| *stats)
        .expect("the feed exists")
}

fn price(update: &PriceUpdate) -> Fixed {
    update.price_fixed().expect("representable")
}

fn bps(text: &str) -> Fixed {
    text.parse().expect("valid decimal")
}

/// The largest distance, in basis points, between an attacked update and the
/// clean price in force at the same moment, over updates published at or
/// after `from_ns`.
fn max_deviation_bps(clean: &Outcome, attacked: &Outcome, from_ns: u64) -> Fixed {
    let mut worst = Fixed::ZERO;
    for update in attacked
        .updates
        .iter()
        .filter(|u| u.publish_time_ns >= from_ns)
    {
        let reference = clean
            .updates
            .iter()
            .filter(|c| c.publish_time_ns <= update.publish_time_ns)
            .next_back()
            .expect("the clean replay published before this instant");
        let (a, c) = (price(update), price(reference));
        let distance = if a > c {
            a.checked_sub(c)
        } else {
            c.checked_sub(a)
        }
        .expect("in range");
        let deviation = distance.to_bps_of(c).expect("positive reference");
        worst = worst.max(deviation);
    }
    worst
}

/// Updates published in `[from_ns, until_ns)`.
fn between(outcome: &Outcome, from_ns: u64, until_ns: u64) -> Vec<&PriceUpdate> {
    outcome
        .updates
        .iter()
        .filter(|u| u.publish_time_ns >= from_ns && u.publish_time_ns < until_ns)
        .collect()
}

#[tokio::test]
async fn the_clean_fixture_publishes_from_three_venues_without_degrading() {
    let records = records();
    let (start, end) = (start_ns(&records), end_ns(&records));
    let clean = replay(records).await;
    let published = between(&clean, start, end);
    assert!(published.len() >= 10, "{:?}", clean.stats);
    assert!(published.iter().any(|u| u.num_sources == 3));
    assert!(published.iter().all(|u| !u.flags.is_halted()));
    assert!(published.iter().all(|u| !u.flags.is_degraded()));
    let stats = stats(&clean);
    assert_eq!(stats.outliers_rejected, 0, "a clean market rejects nothing");
    assert_eq!(stats.degraded, 0);
}

/// §5.4: one venue jumps ten percent and stays there. The median ignores it,
/// outlier rejection drops it, and the published price does not move.
#[tokio::test]
async fn a_ten_percent_jump_on_one_venue_is_rejected() {
    let records = records();
    let (at, end) = (start_ns(&records) + 4 * NANOS_PER_SEC, end_ns(&records));
    let clean = replay(records.clone()).await;
    let attacked = replay(scale_prices(
        &records,
        BINANCE_SPOT,
        bps("1.10"),
        at,
        u64::MAX,
    ))
    .await;

    let deviation = max_deviation_bps(&clean, &attacked, at);
    assert!(
        deviation <= bps("20"),
        "price moved {deviation} bps on a 1000 bps lie"
    );
    assert!(
        stats(&attacked).outliers_rejected > 0,
        "{:?}",
        stats(&attacked)
    );
    let later = between(&attacked, at, end);
    assert!(!later.is_empty());
    assert!(later.iter().all(|u| !u.flags.is_halted()));
}

/// §5.4: fifty percent quotes for one second, then back to normal. The classic
/// spoof, on the venue that sends most often in this recording.
#[tokio::test]
async fn a_spoofed_print_window_is_rejected() {
    let records = records();
    let at = start_ns(&records) + 6 * NANOS_PER_SEC;
    let clean = replay(records.clone()).await;
    let attacked = replay(scale_prices(
        &records,
        BINANCE_SPOT,
        bps("1.50"),
        at,
        at + NANOS_PER_SEC,
    ))
    .await;

    let deviation = max_deviation_bps(&clean, &attacked, at);
    assert!(
        deviation <= bps("20"),
        "price moved {deviation} bps on a 5000 bps spoof"
    );
    assert!(
        stats(&attacked).outliers_rejected > 0,
        "{:?}",
        stats(&attacked)
    );
}

/// §5.4: a slow drift stays inside the band at first, then leaves it. The
/// published price may follow a little, bounded by the honest venues' spread,
/// and the drifting venue is shed once it crosses the floor.
#[tokio::test]
async fn a_slow_drift_is_shed_once_it_leaves_the_band() {
    let records = records();
    let at = start_ns(&records) + 2 * NANOS_PER_SEC;
    let clean = replay(records.clone()).await;
    let attacked = replay(drift_prices(&records, OKX, 25, at)).await;

    let deviation = max_deviation_bps(&clean, &attacked, at);
    assert!(
        deviation <= bps("15"),
        "price followed the drift by {deviation} bps"
    );
    assert!(
        stats(&attacked).outliers_rejected > 0,
        "{:?}",
        stats(&attacked)
    );
}

/// A crossed book is a broken venue. The quote derivation drops it and falls
/// through to that venue's prints, and the price stays with the market.
#[tokio::test]
async fn a_crossed_book_does_not_move_the_price() {
    let records = records();
    let (at, end) = (start_ns(&records) + 3 * NANOS_PER_SEC, end_ns(&records));
    let clean = replay(records.clone()).await;
    let attacked = replay(cross_book(&records, BINANCE_SPOT, at)).await;

    let deviation = max_deviation_bps(&clean, &attacked, at);
    assert!(
        deviation <= bps("20"),
        "a crossed book moved the price {deviation} bps"
    );
    assert!(
        between(&attacked, at, end)
            .iter()
            .all(|u| !u.flags.is_halted())
    );
}

/// §5.2: a venue that stops sending on an open connection is shed by the
/// staleness filter after `max_age`, and the feed carries on with two sources.
#[tokio::test]
async fn a_silent_venue_is_shed_by_staleness() {
    let records = records();
    let (at, end) = (start_ns(&records) + 3 * NANOS_PER_SEC, end_ns(&records));
    let clean = replay(records.clone()).await;
    let attacked = replay(silence(&records, OKX, at)).await;

    let settled = at + 3 * NANOS_PER_SEC;
    let later = between(&attacked, settled, end);
    assert!(
        !later.is_empty(),
        "the feed must keep publishing on two venues"
    );
    assert!(
        later.iter().all(|u| u.num_sources == 2),
        "the silent venue must stop counting: {:?}",
        later.iter().map(|u| u.num_sources).collect::<Vec<_>>()
    );
    assert!(later.iter().all(|u| !u.flags.is_halted()));
    let deviation = max_deviation_bps(&clean, &attacked, at);
    assert!(deviation <= bps("20"), "{deviation} bps");
}

/// A frozen quote that keeps arriving is indistinguishable from a quiet venue
/// in a quiet market. Nothing flags it, and in this recording nothing needs to:
/// the bound holds because the market barely moved. This test documents the
/// limitation; the defence against it is divergence over time, not a rule.
#[tokio::test]
async fn a_frozen_quote_in_a_quiet_market_stays_within_the_band() {
    let records = records();
    let (at, end) = (start_ns(&records) + 3 * NANOS_PER_SEC, end_ns(&records));
    let clean = replay(records.clone()).await;
    let attacked = replay(freeze(&records, BYBIT_SPOT, at)).await;

    let deviation = max_deviation_bps(&clean, &attacked, at);
    assert!(deviation <= bps("20"), "{deviation} bps");
    assert!(
        between(&attacked, at, end)
            .iter()
            .all(|u| !u.flags.is_halted())
    );
}

/// §5.7, last row: the whole market jumps far outside the sanity band. The
/// feed halts rather than publish the new level with a straight face. Any
/// price it does publish at the new level carries the halt flag.
#[tokio::test]
async fn a_market_wide_jump_trips_the_sanity_band() {
    let records = records();
    let at = start_ns(&records) + 6 * NANOS_PER_SEC;
    let clean = replay(records.clone()).await;
    let mut attacked = records;
    for host in [BINANCE_SPOT, BYBIT_SPOT, OKX] {
        attacked = scale_prices(&attacked, host, bps("2.5"), at, u64::MAX);
    }
    let attacked = replay(attacked).await;

    assert!(stats(&attacked).halted > 0, "{:?}", stats(&attacked));
    let reference = price(clean.updates.last().expect("clean published"));
    let ceiling = reference.checked_mul(bps("1.5")).expect("in range");
    for update in between(&attacked, at, u64::MAX) {
        if price(update) > ceiling {
            assert!(
                update.flags.is_halted(),
                "published {} without a halt flag against a market near {}",
                price(update),
                reference
            );
        }
    }
}
