//! Each adapter reads the funding fields of a recorded venue message. The
//! fixtures are live messages, captured on 2026-10-09.

use oracle_ingest::binance::BinanceHandler;
use oracle_ingest::testing::{Feed, fixed, instrument};
use oracle_ingest::venues::{DecodeFn, bybit, deribit, kraken_futures, okx};
use oracle_ingest::{DecodeError, InstrumentMap};
use oracle_types::{
    Fixed, FundingBasis, FundingInfo, MarketKind, NANOS_PER_SEC, ObsKind, Observation,
    OpenInterestUnit, Venue,
};

const HOUR_NS: u64 = 3_600 * NANOS_PER_SEC;

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/funding")
        .join(name);
    std::fs::read_to_string(path).expect("a fixture")
}

/// One perpetual through a venue's decoder.
fn perp(decode: DecodeFn, venue: Venue, market: MarketKind, symbol: &str) -> Feed {
    Feed::venue(decode, venue, market, &[instrument(symbol, market)])
}

/// Binance's perpetuals of `symbols`.
fn binance(symbols: &[&str]) -> Feed {
    let specs: Vec<_> = symbols
        .iter()
        .map(|symbol| instrument(symbol, MarketKind::LinearPerp))
        .collect();
    let map = InstrumentMap::new(Venue::Binance, MarketKind::LinearPerp, &specs).expect("a map");
    Feed::new(BinanceHandler::new(map))
}

fn ms(millis: u64) -> Option<u64> {
    Some(millis * 1_000_000)
}

/// The rate and the info of the one funding observation.
fn funding(observations: &[Observation]) -> (Fixed, FundingInfo) {
    let mut funding = observations
        .iter()
        .filter(|observation| observation.kind == ObsKind::Funding);
    let observation = funding.next().expect("a funding observation");
    assert!(funding.next().is_none(), "one funding observation");
    for other in observations.iter().filter(|o| o.kind != ObsKind::Funding) {
        assert!(other.funding.is_none(), "only funding carries the info");
    }
    let info = observation
        .funding
        .as_deref()
        .expect("funding info")
        .clone();
    (observation.price, info)
}

#[test]
fn binance_sends_the_rate_and_the_next_funding_time() {
    let out = binance(&["BTCUSDT"]).decoded(fixture("binance-mark-price.json"));
    let (rate, info) = funding(&out);
    assert_eq!(rate, fixed("0.00002663"));
    assert_eq!(
        info,
        FundingInfo {
            next_funding_time_ns: ms(1_791_561_600_000),
            ..FundingInfo::new(FundingBasis::Interval)
        }
    );
}

/// The interval list was captured on 2026-10-21 and cut to four perpetuals:
/// BTCUSDT pays every 8 hours, HYPEUSDT and GTCUSDT every 4, ERAUSDT every hour.
#[test]
fn binance_states_the_interval_from_the_funding_info_list() {
    let mut feed = binance(&["BTCUSDT", "HYPEUSDT", "ERAUSDT", "XYZUSDT"]);
    let mark_price = fixture("binance-mark-price.json");
    let interval = |feed: &mut Feed, symbol: &str| {
        funding(&feed.decoded(mark_price.replace("BTCUSDT", symbol)))
            .1
            .interval_ns
    };

    assert_eq!(interval(&mut feed, "BTCUSDT"), None, "no list yet");
    let _ = feed.decoded(fixture("binance-funding-info.json"));
    assert_eq!(interval(&mut feed, "BTCUSDT"), Some(8 * HOUR_NS));
    assert_eq!(interval(&mut feed, "HYPEUSDT"), Some(4 * HOUR_NS));
    assert_eq!(interval(&mut feed, "ERAUSDT"), Some(HOUR_NS));
    assert_eq!(
        interval(&mut feed, "XYZUSDT"),
        Some(8 * HOUR_NS),
        "a perpetual the list leaves out pays every 8 hours"
    );

    let error =
        feed.refused(r#"{"stream":"!fundingInfo","error":"HTTP status server error (503)"}"#);
    assert!(!error.is_benign());
    assert!(!matches!(error, DecodeError::Resync(_)), "the socket stays");
    assert_eq!(
        interval(&mut feed, "HYPEUSDT"),
        Some(4 * HOUR_NS),
        "a failed fetch keeps the last list"
    );
}

#[test]
fn bybit_deltas_keep_the_fields_that_did_not_change() {
    let text = fixture("bybit-tickers.jsonl");
    let mut lines = text.lines();
    let (snapshot, delta) = (
        lines.next().expect("a snapshot"),
        lines.next().expect("a delta"),
    );
    let mut feed = perp(
        bybit::decode,
        Venue::Bybit,
        MarketKind::LinearPerp,
        "BTCUSDT",
    );

    let full = FundingInfo {
        interval_ns: Some(8 * HOUR_NS),
        next_funding_time_ns: ms(1_791_561_600_000),
        open_interest: Some((fixed("57845.537"), OpenInterestUnit::Base)),
        ..FundingInfo::new(FundingBasis::Interval)
    };
    assert_eq!(
        funding(&feed.decoded(snapshot)),
        (fixed("0.00005547"), full.clone())
    );

    // The delta has only the open interest; the rest is the snapshot's.
    let expected = FundingInfo {
        open_interest: Some((fixed("57823.041"), OpenInterestUnit::Base)),
        ..full
    };
    assert_eq!(
        funding(&feed.decoded(delta)),
        (fixed("0.00005547"), expected)
    );

    // A new connection forgets the old state: a delta alone gives no rate.
    feed.reconnect();
    let out = feed.push(delta).unwrap_or_default();
    assert!(out.iter().all(|o| o.kind != ObsKind::Funding));
}

#[test]
fn okx_sends_the_next_settlement_the_interval_and_the_last_settled_rate() {
    let mut feed = perp(
        okx::decode,
        Venue::Okx,
        MarketKind::LinearPerp,
        "BTC-USDT-SWAP",
    );
    let (rate, info) = funding(&feed.decoded(fixture("okx-funding-rate.json")));
    // OKX sends 16 decimals; the node keeps 12.
    assert_eq!(rate, fixed("-0.000030339016"));
    assert_eq!(
        info,
        FundingInfo {
            // `nextFundingRate` is empty: OKX predicts nothing for this contract.
            predicted: None,
            interval_ns: Some(8 * HOUR_NS),
            next_funding_time_ns: ms(1_791_561_600_000),
            settled: Some((fixed("0.000006729944"), 1_791_532_800_000 * 1_000_000)),
            ..FundingInfo::new(FundingBasis::Interval)
        }
    );
}

#[test]
fn kraken_futures_pays_every_hour_and_counts_contracts() {
    let mut feed = perp(
        kraken_futures::decode,
        Venue::Kraken,
        MarketKind::LinearPerp,
        "PF_XBTUSD",
    );
    let (rate, info) = funding(&feed.decoded(fixture("kraken-futures-ticker.json")));
    assert_eq!(rate, fixed("0.00000742875"));
    assert_eq!(
        info,
        FundingInfo {
            predicted: Some(fixed("0.00001032665")),
            interval_ns: Some(HOUR_NS),
            next_funding_time_ns: ms(1_791_543_600_000),
            open_interest: Some((fixed("2366.409"), OpenInterestUnit::Contracts)),
            ..FundingInfo::new(FundingBasis::Interval)
        }
    );
}

#[test]
fn deribit_sends_an_eight_hour_rate_and_usd_open_interest() {
    let mut feed = perp(
        deribit::decode,
        Venue::Deribit,
        MarketKind::InversePerp,
        "BTC-PERPETUAL",
    );
    let (rate, info) = funding(&feed.decoded(fixture("deribit-ticker.json")));
    assert_eq!(rate, fixed("0.00010846"));
    assert_eq!(
        info,
        FundingInfo {
            open_interest: Some((fixed("819195850"), OpenInterestUnit::Quote)),
            ..FundingInfo::new(FundingBasis::EightHours)
        }
    );
}
