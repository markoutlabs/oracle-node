//! Each adapter reads the funding fields of a recorded venue message. The
//! fixtures are live messages, captured on 2026-10-09.

use oracle_ingest::binance::BinanceHandler;
use oracle_ingest::book::Books;
use oracle_ingest::session::MessageHandler as _;
use oracle_ingest::venues::{bybit, deribit, kraken_futures, okx};
use oracle_ingest::{DecodeError, InstrumentMap, InstrumentSpec};
use oracle_types::{
    Fixed, FundingBasis, FundingInfo, MarketKind, NANOS_PER_SEC, ObsKind, Observation,
    OpenInterestUnit, Venue,
};

const RECV_NS: u64 = 1_791_542_610_000_000_000;
const HOUR_NS: u64 = 3_600 * NANOS_PER_SEC;

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/funding")
        .join(name);
    std::fs::read_to_string(path).expect("a fixture")
}

fn map(venue: Venue, market: MarketKind, symbol: &str, feed: &str) -> InstrumentMap {
    let spec = InstrumentSpec::new(symbol, market, feed).expect("a valid spec");
    InstrumentMap::new(venue, market, &[spec]).expect("a valid map")
}

fn fixed(text: &str) -> Fixed {
    text.parse().expect("a decimal")
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
    let map = map(
        Venue::Binance,
        MarketKind::LinearPerp,
        "BTCUSDT",
        "CRYPTO.BTC/USD.FUNDING_8H",
    );
    let mut out = Vec::new();
    BinanceHandler::new(map)
        .on_payload(
            fixture("binance-mark-price.json").as_bytes(),
            RECV_NS,
            &mut out,
        )
        .expect("decodes");
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
    let specs = ["BTCUSDT", "HYPEUSDT", "ERAUSDT", "XYZUSDT"].map(|symbol| {
        let feed = format!("CRYPTO.{}/USDT.PERP_MARK", symbol.trim_end_matches("USDT"));
        InstrumentSpec::new(symbol, MarketKind::LinearPerp, &feed).expect("a valid spec")
    });
    let map = InstrumentMap::new(Venue::Binance, MarketKind::LinearPerp, &specs).expect("a map");
    let mut handler = BinanceHandler::new(map);
    let mark_price = fixture("binance-mark-price.json");
    let interval = |handler: &mut BinanceHandler, symbol: &str| {
        let payload = mark_price.replace("BTCUSDT", symbol);
        let mut out = Vec::new();
        handler
            .on_payload(payload.as_bytes(), RECV_NS, &mut out)
            .expect("decodes");
        funding(&out).1.interval_ns
    };

    assert_eq!(interval(&mut handler, "BTCUSDT"), None, "no list yet");
    handler
        .on_payload(
            fixture("binance-funding-info.json").as_bytes(),
            RECV_NS,
            &mut Vec::new(),
        )
        .expect("decodes the list");
    assert_eq!(interval(&mut handler, "BTCUSDT"), Some(8 * HOUR_NS));
    assert_eq!(interval(&mut handler, "HYPEUSDT"), Some(4 * HOUR_NS));
    assert_eq!(interval(&mut handler, "ERAUSDT"), Some(HOUR_NS));
    assert_eq!(
        interval(&mut handler, "XYZUSDT"),
        Some(8 * HOUR_NS),
        "a perpetual the list leaves out pays every 8 hours"
    );

    let failed = r#"{"stream":"!fundingInfo","error":"HTTP status server error (503)"}"#;
    let error = handler
        .on_payload(failed.as_bytes(), RECV_NS, &mut Vec::new())
        .expect_err("a failed fetch");
    assert!(!error.is_benign());
    assert!(!matches!(error, DecodeError::Resync(_)), "the socket stays");
    assert_eq!(
        interval(&mut handler, "HYPEUSDT"),
        Some(4 * HOUR_NS),
        "a failed fetch keeps the last list"
    );
}

#[test]
fn bybit_deltas_keep_the_fields_that_did_not_change() {
    let map = map(
        Venue::Bybit,
        MarketKind::LinearPerp,
        "BTCUSDT",
        "CRYPTO.BTC/USD.FUNDING_8H",
    );
    let text = fixture("bybit-tickers.jsonl");
    let mut lines = text.lines();
    let mut books = Books::default();

    let mut out = Vec::new();
    let snapshot = lines.next().expect("a snapshot");
    bybit::decode(snapshot.as_bytes(), &map, &mut books, RECV_NS, &mut out).expect("decodes");
    let (rate, info) = funding(&out);
    let full = FundingInfo {
        interval_ns: Some(8 * HOUR_NS),
        next_funding_time_ns: ms(1_791_561_600_000),
        open_interest: Some((fixed("57845.537"), OpenInterestUnit::Base)),
        ..FundingInfo::new(FundingBasis::Interval)
    };
    assert_eq!((rate, info), (fixed("0.00005547"), full.clone()));

    // The delta has only the open interest; the rest is the snapshot's.
    let mut out = Vec::new();
    let delta = lines.next().expect("a delta");
    bybit::decode(delta.as_bytes(), &map, &mut books, RECV_NS, &mut out).expect("decodes");
    let (rate, info) = funding(&out);
    let expected = FundingInfo {
        open_interest: Some((fixed("57823.041"), OpenInterestUnit::Base)),
        ..full
    };
    assert_eq!((rate, info), (fixed("0.00005547"), expected));

    // A new connection forgets the old state: a delta alone gives no rate.
    books.clear();
    let mut out = Vec::new();
    let _ = bybit::decode(delta.as_bytes(), &map, &mut books, RECV_NS, &mut out);
    assert!(out.iter().all(|o| o.kind != ObsKind::Funding));
}

#[test]
fn okx_sends_the_next_settlement_the_interval_and_the_last_settled_rate() {
    let map = map(
        Venue::Okx,
        MarketKind::LinearPerp,
        "BTC-USDT-SWAP",
        "CRYPTO.BTC/USD.FUNDING_8H",
    );
    let mut out = Vec::new();
    okx::decode_payload(
        fixture("okx-funding-rate.json").as_bytes(),
        &map,
        RECV_NS,
        &mut out,
    )
    .expect("decodes");
    let (rate, info) = funding(&out);
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
    let map = map(
        Venue::Kraken,
        MarketKind::LinearPerp,
        "PF_XBTUSD",
        "CRYPTO.BTC/USD.FUNDING_8H",
    );
    let mut out = Vec::new();
    kraken_futures::decode_payload(
        fixture("kraken-futures-ticker.json").as_bytes(),
        &map,
        RECV_NS,
        &mut out,
    )
    .expect("decodes");
    let (rate, info) = funding(&out);
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
    let map = map(
        Venue::Deribit,
        MarketKind::InversePerp,
        "BTC-PERPETUAL",
        "CRYPTO.BTC/USD.FUNDING_8H",
    );
    let mut out = Vec::new();
    deribit::decode(
        fixture("deribit-ticker.json").as_bytes(),
        &map,
        &mut Books::default(),
        RECV_NS,
        &mut out,
    )
    .expect("decodes");
    let (rate, info) = funding(&out);
    assert_eq!(rate, fixed("0.00010846"));
    assert_eq!(
        info,
        FundingInfo {
            open_interest: Some((fixed("819195850"), OpenInterestUnit::Quote)),
            ..FundingInfo::new(FundingBasis::EightHours)
        }
    );
}
