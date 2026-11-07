//! End-to-end ingest: real Binance payloads through the real decoder and the
//! real session loop, over a scripted transport.
//!
//! The unit tests cover decoding and reconnect separately. This covers them
//! wired together, which is where the interesting mistakes live: a handler built
//! with the wrong market's instrument map, a disconnect notice that arrives after
//! the quotes it was supposed to invalidate, a session that stops pumping after
//! its first benign decode failure.

use oracle_ingest::binance::BinanceHandler;
use oracle_ingest::clock::MonotonicClock;
use oracle_ingest::testing::{
    RECV_NS, Run, Script, ScriptedConnector, instrument, run_until, session_config,
};
use oracle_ingest::{InstrumentMap, InstrumentSpec, Session, StreamId};
use oracle_types::{MarketKind, ObsKind, Venue};

fn map(market: MarketKind, symbols: &[&str]) -> InstrumentMap {
    let specs: Vec<InstrumentSpec> = symbols
        .iter()
        .map(|symbol| instrument(symbol, market))
        .collect();
    InstrumentMap::new(Venue::Binance, market, &specs).expect("valid")
}

/// Runs one Binance session over `scripts`, one for each connection, until it
/// emits `events` events other than liveness reports.
async fn run(market: MarketKind, symbols: &[&str], scripts: Vec<Script>, events: usize) -> Run {
    let mut config = session_config();
    config.stream = StreamId::new(Venue::Binance, market);
    let session = Session::new(
        config,
        ScriptedConnector::new(scripts),
        BinanceHandler::new(map(market, symbols)),
        MonotonicClock::anchored_at(RECV_NS),
    );
    run_until(session, events).await
}

const SPOT_BOOK: &str = r#"{"stream":"btcusdt@bookTicker","data":{"u":400900217,"s":"BTCUSDT","b":"64312.00000000","B":"1.25000000","a":"64313.00000000","A":"0.75000000"}}"#;
const SPOT_BOOK_ETH: &str = r#"{"stream":"ethusdt@bookTicker","data":{"u":400900218,"s":"ETHUSDT","b":"3150.10000000","B":"12.00000000","a":"3150.20000000","A":"8.00000000"}}"#;
const SPOT_TRADE: &str = r#"{"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":1754582400123,"s":"BTCUSDT","a":12345,"p":"64312.10","q":"0.05","f":100,"l":105,"T":1754582400100,"m":true,"M":true}}"#;
const SUB_ACK: &str = r#"{"result":null,"id":1}"#;
const UNTRACKED: &str = r#"{"stream":"solusdt@bookTicker","data":{"u":9,"s":"SOLUSDT","b":"150","B":"1","a":"151","A":"1"}}"#;
const PERP_MARK: &str = r#"{"stream":"btcusdt@markPrice@1s","data":{"e":"markPriceUpdate","E":1754582400000,"s":"BTCUSDT","p":"64315.00000000","i":"64310.00000000","P":"64320.00000000","r":"0.00010000","T":1754596800000}}"#;

#[tokio::test(start_paused = true)]
async fn a_spot_session_produces_a_clean_observation_stream() {
    let session = Script::new()
        .text(SUB_ACK)
        .text(SPOT_BOOK)
        .text(UNTRACKED)
        .text(SPOT_BOOK_ETH)
        .text(SPOT_TRADE)
        .close();
    let run = run(MarketKind::Spot, &["BTCUSDT", "ETHUSDT"], vec![session], 5).await;

    let observations: Vec<_> = run.observations().collect();
    let [btc, eth, trade] = observations.as_slice() else {
        panic!("the ack and the untracked symbol must not surface: {observations:?}");
    };
    assert_eq!(btc.kind, ObsKind::BookTop);
    assert_eq!(&*btc.instrument.symbol, "BTCUSDT");
    assert_eq!(btc.instrument.market, MarketKind::Spot);
    assert_eq!(btc.price, "64312.5".parse().expect("valid"));
    assert_eq!(
        btc.exchange_time_ns, None,
        "spot bookTicker carries no venue clock"
    );
    // Stamped by our own clock, which advances in real time even under tokio's
    // paused timer: the anchor is a floor, not an exact value.
    assert!(
        (RECV_NS..RECV_NS + 1_000_000_000).contains(&btc.local_recv_ns),
        "receipt stamp {} is not just after the anchor",
        btc.local_recv_ns
    );

    assert_eq!(&*eth.instrument.symbol, "ETHUSDT");
    assert_eq!(eth.mid(), Some("3150.15".parse().expect("valid")));

    assert_eq!(trade.kind, ObsKind::Trade);
    assert_eq!(trade.price, "64312.1".parse().expect("valid"));
    assert!(trade.bid.is_none());
}

#[tokio::test(start_paused = true)]
async fn a_perp_session_expands_a_mark_price_into_three_observations() {
    let run = run(
        MarketKind::LinearPerp,
        &["BTCUSDT"],
        vec![Script::new().text(PERP_MARK).close()],
        5,
    )
    .await;

    let kinds: Vec<_> = run.observations().map(|o| o.kind).collect();
    assert_eq!(
        kinds,
        [ObsKind::MarkPrice, ObsKind::IndexPrice, ObsKind::Funding]
    );
    for observation in run.observations() {
        assert_eq!(observation.instrument.market, MarketKind::LinearPerp);
        assert_eq!(
            observation.exchange_time_ns,
            Some(1_754_582_400_000_000_000)
        );
    }
}

/// The ordering contract: nothing from after a gap may reach a consumer before
/// it has been told to discard what it had from before the gap.
#[tokio::test(start_paused = true)]
async fn a_disconnect_is_announced_before_any_post_reconnect_quote() {
    let sessions = vec![
        Script::new().text(SPOT_BOOK).close(),
        Script::new().text(SPOT_BOOK_ETH).close(),
    ];
    let run = run(MarketKind::Spot, &["BTCUSDT", "ETHUSDT"], sessions, 6).await;
    assert_eq!(
        run.shape(),
        [
            "connected",
            "observation",
            "disconnected",
            "connected",
            "observation",
            "disconnected"
        ]
    );
}

/// A malformed frame is a bad frame, not a bad connection.
#[tokio::test(start_paused = true)]
async fn garbage_in_the_middle_of_a_stream_does_not_break_it() {
    let session = Script::new()
        .text(SPOT_BOOK)
        .text("{ this is not json")
        .text(r#"{"stream":"btcusdt@bookTicker","data":{"u":1,"s":"BTCUSDT","b":"oops","B":"1","a":"2","A":"1"}}"#)
        .text(SPOT_TRADE)
        .close();
    let run = run(MarketKind::Spot, &["BTCUSDT", "ETHUSDT"], vec![session], 4).await;
    let kinds: Vec<_> = run.observations().map(|o| o.kind).collect();
    assert_eq!(
        kinds,
        [ObsKind::BookTop, ObsKind::Trade],
        "the good frames on either side must still arrive"
    );
}

/// A transport error mid-stream is recoverable, and the frames that preceded it
/// are still delivered.
#[tokio::test(start_paused = true)]
async fn a_mid_stream_transport_error_reconnects() {
    let sessions = vec![
        Script::new().text(SPOT_BOOK).fail("connection reset"),
        Script::new().text(SPOT_TRADE).close(),
    ];
    let run = run(MarketKind::Spot, &["BTCUSDT", "ETHUSDT"], sessions, 6).await;
    assert!(
        run.disconnects()
            .first()
            .is_some_and(|r| r.contains("connection reset")),
        "the disconnect reason should name the cause, got {:?}",
        run.disconnects()
    );
    assert_eq!(run.observations().count(), 2);
}
