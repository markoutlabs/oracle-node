//! End-to-end ingest: real Binance payloads through the real decoder and the
//! real session loop, over a scripted transport.
//!
//! The unit tests cover decoding and reconnect separately. This covers them
//! wired together, which is where the interesting mistakes live: a handler built
//! with the wrong market's instrument map, a disconnect notice that arrives after
//! the quotes it was supposed to invalidate, a session that stops pumping after
//! its first benign decode failure.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oracle_ingest::binance::{BinanceHandler, streams};
use oracle_ingest::clock::MonotonicClock;
use oracle_ingest::{
    BackoffConfig, Connector, Frame, IngestEvent, InstrumentMap, InstrumentSpec, Session,
    SessionConfig, StreamId, Transport, TransportError,
};
use oracle_types::{MarketKind, ObsKind, Venue};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// One scripted connection's worth of frames.
type Script = Vec<Result<Option<Frame>, TransportError>>;

struct ScriptedConn {
    frames: Script,
}

impl Transport for ScriptedConn {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        if self.frames.is_empty() {
            std::future::pending::<()>().await;
        }
        self.frames.remove(0)
    }

    async fn send_text(&mut self, _text: String) -> Result<(), TransportError> {
        Ok(())
    }
}

#[derive(Clone)]
struct ScriptedConnector {
    sessions: Arc<Mutex<Vec<Script>>>,
    attempts: Arc<AtomicUsize>,
}

impl Connector for ScriptedConnector {
    type Conn = ScriptedConn;

    async fn connect(&self, _url: &str) -> Result<Self::Conn, TransportError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let frames = self
            .sessions
            .lock()
            .ok()
            .and_then(|mut s| {
                if s.is_empty() {
                    None
                } else {
                    Some(s.remove(0))
                }
            })
            .unwrap_or_default();
        Ok(ScriptedConn { frames })
    }
}

fn text(payload: &str) -> Result<Option<Frame>, TransportError> {
    Ok(Some(Frame::Text(payload.to_owned())))
}

fn spot_map() -> InstrumentMap {
    let specs = vec![
        InstrumentSpec::new("BTCUSDT", MarketKind::Spot, "CRYPTO.BTC/USDT").expect("valid"),
        InstrumentSpec::new("ETHUSDT", MarketKind::Spot, "CRYPTO.ETH/USDT").expect("valid"),
    ];
    InstrumentMap::new(Venue::Binance, MarketKind::Spot, &specs).expect("valid")
}

fn perp_map() -> InstrumentMap {
    let specs = vec![
        InstrumentSpec::new(
            "BTCUSDT",
            MarketKind::LinearPerp,
            "CRYPTO.BTC/USDT.PERP_MARK",
        )
        .expect("valid"),
    ];
    InstrumentMap::new(Venue::Binance, MarketKind::LinearPerp, &specs).expect("valid")
}

fn config(market: MarketKind) -> SessionConfig {
    let mut config = SessionConfig::new(
        StreamId::new(Venue::Binance, market),
        format!("{}?streams=btcusdt@bookTicker", streams::base_url(market)),
    );
    config.idle_timeout = Duration::from_millis(50);
    config.backoff = BackoffConfig {
        initial: Duration::from_millis(1),
        max: Duration::from_millis(5),
        multiplier: 2,
        jitter_percent: 0,
        reset_after_stable: Duration::from_secs(60),
    };
    config
}

const SPOT_BOOK: &str = r#"{"stream":"btcusdt@bookTicker","data":{"u":400900217,"s":"BTCUSDT","b":"64312.00000000","B":"1.25000000","a":"64313.00000000","A":"0.75000000"}}"#;
const SPOT_BOOK_ETH: &str = r#"{"stream":"ethusdt@bookTicker","data":{"u":400900218,"s":"ETHUSDT","b":"3150.10000000","B":"12.00000000","a":"3150.20000000","A":"8.00000000"}}"#;
const SPOT_TRADE: &str = r#"{"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":1754582400123,"s":"BTCUSDT","a":12345,"p":"64312.10","q":"0.05","f":100,"l":105,"T":1754582400100,"m":true,"M":true}}"#;
const SUB_ACK: &str = r#"{"result":null,"id":1}"#;
const UNTRACKED: &str = r#"{"stream":"solusdt@bookTicker","data":{"u":9,"s":"SOLUSDT","b":"150","B":"1","a":"151","A":"1"}}"#;
const PERP_MARK: &str = r#"{"stream":"btcusdt@markPrice@1s","data":{"e":"markPriceUpdate","E":1754582400000,"s":"BTCUSDT","p":"64315.00000000","i":"64310.00000000","P":"64320.00000000","r":"0.00010000","T":1754596800000}}"#;

/// Drives a session to completion and collects everything it emitted.
async fn run(
    market: MarketKind,
    map: InstrumentMap,
    sessions: Vec<Script>,
    expected_events: usize,
) -> Vec<IngestEvent> {
    let connector = ScriptedConnector {
        sessions: Arc::new(Mutex::new(sessions)),
        attempts: Arc::new(AtomicUsize::new(0)),
    };
    let session = Session::new(
        config(market),
        connector,
        BinanceHandler::new(map),
        MonotonicClock::anchored_at(1_754_582_400_500_000_000),
    );

    let (tx, mut rx) = mpsc::channel(256);
    let shutdown = CancellationToken::new();
    let handle = tokio::spawn(session.run(tx, shutdown.clone()));

    let mut events = Vec::new();
    while events.len() < expected_events {
        match rx.recv().await {
            Some(event) => events.push(event),
            None => break,
        }
    }
    shutdown.cancel();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    handle.await.expect("joins").expect("runs");
    events
}

#[tokio::test(start_paused = true)]
async fn a_spot_session_produces_a_clean_observation_stream() {
    let events = run(
        MarketKind::Spot,
        spot_map(),
        vec![vec![
            text(SUB_ACK),
            text(SPOT_BOOK),
            text(UNTRACKED),
            text(SPOT_BOOK_ETH),
            text(SPOT_TRADE),
            Ok(None),
        ]],
        5,
    )
    .await;

    let observations: Vec<_> = events
        .iter()
        .filter_map(IngestEvent::as_observation)
        .collect();
    assert_eq!(
        observations.len(),
        3,
        "the ack and the untracked symbol must not surface"
    );

    let btc = observations.first().expect("first observation");
    assert_eq!(btc.kind, ObsKind::BookTop);
    assert_eq!(&*btc.instrument.symbol, "BTCUSDT");
    assert_eq!(btc.instrument.market, MarketKind::Spot);
    assert_eq!(btc.price, "64312.5".parse().expect("valid"));
    assert_eq!(
        btc.exchange_time_ns, None,
        "spot bookTicker carries no venue clock"
    );
    // Stamped by our own clock, which advances in real time even under tokio's
    // paused timer — the anchor is a floor, not an exact value.
    let anchor = 1_754_582_400_500_000_000;
    assert!(
        (anchor..anchor + 1_000_000_000).contains(&btc.local_recv_ns),
        "receipt stamp {} is not just after the anchor",
        btc.local_recv_ns
    );

    let eth = observations.get(1).expect("second observation");
    assert_eq!(&*eth.instrument.symbol, "ETHUSDT");
    assert_eq!(eth.mid(), Some("3150.15".parse().expect("valid")));

    let trade = observations.get(2).expect("third observation");
    assert_eq!(trade.kind, ObsKind::Trade);
    assert_eq!(trade.price, "64312.1".parse().expect("valid"));
    assert!(trade.bid.is_none());
}

#[tokio::test(start_paused = true)]
async fn a_perp_session_expands_a_mark_price_into_three_observations() {
    let events = run(
        MarketKind::LinearPerp,
        perp_map(),
        vec![vec![text(PERP_MARK), Ok(None)]],
        5,
    )
    .await;

    let kinds: Vec<_> = events
        .iter()
        .filter_map(IngestEvent::as_observation)
        .map(|o| o.kind)
        .collect();
    assert_eq!(
        kinds,
        [ObsKind::MarkPrice, ObsKind::IndexPrice, ObsKind::Funding]
    );

    let observations: Vec<_> = events
        .iter()
        .filter_map(IngestEvent::as_observation)
        .collect();
    for observation in &observations {
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
    let events = run(
        MarketKind::Spot,
        spot_map(),
        vec![
            vec![text(SPOT_BOOK), Ok(None)],
            vec![text(SPOT_BOOK_ETH), Ok(None)],
        ],
        6,
    )
    .await;

    let shape: Vec<&str> = events
        .iter()
        .map(|event| match event {
            IngestEvent::Connected { .. } => "connected",
            IngestEvent::Disconnected { .. } => "disconnected",
            IngestEvent::Observation(_) => "observation",
            _ => "unexpected",
        })
        .collect();
    assert_eq!(
        shape,
        [
            "connected",
            "observation",
            "disconnected",
            "connected",
            "observation",
            "disconnected",
        ]
    );
}

/// A malformed frame is a bad frame, not a bad connection.
#[tokio::test(start_paused = true)]
async fn garbage_in_the_middle_of_a_stream_does_not_break_it() {
    let events = run(
        MarketKind::Spot,
        spot_map(),
        vec![vec![
            text(SPOT_BOOK),
            text("{ this is not json"),
            text(r#"{"stream":"btcusdt@bookTicker","data":{"u":1,"s":"BTCUSDT","b":"oops","B":"1","a":"2","A":"1"}}"#),
            text(SPOT_TRADE),
            Ok(None),
        ]],
        4,
    )
    .await;

    let observations: Vec<_> = events
        .iter()
        .filter_map(IngestEvent::as_observation)
        .collect();
    assert_eq!(
        observations.len(),
        2,
        "the good frames on either side must still arrive"
    );
    let kinds: Vec<_> = observations.iter().map(|o| o.kind).collect();
    assert_eq!(kinds, [ObsKind::BookTop, ObsKind::Trade]);
}

/// A transport error mid-stream is recoverable, and the frames that preceded it
/// are still delivered.
#[tokio::test(start_paused = true)]
async fn a_mid_stream_transport_error_reconnects() {
    let events = run(
        MarketKind::Spot,
        spot_map(),
        vec![
            vec![
                text(SPOT_BOOK),
                Err(TransportError::Io("connection reset".to_owned())),
            ],
            vec![text(SPOT_TRADE), Ok(None)],
        ],
        6,
    )
    .await;

    let reasons: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            IngestEvent::Disconnected { reason, .. } => Some(reason.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        reasons
            .first()
            .is_some_and(|r| r.contains("connection reset")),
        "the disconnect reason should name the cause, got {reasons:?}"
    );
    assert_eq!(
        events
            .iter()
            .filter_map(IngestEvent::as_observation)
            .count(),
        2
    );
}
