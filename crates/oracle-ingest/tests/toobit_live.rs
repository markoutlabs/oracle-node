//! Toobit's REST books through the real connector, decoder and session, against
//! the live venue.
//!
//! Ignored by default because it needs the internet:
//! `cargo test -p oracle-ingest --test toobit_live -- --ignored --nocapture`.
//! `LIVE_SECS` sets the span (default 120).

use std::collections::BTreeMap;
use std::time::Duration;

use oracle_ingest::transport::WebSocketConnector;
use oracle_ingest::venues::toobit_connect::ToobitConnector;
use oracle_ingest::venues::{VenueAdapter, VenueSpec, toobit};
use oracle_ingest::{ExchangeAdapter as _, IngestEvent, InstrumentSpec};
use oracle_types::{MarketKind, Venue};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const BOOKS: [&str; 4] = ["ICPUSDT", "ETHUSDT", "BTCUSDT", "SOLUSDC"];

/// What arrived for one book: the count, and the venue's age of each book at receipt.
#[derive(Default)]
struct Received {
    books: u32,
    ages_ms: Vec<u64>,
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the internet"]
async fn live_toobit_books_arrive_each_second() {
    let span = std::env::var("LIVE_SECS")
        .ok()
        .and_then(|secs| secs.parse().ok())
        .map_or(Duration::from_secs(120), Duration::from_secs);
    let instruments: Vec<InstrumentSpec> = BOOKS
        .iter()
        .map(|symbol| {
            InstrumentSpec::new(*symbol, MarketKind::Spot, "CRYPTO.X/USDT")
                .expect("a symbol")
                .with_depth()
        })
        .collect();
    let spec = VenueSpec {
        venue: Venue::Toobit,
        market: MarketKind::Spot,
        url: toobit::url(BOOKS.into_iter()),
        subscribe: Vec::new(),
        keepalive: None,
        idle_timeout: Duration::from_secs(10),
        resubscribe_after: None,
        max_session: Duration::from_secs(3_600),
        decode: toobit::decode,
    };
    let connector = ToobitConnector::new(WebSocketConnector).expect("a client");
    let adapter =
        VenueAdapter::new(Venue::Toobit, vec![(spec, instruments)], connector).expect("an adapter");
    let health = adapter.health();
    let (out, mut events) = mpsc::channel(4_096);
    let shutdown = CancellationToken::new();
    let run = tokio::spawn(Box::new(adapter).run(out, shutdown.clone()));

    let mut received: BTreeMap<String, Received> = BTreeMap::new();
    let mut disconnects = Vec::new();
    let deadline = tokio::time::Instant::now() + span;
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.recv()).await {
        match event {
            IngestEvent::Observation(observation) => {
                let book = received
                    .entry(observation.instrument.symbol.to_string())
                    .or_default();
                book.books += 1;
                if let Some(time) = observation.exchange_time_ns {
                    let age = observation.local_recv_ns.saturating_sub(time) / 1_000_000;
                    book.ages_ms.push(age);
                }
            }
            IngestEvent::Disconnected { reason, .. } => disconnects.push(reason),
            _ => {}
        }
    }
    shutdown.cancel();
    let _ = run.await;

    let secs = span.as_secs_f64();
    println!("\nToobit over {secs} s:");
    for (symbol, book) in &received {
        let mut ages = book.ages_ms.clone();
        ages.sort_unstable();
        let at = |share: usize| ages.get(ages.len() * share / 100).copied().unwrap_or(0);
        println!(
            "  {symbol}: {} books, {:.2} a second; age of `t` at receipt: p50 {} ms, p95 {} ms, max {} ms",
            book.books,
            f64::from(book.books) / secs,
            at(50),
            at(95),
            ages.last().copied().unwrap_or(0),
        );
    }
    let counts = health.first().map(oracle_ingest::VenueHealth::counts);
    println!("  disconnects: {disconnects:?}\n  counters: {counts:?}");
    assert_eq!(received.len(), BOOKS.len(), "a book never arrived");
}
