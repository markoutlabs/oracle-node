//! Tails live Binance and prints normalized observations.
//!
//! This is the manual check behind M1's "sustained clean observation stream"
//! criterion — the automated tests prove the decoding and the reconnect logic,
//! but only a real connection proves the stream names, the TLS setup, and the
//! venue's actual payload shapes.
//!
//! ```sh
//! cargo run -p oracle-ingest --example binance_tail
//! cargo run -p oracle-ingest --example binance_tail -- 60   # stop after 60s
//! ```
//!
//! Prints a per-venue-symbol summary every second rather than every tick, since
//! `bookTicker` alone is a few hundred messages a second on the majors.

use std::collections::BTreeMap;
use std::time::Duration;

use oracle_ingest::binance::{BinanceAdapter, BinanceConfig};
use oracle_ingest::transport::WebSocketConnector;
use oracle_ingest::{ExchangeAdapter as _, IngestEvent, InstrumentSpec};
use oracle_types::{MarketKind, ObsKind};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Counters {
    messages: u64,
    last_price: String,
    /// `None` when the venue supplies no timestamp, which is not the same as a
    /// lag of zero — spot `bookTicker` sends no clock at all.
    max_lag_ms: Option<i64>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let run_for: Option<u64> = std::env::args().nth(1).and_then(|a| a.parse().ok());

    let config = BinanceConfig {
        spot: vec![
            InstrumentSpec::new("BTCUSDT", MarketKind::Spot, "CRYPTO.BTC/USDT")?,
            InstrumentSpec::new("ETHUSDT", MarketKind::Spot, "CRYPTO.ETH/USDT")?,
            InstrumentSpec::new("SOLUSDT", MarketKind::Spot, "CRYPTO.SOL/USDT")?,
        ],
        perp: vec![
            InstrumentSpec::new(
                "BTCUSDT",
                MarketKind::LinearPerp,
                "CRYPTO.BTC/USDT.PERP_MARK",
            )?,
            InstrumentSpec::new(
                "ETHUSDT",
                MarketKind::LinearPerp,
                "CRYPTO.ETH/USDT.PERP_MARK",
            )?,
        ],
        ..BinanceConfig::default()
    };

    let adapter = Box::new(BinanceAdapter::new(config, WebSocketConnector)?);
    for (session, market, _) in adapter.plan()? {
        println!("{market:>12}  {}", session.url);
    }
    println!();

    let (tx, mut rx) = mpsc::channel(4_096);
    let shutdown = CancellationToken::new();
    let handle = tokio::spawn(adapter.run(tx, shutdown.clone()));

    if let Some(seconds) = run_for {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(seconds)).await;
            shutdown.cancel();
        });
    }
    let ctrl_c = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        ctrl_c.cancel();
    });

    let mut counters: BTreeMap<(String, ObsKind), Counters> = BTreeMap::new();
    let mut report = tokio::time::interval(Duration::from_secs(1));
    report.tick().await;

    loop {
        tokio::select! {
            event = rx.recv() => {
                let Some(event) = event else { break };
                match event {
                    IngestEvent::Connected { stream } => println!("[up]   {stream}"),
                    IngestEvent::Disconnected { stream, reason } => {
                        println!("[down] {stream}: {reason}");
                    }
                    IngestEvent::Observation(obs) => {
                        let key = (
                            format!("{}:{}", obs.instrument.market, obs.instrument.symbol),
                            obs.kind,
                        );
                        let entry = counters.entry(key).or_default();
                        entry.messages += 1;
                        entry.last_price = obs.price.to_string();
                        if let Some(lag) = obs.venue_lag_ns() {
                            let lag_ms = lag / 1_000_000;
                            entry.max_lag_ms =
                                Some(entry.max_lag_ms.map_or(lag_ms, |m| m.max(lag_ms)));
                        }
                    }
                    // `IngestEvent` is non-exhaustive: new event kinds are
                    // additive for a consumer that only cares about prices.
                    _ => {}
                }
            }
            _ = report.tick() => {
                if counters.is_empty() {
                    continue;
                }
                println!("---");
                for ((instrument, kind), c) in &counters {
                    let lag = c
                        .max_lag_ms
                        .map_or_else(|| "n/a".to_owned(), |ms| format!("{ms}ms"));
                    println!(
                        "{instrument:<28} {kind:<13} {:>6}/s  last={:<16} max_lag={lag}",
                        c.messages, c.last_price
                    );
                }
                counters.clear();
            }
            () = shutdown.cancelled() => break,
        }
    }

    shutdown.cancel();
    handle.await??;
    println!("stopped cleanly");
    Ok(())
}
