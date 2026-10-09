//! A host that accepts TCP and never answers the upgrade. After a network
//! outage this held venue streams for 25 minutes, with every feed halted.

use std::time::Duration;

use oracle_ingest::clock::MonotonicClock;
use oracle_ingest::session::MessageHandler;
use oracle_ingest::transport::WebSocketConnector;
use oracle_ingest::{BackoffConfig, DecodeError, Session, SessionConfig, StreamId};
use oracle_types::{MarketKind, Observation, Venue};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

struct Ignore;

impl MessageHandler for Ignore {
    fn on_payload(
        &mut self,
        _payload: &[u8],
        _local_recv_ns: u64,
        _out: &mut Vec<Observation>,
    ) -> Result<(), DecodeError> {
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn a_connect_that_never_finishes_fails_and_retries() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let url = format!("ws://{}/stream", listener.local_addr().expect("bound"));
    // Accepts each connection and holds it open without a byte.
    let held = tokio::spawn(async move {
        let mut sockets = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            sockets.push(socket);
        }
    });

    let mut config = SessionConfig::new(StreamId::new(Venue::Binance, MarketKind::Spot), url);
    config.backoff = BackoffConfig {
        initial: Duration::from_millis(100),
        max: Duration::from_millis(100),
        multiplier: 1,
        jitter: false,
        ..BackoffConfig::default()
    };
    let session = Session::new(config, WebSocketConnector, Ignore, MonotonicClock::new());
    let (out, _rx) = mpsc::channel(16);
    let shutdown = CancellationToken::new();
    let running = tokio::spawn(session.run(out, shutdown.clone()));

    // Three 10 s timeouts and their retries, in paused time.
    tokio::time::sleep(Duration::from_secs(35)).await;
    shutdown.cancel();
    let stats = running.await.expect("joins").expect("runs");
    held.abort();
    assert!(stats.connect_failures >= 3, "{stats:?}");
    assert_eq!(stats.connects, 0);
}
