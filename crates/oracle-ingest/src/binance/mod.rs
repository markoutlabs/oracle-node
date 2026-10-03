//! Binance spot and USD-margined futures ingest.
//!
//! # Operational notes that are not obvious from the API docs
//!
//! - Streams are named in **lowercase**; payloads stamp the symbol in
//!   **uppercase**. [`InstrumentMap`] handles both without allocating.
//! - Spot `bookTicker` carries **no timestamp at all** — not even an event time.
//!   Only the futures variant has `E` and `T`.
//! - Binance closes a stream connection at **24 hours**. Sessions recycle at 23
//!   so the disconnect happens at a moment of our choosing, not the venue's.
//! - Spot and futures live on different hosts and fail independently, so they get
//!   separate connections and separate backoff ladders.
//! - `BTCUSDT` exists on both spot and futures. Each connection carries its own
//!   [`InstrumentMap`] for one market, which is what keeps a perpetual mark from
//!   being mistaken for a spot quote.

pub mod decode;
pub mod streams;

use std::time::Duration;

use oracle_types::{MarketKind, Observation, Venue};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::clock::MonotonicClock;
use crate::session::{MessageHandler, Session, SessionConfig, SessionStats};
use crate::{
    Connector, DecodeError, ExchangeAdapter, IngestError, IngestEvent, InstrumentMap,
    InstrumentSpec, StreamId,
};

use streams::{MAX_STREAMS_PER_CONNECTION, combined_urls, stream_names};

/// Binance adapter configuration.
#[derive(Clone, Debug)]
pub struct BinanceConfig {
    /// Spot instruments to stream.
    pub spot: Vec<InstrumentSpec>,
    /// Linear perpetual instruments to stream.
    pub perp: Vec<InstrumentSpec>,
    /// Override the spot endpoint. Tests point this at a local server.
    pub spot_base_url: String,
    /// Override the futures endpoint.
    pub perp_base_url: String,
    /// Reconnect if nothing arrives for this long.
    ///
    /// Binance sends a protocol ping roughly every 20 seconds, and a quiet
    /// instrument may not quote for a while, so this has to sit comfortably above
    /// the ping period rather than the quote rate.
    pub idle_timeout: Duration,
    /// Recycle connections at this age, below Binance's own 24-hour limit.
    pub max_session: Duration,
    /// Streams per connection.
    pub streams_per_connection: usize,
}

impl Default for BinanceConfig {
    fn default() -> Self {
        Self {
            spot: Vec::new(),
            perp: Vec::new(),
            spot_base_url: streams::SPOT_BASE.to_owned(),
            perp_base_url: streams::FUTURES_BASE.to_owned(),
            idle_timeout: Duration::from_secs(60),
            max_session: Duration::from_secs(23 * 3_600),
            streams_per_connection: MAX_STREAMS_PER_CONNECTION,
        }
    }
}

/// Decodes Binance payloads for one market.
///
/// The market is implicit in the [`InstrumentMap`]: one map per market is what
/// keeps `BTCUSDT` the perpetual from being confused with `BTCUSDT` the spot pair.
pub struct BinanceHandler {
    map: InstrumentMap,
}

impl BinanceHandler {
    /// Builds a handler for the market its map serves.
    #[must_use]
    pub const fn new(map: InstrumentMap) -> Self {
        Self { map }
    }
}

impl MessageHandler for BinanceHandler {
    fn on_payload(
        &mut self,
        payload: &[u8],
        local_recv_ns: u64,
        out: &mut Vec<Observation>,
    ) -> Result<(), DecodeError> {
        decode::decode_payload(payload, &self.map, local_recv_ns, out)
    }
}

/// The Binance adapter.
pub struct BinanceAdapter<C> {
    config: BinanceConfig,
    connector: C,
    label: String,
    clock: MonotonicClock,
}

impl<C: Connector + Clone + 'static> BinanceAdapter<C> {
    /// Builds an adapter.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError::NoInstruments`] if nothing is configured, or
    /// [`IngestError::Config`] / [`IngestError::DuplicateInstrument`] for a bad
    /// instrument list.
    pub fn new(config: BinanceConfig, connector: C) -> Result<Self, IngestError> {
        if config.spot.is_empty() && config.perp.is_empty() {
            return Err(IngestError::NoInstruments {
                venue: Venue::Binance,
            });
        }
        // Validate both maps now so a typo fails at startup rather than silently
        // dropping a feed at runtime.
        InstrumentMap::new(Venue::Binance, MarketKind::Spot, &config.spot)?;
        InstrumentMap::new(Venue::Binance, MarketKind::LinearPerp, &config.perp)?;
        Ok(Self {
            config,
            connector,
            clock: MonotonicClock::new(),
            label: "binance".to_owned(),
        })
    }

    /// Stamps observations with `clock` instead of real time.
    ///
    /// For replay, where receipt times come from the recording.
    #[must_use]
    pub fn with_clock(mut self, clock: MonotonicClock) -> Self {
        self.clock = clock;
        self
    }

    /// Builds the session configs this adapter will run.
    ///
    /// Exposed so a deployment can log or assert its connection plan before
    /// opening a socket.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError`] if an instrument list is invalid.
    pub fn plan(&self) -> Result<Vec<(SessionConfig, MarketKind, InstrumentMap)>, IngestError> {
        let mut plan = Vec::new();
        for (market, specs, base) in [
            (
                MarketKind::Spot,
                &self.config.spot,
                &self.config.spot_base_url,
            ),
            (
                MarketKind::LinearPerp,
                &self.config.perp,
                &self.config.perp_base_url,
            ),
        ] {
            if specs.is_empty() {
                continue;
            }
            let map = InstrumentMap::new(Venue::Binance, market, specs)?;
            let names = stream_names(map.venue_symbols(), market);
            let urls = combined_urls(base, &names, self.config.streams_per_connection);
            for url in urls {
                let mut session = SessionConfig::new(StreamId::new(Venue::Binance, market), url);
                session.idle_timeout = self.config.idle_timeout;
                session.max_session = self.config.max_session;
                plan.push((session, market, map.clone()));
            }
        }
        Ok(plan)
    }
}

#[async_trait::async_trait]
impl<C: Connector + Clone + 'static> ExchangeAdapter for BinanceAdapter<C> {
    fn venue(&self) -> Venue {
        Venue::Binance
    }

    fn label(&self) -> &str {
        &self.label
    }

    async fn run(
        self: Box<Self>,
        out: mpsc::Sender<IngestEvent>,
        shutdown: CancellationToken,
    ) -> Result<(), IngestError> {
        let plan = self.plan()?;
        let mut sessions = Vec::with_capacity(plan.len());

        for (config, _market, map) in plan {
            let session = Session::new(
                config,
                self.connector.clone(),
                BinanceHandler::new(map),
                self.clock.clone(),
            );
            sessions.push(session.run(out.clone(), shutdown.clone()));
        }

        // Every session runs until shutdown. The first fatal error stops the
        // adapter — the only fatal errors are a closed output channel and a bad
        // configuration, and neither improves by continuing.
        let results: Vec<Result<SessionStats, IngestError>> =
            futures_util::future::join_all(sessions).await;
        for result in results {
            result?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Frame, Transport, TransportError};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct NullConnector;

    struct NullConn;

    impl Transport for NullConn {
        async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
            Ok(None)
        }
        async fn send_text(&mut self, _text: String) -> Result<(), TransportError> {
            Ok(())
        }
    }

    impl Connector for NullConnector {
        type Conn = NullConn;
        async fn connect(&self, _url: &str) -> Result<Self::Conn, TransportError> {
            Ok(NullConn)
        }
    }

    /// Records every URL it is asked to connect to.
    #[derive(Clone)]
    struct RecordingConnector {
        urls: Arc<std::sync::Mutex<Vec<String>>>,
        opens: Arc<AtomicUsize>,
    }

    impl Connector for RecordingConnector {
        type Conn = NullConn;
        async fn connect(&self, url: &str) -> Result<Self::Conn, TransportError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut urls) = self.urls.lock() {
                urls.push(url.to_owned());
            }
            Ok(NullConn)
        }
    }

    fn config() -> BinanceConfig {
        BinanceConfig {
            spot: vec![
                InstrumentSpec::new("BTCUSDT", MarketKind::Spot, "CRYPTO.BTC/USDT").expect("valid"),
                InstrumentSpec::new("ETHUSDT", MarketKind::Spot, "CRYPTO.ETH/USDT").expect("valid"),
            ],
            perp: vec![
                InstrumentSpec::new(
                    "BTCUSDT",
                    MarketKind::LinearPerp,
                    "CRYPTO.BTC/USDT.PERP_MARK",
                )
                .expect("valid"),
            ],
            ..BinanceConfig::default()
        }
    }

    #[test]
    fn empty_configuration_is_rejected() {
        assert!(matches!(
            BinanceAdapter::new(BinanceConfig::default(), NullConnector),
            Err(IngestError::NoInstruments {
                venue: Venue::Binance
            })
        ));
    }

    #[test]
    fn duplicate_instruments_fail_at_construction_not_at_runtime() {
        let mut config = config();
        config.spot.push(
            InstrumentSpec::new("btcusdt", MarketKind::Spot, "CRYPTO.BTC/USDT").expect("valid"),
        );
        assert!(matches!(
            BinanceAdapter::new(config, NullConnector),
            Err(IngestError::DuplicateInstrument { .. })
        ));
    }

    #[test]
    fn plan_separates_spot_from_perpetuals() {
        let adapter = BinanceAdapter::new(config(), NullConnector).expect("valid");
        let plan = adapter.plan().expect("plans");
        assert_eq!(
            plan.len(),
            2,
            "one spot connection and one futures connection"
        );

        let spot = plan
            .iter()
            .find(|(_, m, _)| *m == MarketKind::Spot)
            .expect("spot");
        assert!(spot.0.url.starts_with(streams::SPOT_BASE));
        assert!(spot.0.url.contains("btcusdt@bookTicker"));
        assert!(spot.0.url.contains("ethusdt@aggTrade"));
        assert!(!spot.0.url.contains("markPrice"), "spot has no mark price");

        let perp = plan
            .iter()
            .find(|(_, m, _)| *m == MarketKind::LinearPerp)
            .expect("perp");
        assert!(perp.0.url.starts_with(streams::FUTURES_BASE));
        assert!(perp.0.url.contains("btcusdt@markPrice@1s"));
    }

    #[test]
    fn sessions_recycle_below_the_venue_limit() {
        let adapter = BinanceAdapter::new(config(), NullConnector).expect("valid");
        for (session, _, _) in adapter.plan().expect("plans") {
            assert!(
                session.max_session < Duration::from_secs(24 * 3_600),
                "must reconnect before Binance forces it"
            );
        }
    }

    #[test]
    fn spot_only_configuration_opens_one_connection() {
        let mut config = config();
        config.perp.clear();
        let adapter = BinanceAdapter::new(config, NullConnector).expect("valid");
        let plan = adapter.plan().expect("plans");
        assert_eq!(plan.len(), 1);
        assert_eq!(
            plan.first().map(|(_, market, _)| *market),
            Some(MarketKind::Spot)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn run_opens_both_endpoints_and_stops_on_shutdown() {
        let urls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let connector = RecordingConnector {
            urls: Arc::clone(&urls),
            opens: Arc::new(AtomicUsize::new(0)),
        };
        let adapter = Box::new(BinanceAdapter::new(config(), connector).expect("valid"));

        let (tx, mut rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(adapter.run(tx, shutdown.clone()));

        // Let both sessions connect at least once.
        let mut connected = 0;
        while connected < 2 {
            match rx.recv().await {
                Some(IngestEvent::Connected { .. }) => connected += 1,
                Some(_) => {}
                None => break,
            }
        }
        shutdown.cancel();
        // Drain so the sessions are never blocked on a full channel.
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        handle.await.expect("joins").expect("runs");

        let urls = urls.lock().expect("lock").clone();
        assert!(urls.iter().any(|u| u.starts_with(streams::SPOT_BASE)));
        assert!(urls.iter().any(|u| u.starts_with(streams::FUTURES_BASE)));
    }
}
