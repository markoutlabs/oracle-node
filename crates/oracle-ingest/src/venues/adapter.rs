//! A generic adapter for the venues that subscribe over the socket.
//!
//! Binance puts its subscription in the URL and needs none of this. Every other
//! venue in scope connects, sends a subscribe frame, and needs an
//! application-level keepalive — so one adapter parameterised by those three
//! things covers all of them, and each venue module supplies only its naming and
//! its decoder.

use std::time::Duration;

use oracle_types::{MarketKind, Observation, Venue};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::book::Books;
use crate::clock::MonotonicClock;
use crate::session::{MessageHandler, Session, SessionConfig, SessionStats};
use crate::{
    Connector, DecodeError, ExchangeAdapter, IngestError, IngestEvent, InstrumentMap,
    InstrumentSpec, StreamId,
};

/// How one venue's connection is built and decoded.
#[derive(Clone)]
pub struct VenueSpec {
    /// The venue.
    pub venue: Venue,
    /// Which market this connection serves.
    pub market: MarketKind,
    /// The endpoint.
    pub url: String,
    /// Frames sent immediately after connecting, in order.
    pub subscribe: Vec<String>,
    /// Application keepalive: how often, and what to send.
    pub keepalive: Option<(Duration, String)>,
    /// Reconnect if nothing arrives for this long.
    pub idle_timeout: Duration,
    /// Reconnect when one instrument falls silent for this long; see
    /// [`SessionConfig::resubscribe_after`](crate::SessionConfig::resubscribe_after).
    pub resubscribe_after: Option<Duration>,
    /// Recycle the connection at this age.
    pub max_session: Duration,
    /// How to decode this connection's payloads.
    ///
    /// Per connection rather than per venue: one exchange can speak entirely
    /// different protocols on different markets. Kraken's v2 spot feed and
    /// Kraken Futures share a venue and a brand and nothing else — different
    /// host, different envelope, different field names.
    pub decode: DecodeFn,
}

/// Decodes one venue's payloads.
pub type DecodeFn =
    fn(&[u8], &InstrumentMap, &mut Books, u64, &mut Vec<Observation>) -> Result<(), DecodeError>;

/// A handler that dispatches to a venue's decode function, and keeps the
/// connection's local books.
pub struct VenueHandler {
    map: InstrumentMap,
    decode: DecodeFn,
    books: Books,
}

impl VenueHandler {
    /// Builds a handler.
    #[must_use]
    pub fn new(map: InstrumentMap, decode: DecodeFn) -> Self {
        Self {
            map,
            decode,
            books: Books::default(),
        }
    }
}

impl MessageHandler for VenueHandler {
    fn on_payload(
        &mut self,
        payload: &[u8],
        local_recv_ns: u64,
        out: &mut Vec<Observation>,
    ) -> Result<(), DecodeError> {
        (self.decode)(payload, &self.map, &mut self.books, local_recv_ns, out)
    }

    fn on_connect(&mut self) {
        self.books.clear();
    }
}

/// A venue adapter built from a [`VenueSpec`] and a decode function.
pub struct VenueAdapter<C> {
    specs: Vec<(VenueSpec, InstrumentMap)>,
    connector: C,
    label: String,
    venue: Venue,
    clock: MonotonicClock,
}

impl<C: Connector + Clone + 'static> VenueAdapter<C> {
    /// Builds an adapter from one connection spec per market.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError::NoInstruments`] if nothing is configured.
    pub fn new(
        venue: Venue,
        connections: Vec<(VenueSpec, Vec<InstrumentSpec>)>,
        connector: C,
    ) -> Result<Self, IngestError> {
        if connections
            .iter()
            .all(|(_, instruments)| instruments.is_empty())
        {
            return Err(IngestError::NoInstruments { venue });
        }
        let mut specs = Vec::with_capacity(connections.len());
        for (spec, instruments) in connections {
            if instruments.is_empty() {
                continue;
            }
            // Validated here so a typo fails at startup rather than silently
            // dropping a feed at runtime.
            let map = InstrumentMap::new(venue, spec.market, &instruments)?;
            specs.push((spec, map));
        }
        Ok(Self {
            clock: MonotonicClock::new(),
            specs,
            connector,
            label: venue.as_str().to_owned(),
            venue,
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

    /// Returns the session configuration this adapter will run.
    #[must_use]
    pub fn plan(&self) -> Vec<SessionConfig> {
        self.specs
            .iter()
            .map(|(spec, _)| session_config(spec, self.venue))
            .collect()
    }
}

fn session_config(spec: &VenueSpec, venue: Venue) -> SessionConfig {
    let mut config = SessionConfig::new(StreamId::new(venue, spec.market), spec.url.clone());
    config.subscribe = spec.subscribe.clone();
    config.keepalive = spec.keepalive.clone();
    config.idle_timeout = spec.idle_timeout;
    config.resubscribe_after = spec.resubscribe_after;
    config.max_session = spec.max_session;
    config
}

#[async_trait::async_trait]
impl<C: Connector + Clone + 'static> ExchangeAdapter for VenueAdapter<C> {
    fn venue(&self) -> Venue {
        self.venue
    }

    fn label(&self) -> &str {
        &self.label
    }

    async fn run(
        self: Box<Self>,
        out: mpsc::Sender<IngestEvent>,
        shutdown: CancellationToken,
    ) -> Result<(), IngestError> {
        let mut sessions = Vec::with_capacity(self.specs.len());
        for (spec, map) in &self.specs {
            let session = Session::new(
                session_config(spec, self.venue),
                self.connector.clone(),
                VenueHandler::new(map.clone(), spec.decode),
                self.clock.clone(),
            );
            sessions.push(session.run(out.clone(), shutdown.clone()));
        }
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
    struct NullConnector {
        opens: Arc<AtomicUsize>,
    }

    struct NullConn;

    impl Transport for NullConn {
        async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
            Ok(None)
        }
        async fn send_text(&mut self, _text: String) -> Result<(), TransportError> {
            Ok(())
        }
        async fn send_ping(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    impl Connector for NullConnector {
        type Conn = NullConn;
        async fn connect(&self, _url: &str) -> Result<Self::Conn, TransportError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Ok(NullConn)
        }
    }

    fn spec(market: MarketKind, url: &str) -> VenueSpec {
        VenueSpec {
            venue: Venue::Bybit,
            market,
            url: url.to_owned(),
            subscribe: vec![r#"{"op":"subscribe"}"#.to_owned()],
            keepalive: Some((Duration::from_secs(20), r#"{"op":"ping"}"#.to_owned())),
            idle_timeout: Duration::from_secs(30),
            resubscribe_after: None,
            max_session: Duration::from_secs(3_600),
            decode,
        }
    }

    fn instruments(market: MarketKind) -> Vec<InstrumentSpec> {
        vec![InstrumentSpec::new("BTCUSDT", market, "CRYPTO.BTC/USDT").expect("valid")]
    }

    fn decode(
        _payload: &[u8],
        _map: &InstrumentMap,
        _books: &mut Books,
        _now: u64,
        _out: &mut Vec<Observation>,
    ) -> Result<(), DecodeError> {
        Err(DecodeError::Control)
    }

    #[test]
    fn an_empty_configuration_is_refused() {
        let result = VenueAdapter::new(
            Venue::Bybit,
            vec![(spec(MarketKind::Spot, "wss://x"), vec![])],
            NullConnector {
                opens: Arc::new(AtomicUsize::new(0)),
            },
        );
        assert!(matches!(result, Err(IngestError::NoInstruments { .. })));
    }

    #[test]
    fn each_market_becomes_its_own_connection() {
        let adapter = VenueAdapter::new(
            Venue::Bybit,
            vec![
                (
                    spec(MarketKind::Spot, "wss://spot"),
                    instruments(MarketKind::Spot),
                ),
                (
                    spec(MarketKind::LinearPerp, "wss://linear"),
                    instruments(MarketKind::LinearPerp),
                ),
            ],
            NullConnector {
                opens: Arc::new(AtomicUsize::new(0)),
            },
        )
        .expect("valid");

        let plan = adapter.plan();
        let urls: Vec<&str> = plan.iter().map(|config| config.url.as_str()).collect();
        assert_eq!(urls, ["wss://spot", "wss://linear"]);
        assert!(
            plan.first()
                .is_some_and(|config| config.keepalive.is_some()),
            "these venues need an app keepalive"
        );
    }

    #[test]
    fn a_market_with_no_instruments_opens_no_connection() {
        let adapter = VenueAdapter::new(
            Venue::Bybit,
            vec![
                (
                    spec(MarketKind::Spot, "wss://spot"),
                    instruments(MarketKind::Spot),
                ),
                (spec(MarketKind::LinearPerp, "wss://linear"), vec![]),
            ],
            NullConnector {
                opens: Arc::new(AtomicUsize::new(0)),
            },
        )
        .expect("valid");
        assert_eq!(adapter.plan().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn run_opens_every_configured_connection() {
        let opens = Arc::new(AtomicUsize::new(0));
        let adapter = Box::new(
            VenueAdapter::new(
                Venue::Bybit,
                vec![
                    (
                        spec(MarketKind::Spot, "wss://spot"),
                        instruments(MarketKind::Spot),
                    ),
                    (
                        spec(MarketKind::LinearPerp, "wss://linear"),
                        instruments(MarketKind::LinearPerp),
                    ),
                ],
                NullConnector {
                    opens: Arc::clone(&opens),
                },
            )
            .expect("valid"),
        );

        let (tx, mut rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(adapter.run(tx, shutdown.clone()));

        let mut connected = 0;
        while connected < 2 {
            match rx.recv().await {
                Some(IngestEvent::Connected { .. }) => connected += 1,
                Some(_) => {}
                None => break,
            }
        }
        shutdown.cancel();
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        handle.await.expect("joins").expect("runs");
        assert!(opens.load(Ordering::SeqCst) >= 2);
    }
}
