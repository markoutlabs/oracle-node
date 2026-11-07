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

mod book;
pub mod decode;
pub mod snapshot;
pub mod streams;

use std::time::Duration;

use oracle_types::{InstrumentId, MarketKind, ObsKind, Observation, Venue};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::clock::MonotonicClock;
use crate::session::{MessageHandler, Session, SessionConfig, SessionStats};
use crate::{
    Connector, DecodeError, ExchangeAdapter, IngestError, IngestEvent, InstrumentMap,
    InstrumentSpec, StreamId, VenueHealth,
};

use streams::{
    MAX_STREAMS_PER_CONNECTION, PERP_BOOK_TICKERS_PER_CONNECTION, StreamKind, combined_urls,
    perp_urls, stream_names,
};

/// Binance adapter configuration.
#[derive(Clone, Debug)]
pub struct BinanceConfig {
    /// Spot instruments to stream.
    pub spot: Vec<InstrumentSpec>,
    /// Linear perpetual instruments to stream.
    pub perp: Vec<InstrumentSpec>,
    /// Override the spot endpoint. Tests point this at a local server.
    pub spot_base_url: String,
    /// Override the futures endpoint of the book ticker and depth.
    pub perp_base_url: String,
    /// Override the futures endpoint of trades and the mark price.
    pub perp_market_url: String,
    /// The REST endpoint spot depth snapshots come from.
    pub spot_rest_url: String,
    /// The REST endpoint futures depth snapshots come from.
    pub perp_rest_url: String,
    /// The REST endpoint of the adjusted funding intervals. Empty: no fetch.
    pub perp_funding_info_url: String,
    /// The REST endpoint of a perpetual's open interest. Empty: no fetch.
    pub perp_open_interest_url: String,
    /// Reconnect if nothing arrives for this long. The session probes a quiet
    /// connection (`SessionConfig::probe_after`), so this only has to cover a
    /// slow pong.
    pub idle_timeout: Duration,
    /// Recycle connections at this age, below Binance's own 24-hour limit.
    pub max_session: Duration,
    /// Streams per connection.
    pub streams_per_connection: usize,
    /// Book ticker streams per futures connection.
    pub perp_book_tickers_per_connection: usize,
}

impl BinanceConfig {
    /// Each socket base URL with the REST endpoint its depth snapshots come
    /// from, for [`snapshot::SnapshotConnector`].
    #[must_use]
    pub fn snapshot_routes(&self) -> Vec<(String, String)> {
        vec![
            (self.spot_base_url.clone(), self.spot_rest_url.clone()),
            (self.perp_base_url.clone(), self.perp_rest_url.clone()),
        ]
    }

    /// The routes for [`snapshot::SnapshotConnector::with_funding_info`]; none without a REST URL.
    #[must_use]
    pub fn funding_info_routes(&self) -> Vec<(String, String)> {
        if self.perp_funding_info_url.is_empty() {
            return Vec::new();
        }
        vec![(
            self.perp_market_url.clone(),
            self.perp_funding_info_url.clone(),
        )]
    }

    /// The mark-price socket base URL with the REST endpoint of the open
    /// interest, for [`snapshot::SnapshotConnector`].
    #[must_use]
    pub fn open_interest_routes(&self) -> Vec<(String, String)> {
        if self.perp_open_interest_url.is_empty() {
            return Vec::new();
        }
        vec![(
            self.perp_market_url.clone(),
            self.perp_open_interest_url.clone(),
        )]
    }
}

impl Default for BinanceConfig {
    fn default() -> Self {
        Self {
            spot: Vec::new(),
            perp: Vec::new(),
            spot_base_url: streams::SPOT_BASE.to_owned(),
            perp_base_url: streams::FUTURES_BASE.to_owned(),
            perp_market_url: streams::FUTURES_MARKET_BASE.to_owned(),
            spot_rest_url: snapshot::SPOT_REST.to_owned(),
            perp_rest_url: snapshot::FUTURES_REST.to_owned(),
            perp_funding_info_url: snapshot::FUTURES_FUNDING_INFO_REST.to_owned(),
            perp_open_interest_url: snapshot::FUTURES_OPEN_INTEREST_REST.to_owned(),
            idle_timeout: Duration::from_secs(10),
            max_session: Duration::from_secs(23 * 3_600),
            streams_per_connection: MAX_STREAMS_PER_CONNECTION,
            perp_book_tickers_per_connection: PERP_BOOK_TICKERS_PER_CONNECTION,
        }
    }
}

/// Decodes Binance payloads for one market.
///
/// The market is implicit in the [`InstrumentMap`]: one map per market is what
/// keeps `BTCUSDT` the perpetual from being confused with `BTCUSDT` the spot pair.
pub struct BinanceHandler {
    map: InstrumentMap,
    books: book::BinanceBooks,
    intervals: decode::FundingIntervals,
    subscribed: Vec<(InstrumentId, Option<ObsKind>)>,
}

impl BinanceHandler {
    /// Builds a handler for the market its map serves.
    #[must_use]
    pub fn new(map: InstrumentMap) -> Self {
        Self {
            map,
            books: book::BinanceBooks::default(),
            intervals: decode::FundingIntervals::default(),
            subscribed: Vec::new(),
        }
    }

    /// Expects a value from each moving stream that `url` subscribes to. The
    /// map holds every instrument of the market, and one connection carries
    /// only some of their streams.
    #[must_use]
    pub fn expecting(mut self, url: &str) -> Self {
        let streams = url
            .split_once("streams=")
            .map_or("", |(_, streams)| streams);
        self.subscribed = streams
            .split('/')
            .filter_map(|stream| {
                let kind = match StreamKind::from_stream_name(stream)? {
                    StreamKind::BookTicker => ObsKind::BookTop,
                    StreamKind::Depth => ObsKind::Depth,
                    StreamKind::MarkPrice => ObsKind::MarkPrice,
                    _ => return None,
                };
                let symbol = stream.split('@').next()?;
                let entry = self.map.lookup(symbol)?;
                Some((entry.instrument.clone(), Some(kind)))
            })
            .collect();
        self
    }
}

impl MessageHandler for BinanceHandler {
    fn on_payload(
        &mut self,
        payload: &[u8],
        local_recv_ns: u64,
        out: &mut Vec<Observation>,
    ) -> Result<(), DecodeError> {
        decode::decode(
            payload,
            &self.map,
            &mut self.books,
            &mut self.intervals,
            local_recv_ns,
            out,
        )
    }

    fn on_connect(&mut self) {
        // The intervals stay: the new connection fetches them again.
        self.books.clear();
    }

    fn subscribed(&self) -> Vec<(InstrumentId, Option<ObsKind>)> {
        self.subscribed.clone()
    }
}

/// The Binance adapter.
pub struct BinanceAdapter<C> {
    config: BinanceConfig,
    connector: C,
    label: String,
    clock: MonotonicClock,
    health: Vec<VenueHealth>,
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
        let mut adapter = Self {
            config,
            connector,
            clock: MonotonicClock::new(),
            label: "binance".to_owned(),
            health: Vec::new(),
        };
        adapter.health = adapter
            .plan()?
            .iter()
            .map(|(session, _, _)| VenueHealth::new(session.stream, session.url.clone()))
            .collect();
        Ok(adapter)
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
            let mut names = stream_names(map.venue_symbols(), market);
            // Only for a market this adapter serves: no streams means no connection.
            if !names.is_empty() {
                names.extend(map.depth_symbols().map(|symbol| {
                    format!(
                        "{}{}",
                        symbol.to_ascii_lowercase(),
                        StreamKind::Depth.suffix()
                    )
                }));
                names.sort_unstable();
            }
            let chunk = self.config.streams_per_connection;
            let urls = match market {
                MarketKind::LinearPerp => perp_urls(
                    base,
                    &self.config.perp_market_url,
                    names,
                    chunk,
                    self.config.perp_book_tickers_per_connection,
                ),
                _ => combined_urls(base, &names, chunk),
            };
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

    fn health(&self) -> Vec<VenueHealth> {
        self.health.clone()
    }

    async fn run(
        self: Box<Self>,
        out: mpsc::Sender<IngestEvent>,
        shutdown: CancellationToken,
    ) -> Result<(), IngestError> {
        let plan = self.plan()?;
        let mut sessions = Vec::with_capacity(plan.len());

        for (index, (config, _market, map)) in plan.into_iter().enumerate() {
            let handler = BinanceHandler::new(map).expecting(&config.url);
            let health = self
                .health
                .get(index)
                .cloned()
                .unwrap_or_else(|| VenueHealth::new(config.stream, config.url.clone()));
            let session = Session::new(config, self.connector.clone(), handler, self.clock.clone())
                .with_health(health);
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
    use crate::testing::{Script, ScriptedConnector, instrument, run_adapter_until_connected};

    /// Each connection closes at once, so the adapter reconnects at its backoff.
    fn closing() -> ScriptedConnector {
        ScriptedConnector::repeating(Script::new().close())
    }

    fn config() -> BinanceConfig {
        BinanceConfig {
            spot: vec![
                instrument("BTCUSDT", MarketKind::Spot),
                instrument("ETHUSDT", MarketKind::Spot),
            ],
            perp: vec![instrument("BTCUSDT", MarketKind::LinearPerp)],
            ..BinanceConfig::default()
        }
    }

    #[test]
    fn empty_configuration_is_rejected() {
        assert!(matches!(
            BinanceAdapter::new(BinanceConfig::default(), closing()),
            Err(IngestError::NoInstruments {
                venue: Venue::Binance
            })
        ));
    }

    #[test]
    fn duplicate_instruments_fail_at_construction_not_at_runtime() {
        let mut config = config();
        config.spot.push(instrument("btcusdt", MarketKind::Spot));
        assert!(matches!(
            BinanceAdapter::new(config, closing()),
            Err(IngestError::DuplicateInstrument { .. })
        ));
    }

    #[test]
    fn plan_separates_spot_from_perpetuals() {
        let adapter = BinanceAdapter::new(config(), closing()).expect("valid");
        let plan = adapter.plan().expect("plans");
        assert_eq!(
            plan.len(),
            3,
            "one spot connection and one for each futures route"
        );

        let spot = plan
            .iter()
            .find(|(_, m, _)| *m == MarketKind::Spot)
            .expect("spot");
        assert!(spot.0.url.starts_with(streams::SPOT_BASE));
        assert!(spot.0.url.contains("btcusdt@bookTicker"));
        assert!(spot.0.url.contains("ethusdt@aggTrade"));
        assert!(!spot.0.url.contains("markPrice"), "spot has no mark price");

        let perp: Vec<&str> = plan
            .iter()
            .filter(|(_, m, _)| *m == MarketKind::LinearPerp)
            .map(|(session, _, _)| session.url.as_str())
            .collect();
        let [public, market] = perp.as_slice() else {
            panic!("two futures connections: {perp:?}");
        };
        assert!(public.starts_with(streams::FUTURES_BASE));
        assert!(public.contains("btcusdt@bookTicker") && !public.contains("markPrice"));
        assert!(market.starts_with(streams::FUTURES_MARKET_BASE));
        assert!(market.contains("btcusdt@markPrice@1s") && market.contains("btcusdt@aggTrade"));
        assert!(!market.contains("bookTicker"));
    }

    #[test]
    fn perp_depth_gets_its_own_connection() {
        let mut config = config();
        config.perp = vec![instrument("BTCUSDT", MarketKind::LinearPerp).with_depth()];
        let adapter = BinanceAdapter::new(config, closing()).expect("valid");
        let perp: Vec<String> = adapter
            .plan()
            .expect("plans")
            .into_iter()
            .filter(|(_, market, _)| *market == MarketKind::LinearPerp)
            .map(|(session, _, _)| session.url)
            .collect();
        assert_eq!(
            perp,
            [
                format!("{}?streams=btcusdt@depth@100ms", streams::FUTURES_BASE),
                format!("{}?streams=btcusdt@bookTicker", streams::FUTURES_BASE),
                format!(
                    "{}?streams=btcusdt@aggTrade/btcusdt@markPrice@1s",
                    streams::FUTURES_MARKET_BASE
                ),
            ]
        );
    }

    #[test]
    fn sessions_recycle_below_the_venue_limit() {
        let adapter = BinanceAdapter::new(config(), closing()).expect("valid");
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
        let adapter = BinanceAdapter::new(config, closing()).expect("valid");
        let plan = adapter.plan().expect("plans");
        assert_eq!(plan.len(), 1);
        assert_eq!(
            plan.first().map(|(_, market, _)| *market),
            Some(MarketKind::Spot)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn run_opens_both_endpoints_and_stops_on_shutdown() {
        let connector = closing();
        let adapter = BinanceAdapter::new(config(), connector.clone()).expect("valid");
        run_adapter_until_connected(Box::new(adapter), 2).await;
        let urls = connector.urls();
        assert!(urls.iter().any(|u| u.starts_with(streams::SPOT_BASE)));
        assert!(urls.iter().any(|u| u.starts_with(streams::FUTURES_BASE)));
    }
}
