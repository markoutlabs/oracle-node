//! One node inside the caller's process: the venue readers, the aggregator and
//! the signer, with the signed frames on a channel in place of a server.
//!
//! It runs no server, fetches no registry or client list, pushes nothing to the
//! canister, and sets no logger, signal handler or file limit: the process is
//! the caller's. [`local_registry`] signs the one-node registry that the SDK
//! checks the frames against.
//!
//! With the feature `local-unsigned`, `LocalNode::start_unsigned` signs no frame:
//! the SDK in the same process takes each value with `OracleClient::ingest_local`.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use oracle_client::{OracleClient, Subscription, now_unix_nanos};
//! use oracle_node::Seed;
//! use oracle_node::config::{DEFAULT_TICK_MS, FeedSettings};
//! use oracle_node::embed::{BookFrames, EmbedConfig, LocalNode, MonotonicClock, local_registry};
//! use tokio_util::sync::CancellationToken;
//!
//! # async fn run(feeds: Vec<FeedSettings>) -> Result<(), Box<dyn std::error::Error>> {
//! // The app keeps both seeds, for example in the OS keychain.
//! let signer = Arc::new(Seed::generate()?.signer()?);
//! let governance = Seed::generate()?.signer()?;
//! let symbols: Vec<String> = feeds.iter().map(|feed| feed.symbol.clone()).collect();
//! let symbols: Vec<&str> = symbols.iter().map(String::as_str).collect();
//!
//! let mut node = LocalNode::start(
//!     EmbedConfig {
//!         feeds,
//!         endpoints: Vec::new(),
//!         tick_interval_ms: DEFAULT_TICK_MS,
//!         signer: Arc::clone(&signer),
//!         clock: MonotonicClock::new(),
//!         venue_reports: false,
//!         books: BookFrames::All,
//!         funding: true,
//!     },
//!     CancellationToken::new(),
//! )?;
//! let mut frames = node.take_frames().ok_or("taken once")?;
//!
//! let registry = local_registry(signer.address(), &governance, 1, 0)?;
//! let mut client = OracleClient::builder(registry)
//!     .quorum(1)
//!     .i_understand_this_provides_no_protection_against_a_bad_node()
//!     .build()?;
//! client.subscribe_local(Subscription {
//!     prices: &symbols,
//!     ..Subscription::default()
//! })?;
//! while let Some(frame) = frames.recv().await {
//!     match client.ingest_event(&frame.encode_frame(), now_unix_nanos()) {
//!         Ok(_event) => { /* a price, a book or a funding frame */ }
//!         Err(_reason) => { /* a frame the SDK refused */ }
//!     }
//! }
//! node.stop().await;
//! # Ok(())
//! # }
//! ```

use std::collections::HashSet;
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use oracle_agg::{AggError, FeedConfig};
use oracle_ingest::clock::wall_clock_unix_nanos;
use oracle_ingest::{Connector, IngestError, IngestEvent};
use oracle_types::{InstrumentId, Symbol};
use oracle_wire::{
    Address, NodeEntry, Quorum, Registry, SignedBookUpdate, SignedFundingUpdate, SignedUpdate,
    SignedVenueReport, Signer, VerifiedRegistry, VerifyError, WireError,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::warn;

pub use oracle_ingest::VenueHealth;
pub use oracle_ingest::clock::MonotonicClock;
/// The token that [`LocalNode::start`] takes, so a caller needs no `tokio-util` of its own.
pub use tokio_util::sync::CancellationToken;

#[cfg(feature = "local-unsigned")]
use oracle_client::LocalFrame;
#[cfg(feature = "local-unsigned")]
use oracle_wire::Recovered;

use crate::config::{ConfigError, EndpointSettings, FeedSettings, ResolvedConfig, resolve_feeds};
use crate::ingest::{Health, Ingest, connectors};
use crate::run::{INGEST_CAPACITY, Outlet, Signing, Sink, drive, sync_clock};
use crate::{Pipeline, build_adapters};

/// Bound on the frame channel. A full channel drops the frame and counts it, so a slow consumer never stalls the venue readers.
pub const FRAME_CAPACITY: usize = 8_192;

/// What the local node runs.
pub struct EmbedConfig {
    /// The feeds, as in a node config.
    pub feeds: Vec<FeedSettings>,
    /// Venue endpoints in place of the built-in ones.
    pub endpoints: Vec<EndpointSettings>,
    /// How often every feed is evaluated with no new input, in milliseconds.
    pub tick_interval_ms: u64,
    /// Signs every frame. Its address is the node of [`local_registry`].
    pub signer: Arc<Signer>,
    /// Stamps the receipt and publish times. The node keeps it on wall time.
    pub clock: MonotonicClock,
    /// Sign a venue report for every feed.
    pub venue_reports: bool,
    /// The books to sign frames for.
    pub books: BookFrames,
    /// Sign the funding frames of every perpetual source.
    pub funding: bool,
}

/// The books whose frames the local node signs. Only a source that a feed with `impact_notional`
/// reads has a book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BookFrames {
    /// No book frames.
    None,
    /// The book of every source.
    All,
    /// The books of these feeds' sources, as the node's server serves a book subscription.
    Only(Vec<Symbol>),
}

/// One signed frame of the local node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignedFrame {
    /// A price update.
    Price(SignedUpdate),
    /// A venue report.
    Venues(SignedVenueReport),
    /// A book snapshot or delta.
    Book(SignedBookUpdate),
    /// A funding update.
    Funding(SignedFundingUpdate),
}

impl SignedFrame {
    /// The wire frame that `OracleClient::ingest_event` takes. The payload is encoded at signing, so this only joins the parts.
    #[must_use]
    pub fn encode_frame(&self) -> Vec<u8> {
        match self {
            Self::Price(update) => update.encode_frame().to_vec(),
            Self::Venues(report) => report.encode_frame(),
            Self::Book(update) => update.encode_frame(),
            Self::Funding(update) => update.encode_frame(),
        }
    }
}

/// Why the local node or its registry could not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EmbedError {
    /// The caller is not inside a tokio runtime.
    #[error("the local node starts only inside a tokio runtime")]
    NoRuntime,
    /// The feeds or the endpoints do not resolve.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The aggregator refused the feeds.
    #[error(transparent)]
    Aggregator(#[from] oracle_agg::ConfigError),
    /// A venue adapter refused its instruments.
    #[error(transparent)]
    Ingest(#[from] IngestError),
    /// A venue connector could not build its REST client.
    #[error(transparent)]
    Connector(anyhow::Error),
    /// The local registry could not be signed.
    #[error(transparent)]
    Registry(#[from] WireError),
    /// The local registry did not verify.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// [`BookFrames::Only`] names a feed that the node does not run.
    #[error("the book frames name {0}, which is not a feed of the node")]
    UnknownBookFeed(Symbol),
}

/// Signs and verifies a registry that lists `node` alone, at quorum 1. `version` starts at 1.
///
/// `governance` is a local key: it ties the frames to this one node, and to
/// nothing on the network. The entry has no endpoint, so the SDK dials nothing.
///
/// # Errors
///
/// Returns [`EmbedError::Registry`] or [`EmbedError::Verify`], for example for a `version` of 0.
pub fn local_registry(
    node: Address,
    governance: &Signer,
    version: u64,
    effective_from: u64,
) -> Result<VerifiedRegistry, EmbedError> {
    let entry = NodeEntry {
        address: node,
        endpoints: Vec::new(),
        weight: 1,
    };
    let quorum = Quorum {
        min_nodes: 1,
        recommended: 1,
    };
    let registry = Registry::sign(governance, version, effective_from, vec![entry], quorum)?;
    Ok(registry.verify(governance.address(), 0)?)
}

/// One node in the caller's process. Drop it or call [`Self::stop`] to close its sockets.
pub struct LocalNode {
    ingest: Ingest,
    health: Health,
    tasks: Vec<JoinHandle<()>>,
    frames: Option<mpsc::Receiver<SignedFrame>>,
    #[cfg(feature = "local-unsigned")]
    local: Option<mpsc::Receiver<LocalFrame>>,
    dropped: Arc<AtomicU64>,
    shutdown: CancellationToken,
}

impl LocalNode {
    /// Starts the node on the current tokio runtime, with the real venue connectors.
    ///
    /// # Errors
    ///
    /// Returns [`EmbedError::NoRuntime`] outside a tokio runtime, and another
    /// [`EmbedError`] for feeds, endpoints or connectors that the node cannot run.
    pub fn start(config: EmbedConfig, shutdown: CancellationToken) -> Result<Self, EmbedError> {
        let resolved = resolve(&config)?;
        let connector = connectors(&resolved.binance).map_err(EmbedError::Connector)?;
        Self::signed(config, resolved, connector, shutdown)
    }

    /// Starts the node with `connector` in place of the venue sockets, for tests and replays.
    ///
    /// # Errors
    ///
    /// As [`Self::start`].
    pub fn start_with_connector<C: Connector + Clone + 'static>(
        config: EmbedConfig,
        connector: C,
        shutdown: CancellationToken,
    ) -> Result<Self, EmbedError> {
        let resolved = resolve(&config)?;
        Self::signed(config, resolved, connector, shutdown)
    }

    /// Starts the node as [`Self::start`] does, but it signs nothing: it gives each value to
    /// [`Self::take_local_frames`] with the address of `config.signer` as its author.
    ///
    /// The values, their order and their contents are those that [`Self::start`] signs. For an
    /// app whose SDK runs in this process; `OracleClient::ingest_local` takes each value.
    ///
    /// # Errors
    ///
    /// As [`Self::start`].
    #[cfg(feature = "local-unsigned")]
    pub fn start_unsigned(
        config: EmbedConfig,
        shutdown: CancellationToken,
    ) -> Result<Self, EmbedError> {
        let resolved = resolve(&config)?;
        let connector = connectors(&resolved.binance).map_err(EmbedError::Connector)?;
        Self::unsigned(config, resolved, connector, shutdown)
    }

    /// [`Self::start_unsigned`] with `connector` in place of the venue sockets, for tests.
    ///
    /// # Errors
    ///
    /// As [`Self::start`].
    #[cfg(feature = "local-unsigned")]
    pub fn start_unsigned_with_connector<C: Connector + Clone + 'static>(
        config: EmbedConfig,
        connector: C,
        shutdown: CancellationToken,
    ) -> Result<Self, EmbedError> {
        let resolved = resolve(&config)?;
        Self::unsigned(config, resolved, connector, shutdown)
    }

    fn signed<C: Connector + Clone + 'static>(
        config: EmbedConfig,
        resolved: ResolvedConfig,
        connector: C,
        shutdown: CancellationToken,
    ) -> Result<Self, EmbedError> {
        let (sender, frames) = mpsc::channel(FRAME_CAPACITY);
        let outlet = ChannelOutlet::new(sender, &config);
        let dropped = Arc::clone(&outlet.dropped);
        let mut node = Self::launch(
            config,
            resolved,
            connector,
            Signing(outlet),
            dropped,
            shutdown,
        )?;
        node.frames = Some(frames);
        Ok(node)
    }

    #[cfg(feature = "local-unsigned")]
    fn unsigned<C: Connector + Clone + 'static>(
        config: EmbedConfig,
        resolved: ResolvedConfig,
        connector: C,
        shutdown: CancellationToken,
    ) -> Result<Self, EmbedError> {
        let (sender, frames) = mpsc::channel(FRAME_CAPACITY);
        let outlet = LocalOutlet {
            outlet: ChannelOutlet::new(sender, &config),
            author: config.signer.address(),
        };
        let dropped = Arc::clone(&outlet.outlet.dropped);
        let mut node = Self::launch(config, resolved, connector, outlet, dropped, shutdown)?;
        node.local = Some(frames);
        Ok(node)
    }

    fn launch<C: Connector + Clone + 'static, S: Sink + 'static>(
        config: EmbedConfig,
        resolved: ResolvedConfig,
        connector: C,
        sink: S,
        dropped: Arc<AtomicU64>,
        shutdown: CancellationToken,
    ) -> Result<Self, EmbedError> {
        tokio::runtime::Handle::try_current().map_err(|_| EmbedError::NoRuntime)?;
        // Sequence numbers must never go backwards for this node, including across
        // restarts. Milliseconds since the epoch outrun any publish counter.
        let seq_floor = wall_clock_unix_nanos() / 1_000_000;
        let pipeline = pipeline(resolved.feeds, &config.books, config.signer, seq_floor)?;
        let adapters = build_adapters(
            resolved.binance,
            resolved.venues,
            connector,
            config.clock.clone(),
        )?;

        // A child, so that `stop` does not cancel the caller's other work.
        let shutdown = shutdown.child_token();
        let clock_sync = tokio::spawn(sync_clock(config.clock.clone(), shutdown.clone()));
        let (events, queue) = mpsc::channel::<IngestEvent>(INGEST_CAPACITY);
        let mut ingest = Ingest::new(events, config.clock.clone(), shutdown.clone());
        ingest.start(adapters);
        let health = ingest.health();
        let pipeline = tokio::spawn(drive(
            pipeline,
            queue,
            resolved.tick_interval,
            config.clock,
            sink,
            shutdown.clone(),
        ));
        Ok(Self {
            ingest,
            health,
            tasks: vec![pipeline, clock_sync],
            frames: None,
            #[cfg(feature = "local-unsigned")]
            local: None,
            dropped,
            shutdown,
        })
    }

    /// The signed frames, in the order the node signed them. `None` after the first call.
    pub fn take_frames(&mut self) -> Option<mpsc::Receiver<SignedFrame>> {
        self.frames.take()
    }

    /// The values of [`Self::start_unsigned`], in the order the node made them. `None` after the
    /// first call, and for a node that signs.
    #[cfg(feature = "local-unsigned")]
    pub fn take_local_frames(&mut self) -> Option<mpsc::Receiver<LocalFrame>> {
        self.local.take()
    }

    /// The counters of each venue connection.
    #[must_use]
    pub fn health(&self) -> Vec<VenueHealth> {
        self.health
            .lock()
            .map(|health| health.clone())
            .unwrap_or_default()
    }

    /// The frames that a full channel dropped.
    #[must_use]
    pub fn dropped_frames(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Stops the node, and waits for its tasks and for each venue to close its sockets.
    pub async fn stop(mut self) {
        self.shutdown.cancel();
        for task in std::mem::take(&mut self.tasks) {
            let _ = task.await;
        }
        self.ingest.stop_all().await;
    }
}

impl Drop for LocalNode {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

fn resolve(config: &EmbedConfig) -> Result<ResolvedConfig, ConfigError> {
    resolve_feeds(&config.feeds, &config.endpoints, config.tick_interval_ms)
}

/// The pipeline of both modes, with every sequence from `seq_floor`.
fn pipeline(
    feeds: Vec<FeedConfig>,
    books: &BookFrames,
    signer: Arc<Signer>,
    seq_floor: u64,
) -> Result<Pipeline, EmbedError> {
    let books = books_only(books, &feeds)?;
    let aggregator = oracle_agg::Aggregator::new(feeds)?.with_sequence_floor(seq_floor);
    let mut pipeline = Pipeline::new(aggregator, signer).with_stream_sequence_floor(seq_floor);
    if let Some(books) = books {
        pipeline = pipeline.with_books_only(books);
    }
    Ok(pipeline)
}

/// The books that get frames, or `None` for every book.
fn books_only(
    books: &BookFrames,
    feeds: &[FeedConfig],
) -> Result<Option<HashSet<InstrumentId>>, EmbedError> {
    let names = match books {
        BookFrames::All => return Ok(None),
        BookFrames::None => return Ok(Some(HashSet::new())),
        BookFrames::Only(names) => names,
    };
    let mut only = HashSet::new();
    for name in names {
        let feed = feeds
            .iter()
            .find(|feed| feed.symbol == *name)
            .ok_or(EmbedError::UnknownBookFeed(*name))?;
        only.extend(feed.sources.iter().map(|source| source.instrument.clone()));
    }
    Ok(Some(only))
}

/// The frame channel and the kinds that the config asks for. Its [`Outlet`] signs them, on the
/// cadence of the node binary.
struct ChannelOutlet<F> {
    frames: mpsc::Sender<F>,
    dropped: Arc<AtomicU64>,
    venue_reports: bool,
    funding: bool,
}

impl<F> ChannelOutlet<F> {
    fn new(frames: mpsc::Sender<F>, config: &EmbedConfig) -> Self {
        Self {
            frames,
            dropped: Arc::new(AtomicU64::new(0)),
            venue_reports: config.venue_reports,
            funding: config.funding,
        }
    }

    fn send(&self, frame: F) {
        // A closed channel is a caller that stopped reading. The node runs on until `stop`.
        if let Err(mpsc::error::TrySendError::Full(_)) = self.frames.try_send(frame) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Outlet for ChannelOutlet<SignedFrame> {
    type Extra = Infallible;

    fn extra(&mut self) -> impl Future<Output = Infallible> + Send {
        std::future::pending()
    }

    fn on_extra(&mut self, extra: Infallible, _: &mut Pipeline) {
        match extra {}
    }

    fn observed(&mut self, _: &IngestEvent) {}

    fn publish(
        &mut self,
        _: &Pipeline,
        (signed, errors): (Vec<SignedUpdate>, Vec<AggError>),
        _: Option<&MonotonicClock>,
    ) {
        for error in errors {
            warn!(%error, "feed could not be encoded");
        }
        for update in signed {
            self.send(SignedFrame::Price(update));
        }
    }

    fn publish_venues(&mut self, pipeline: &mut Pipeline, now_ns: u64) {
        if self.venue_reports {
            let (reports, errors) = pipeline.venue_reports(now_ns, |_| true);
            for error in errors {
                warn!(%error, "venue report could not be encoded");
            }
            for report in reports {
                self.send(SignedFrame::Venues(report));
            }
        }
        // The pipeline holds only the books of `EmbedConfig::books`, so each one is wanted.
        let (books, errors) = pipeline.book_updates(now_ns, |_| true);
        for error in errors {
            warn!(%error, "book update could not be encoded");
        }
        for update in books {
            self.send(SignedFrame::Book(update));
        }
        if self.funding {
            let (funding, errors) = pipeline.funding_updates(now_ns);
            for error in errors {
                warn!(%error, "funding update could not be encoded");
            }
            for update in funding {
                self.send(SignedFrame::Funding(update));
            }
        }
    }

    fn stepped(&mut self) {}
}

/// The kinds of [`ChannelOutlet`] on the same cadence, with no signature.
#[cfg(feature = "local-unsigned")]
struct LocalOutlet {
    outlet: ChannelOutlet<LocalFrame>,
    author: Address,
}

#[cfg(feature = "local-unsigned")]
impl Sink for LocalOutlet {
    type Extra = Infallible;

    fn extra(&mut self) -> impl Future<Output = Infallible> + Send {
        std::future::pending()
    }

    fn on_extra(&mut self, extra: Infallible, _: &mut Pipeline) {
        match extra {}
    }

    fn observed(&mut self, _: &IngestEvent) {}

    // The steps and the clock reads of `Signing::evaluate` with `ChannelOutlet`, in the same
    // order, so that both modes give the same values.
    fn evaluate(&mut self, pipeline: &mut Pipeline, clock: &MonotonicClock, timed: bool) {
        let (prices, errors) = if timed {
            pipeline.flush_unsigned(clock.now_ns())
        } else {
            pipeline.tick_unsigned(clock.now_ns())
        };
        for error in errors {
            warn!(%error, "feed could not be encoded");
        }
        let author = self.author;
        for update in prices {
            self.outlet
                .send(LocalFrame::Price(Recovered::local(update, author)));
        }
        let now_ns = clock.now_ns();
        if self.outlet.venue_reports {
            let (reports, errors) = pipeline.venue_reports_unsigned(now_ns, |_| true);
            for error in errors {
                warn!(%error, "venue report could not be encoded");
            }
            for report in reports {
                self.outlet
                    .send(LocalFrame::Venues(Recovered::local(report, author)));
            }
        }
        let (books, errors) = pipeline.book_updates_unsigned(now_ns, |_| true);
        for error in errors {
            warn!(%error, "book update could not be encoded");
        }
        for update in books {
            self.outlet
                .send(LocalFrame::Book(Recovered::local(update, author)));
        }
        if self.outlet.funding {
            let (funding, errors) = pipeline.funding_updates_unsigned(now_ns);
            for error in errors {
                warn!(%error, "funding update could not be encoded");
            }
            for update in funding {
                self.outlet
                    .send(LocalFrame::Funding(Recovered::local(update, author)));
            }
        }
    }

    fn stepped(&mut self) {}
}

#[cfg(all(test, feature = "local-unsigned"))]
mod tests {
    use std::sync::atomic::AtomicU64;

    use oracle_ingest::StreamId;
    use oracle_types::{
        BookDepth, Fixed, FundingBasis, FundingInfo, Level, MarketKind, ObsKind, Observation, Venue,
    };
    use oracle_wire::{
        UnverifiedBookFrame, UnverifiedFrame, UnverifiedFundingFrame, UnverifiedVenueFrame,
    };

    use super::*;
    use crate::PipelineStats;

    const MS: u64 = 1_000_000;
    const START: u64 = 1_754_582_400_000 * MS;
    /// One floor for both modes. A started node takes it from the wall clock.
    const FLOOR: u64 = START / MS;
    const STEPS: u64 = 48;
    /// The steps of the script, 250 ms apart: the spot connection drops at the first and comes
    /// back at the second.
    const DROP: u64 = 20;
    const BACK: u64 = 23;

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("a decimal")
    }

    fn spot() -> InstrumentId {
        InstrumentId::new(Venue::Bybit, MarketKind::Spot, "BTCUSDT")
    }

    fn perp() -> InstrumentId {
        InstrumentId::new(Venue::Bybit, MarketKind::LinearPerp, "BTCUSDT")
    }

    fn config(clock: MonotonicClock) -> EmbedConfig {
        let feeds = serde_json::json!([
            { "symbol": "CRYPTO.BTC/USDT", "min_sources": 1, "impact_notional": "1000",
              "sources": [{ "venue": "bybit", "market": "spot", "symbol": "BTCUSDT" }] },
            { "symbol": "CRYPTO.BTC/USDT.FUNDING_8H", "min_sources": 1,
              "sources": [{ "venue": "bybit", "market": "linear_perp", "symbol": "BTCUSDT",
                            "kinds": ["funding"] }] },
        ]);
        EmbedConfig {
            feeds: serde_json::from_value(feeds).expect("two feeds"),
            endpoints: Vec::new(),
            tick_interval_ms: 1_000,
            signer: Arc::new(Signer::from_secret(&[0x51; 32].into()).expect("a key")),
            clock,
            venue_reports: true,
            books: BookFrames::All,
            funding: true,
        }
    }

    fn observation(instrument: InstrumentId, kind: ObsKind, price: &str, at: u64) -> Observation {
        Observation {
            instrument,
            kind,
            price: fixed(price),
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            depth_notional_1bp: None,
            exchange_time_ns: None,
            local_recv_ns: at,
            seq: None,
            book: None,
            funding: None,
        }
    }

    /// The spot top of book and its depth, with the bid `ticks` tenths above 64,000.
    fn book(ticks: u64, at: u64) -> [IngestEvent; 2] {
        let bid = format!("64000.{ticks}");
        let ask = format!("64001.{ticks}");
        let mid = format!("64000.{ticks}5");
        let level = |price: &str| Level {
            price: fixed(price),
            qty: Fixed::ONE,
        };
        let top = Observation {
            bid: Some(fixed(&bid)),
            ask: Some(fixed(&ask)),
            bid_qty: Some(Fixed::ONE),
            ask_qty: Some(Fixed::ONE),
            ..observation(spot(), ObsKind::BookTop, &mid, at)
        };
        let depth = Observation {
            book: Some(Arc::new(BookDepth {
                bids: vec![level(&bid)],
                asks: vec![level(&ask)],
            })),
            ..observation(spot(), ObsKind::Depth, &mid, at)
        };
        [top, depth].map(IngestEvent::observation)
    }

    fn funding(rate: &str, at: u64) -> IngestEvent {
        let info = FundingInfo {
            interval_ns: Some(8 * 3_600 * 1_000 * MS),
            next_funding_time_ns: Some(START + 3_600 * 1_000 * MS),
            ..FundingInfo::new(FundingBasis::Interval)
        };
        IngestEvent::observation(Observation {
            funding: Some(Arc::new(info)),
            ..observation(perp(), ObsKind::Funding, rate, at)
        })
    }

    fn connected(market: MarketKind) -> IngestEvent {
        IngestEvent::Connected {
            stream: StreamId::new(Venue::Bybit, market),
        }
    }

    /// Runs the script through `sink` as the loop does: each step observes its events, then
    /// evaluates; every fourth step also ticks.
    fn run<S: Sink>(mut sink: S, config: &EmbedConfig, now: &AtomicU64) -> PipelineStats {
        let resolved = resolve(config).expect("the feeds resolve");
        let mut pipeline = pipeline(
            resolved.feeds,
            &config.books,
            Arc::clone(&config.signer),
            FLOOR,
        )
        .expect("a pipeline");
        for step in 0..STEPS {
            let at = START + step * 250 * MS;
            now.store(at, Ordering::Release);
            let mut events = Vec::new();
            if step == 0 {
                events.extend([
                    connected(MarketKind::Spot),
                    connected(MarketKind::LinearPerp),
                ]);
            }
            match step {
                DROP => events.push(IngestEvent::Disconnected {
                    stream: StreamId::new(Venue::Bybit, MarketKind::Spot),
                    reason: "reset".to_owned(),
                    sources: Arc::from([(spot(), ObsKind::BookTop), (spot(), ObsKind::Depth)]),
                }),
                BACK => events.push(connected(MarketKind::Spot)),
                _ => {}
            }
            if !(DROP..BACK).contains(&step) {
                events.extend(book(step % 7, at));
            }
            if step % 4 == 0 {
                let rate = if step % 16 < 8 { "0.0001" } else { "0.00015" };
                events.push(funding(rate, at));
            }
            for event in &events {
                sink.observed(event);
                pipeline.observe(event);
            }
            sink.evaluate(&mut pipeline, &config.clock, true);
            if step % 4 == 3 {
                sink.evaluate(&mut pipeline, &config.clock, false);
            }
            sink.stepped();
        }
        pipeline.stats()
    }

    fn drain<T>(frames: &mut mpsc::Receiver<T>) -> Vec<T> {
        std::iter::from_fn(|| frames.try_recv().ok()).collect()
    }

    /// What the SDK recovers from the wire bytes of a signed frame.
    fn recovered(frame: &SignedFrame) -> LocalFrame {
        let bytes = frame.encode_frame();
        match frame {
            SignedFrame::Price(_) => LocalFrame::Price(
                UnverifiedFrame::parse(&bytes)
                    .map_err(VerifyError::from)
                    .and_then(|frame| frame.recover())
                    .expect("recovers"),
            ),
            SignedFrame::Venues(_) => LocalFrame::Venues(
                UnverifiedVenueFrame::parse(&bytes)
                    .map_err(VerifyError::from)
                    .and_then(|frame| frame.recover())
                    .expect("recovers"),
            ),
            SignedFrame::Book(_) => LocalFrame::Book(
                UnverifiedBookFrame::parse(&bytes)
                    .map_err(VerifyError::from)
                    .and_then(|frame| frame.recover())
                    .expect("recovers"),
            ),
            SignedFrame::Funding(_) => LocalFrame::Funding(
                UnverifiedFundingFrame::parse(&bytes)
                    .map_err(VerifyError::from)
                    .and_then(|frame| frame.recover())
                    .expect("recovers"),
            ),
        }
    }

    #[test]
    fn the_unsigned_mode_gives_each_value_that_the_signed_mode_signs_in_the_same_order() {
        let now = Arc::new(AtomicU64::new(START));
        let config = config(MonotonicClock::driven(Arc::clone(&now)));
        let (signed_sender, mut signed) = mpsc::channel(FRAME_CAPACITY);
        let (local_sender, mut local) = mpsc::channel(FRAME_CAPACITY);
        let signed_stats = run(
            Signing(ChannelOutlet::new(signed_sender, &config)),
            &config,
            &now,
        );
        let local_stats = run(
            LocalOutlet {
                outlet: ChannelOutlet::new(local_sender, &config),
                author: config.signer.address(),
            },
            &config,
            &now,
        );
        assert_eq!(local_stats, signed_stats);

        let signed: Vec<LocalFrame> = drain(&mut signed).iter().map(recovered).collect();
        let local = drain(&mut local);
        assert_eq!(local, signed);
        let count =
            |kind: fn(&LocalFrame) -> bool| local.iter().filter(|frame| kind(frame)).count();
        let prices = count(|frame| matches!(frame, LocalFrame::Price(_)));
        let venues = count(|frame| matches!(frame, LocalFrame::Venues(_)));
        let books = count(|frame| matches!(frame, LocalFrame::Book(_)));
        let funding = count(|frame| matches!(frame, LocalFrame::Funding(_)));
        assert!(
            prices > 0 && venues > 0 && books > 0 && funding > 0,
            "prices {prices}, venue reports {venues}, books {books}, funding {funding}"
        );
        let author = config.signer.address();
        assert!(local.iter().all(|frame| match frame {
            LocalFrame::Price(value) => value.signer() == author,
            LocalFrame::Venues(value) => value.signer() == author,
            LocalFrame::Book(value) => value.signer() == author,
            LocalFrame::Funding(value) => value.signer() == author,
        }));
    }
}
