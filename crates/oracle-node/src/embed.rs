//! One node inside the caller's process: the venue readers, the aggregator and
//! the signer, with the signed frames on a channel in place of a server.
//!
//! It runs no server, fetches no registry or client list, pushes nothing to the
//! canister, and sets no logger, signal handler or file limit: the process is
//! the caller's. [`local_registry`] signs the one-node registry that the SDK
//! checks the frames against.
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

use crate::config::{ConfigError, EndpointSettings, FeedSettings, ResolvedConfig, resolve_feeds};
use crate::ingest::{Health, Ingest, connectors};
use crate::run::{INGEST_CAPACITY, Outlet, PipelineLoop, sync_clock};
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
        Self::launch(config, resolved, connector, shutdown)
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
        Self::launch(config, resolved, connector, shutdown)
    }

    fn launch<C: Connector + Clone + 'static>(
        config: EmbedConfig,
        resolved: ResolvedConfig,
        connector: C,
        shutdown: CancellationToken,
    ) -> Result<Self, EmbedError> {
        tokio::runtime::Handle::try_current().map_err(|_| EmbedError::NoRuntime)?;
        // Sequence numbers must never go backwards for this node, including across
        // restarts. Milliseconds since the epoch outrun any publish counter.
        let seq_floor = wall_clock_unix_nanos() / 1_000_000;
        let books = books_only(&config.books, &resolved.feeds)?;
        let aggregator =
            oracle_agg::Aggregator::new(resolved.feeds)?.with_sequence_floor(seq_floor);
        let mut pipeline =
            Pipeline::new(aggregator, config.signer).with_stream_sequence_floor(seq_floor);
        if let Some(books) = books {
            pipeline = pipeline.with_books_only(books);
        }
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
        let (sender, frames) = mpsc::channel(FRAME_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let outlet = ChannelOutlet {
            frames: sender,
            dropped: Arc::clone(&dropped),
            venue_reports: config.venue_reports,
            funding: config.funding,
        };
        let pipeline = tokio::spawn(
            PipelineLoop {
                pipeline,
                ingest: queue,
                tick: resolved.tick_interval,
                clock: config.clock,
                outlet,
                shutdown: shutdown.clone(),
            }
            .run(),
        );
        Ok(Self {
            ingest,
            health,
            tasks: vec![pipeline, clock_sync],
            frames: Some(frames),
            dropped,
            shutdown,
        })
    }

    /// The signed frames, in the order the node signed them. `None` after the first call.
    pub fn take_frames(&mut self) -> Option<mpsc::Receiver<SignedFrame>> {
        self.frames.take()
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

/// Signs the kinds that the config asks for, on the cadence of the node binary.
struct ChannelOutlet {
    frames: mpsc::Sender<SignedFrame>,
    dropped: Arc<AtomicU64>,
    venue_reports: bool,
    funding: bool,
}

impl ChannelOutlet {
    fn send(&self, frame: SignedFrame) {
        // A closed channel is a caller that stopped reading. The node runs on until `stop`.
        if let Err(mpsc::error::TrySendError::Full(_)) = self.frames.try_send(frame) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Outlet for ChannelOutlet {
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
