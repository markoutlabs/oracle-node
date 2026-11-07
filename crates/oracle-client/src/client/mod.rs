//! The async multi-node client.
//!
//! Deliberately thin. Everything that decides whether a price is trustworthy
//! lives in [`crate::verify`] and [`crate::quorum`], which are pure and
//! synchronous; this layer only moves bytes and calls them.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use oracle_types::{FeedId, InstrumentId, Symbol};
use oracle_wire::{
    Address, Registry, Signer, VerifiedFeedSet, VerifiedRegistry, VerifyError, feed_id,
};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::book::Book;
use crate::latency::{Latency, LatencyReport};
use crate::nodes::{Links, NodeFeed, NodeReport, Tally};
use crate::quorum::{FeedView, NodeFeedState, QuorumConfig, Resolved};
use crate::source::{FetchError, HttpRegistrySource, RegistrySource};
use crate::tap::{FrameKind, Tap, TappedFrame};
use crate::verify::{
    AcceptedBook, AcceptedFunding, AcceptedVenues, RejectReason, Verifier, VerifyConfig,
};

use connection::{IDLE_TIMEOUT, NodeConnection};
use ingest::RecoveredFrame;
use selection::Choice;

mod connection;
mod ingest;
mod registry;
mod selection;

/// The quorum below which the builder demands an explicit acknowledgement.
const SAFE_QUORUM: usize = 3;

/// Default floor between two registry fetches triggered by unknown signers.
///
/// Anyone who can inject a frame can trigger a fetch, so the floor is what
/// stops a hostile relay from turning the client into a load generator
/// against the registry.
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// Default time without a freshness confirmation before feeds are reported
/// degraded.
///
/// Each certified fetch confirms the registry (SPEC §3.6). This long without
/// one means the fetch path is broken or newer versions are being withheld.
const DEFAULT_MAX_REGISTRY_AGE: Duration = Duration::from_secs(48 * 3_600);

/// Bounds how long a de-listed node keeps its seat.
const DEFAULT_REGISTRY_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// What [`OracleClient::next_event`] yields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A price, resolved across the nodes.
    Price(Resolved),
    /// One node's verified venue report. Not resolved across nodes: each node
    /// reports what it saw.
    Venues(AcceptedVenues),
    /// One node's verified book frame, already applied. Read the book with
    /// [`OracleClient::book`].
    Book(AcceptedBook),
    /// One node's verified funding frame. Each frame carries the whole state;
    /// [`OracleClient::funding`] reads the one nearest the median of the nodes.
    Funding(AcceptedFunding),
}

/// A client construction or connection failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// A quorum below three was requested without acknowledgement.
    ///
    /// Verifying signatures from one node confirms who is talking and nothing
    /// about whether to believe them: a single compromised node is a single
    /// compromised price. This is the mistake most likely to be made during
    /// integration and then never revisited, so the API makes it loud.
    #[error(
        "a quorum of {requested} provides no protection against a bad node; \
         use at least {SAFE_QUORUM}, or call \
         `i_understand_this_provides_no_protection_against_a_bad_node()`"
    )]
    UnsafeQuorum {
        /// What was asked for.
        requested: usize,
    },

    /// The registry lists fewer nodes than the requested quorum.
    #[error("quorum of {requested} is unreachable: the registry lists {available} nodes")]
    UnreachableQuorum {
        /// What was asked for.
        requested: usize,
        /// What the registry offers.
        available: usize,
    },

    /// A symbol did not parse.
    #[error("invalid symbol `{0}`")]
    InvalidSymbol(String),

    /// No node endpoints could be reached.
    #[error("no node endpoints available")]
    NoEndpoints,

    /// Nodes serve only listed clients; set one with `client_key`.
    #[error("no client key: nodes serve only listed clients (SPEC §6.1)")]
    NoClientKey,

    /// A connection failed.
    #[error("connection to {endpoint} failed: {reason}")]
    Connect {
        /// Which endpoint.
        endpoint: String,
        /// Why.
        reason: String,
    },

    /// A replacement registry did not verify against the pinned governance key.
    #[error("cannot adopt this registry: {0}")]
    Registry(#[from] VerifyError),

    /// A feed set is not signed by the governance of the registry.
    #[error("cannot adopt this feed set: {0}")]
    FeedSet(VerifyError),

    /// The registry source could not deliver a document.
    #[error(transparent)]
    Fetch(#[from] FetchError),
}

/// Builds an [`OracleClient`].
pub struct OracleClientBuilder {
    registry: VerifiedRegistry,
    quorum: usize,
    quorum_acknowledged: bool,
    verify: VerifyConfig,
    quorum_config: QuorumConfig,
    channel_capacity: usize,
    source: Option<Arc<dyn RegistrySource>>,
    refresh_interval: Duration,
    poll_interval: Duration,
    max_registry_age: Duration,
    client_key: Option<Arc<Signer>>,
    idle_timeout: Duration,
    feed_set: Option<VerifiedFeedSet>,
}

impl OracleClientBuilder {
    /// Authenticates to nodes (SPEC §6.1) with the client's secp256k1 API key.
    /// Governance must list the key's address in the client list. Needed for
    /// [`OracleClient::subscribe`].
    #[must_use]
    pub fn client_key(mut self, key: Signer) -> Self {
        self.client_key = Some(Arc::new(key));
        self
    }

    /// Starts with this governance-signed feed set, as [`OracleClient::set_feed_set`] adopts one.
    #[must_use]
    pub fn feed_set(mut self, set: VerifiedFeedSet) -> Self {
        self.feed_set = Some(set);
        self
    }

    /// Sets where newer registry versions are fetched from.
    ///
    /// Without a source the client stays on the registry it was built with
    /// until [`OracleClient::refresh_registry`] is called by hand, and a node
    /// that rotates its key is lost until then.
    #[must_use]
    pub fn registry_source(mut self, source: Arc<dyn RegistrySource>) -> Self {
        self.source = Some(source);
        self
    }

    /// Sets the floor between two fetches triggered by unknown signers.
    #[must_use]
    pub const fn refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval;
        self
    }

    /// Sets the longest time between two scheduled registry fetches.
    #[must_use]
    pub const fn registry_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Reconnects to a node that sends nothing for this long; 30 s by default.
    /// The client pings each node three times in that time, and the node
    /// answers each ping, so only a dead connection stays quiet.
    #[must_use]
    pub const fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Sets how long the source may go without confirming the registry before
    /// feeds are reported degraded.
    #[must_use]
    pub const fn max_registry_age(mut self, age: Duration) -> Self {
        self.max_registry_age = age;
        self
    }

    /// Sets the number of distinct nodes required.
    #[must_use]
    pub const fn quorum(mut self, nodes: usize) -> Self {
        self.quorum = nodes;
        self
    }

    /// Acknowledges that a quorum below three offers no protection against a bad node.
    ///
    /// Intended for local development against a single node. Using it in
    /// production means trusting one machine's honesty completely.
    #[must_use]
    pub const fn i_understand_this_provides_no_protection_against_a_bad_node(mut self) -> Self {
        self.quorum_acknowledged = true;
        self
    }

    /// Sets how old a price update may be before it is refused. The default is
    /// 2 s, two of the nodes' 1 s heartbeats. Books use it too.
    #[must_use]
    pub const fn max_age(mut self, max_age: Duration) -> Self {
        self.verify.max_age = max_age;
        self.quorum_config.max_age = max_age;
        self
    }

    /// Sets the same limit for a slow feed (funding, open interest). The
    /// default is 25 s: nodes publish these feeds on a 10 s heartbeat.
    #[must_use]
    pub const fn slow_max_age(mut self, max_age: Duration) -> Self {
        self.verify.slow_max_age = max_age;
        self.quorum_config.slow_max_age = max_age;
        self
    }

    /// Sets the tolerance for a node's clock running ahead of ours.
    #[must_use]
    pub const fn max_skew(mut self, max_skew: Duration) -> Self {
        self.verify.max_skew = max_skew;
        self
    }

    /// Sets the inter-node spread above which a feed is reported degraded.
    #[must_use]
    pub const fn max_divergence_bps(mut self, bps: oracle_types::Fixed) -> Self {
        self.quorum_config.max_divergence_bps = bps;
        self
    }

    /// Sets the capacity of the resolved-price channel.
    #[must_use]
    pub const fn channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = capacity;
        self
    }

    /// Builds the client.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnsafeQuorum`] for a quorum below three without an
    /// explicit acknowledgement, or [`ClientError::UnreachableQuorum`] if the
    /// registry lists fewer nodes than required.
    pub fn build(mut self) -> Result<OracleClient, ClientError> {
        if self.quorum < SAFE_QUORUM && !self.quorum_acknowledged {
            return Err(ClientError::UnsafeQuorum {
                requested: self.quorum,
            });
        }
        let available = self.registry.nodes().len();
        if self.quorum > available {
            return Err(ClientError::UnreachableQuorum {
                requested: self.quorum,
                available,
            });
        }
        self.quorum_config.quorum = self.quorum;

        let (tx, rx) = mpsc::channel(self.channel_capacity);
        let mut client = OracleClient {
            verifier: Verifier::new(self.registry.clone(), self.verify),
            registry: self.registry,
            quorum_config: self.quorum_config,
            views: HashMap::new(),
            symbols: HashMap::new(),
            venue_symbols: HashMap::new(),
            book_symbols: HashMap::new(),
            books: HashMap::new(),
            book_nodes: HashMap::new(),
            funding_nodes: HashMap::new(),
            funding_symbols: HashMap::new(),
            all_funding: false,
            funding: HashMap::new(),
            inbound_tx: tx,
            inbound_rx: rx,
            shutdown: CancellationToken::new(),
            stats: ClientStats::default(),
            latency: Latency::default(),
            links: Links::default(),
            tallies: HashMap::new(),
            source: self.source,
            refresh_interval: self.refresh_interval,
            poll_interval: self.poll_interval,
            max_registry_age: self.max_registry_age,
            confirmed_ns: now_unix_nanos(),
            last_refresh_attempt_ns: None,
            subscription: None,
            runtime: None,
            connections: HashMap::new(),
            polling: false,
            client_key: self.client_key,
            idle_timeout: self.idle_timeout,
            tap: Tap::default(),
            feed_set_version: None,
        };
        if let Some(set) = &self.feed_set {
            client.set_feed_set(set)?;
        }
        Ok(client)
    }
}

/// Counters describing what the client has seen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientStats {
    /// Price frames accepted.
    pub accepted: u64,
    /// Venue report frames accepted.
    pub venue_reports: u64,
    /// Book frames accepted.
    pub book_updates: u64,
    /// Funding frames accepted.
    pub funding_updates: u64,
    /// Frames refused because they were not signed by a registered node.
    pub untrusted: u64,
    /// Frames refused as replays.
    pub replayed: u64,
    /// Frames refused as stale or future-dated.
    pub out_of_time: u64,
    /// Frames refused for incoherent timestamps.
    pub incoherent: u64,
    /// Frames refused because their key has been retired.
    pub retired: u64,
    /// Registry fetches made outside the schedule: unknown signers and manual calls.
    pub refreshes: u64,
    /// Scheduled registry fetches.
    pub polls: u64,
    /// Registry fetches that failed or did not verify.
    pub refresh_failures: u64,
    /// Frame copies that [`OracleClient::frames`] had no room for.
    pub tap_dropped: u64,
    /// Book and funding frames refused because the feed set does not list their instrument.
    pub unlisted: u64,
    /// Frames refused because their node already has the most feeds or books it may have.
    pub over_limit: u64,
}

impl ClientStats {
    fn record(&mut self, reason: &RejectReason) {
        match reason {
            RejectReason::Untrusted(_) => self.untrusted = self.untrusted.saturating_add(1),
            RejectReason::RetiredKey { .. } => self.retired = self.retired.saturating_add(1),
            RejectReason::Replayed { .. } => self.replayed = self.replayed.saturating_add(1),
            RejectReason::TooOld { .. } | RejectReason::FromTheFuture { .. } => {
                self.out_of_time = self.out_of_time.saturating_add(1);
            }
            RejectReason::IncoherentTimestamps { .. } => {
                self.incoherent = self.incoherent.saturating_add(1);
            }
            RejectReason::Unlisted { .. } => self.unlisted = self.unlisted.saturating_add(1),
            RejectReason::OverLimit { .. } => self.over_limit = self.over_limit.saturating_add(1),
            // Non-exhaustive outside oracle-quorum: a reason added there is not counted.
            _ => {}
        }
    }
}

enum Inbound {
    Frame {
        frame: Vec<u8>,
        /// Stamped as the message arrives, before decryption.
        received_ns: u64,
        /// Not trusted until the verifier finds the signer in its registry.
        recovered: Result<RecoveredFrame, VerifyError>,
    },
    Polled(Result<Registry, FetchError>),
    /// The result of a fetch that an unknown signer or a moved node started.
    Refreshed(Result<Registry, FetchError>),
    /// A node's endpoint now serves another address: the node probably
    /// rotated. The handshake twin of an unknown signer on a frame.
    NodeMoved {
        /// The address in the node's challenge.
        got: Address,
    },
}

/// Every topic list of one subscription, for [`OracleClient::subscribe_all`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Subscription<'a> {
    /// Feeds whose prices to resolve.
    pub prices: &'a [&'a str],
    /// Feeds whose venue reports to receive.
    pub venues: &'a [&'a str],
    /// Feeds whose sources' books to receive.
    pub books: &'a [&'a str],
    /// Feeds whose perpetual sources' funding to receive, or `"*"` for every
    /// perpetual.
    pub funding: &'a [&'a str],
}

/// Verifies signed updates from many nodes and resolves them into one price.
pub struct OracleClient {
    verifier: Verifier,
    registry: VerifiedRegistry,
    quorum_config: QuorumConfig,
    views: HashMap<FeedId, FeedView>,
    symbols: HashMap<FeedId, Symbol>,
    /// Feeds whose venue reports to request.
    venue_symbols: HashMap<FeedId, Symbol>,
    /// Feeds whose sources' books to request.
    book_symbols: HashMap<FeedId, Symbol>,
    /// One book per node and venue instrument.
    books: HashMap<(Address, InstrumentId), Book>,
    /// The node of the book that `book` last returned, per instrument.
    book_nodes: HashMap<InstrumentId, Choice>,
    /// The node of the frame that `funding` last returned, per perpetual.
    funding_nodes: HashMap<InstrumentId, Address>,
    /// Feeds whose perpetual sources' funding to request.
    funding_symbols: HashMap<FeedId, Symbol>,
    /// Request the funding of every perpetual.
    all_funding: bool,
    /// The latest funding frame of each node and perpetual.
    funding: HashMap<(Address, InstrumentId), AcceptedFunding>,
    inbound_tx: mpsc::Sender<Inbound>,
    inbound_rx: mpsc::Receiver<Inbound>,
    shutdown: CancellationToken,
    stats: ClientStats,
    latency: Latency,
    /// Each node's connection, written by its connection task.
    links: Links,
    /// Each node's frames, keyed by signer.
    tallies: HashMap<Address, Tally>,
    source: Option<Arc<dyn RegistrySource>>,
    refresh_interval: Duration,
    poll_interval: Duration,
    max_registry_age: Duration,
    /// When a source last proved the trusted registry current.
    confirmed_ns: u64,
    last_refresh_attempt_ns: Option<u64>,
    subscription: Option<String>,
    // Kept so that `refresh_registry` can open connections from any thread.
    runtime: Option<Handle>,
    connections: HashMap<Address, NodeConnection>,
    polling: bool,
    client_key: Option<Arc<Signer>>,
    idle_timeout: Duration,
    tap: Tap,
    /// The version of the feed set in use, if any.
    feed_set_version: Option<u64>,
}

impl OracleClient {
    /// Starts building a client against a pinned registry.
    #[must_use]
    pub fn builder(registry: VerifiedRegistry) -> OracleClientBuilder {
        OracleClientBuilder {
            registry,
            quorum: SAFE_QUORUM,
            quorum_acknowledged: false,
            verify: VerifyConfig::default(),
            quorum_config: QuorumConfig::default(),
            channel_capacity: 4_096,
            source: None,
            client_key: None,
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
            poll_interval: DEFAULT_REGISTRY_POLL_INTERVAL,
            max_registry_age: DEFAULT_MAX_REGISTRY_AGE,
            idle_timeout: IDLE_TIMEOUT,
            feed_set: None,
        }
    }

    /// Starts building a client against the mainnet registry, from the trust
    /// root this crate knows: the registry canister and the governance address.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Fetch`] if this build has no mainnet trust root or
    /// the registry cannot be fetched, or [`ClientError::Registry`] if the
    /// document is not signed by governance.
    pub async fn mainnet() -> Result<OracleClientBuilder, ClientError> {
        let missing =
            |what: &str| FetchError::Settings(format!("this build has no mainnet {what}"));
        let canister = crate::mainnet::CANISTER_ID.ok_or_else(|| missing("canister"))?;
        let governance: Address = crate::mainnet::GOVERNANCE_ADDRESS
            .ok_or_else(|| missing("governance address"))?
            .parse()
            .map_err(|error| FetchError::Settings(format!("governance address: {error}")))?;
        let source = Arc::new(HttpRegistrySource::canister(canister)?);
        Self::builder_from_source(source, governance).await
    }

    /// Fetches the registry from `source`, verifies it against `governance`,
    /// and starts building a client that keeps refreshing from that source.
    ///
    /// `governance` is the pinned trust root. It comes from the operator's
    /// documentation, never from the document being fetched.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Fetch`] if the source fails, or
    /// [`ClientError::Registry`] if the document is not signed by `governance`.
    pub async fn builder_from_source(
        source: Arc<dyn RegistrySource>,
        governance: Address,
    ) -> Result<OracleClientBuilder, ClientError> {
        let registry = source.fetch().await?;
        let verified = registry.verify(governance, 0)?;
        Ok(Self::builder(verified).registry_source(source))
    }

    /// Returns the counters.
    #[must_use]
    pub const fn stats(&self) -> ClientStats {
        self.stats
    }

    /// Returns the latency of the updates accepted since the start, or since
    /// [`Self::reset_latency`].
    #[must_use]
    pub fn latency(&self) -> LatencyReport {
        self.latency.report()
    }

    /// Starts the latency report again, for example after a warm-up.
    pub fn reset_latency(&mut self) {
        self.latency.reset();
    }

    /// Returns the registry version currently trusted.
    #[must_use]
    pub const fn registry_version(&self) -> u64 {
        self.registry.version()
    }

    /// Returns the governance-signed registry that the client verifies against.
    #[must_use]
    pub const fn registry(&self) -> &VerifiedRegistry {
        &self.registry
    }

    /// Opens a channel with a copy of each frame whose signature and registry
    /// check pass, accepted or not, for an archive. The client never waits on
    /// it: when it is full, a copy is dropped and counted in
    /// [`ClientStats::tap_dropped`]. A second call replaces the first channel.
    pub fn frames(&mut self, capacity: usize) -> mpsc::Receiver<TappedFrame> {
        self.tap.open(capacity, None)
    }

    /// Like [`OracleClient::frames`], but copies only the frames of `kinds`.
    /// [`ClientStats::tap_dropped`] then counts only those.
    pub fn frames_of(
        &mut self,
        capacity: usize,
        kinds: &[FrameKind],
    ) -> mpsc::Receiver<TappedFrame> {
        self.tap.open(capacity, Some(kinds.to_vec()))
    }

    /// Returns the quorum rules the client resolves with.
    #[must_use]
    pub const fn quorum_config(&self) -> QuorumConfig {
        self.quorum_config
    }

    /// Reports every node in the registry: its connection, its frames, and its
    /// latest update for each subscribed price feed against the median.
    ///
    /// For monitoring. The quorum, not this report, decides what a price is.
    #[must_use]
    pub fn nodes(&self, now_ns: u64) -> Vec<NodeReport> {
        let mut feeds: Vec<(&Symbol, Option<&FeedView>)> = self
            .symbols
            .iter()
            .map(|(id, symbol)| (symbol, self.views.get(id)))
            .collect();
        feeds.sort_by_key(|(symbol, _)| symbol.to_string());
        let medians: Vec<Option<_>> = feeds
            .iter()
            .map(|(_, view)| view.and_then(|view| view.resolve(&self.quorum_config, now_ns).price))
            .collect();

        self.registry
            .nodes()
            .iter()
            .map(|entry| {
                let link = self.links.get(&entry.address);
                let tally = self.tallies.get(&entry.address);
                NodeReport {
                    address: entry.address,
                    weight: entry.weight,
                    endpoints: entry.endpoints.clone(),
                    connection: link.state,
                    connects: link.connects,
                    failures: link.failures,
                    last_error: link.last_error,
                    last_frame_ns: tally.and_then(|tally| tally.last_frame_ns),
                    frames: tally.map(|tally| tally.frames).unwrap_or_default(),
                    delivery: tally.and_then(|tally| tally.delivery(now_ns)),
                    feeds: feeds
                        .iter()
                        .zip(&medians)
                        .map(|((symbol, view), median)| {
                            let update = view.and_then(|view| view.get(&entry.address));
                            let max_age = self.quorum_config.max_age_for(symbol.kind());
                            let state =
                                update.map(|update| NodeFeedState::of(update, max_age, now_ns));
                            NodeFeed::new(**symbol, update, state, *median)
                        })
                        .collect(),
                }
            })
            .collect()
    }

    /// The per-node view behind a feed, for monitoring which node says what.
    #[must_use]
    pub fn view(&self, symbol: &Symbol) -> Option<&FeedView> {
        self.views.get(&feed_id(symbol))
    }

    /// Resolves a feed's current state without waiting for a new frame.
    #[must_use]
    pub fn resolve(&self, symbol: &Symbol, now_ns: u64) -> Option<Resolved> {
        let id = feed_id(symbol);
        self.views.get(&id).map(|view| {
            let mut resolved = view.resolve(&self.quorum_config, now_ns);
            self.annotate(&mut resolved, now_ns);
            resolved
        })
    }

    /// Stops every node connection.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

impl Drop for OracleClient {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Reads the wall clock in unix nanoseconds.
///
/// What [`OracleClient::next`] stamps frames with. Public so a monitor can ask
/// the same clock for the registry age.
#[must_use]
pub fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod live;

#[cfg(test)]
mod tests;
