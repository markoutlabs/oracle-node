//! The async multi-node client.
//!
//! Deliberately thin. Everything that decides whether a price is trustworthy
//! lives in [`crate::verify`] and [`crate::quorum`], which are pure and
//! synchronous; this layer only moves bytes and calls them.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use backon::{BackoffBuilder, ConstantBuilder, ExponentialBuilder};
use futures_util::{SinkExt as _, StreamExt as _};
use oracle_transport::{
    ClientHandshake, ClientSession, Control, HandshakeMessage, KEY_GRACE_SECS, TYPE_CONTROL,
    TYPE_FRAME, TransportError, os_rng,
};
use oracle_types::{FeedId, InstrumentId, NANOS_PER_SEC, Symbol};
use oracle_wire::{
    Address, FRAME_TYPE_BOOK_UPDATE, FRAME_TYPE_VENUE_REPORT, Registry, Signer, VerifiedRegistry,
    VerifyError, feed_id,
};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::book::Book;
use crate::latency::{Latency, LatencyReport};
use crate::quorum::{Concern, FeedView, QuorumConfig, Resolved, Status};
use crate::source::{FetchError, RegistrySource};
use crate::verify::{AcceptedBook, AcceptedVenues, RejectReason, Verifier, VerifyConfig};

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

    /// Sets how old an update may be before it is refused.
    #[must_use]
    pub const fn max_age(mut self, max_age: Duration) -> Self {
        self.verify.max_age = max_age;
        self.quorum_config.max_age = max_age;
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
        Ok(OracleClient {
            verifier: Verifier::new(self.registry.clone(), self.verify),
            registry: self.registry,
            quorum_config: self.quorum_config,
            views: HashMap::new(),
            symbols: HashMap::new(),
            venue_symbols: HashMap::new(),
            book_symbols: HashMap::new(),
            books: HashMap::new(),
            inbound_tx: tx,
            inbound_rx: rx,
            shutdown: CancellationToken::new(),
            stats: ClientStats::default(),
            latency: Latency::default(),
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
        })
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
        }
    }
}

enum Inbound {
    Frame {
        frame: Vec<u8>,
        /// Stamped as the message arrives, before decryption.
        received_ns: u64,
    },
    Polled(Result<Registry, FetchError>),
    /// A node's endpoint now serves another address: the node probably
    /// rotated. The handshake twin of an unknown signer on a frame.
    NodeMoved {
        /// The address in the node's challenge.
        got: Address,
    },
}

struct NodeConnection {
    endpoint: String,
    cancel: CancellationToken,
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
    inbound_tx: mpsc::Sender<Inbound>,
    inbound_rx: mpsc::Receiver<Inbound>,
    shutdown: CancellationToken,
    stats: ClientStats,
    latency: Latency,
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
        }
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

    /// Returns how long ago a source last proved the trusted registry current,
    /// or how long ago the client was built if none has yet.
    #[must_use]
    pub fn registry_age(&self, now_ns: u64) -> Duration {
        Duration::from_nanos(now_ns.saturating_sub(self.confirmed_ns))
    }

    /// Returns `true` if the source has not confirmed the registry within
    /// `max_registry_age`. A registry with no source is pinned, never stale.
    #[must_use]
    pub fn registry_is_stale(&self, now_ns: u64) -> bool {
        self.source.is_some() && self.registry_age(now_ns) > self.max_registry_age
    }

    /// Fetches from the registry source and adopts the document if it is newer.
    ///
    /// Returns the adopted version, or `None` if the source served the version
    /// already trusted. Unlike the automatic path this is not rate-limited.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Fetch`] if the source fails, or the errors of
    /// [`OracleClient::refresh_registry`] if the document does not verify. With
    /// no source configured it returns `Ok(None)`.
    pub async fn refresh_from_source(&mut self) -> Result<Option<u64>, ClientError> {
        let Some(source) = self.source.clone() else {
            return Ok(None);
        };
        self.stats.refreshes = self.stats.refreshes.saturating_add(1);
        let fetched = source.fetch().await;
        self.adopt_fetched(fetched)
    }

    fn adopt_fetched(
        &mut self,
        fetched: Result<Registry, FetchError>,
    ) -> Result<Option<u64>, ClientError> {
        let current = self.registry.version();
        let outcome = fetched.map_err(ClientError::from).and_then(|registry| {
            match registry.version.cmp(&current) {
                // An older version is not proof that ours is current.
                std::cmp::Ordering::Less => Ok(None),
                std::cmp::Ordering::Equal => {
                    self.confirmed_ns = now_unix_nanos();
                    Ok(None)
                }
                std::cmp::Ordering::Greater => {
                    let version = self.refresh_registry(&registry)?;
                    self.confirmed_ns = now_unix_nanos();
                    Ok(Some(version))
                }
            }
        });
        if outcome.is_err() {
            self.stats.refresh_failures = self.stats.refresh_failures.saturating_add(1);
        }
        outcome
    }

    /// Adopts a newer registry version without interrupting the feed.
    ///
    /// This is how a node rotates a signing key, or is added or removed, without
    /// a consumer release. The replacement is checked against the governance key
    /// this client was pinned to and against the version currently trusted, so
    /// neither a forged document nor a replayed older one can take effect.
    ///
    /// Feed state and replay high-water marks survive the swap. Observations from
    /// nodes the new version de-lists do not — revocation has to bite immediately,
    /// not once the revoked node's last update happens to age out.
    ///
    /// After `subscribe`, the connections follow the new node list.
    ///
    /// Returns the newly adopted version.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Registry`] if the replacement is not strictly newer
    /// or is not signed by the pinned governance key, or
    /// [`ClientError::UnreachableQuorum`] if adopting it would leave fewer nodes
    /// than the configured quorum. The client keeps its existing registry in
    /// every failure case.
    pub fn refresh_registry(
        &mut self,
        registry: &oracle_wire::Registry,
    ) -> Result<u64, ClientError> {
        let verified = self.registry.accept_successor(registry)?;

        // Checked before anything is swapped in: a registry that shrinks below
        // the quorum would leave the client permanently halted, and silently
        // adopting it would turn a governance mistake into an outage with no
        // obvious cause.
        let available = verified.nodes().len();
        if self.quorum_config.quorum > available {
            return Err(ClientError::UnreachableQuorum {
                requested: self.quorum_config.quorum,
                available,
            });
        }

        let listed: HashSet<Address> = verified.nodes().iter().map(|node| node.address).collect();
        for view in self.views.values_mut() {
            view.retain_nodes(&|node| listed.contains(node));
        }

        let version = verified.version();
        self.verifier.set_registry(verified.clone());
        self.registry = verified;
        self.reconcile_connections();
        Ok(version)
    }

    /// Connects to every node in the registry and subscribes to `symbols`.
    ///
    /// A later call adds symbols and reconnects every node with the full set.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoClientKey`] without a client key,
    /// [`ClientError::InvalidSymbol`] for an unparseable symbol, or
    /// [`ClientError::NoEndpoints`] if the registry lists none.
    pub async fn subscribe(&mut self, symbols: &[&str]) -> Result<(), ClientError> {
        if self.client_key.is_none() {
            return Err(ClientError::NoClientKey);
        }
        for symbol in parse_symbols(symbols)? {
            let id = feed_id(&symbol);
            self.symbols.insert(id, symbol);
            self.views.entry(id).or_insert_with(|| FeedView::new(id));
        }
        self.resubscribe()
    }

    /// Adds feeds whose venue reports to receive, and reconnects every node with
    /// the full set. [`OracleClient::next_event`] yields them.
    ///
    /// # Errors
    ///
    /// The same as [`OracleClient::subscribe`].
    pub async fn subscribe_venues(&mut self, symbols: &[&str]) -> Result<(), ClientError> {
        if self.client_key.is_none() {
            return Err(ClientError::NoClientKey);
        }
        for symbol in parse_symbols(symbols)? {
            self.venue_symbols.insert(feed_id(&symbol), symbol);
        }
        self.resubscribe()
    }

    /// Adds feeds whose sources' books to receive, and reconnects every node
    /// with the full set. [`OracleClient::book`] reads them.
    ///
    /// # Errors
    ///
    /// The same as [`OracleClient::subscribe`].
    pub async fn subscribe_books(&mut self, symbols: &[&str]) -> Result<(), ClientError> {
        if self.client_key.is_none() {
            return Err(ClientError::NoClientKey);
        }
        for symbol in parse_symbols(symbols)? {
            self.book_symbols.insert(feed_id(&symbol), symbol);
        }
        self.resubscribe()
    }

    /// The freshest valid book for `instrument` across the nodes, or `None` if
    /// no node's book is valid and younger than `max_age`.
    ///
    /// Each node sends its own view, so two nodes' books differ by their
    /// receipt times. This returns one node's book whole, never a mix.
    #[must_use]
    pub fn book(&self, instrument: &InstrumentId, now_ns: u64) -> Option<&Book> {
        let max_age = u64::try_from(self.quorum_config.max_age.as_nanos()).unwrap_or(u64::MAX);
        self.books
            .iter()
            .filter(|((_, book), _)| book == instrument)
            .map(|(_, book)| book)
            .filter(|book| book.is_valid())
            .filter(|book| now_ns.saturating_sub(book.publish_time_ns) <= max_age)
            .max_by_key(|book| book.publish_time_ns)
    }

    fn resubscribe(&mut self) -> Result<(), ClientError> {
        let prices: Vec<Symbol> = self.symbols.values().copied().collect();
        let venues: Vec<Symbol> = self.venue_symbols.values().copied().collect();
        let books: Vec<Symbol> = self.book_symbols.values().copied().collect();
        self.subscription = Some(subscribe_frame(&prices, &venues, &books));
        self.runtime = Some(Handle::current());
        for (_, connection) in self.connections.drain() {
            connection.cancel.cancel();
        }
        self.reconcile_connections();
        if self.connections.is_empty() {
            return Err(ClientError::NoEndpoints);
        }
        self.start_polling();
        Ok(())
    }

    fn reconcile_connections(&mut self) {
        let (Some(request), Some(runtime), Some(client_key)) =
            (&self.subscription, &self.runtime, &self.client_key)
        else {
            return;
        };
        let wanted: HashMap<Address, &str> = self
            .registry
            .nodes()
            .iter()
            .filter_map(|node| {
                node.endpoints
                    .first()
                    .map(|endpoint| (node.address, endpoint.as_str()))
            })
            .collect();

        self.connections.retain(|node, connection| {
            let keep = wanted.get(node) == Some(&connection.endpoint.as_str());
            if !keep {
                connection.cancel.cancel();
                info!(%node, endpoint = %connection.endpoint, "disconnected from node");
            }
            keep
        });

        for (node, endpoint) in wanted {
            if self.connections.contains_key(&node) {
                continue;
            }
            let cancel = self.shutdown.child_token();
            runtime.spawn(node_loop(
                NodeTarget {
                    node,
                    endpoint: endpoint.to_owned(),
                    request: request.clone(),
                    client_key: Arc::clone(client_key),
                },
                self.inbound_tx.clone(),
                cancel.clone(),
            ));
            info!(%node, %endpoint, "connecting to node");
            self.connections.insert(
                node,
                NodeConnection {
                    endpoint: endpoint.to_owned(),
                    cancel,
                },
            );
        }
    }

    fn start_polling(&mut self) {
        if self.polling {
            return;
        }
        let (Some(source), Some(runtime)) = (self.source.clone(), &self.runtime) else {
            return;
        };
        self.polling = true;
        runtime.spawn(poll_loop(
            source,
            self.poll_interval,
            self.inbound_tx.clone(),
            self.shutdown.clone(),
        ));
    }

    /// Feeds one frame in directly, bypassing the network and the registry source.
    ///
    /// For tests and for consumers running their own transport. An unknown
    /// signer is a plain rejection here; [`OracleClient::ingest_with_refresh`]
    /// is the path that goes looking for a newer registry.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`] if the frame fails verification.
    pub fn ingest(&mut self, frame: &[u8], now_ns: u64) -> Result<Resolved, RejectReason> {
        let outcome = self.try_ingest_price(frame, now_ns, now_ns);
        self.record(&outcome);
        outcome
    }

    /// Feeds one price or venue report frame in directly, like
    /// [`OracleClient::ingest`].
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`] if the frame fails verification.
    pub fn ingest_event(&mut self, frame: &[u8], now_ns: u64) -> Result<Event, RejectReason> {
        let outcome = self.try_ingest(frame, now_ns, now_ns);
        self.record(&outcome);
        outcome
    }

    /// Feeds one frame in, refreshing the registry once if the signer is unknown.
    ///
    /// This is how a rotation reaches the consumer. The first frame from a node's
    /// new key is unknown; the client fetches the registry, adopts it if it is
    /// newer, and retries the frame. The fetch is rate-limited to one per
    /// `refresh_interval`, because anyone who can inject a frame can trigger it.
    /// A retired key never triggers a fetch: the registry already knows it.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`] if the frame still fails after the refresh.
    pub async fn ingest_with_refresh(
        &mut self,
        frame: &[u8],
        now_ns: u64,
    ) -> Result<Resolved, RejectReason> {
        self.ingest_received(frame, now_ns, now_ns, Self::try_ingest_price)
            .await
    }

    async fn ingest_received<T>(
        &mut self,
        frame: &[u8],
        received_ns: u64,
        now_ns: u64,
        accept: fn(&mut Self, &[u8], u64, u64) -> Result<T, RejectReason>,
    ) -> Result<T, RejectReason> {
        let mut outcome = accept(self, frame, received_ns, now_ns);
        if let Err(RejectReason::Untrusted(VerifyError::UnknownSigner { signer })) = &outcome
            && self.refresh_due(now_ns)
        {
            self.last_refresh_attempt_ns = Some(now_ns);
            match self.refresh_from_source().await {
                Ok(Some(version)) => debug!(%signer, version, "adopted a newer registry"),
                Ok(None) => debug!(%signer, "registry unchanged; signer stays unknown"),
                Err(error) => warn!(%signer, %error, "registry refresh failed"),
            }
            outcome = accept(self, frame, received_ns, now_ns);
        }
        self.record(&outcome);
        outcome
    }

    fn try_ingest(
        &mut self,
        frame: &[u8],
        received_ns: u64,
        now_ns: u64,
    ) -> Result<Event, RejectReason> {
        match frame.first().copied() {
            Some(FRAME_TYPE_VENUE_REPORT) => {
                let accepted = self.verifier.accept_venues(frame, now_ns)?;
                self.stats.venue_reports = self.stats.venue_reports.saturating_add(1);
                return Ok(Event::Venues(accepted));
            }
            Some(FRAME_TYPE_BOOK_UPDATE) => {
                let accepted = self.verifier.accept_book(frame, now_ns)?;
                self.stats.book_updates = self.stats.book_updates.saturating_add(1);
                let update = &accepted.update;
                let instrument =
                    InstrumentId::new(update.venue, update.market, update.symbol.as_str());
                self.books
                    .entry((accepted.signer, instrument.clone()))
                    .or_insert_with(|| Book::new(accepted.signer, instrument))
                    .apply(update);
                return Ok(Event::Book(accepted));
            }
            _ => {}
        }
        self.try_ingest_price(frame, received_ns, now_ns)
            .map(Event::Price)
    }

    fn try_ingest_price(
        &mut self,
        frame: &[u8],
        received_ns: u64,
        now_ns: u64,
    ) -> Result<Resolved, RejectReason> {
        let accepted = self.verifier.accept(frame, now_ns)?;
        self.stats.accepted = self.stats.accepted.saturating_add(1);
        self.latency.arrived(&accepted.update, received_ns);
        let feed = accepted.update.feed_id;
        let view = self
            .views
            .entry(feed)
            .or_insert_with(|| FeedView::new(feed));
        view.record(accepted.signer, accepted.update);
        let mut resolved = view.resolve(&self.quorum_config, now_ns);
        self.annotate(&mut resolved, now_ns);
        Ok(resolved)
    }

    /// Counts a rejection once, after any refresh. Acceptances count where they
    /// happen.
    fn record<T>(&mut self, outcome: &Result<T, RejectReason>) {
        if let Err(reason) = outcome {
            self.stats.record(reason);
        }
    }

    fn refresh_due(&self, now_ns: u64) -> bool {
        let floor = u64::try_from(self.refresh_interval.as_nanos()).unwrap_or(u64::MAX);
        self.source.is_some()
            && self
                .last_refresh_attempt_ns
                .is_none_or(|last| now_ns.saturating_sub(last) >= floor)
    }

    /// Adds the client-level concerns a feed view cannot know about.
    fn annotate(&self, resolved: &mut Resolved, now_ns: u64) {
        if self.registry_is_stale(now_ns) {
            resolved.concerns.push(Concern::RegistryStale);
            if resolved.status == Status::Ok {
                resolved.status = Status::Degraded;
            }
        }
    }

    /// Returns the next resolved price.
    ///
    /// Yields one resolution per accepted frame, so a consumer sees the feed
    /// state change as soon as any node reports. Returns `None` once every node
    /// connection has ended.
    /// Scheduled registry fetches are adopted here, so keep calling it. It skips
    /// venue reports; [`OracleClient::next_event`] yields them.
    pub async fn next(&mut self) -> Option<Resolved> {
        loop {
            if let Event::Price(resolved) = self.next_event().await? {
                return Some(resolved);
            }
        }
    }

    /// Returns the next resolved price or verified venue report.
    ///
    /// Returns `None` once every node connection has ended.
    pub async fn next_event(&mut self) -> Option<Event> {
        loop {
            let (frame, received_ns) = match self.inbound_rx.recv().await? {
                Inbound::Frame { frame, received_ns } => (frame, received_ns),
                Inbound::Polled(fetched) => {
                    self.stats.polls = self.stats.polls.saturating_add(1);
                    match self.adopt_fetched(fetched) {
                        Ok(Some(version)) => info!(version, "adopted a newer registry"),
                        Ok(None) => debug!("registry unchanged"),
                        Err(error) => warn!(%error, "scheduled registry fetch failed"),
                    }
                    continue;
                }
                Inbound::NodeMoved { got } => {
                    // A retired address is the node before its restart: the
                    // registry is already ahead of it.
                    let now_ns = now_unix_nanos();
                    if !self.verifier.is_retired(got) && self.refresh_due(now_ns) {
                        self.last_refresh_attempt_ns = Some(now_ns);
                        if let Err(error) = self.refresh_from_source().await {
                            warn!(%error, "registry refresh failed");
                        }
                    }
                    continue;
                }
            };
            let now_ns = now_unix_nanos();
            match self
                .ingest_received(&frame, received_ns, now_ns, Self::try_ingest)
                .await
            {
                Ok(event) => {
                    if let Event::Price(_) = event {
                        self.latency.resolved(received_ns, now_unix_nanos());
                    }
                    return Some(event);
                }
                Err(reason) => {
                    debug!(%reason, "rejected an update");
                }
            }
        }
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

/// Builds the subscribe control frame.
fn subscribe_frame(prices: &[Symbol], venues: &[Symbol], books: &[Symbol]) -> String {
    let names =
        |symbols: &[Symbol]| -> Vec<String> { symbols.iter().map(ToString::to_string).collect() };
    serde_json::json!({
        "op": "subscribe",
        "feeds": names(prices),
        "venues": names(venues),
        "books": names(books),
    })
    .to_string()
}

fn parse_symbols(symbols: &[&str]) -> Result<Vec<Symbol>, ClientError> {
    symbols
        .iter()
        .map(|text| {
            text.parse()
                .map_err(|_| ClientError::InvalidSymbol((*text).to_owned()))
        })
        .collect()
}

/// Ceiling on the reconnect delay.
const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// A fresh reconnect ladder: 100ms to 30s, doubling, jittered.
///
/// Jittered so every subscriber of a node that just restarted does not come
/// back at the same instant.
fn reconnect_ladder() -> backon::ExponentialBackoff {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(100))
        .with_max_delay(RECONNECT_MAX)
        .with_factor(2.0)
        .with_jitter()
        .without_max_times()
        .build()
}

/// Jittered so that clients started together do not fetch together.
fn poll_waits(interval: Duration) -> backon::ConstantBackoff {
    ConstantBuilder::default()
        .with_delay(interval / 2)
        .with_jitter()
        .without_max_times()
        .build()
}

/// Runs off the frame path, because a canister update call takes seconds.
async fn poll_loop(
    source: Arc<dyn RegistrySource>,
    interval: Duration,
    tx: mpsc::Sender<Inbound>,
    shutdown: CancellationToken,
) {
    let mut waits = poll_waits(interval);
    loop {
        let wait = waits.next().unwrap_or(interval);
        let fetched = tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            fetched = async {
                tokio::time::sleep(wait).await;
                source.fetch().await
            } => fetched,
        };
        if tx.send(Inbound::Polled(fetched)).await.is_err() {
            return;
        }
    }
}

/// Everything one connection task needs.
struct NodeTarget {
    node: Address,
    endpoint: String,
    request: String,
    client_key: Arc<Signer>,
}

/// Time from connect to `auth_ok`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Connects to one node and forwards its binary frames, reconnecting on failure.
async fn node_loop(target: NodeTarget, tx: mpsc::Sender<Inbound>, shutdown: CancellationToken) {
    let mut backoff = reconnect_ladder();
    while !shutdown.is_cancelled() {
        // Also drops a de-listed node in the middle of a handshake.
        let outcome = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            outcome = connect_and_pump(&target, &tx) => outcome,
        };
        match outcome {
            Ok(()) => backoff = reconnect_ladder(),
            Err(reason) => {
                warn!(endpoint = %target.endpoint, %reason, "node connection failed");
            }
        }
        if shutdown.is_cancelled() {
            break;
        }
        let delay = backoff.next().unwrap_or(RECONNECT_MAX);
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(delay) => {}
        }
    }
}

async fn connect_and_pump(target: &NodeTarget, tx: &mpsc::Sender<Inbound>) -> Result<(), String> {
    let (mut socket, _) = tokio_tungstenite::connect_async(&target.endpoint)
        .await
        .map_err(|e| e.to_string())?;
    pump(&mut socket, target, tx).await
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// One session: handshake, then sealed control and broadcast frames. Opened
/// frames go to the verifier like any other; decryption proves nothing.
async fn pump(
    socket: &mut Socket,
    target: &NodeTarget,
    tx: &mpsc::Sender<Inbound>,
) -> Result<(), String> {
    let mut session = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(socket, target, tx))
        .await
        .map_err(|_| "handshake timed out".to_owned())??;
    // Only now, after the node proved its key, do the subscriptions leave.
    let subscribe = session
        .sealer
        .seal(&Control::App(target.request.as_bytes().to_vec()))
        .map_err(|e| e.to_string())?;
    socket
        .send(Message::Binary(subscribe.into()))
        .await
        .map_err(|e| e.to_string())?;

    let mut missing_since: Option<u64> = None;
    while let Some(message) = socket.next().await {
        let bytes = match message.map_err(|e| e.to_string())? {
            Message::Binary(bytes) => bytes,
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
            Message::Text(_) => return Err("plaintext after the handshake".to_owned()),
            Message::Close(_) => return Ok(()),
        };
        let received_ns = now_unix_nanos();
        let now = received_ns / NANOS_PER_SEC;
        match bytes.get(1).copied() {
            Some(TYPE_FRAME) => {
                session.keys.prune(now);
                match session.keys.open(&bytes) {
                    Ok(frame) => {
                        missing_since = None;
                        if tx
                            .send(Inbound::Frame { frame, received_ns })
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                    Err(TransportError::UnknownKey) => {
                        let since = *missing_since.get_or_insert(now);
                        if now.saturating_sub(since) > KEY_GRACE_SECS {
                            return Err("no key for the node's frames".to_owned());
                        }
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
            Some(TYPE_CONTROL) => match session.opener.open(&bytes).map_err(|e| e.to_string())? {
                Control::KeyUpdate(grant) => session.keys.insert(grant),
                Control::SessionUpdate { deadline } => session.deadline = deadline,
                Control::Close(reason) => {
                    return Err(format!("node closed the session: {reason:?}"));
                }
                Control::App(_) => {}
            },
            _ => return Err("unknown message type".to_owned()),
        }
    }
    Ok(())
}

async fn handshake(
    socket: &mut Socket,
    target: &NodeTarget,
    tx: &mpsc::Sender<Inbound>,
) -> Result<ClientSession, String> {
    let challenge = next_handshake(socket).await?;
    let (auth, waiting) = ClientHandshake::new(target.node, &mut os_rng())
        .respond(&challenge, &target.client_key)
        .map_err(|error| {
            if let TransportError::WrongNode { got, .. } = error {
                let _ = tx.try_send(Inbound::NodeMoved { got });
            }
            error.to_string()
        })?;
    let auth = serde_json::to_string(&auth).map_err(|e| e.to_string())?;
    socket
        .send(Message::Text(auth.into()))
        .await
        .map_err(|e| e.to_string())?;
    let auth_ok = next_handshake(socket).await?;
    waiting.finish(&auth_ok).map_err(|e| e.to_string())
}

async fn next_handshake(socket: &mut Socket) -> Result<HandshakeMessage, String> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(&text).map_err(|e| e.to_string());
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(other)) => return Err(format!("expected a handshake message, got {other:?}")),
            Some(Err(error)) => return Err(error.to_string()),
            None => return Err("closed during the handshake".to_owned()),
        }
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
mod tests {
    use super::*;
    use crate::Status;
    use crate::testing::{TestNode, book_at, registry_with, update_at};
    use oracle_types::{MarketKind, NANOS_PER_SEC, Venue};

    const NOW: u64 = 1_754_582_400 * NANOS_PER_SEC;

    #[test]
    fn book_frames_build_the_freshest_valid_book() {
        let nodes = nodes();
        let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
        let mut client = OracleClient::builder(registry)
            .build()
            .expect("three nodes");
        let [a, b, _] = nodes.as_slice() else {
            panic!("three nodes");
        };
        let instrument = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");

        for (frame, at) in [
            (a.sign_book(&book_at(NOW, 1, true, 100)), NOW),
            (a.sign_book(&book_at(NOW + 10, 2, false, 300)), NOW + 10),
            (b.sign_book(&book_at(NOW + 5, 7, true, 200)), NOW + 5),
        ] {
            assert!(matches!(
                client.ingest_event(&frame, at),
                Ok(Event::Book(_))
            ));
        }
        let book = client.book(&instrument, NOW + 20).expect("a valid book");
        assert_eq!(book.node, a.signing_address(), "the freshest node");
        assert_eq!(book.best_bid().map(|level| level.qty), Some(300));

        // Node A skips seq 3: its book is unknown, so node B's serves.
        let gap = a.sign_book(&book_at(NOW + 30, 4, false, 900));
        assert!(client.ingest_event(&gap, NOW + 30).is_ok());
        let book = client.book(&instrument, NOW + 40).expect("node B's book");
        assert_eq!(book.node, b.signing_address());
        assert_eq!(client.stats().book_updates, 4);

        let later = NOW + 10 * NANOS_PER_SEC;
        assert!(client.book(&instrument, later).is_none(), "too old");
    }

    fn nodes() -> Vec<TestNode> {
        (1..=3_u8).map(TestNode::new).collect()
    }

    #[test]
    fn a_quorum_below_three_is_refused_by_default() {
        let nodes = nodes();
        let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
        for quorum in [0, 1, 2] {
            let error = OracleClient::builder(registry.clone())
                .quorum(quorum)
                .build()
                .err()
                .expect("must refuse an unsafe quorum");
            assert!(
                matches!(error, ClientError::UnsafeQuorum { .. }),
                "got {error:?}"
            );
        }
    }

    #[test]
    fn a_low_quorum_is_permitted_only_with_an_explicit_acknowledgement() {
        let node = TestNode::new(1);
        let registry = registry_with(&[&node]);
        assert!(
            OracleClient::builder(registry)
                .quorum(1)
                .i_understand_this_provides_no_protection_against_a_bad_node()
                .build()
                .is_ok()
        );
    }

    #[test]
    fn a_quorum_larger_than_the_registry_is_refused() {
        let node = TestNode::new(1);
        let registry = registry_with(&[&node]);
        let error = OracleClient::builder(registry)
            .quorum(3)
            .build()
            .err()
            .expect("must refuse an unreachable quorum");
        assert!(
            matches!(
                error,
                ClientError::UnreachableQuorum {
                    requested: 3,
                    available: 1
                }
            ),
            "got {error:?}"
        );
    }

    #[test]
    fn three_agreeing_nodes_resolve_to_ok() {
        let nodes = nodes();
        let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
        let mut client = OracleClient::builder(registry)
            .quorum(3)
            .build()
            .expect("valid configuration");

        let mut last = None;
        for node in &nodes {
            last = Some(
                client
                    .ingest(&node.sign(&update_at(NOW, 1)), NOW)
                    .expect("accepted"),
            );
        }
        let resolved = last.expect("resolved");
        assert_eq!(resolved.status, Status::Ok);
        assert_eq!(resolved.nodes, 3);
        assert_eq!(client.stats().accepted, 3);
    }

    #[test]
    fn an_impostor_is_counted_and_excluded() {
        let nodes = nodes();
        let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
        let mut client = OracleClient::builder(registry)
            .quorum(3)
            .build()
            .expect("valid configuration");

        let impostor = TestNode::new(200);
        assert!(
            client
                .ingest(&impostor.sign(&update_at(NOW, 1)), NOW)
                .is_err()
        );
        assert_eq!(client.stats().untrusted, 1);
        assert_eq!(client.stats().accepted, 0);
    }

    #[test]
    fn a_replay_is_counted_and_refused() {
        let nodes = nodes();
        let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
        let mut client = OracleClient::builder(registry)
            .quorum(3)
            .build()
            .expect("valid configuration");

        let frame = nodes.first().expect("a node").sign(&update_at(NOW, 1));
        assert!(client.ingest(&frame, NOW).is_ok());
        assert!(client.ingest(&frame, NOW).is_err());
        assert_eq!(client.stats().replayed, 1);
    }

    #[test]
    fn one_lying_node_cannot_move_the_resolved_price() {
        let nodes = nodes();
        let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
        let mut client = OracleClient::builder(registry)
            .quorum(3)
            .build()
            .expect("valid configuration");

        let mut honest = update_at(NOW, 1);
        honest.price = 6_400_000_000_000;
        let mut liar = update_at(NOW, 1);
        liar.price = 1;

        let [first, second, third] = nodes.as_slice() else {
            panic!("three nodes")
        };
        client.ingest(&first.sign(&honest), NOW).expect("accepted");
        client.ingest(&second.sign(&honest), NOW).expect("accepted");
        let resolved = client.ingest(&third.sign(&liar), NOW).expect("accepted");

        assert_eq!(
            resolved.price.expect("a price"),
            honest.price_fixed().expect("representable"),
            "the median must ignore the liar"
        );
        // But the disagreement must be visible without anyone looking for it.
        assert_eq!(resolved.status, Status::Degraded);
        assert!(resolved.conf.expect("a band") > oracle_types::Fixed::from_int(1).expect("ok"));
    }
}
