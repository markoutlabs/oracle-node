//! The async multi-node client.
//!
//! Deliberately thin. Everything that decides whether a price is trustworthy
//! lives in [`crate::verify`] and [`crate::quorum`], which are pure and
//! synchronous; this layer only moves bytes and calls them.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};
use futures_util::{SinkExt as _, StreamExt as _};
use oracle_types::{FeedId, NANOS_PER_SEC, Symbol};
use oracle_wire::{Address, VerifiedRegistry, VerifyError, feed_id};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::quorum::{Concern, FeedView, QuorumConfig, Resolved, Status};
use crate::source::{FetchError, RegistrySource};
use crate::verify::{RejectReason, Verifier, VerifyConfig};

/// The quorum below which the builder demands an explicit acknowledgement.
const SAFE_QUORUM: usize = 3;

/// Default floor between two registry fetches triggered by unknown signers.
///
/// Anyone who can inject a frame can trigger a fetch, so the floor is what
/// stops a hostile relay from turning the client into a load generator
/// against the registry.
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// Default registry age above which feeds are reported degraded.
///
/// The canister re-signs at least daily (SPEC §3.6). Two missed heartbeats
/// means the fetch path is broken or newer versions are being withheld.
const DEFAULT_MAX_REGISTRY_AGE: Duration = Duration::from_secs(48 * 3_600);

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
    max_registry_age: Duration,
}

impl OracleClientBuilder {
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

    /// Sets the registry age above which feeds are reported degraded.
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
            frames_tx: tx,
            frames_rx: rx,
            shutdown: CancellationToken::new(),
            stats: ClientStats::default(),
            source: self.source,
            refresh_interval: self.refresh_interval,
            max_registry_age: self.max_registry_age,
            last_refresh_attempt_ns: None,
        })
    }
}

/// Counters describing what the client has seen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientStats {
    /// Frames accepted.
    pub accepted: u64,
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
    /// Registry fetches made.
    pub refreshes: u64,
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

/// Verifies signed updates from many nodes and resolves them into one price.
pub struct OracleClient {
    verifier: Verifier,
    registry: VerifiedRegistry,
    quorum_config: QuorumConfig,
    views: HashMap<FeedId, FeedView>,
    symbols: HashMap<FeedId, Symbol>,
    frames_tx: mpsc::Sender<Vec<u8>>,
    frames_rx: mpsc::Receiver<Vec<u8>>,
    shutdown: CancellationToken,
    stats: ClientStats,
    source: Option<Arc<dyn RegistrySource>>,
    refresh_interval: Duration,
    max_registry_age: Duration,
    last_refresh_attempt_ns: Option<u64>,
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
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
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

    /// Returns the registry version currently trusted.
    #[must_use]
    pub const fn registry_version(&self) -> u64 {
        self.registry.version()
    }

    /// Returns how long ago the trusted registry was issued.
    #[must_use]
    pub fn registry_age(&self, now_ns: u64) -> Duration {
        let issued_ns = self
            .registry
            .as_registry()
            .effective_from
            .saturating_mul(NANOS_PER_SEC);
        Duration::from_nanos(now_ns.saturating_sub(issued_ns))
    }

    /// Returns `true` if the trusted registry is older than `max_registry_age`.
    #[must_use]
    pub fn registry_is_stale(&self, now_ns: u64) -> bool {
        self.registry_age(now_ns) > self.max_registry_age
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
        let outcome = async {
            let registry = source.fetch().await?;
            if registry.version <= self.registry.version() {
                return Ok(None);
            }
            self.refresh_registry(&registry).map(Some)
        }
        .await;
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

        let listed: HashSet<&str> = verified
            .nodes()
            .iter()
            .map(|node| node.node_id.as_str())
            .collect();
        for view in self.views.values_mut() {
            view.retain_nodes(&|node_id| listed.contains(node_id));
        }
        drop(listed);

        let version = verified.version();
        self.verifier.set_registry(verified.clone());
        self.registry = verified;
        Ok(version)
    }

    /// Connects to every node in the registry and subscribes to `symbols`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidSymbol`] for an unparseable symbol, or
    /// [`ClientError::NoEndpoints`] if the registry lists none.
    pub async fn subscribe(&mut self, symbols: &[&str]) -> Result<(), ClientError> {
        let mut parsed = Vec::with_capacity(symbols.len());
        for text in symbols {
            let symbol: Symbol = text
                .parse()
                .map_err(|_| ClientError::InvalidSymbol((*text).to_owned()))?;
            let id = feed_id(&symbol);
            self.symbols.insert(id, symbol);
            self.views.entry(id).or_insert_with(|| FeedView::new(id));
            parsed.push(symbol);
        }

        let request = subscribe_frame(&parsed);
        let endpoints: Vec<String> = self
            .registry
            .nodes()
            .iter()
            .filter_map(|node| node.endpoints.first().cloned())
            .collect();
        if endpoints.is_empty() {
            return Err(ClientError::NoEndpoints);
        }

        for endpoint in endpoints {
            let tx = self.frames_tx.clone();
            let shutdown = self.shutdown.clone();
            let request = request.clone();
            tokio::spawn(async move {
                node_loop(endpoint, request, tx, shutdown).await;
            });
        }
        Ok(())
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
        let outcome = self.try_ingest(frame, now_ns);
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
        let mut outcome = self.try_ingest(frame, now_ns);
        if let Err(RejectReason::Untrusted(VerifyError::UnknownSigner { signer })) = &outcome
            && self.refresh_due(now_ns)
        {
            self.last_refresh_attempt_ns = Some(now_ns);
            match self.refresh_from_source().await {
                Ok(Some(version)) => debug!(%signer, version, "adopted a newer registry"),
                Ok(None) => debug!(%signer, "registry unchanged; signer stays unknown"),
                Err(error) => warn!(%signer, %error, "registry refresh failed"),
            }
            outcome = self.try_ingest(frame, now_ns);
        }
        self.record(&outcome);
        outcome
    }

    fn try_ingest(&mut self, frame: &[u8], now_ns: u64) -> Result<Resolved, RejectReason> {
        let accepted = self.verifier.accept(frame, now_ns)?;
        let feed = accepted.update.feed_id;
        let view = self
            .views
            .entry(feed)
            .or_insert_with(|| FeedView::new(feed));
        view.record(accepted.node, accepted.update);
        let mut resolved = view.resolve(&self.quorum_config, now_ns);
        self.annotate(&mut resolved, now_ns);
        Ok(resolved)
    }

    fn record(&mut self, outcome: &Result<Resolved, RejectReason>) {
        match outcome {
            Ok(_) => self.stats.accepted = self.stats.accepted.saturating_add(1),
            Err(reason) => self.stats.record(reason),
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
    pub async fn next(&mut self) -> Option<Resolved> {
        loop {
            let frame = self.frames_rx.recv().await?;
            let now_ns = now_unix_nanos();
            match self.ingest_with_refresh(&frame, now_ns).await {
                Ok(resolved) => return Some(resolved),
                Err(reason) => {
                    debug!(%reason, "rejected an update");
                }
            }
        }
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
fn subscribe_frame(symbols: &[Symbol]) -> String {
    let feeds: Vec<String> = symbols.iter().map(ToString::to_string).collect();
    serde_json::json!({ "op": "subscribe", "feeds": feeds, "encoding": "binary" }).to_string()
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

/// Connects to one node and forwards its binary frames, reconnecting on failure.
async fn node_loop(
    endpoint: String,
    request: String,
    tx: mpsc::Sender<Vec<u8>>,
    shutdown: CancellationToken,
) {
    let mut backoff = reconnect_ladder();
    while !shutdown.is_cancelled() {
        match connect_and_pump(&endpoint, &request, &tx, &shutdown).await {
            Ok(()) => backoff = reconnect_ladder(),
            Err(reason) => {
                warn!(%endpoint, %reason, "node connection failed");
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

async fn connect_and_pump(
    endpoint: &str,
    request: &str,
    tx: &mpsc::Sender<Vec<u8>>,
    shutdown: &CancellationToken,
) -> Result<(), String> {
    let (mut socket, _) = tokio_tungstenite::connect_async(endpoint)
        .await
        .map_err(|e| e.to_string())?;
    socket
        .send(Message::Text(request.into()))
        .await
        .map_err(|e| e.to_string())?;

    loop {
        let message = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            message = socket.next() => message,
        };
        let Some(message) = message else {
            return Ok(());
        };
        match message.map_err(|e| e.to_string())? {
            Message::Binary(bytes) => {
                if tx.send(bytes.to_vec()).await.is_err() {
                    return Ok(());
                }
            }
            // Control replies and acknowledgements; the data path is binary.
            Message::Text(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            Message::Close(_) => return Ok(()),
        }
    }
}

/// Reads the wall clock in unix nanoseconds.
fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Status;
    use crate::testing::{TestNode, registry_with, update_at};
    use oracle_types::NANOS_PER_SEC;

    const NOW: u64 = 1_754_582_400 * NANOS_PER_SEC;

    fn nodes() -> Vec<TestNode> {
        (1..=3_u8)
            .map(|seed| TestNode::new(seed, &format!("oracle-{seed}")))
            .collect()
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
        let node = TestNode::new(1, "oracle-1");
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
        let node = TestNode::new(1, "oracle-1");
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

        let impostor = TestNode::new(200, "impostor");
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
