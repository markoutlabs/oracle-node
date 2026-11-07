//! Governance documents: fetch a newer registry, verify it against the pinned
//! governance key, and follow its node list; adopt a newer feed set. A fetch
//! never runs on the frame path.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use backon::{BackoffBuilder, ConstantBuilder};
use oracle_types::{FeedId, FeedKind, InstrumentId, MarketKind, Symbol, Venue};
use oracle_wire::{Address, Registry, VerifiedFeedSet, VerifyError, feed_id};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{ClientError, Inbound, OracleClient, now_unix_nanos};
use crate::source::{FetchError, RegistrySource};

impl OracleClient {
    /// Adopts a governance-signed feed set newer than the one in use; `false` for one that is not.
    ///
    /// Book and funding frames then pass only for its sources, and each feed gets the age limit
    /// of its kind.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::FeedSet`] if the set is not signed by the governance of the registry.
    pub fn set_feed_set(&mut self, set: &VerifiedFeedSet) -> Result<bool, ClientError> {
        let expected = self.registry.governance();
        if set.governance() != expected {
            return Err(ClientError::FeedSet(VerifyError::UntrustedGovernance {
                found: set.governance(),
                expected,
            }));
        }
        if self
            .feed_set_version
            .is_some_and(|version| set.version() <= version)
        {
            return Ok(false);
        }
        let mut instruments = HashSet::new();
        for feed in set.feeds() {
            // The verified set parses; an entry that does not is left out.
            if let Ok(symbol) = feed.symbol.parse::<Symbol>() {
                self.set_feed_kind(feed_id(&symbol), symbol.kind());
            }
            for source in &feed.sources {
                if let (Ok(venue), Ok(market)) = (
                    source.venue.parse::<Venue>(),
                    source.market.parse::<MarketKind>(),
                ) {
                    instruments.insert(InstrumentId::new(venue, market, source.symbol.as_str()));
                }
            }
        }
        self.books.retain(|(_, book), _| instruments.contains(book));
        self.book_nodes.retain(|book, _| instruments.contains(book));
        self.funding_nodes
            .retain(|perpetual, _| instruments.contains(perpetual));
        self.funding
            .retain(|(_, perpetual), _| instruments.contains(perpetual));
        self.verifier.set_instruments(Some(instruments));
        self.feed_set_version = Some(set.version());
        Ok(true)
    }

    /// Records a feed's kind in each place that reads its age limit: the verifier and the view.
    pub(super) fn set_feed_kind(&mut self, id: FeedId, kind: FeedKind) {
        self.verifier.set_feed_kind(id, kind);
        if let Some(view) = self.views.get_mut(&id) {
            view.set_kind(kind);
        }
    }

    /// Returns the version of the feed set in use, if the client has one.
    #[must_use]
    pub const fn feed_set_version(&self) -> Option<u64> {
        self.feed_set_version
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

    pub(super) fn adopt_fetched(
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
    /// A registry that lists fewer nodes than the quorum is adopted too, with a
    /// warning: its feeds halt, which is safer than trusting a removed key.
    ///
    /// Returns the newly adopted version.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Registry`] if the replacement is not strictly newer
    /// or is not signed by the pinned governance key. The client then keeps its
    /// existing registry.
    pub fn refresh_registry(
        &mut self,
        registry: &oracle_wire::Registry,
    ) -> Result<u64, ClientError> {
        let verified = self.registry.accept_successor(registry)?;

        // Governance may remove a stolen key below the quorum. Halting is the safe
        // result, so the client adopts the list and says loudly why its feeds stop.
        let available = verified.nodes().len();
        if self.quorum_config.quorum > available {
            tracing::warn!(
                version = verified.version(),
                requested = self.quorum_config.quorum,
                available,
                "the new registry lists fewer nodes than the quorum, so every feed halts"
            );
        }

        let listed: HashSet<Address> = verified.nodes().iter().map(|node| node.address).collect();
        for view in self.views.values_mut() {
            view.retain_nodes(&|node| listed.contains(node));
        }
        self.books.retain(|(node, _), _| listed.contains(node));
        self.book_nodes
            .retain(|_, choice| listed.contains(&choice.node));
        self.funding_nodes.retain(|_, node| listed.contains(node));
        self.funding.retain(|(node, _), _| listed.contains(node));

        let version = verified.version();
        self.verifier.set_registry(verified.clone());
        self.registry = verified;
        self.reconcile_connections();
        Ok(version)
    }

    pub(super) fn start_polling(&mut self) {
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

    /// Starts a registry fetch off the frame path, at most once in
    /// `refresh_interval`. The result comes back as [`Inbound::Refreshed`].
    pub(super) fn refresh_in_background(&mut self, now_ns: u64) {
        let Some(source) = self.source.clone() else {
            return;
        };
        if !self.refresh_due(now_ns) {
            return;
        }
        self.last_refresh_attempt_ns = Some(now_ns);
        self.stats.refreshes = self.stats.refreshes.saturating_add(1);
        let tx = self.inbound_tx.clone();
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let fetched = tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                fetched = source.fetch() => fetched,
            };
            let _ = tx.send(Inbound::Refreshed(fetched)).await;
        });
    }

    pub(super) fn refresh_due(&self, now_ns: u64) -> bool {
        let floor = u64::try_from(self.refresh_interval.as_nanos()).unwrap_or(u64::MAX);
        self.source.is_some()
            && self
                .last_refresh_attempt_ns
                .is_none_or(|last| now_ns.saturating_sub(last) >= floor)
    }
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
