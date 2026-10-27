//! The network's feed set while the node runs (SPEC §3.8): the choice of a set
//! at start, and the task that takes each new set in this node's slot.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use oracle_agg::FeedConfig;
use oracle_node::NodeConfig;
use oracle_node::feed_set::{self, Chosen, Subscriptions};
use oracle_node::publish::PushPace;
use oracle_server::{ServerState, unix_now};
use oracle_types::{FeedId, InstrumentId, Symbol};
use oracle_wire::{Address, VerifiedFeedSet};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::ingest::Ingest;
use crate::notify;

/// The newest good copy of the network's feed set, cached or fetched; `None` for the config's own feeds.
pub(crate) async fn first_feed_set(
    config: &NodeConfig,
    path: &Path,
    governance: Address,
) -> Option<Chosen> {
    config.network_feeds.as_ref()?;
    notify::status("fetching the network feed set");
    let cache_path = feed_set::cache_path(path);
    let cached = feed_set::read_cache(&cache_path);
    let cached_version = cached.as_ref().map(|set| set.version);
    let mut candidates: Vec<_> = cached.map(|set| ("cached", set)).into_iter().collect();
    match config.fetch_feed_set().await {
        Ok(Some(set)) => candidates.push(("fetched", set)),
        Ok(None) => {}
        Err(error) => warn!(%error, "the network feed set could not be fetched"),
    }
    let (chosen, refused) = feed_set::choose(config, candidates, governance);
    for reason in refused {
        warn!(%reason, "network feed set refused");
    }
    let Some(chosen) = chosen else {
        warn!("no network feed set the node can use; it serves the feeds of its config");
        return None;
    };
    if Some(chosen.set.version()) != cached_version {
        cache(&cache_path, chosen.set.as_feed_set());
    }
    warn_dropped(&chosen.checked.dropped_endpoints);
    info!(
        version = chosen.set.version(),
        feeds = chosen.set.feeds().len(),
        "serving the network feed set"
    );
    Some(chosen)
}

/// Caches the set the node serves. A failure only costs a fetch at the next start.
fn cache(path: &Path, set: &oracle_wire::FeedSet) {
    if let Err(error) = feed_set::write_cache(path, set) {
        warn!(%error, path = %path.display(), "cannot cache the network feed set; the next start fetches it again");
    }
}

fn warn_dropped(endpoints: &[String]) {
    for endpoint in endpoints {
        warn!(%endpoint, "the feed set does not read this market; its [[endpoints]] override is dropped");
    }
}

/// A new feed set for the pipeline task, which alone owns the aggregator.
pub(crate) struct Reconfigure {
    pub(crate) feeds: Vec<FeedConfig>,
    pub(crate) reply: oneshot::Sender<Result<(), String>>,
}

/// The books of each feed's sources, which the server serves.
pub(crate) fn books_of(feeds: &[FeedConfig]) -> HashMap<FeedId, Vec<InstrumentId>> {
    feeds
        .iter()
        .map(|feed| {
            let sources = feed.sources.iter().map(|source| source.instrument.clone());
            (feed.feed_id, sources.collect())
        })
        .collect()
}

/// The symbol of each feed id, for the tail.
pub(crate) fn names(feeds: &[FeedConfig]) -> HashMap<FeedId, Symbol> {
    feeds
        .iter()
        .map(|feed| (feed.feed_id, feed.symbol))
        .collect()
}

/// The push task's pace: the feed set's, else the node's own `[publish]` pace.
pub(crate) struct Pace {
    sender: watch::Sender<PushPace>,
    own: PushPace,
}

impl Pace {
    /// The pace for `set`, and the receiver for the push task.
    pub(crate) fn new(
        own: PushPace,
        set: Option<&VerifiedFeedSet>,
    ) -> (Self, watch::Receiver<PushPace>) {
        let (sender, paced) = watch::channel(Self::of(own, set));
        (Self { sender, own }, paced)
    }

    fn of(own: PushPace, set: Option<&VerifiedFeedSet>) -> PushPace {
        set.and_then(VerifiedFeedSet::push)
            .map_or(own, PushPace::from)
    }

    /// Moves the push task to the pace of `set`.
    fn follow(&self, set: &VerifiedFeedSet) {
        let next = Self::of(self.own, Some(set));
        self.sender.send_if_modified(|current| {
            let changed = *current != next;
            *current = next;
            changed
        });
    }
}

/// The feeds in force and where this node's change slot is.
pub(crate) struct FeedSetTask {
    /// The node's config with the feeds in force.
    pub(crate) config: NodeConfig,
    /// The same feeds, resolved, as the pipeline runs them.
    pub(crate) feeds_in_force: Vec<FeedConfig>,
    /// The instruments of each venue's adapter.
    pub(crate) subscriptions: Subscriptions,
    pub(crate) version: u64,
    pub(crate) governance: Address,
    /// This node's place in the registry, and the node count.
    pub(crate) index: usize,
    pub(crate) nodes: usize,
    pub(crate) slots: oracle_wire::Slots,
    pub(crate) poll: Duration,
    pub(crate) cache: PathBuf,
    pub(crate) state: Arc<ServerState>,
    pub(crate) ingest: Ingest,
    pub(crate) pipeline: mpsc::Sender<Reconfigure>,
    pub(crate) pace: Option<Pace>,
    /// A `--record` run: the node stops at its slot instead, so a recording
    /// holds one feed set.
    pub(crate) recording: bool,
    /// Cancelled when the node must restart on the new set.
    pub(crate) restart: CancellationToken,
    pub(crate) shutdown: CancellationToken,
}

impl FeedSetTask {
    pub(crate) async fn run(mut self) {
        let mut ticker = tokio::time::interval(self.poll);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        // Until the canister serves a set, each poll fails the same way.
        let mut last_failure: Option<String> = None;
        loop {
            tokio::select! {
                biased;
                () = self.shutdown.cancelled() => return,
                _ = ticker.tick() => {}
            }
            let set = match self.config.fetch_feed_set().await {
                Ok(Some(set)) => set,
                Ok(None) => return,
                Err(error) => {
                    let error = error.to_string();
                    if last_failure.as_ref() != Some(&error) {
                        warn!(%error, "the network feed set could not be fetched; the node keeps its feeds and logs this again only when it changes");
                        last_failure = Some(error);
                    }
                    continue;
                }
            };
            if last_failure.take().is_some() {
                info!(
                    version = set.version,
                    "the network feed set can be fetched again"
                );
            }
            if set.version <= self.version {
                continue;
            }
            let chosen = match feed_set::accept(&self.config, &set, self.governance, self.version) {
                Ok(chosen) => chosen,
                Err(reason) => {
                    warn!(version = set.version, %reason, "network feed set refused; the node keeps its feeds");
                    continue;
                }
            };
            cache(&self.cache, chosen.set.as_feed_set());
            let now = unix_now();
            let at = self
                .slots
                .apply_at(chosen.set.effective_from(), self.index, self.nodes, now);
            info!(
                version = chosen.set.version(),
                in_secs = at.saturating_sub(now),
                "new network feed set; the node takes it in its slot"
            );
            tokio::select! {
                () = self.shutdown.cancelled() => return,
                () = tokio::time::sleep(Duration::from_secs(at.saturating_sub(now))) => {}
            }
            if self.recording {
                info!(
                    "a new feed set: the node stops at its slot, so the recording holds one feed set"
                );
                self.restart.cancel();
                return;
            }
            if let Err(error) = self.apply(chosen).await {
                error!(%error, "the live feed set change failed; the node restarts on the new set");
                self.restart.cancel();
                return;
            }
        }
    }

    /// New feeds join the catalog first and old ones leave last, so the server lists every feed it serves.
    async fn apply(&mut self, chosen: Chosen) -> anyhow::Result<()> {
        let version = chosen.set.version();
        warn_dropped(&chosen.checked.dropped_endpoints);
        let resolved = chosen.checked.resolved;
        let subscriptions = feed_set::subscriptions(&resolved);
        let changed = feed_set::changed_venues(&self.subscriptions, &subscriptions);

        let new_books = books_of(&resolved.feeds);
        let mut both: HashMap<FeedId, Vec<InstrumentId>> = books_of(&self.feeds_in_force);
        both.extend(new_books.clone());
        let mut symbols: Vec<Symbol> = self.feeds_in_force.iter().map(|feed| feed.symbol).collect();
        for symbol in &resolved.symbols {
            if !symbols.contains(symbol) {
                symbols.push(*symbol);
            }
        }
        let max_pending = self.config.max_pending_for(symbols.len());
        self.state
            .set_feeds(&symbols, both, self.version, max_pending);

        let (reply, answer) = oneshot::channel();
        self.pipeline
            .send(Reconfigure {
                feeds: resolved.feeds.clone(),
                reply,
            })
            .await
            .map_err(|_| anyhow::anyhow!("the pipeline task stopped"))?;
        answer
            .await
            .map_err(|_| anyhow::anyhow!("the pipeline task stopped"))?
            .map_err(|error| anyhow::anyhow!("the aggregator refused the set: {error}"))?;

        self.ingest
            .swap(&changed, resolved.binance, resolved.venues)
            .await?;

        let max_pending = self.config.max_pending_for(resolved.symbols.len());
        self.state
            .set_feeds(&resolved.symbols, new_books, version, max_pending);
        if let Some(pace) = &self.pace {
            pace.follow(&chosen.set);
        }
        info!(
            version,
            feeds = resolved.symbols.len(),
            venues = ?changed.iter().map(|venue| venue.as_str()).collect::<Vec<_>>(),
            "network feed set applied"
        );
        self.config = chosen.checked.config;
        self.version = version;
        self.feeds_in_force = resolved.feeds;
        self.subscriptions = subscriptions;
        Ok(())
    }
}
