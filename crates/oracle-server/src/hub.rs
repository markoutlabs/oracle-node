//! Fanout with conflation.
//!
//! # Why conflate rather than queue
//!
//! For a price feed, a stale update has negative value. Delivering a
//! four-second-old price from behind a backlog is worse than skipping it: the
//! consumer acts on it as though it were current. So each subscriber gets **one
//! slot per feed**, and a newer update for a feed replaces the pending older one
//! rather than queueing behind it.
//!
//! The consequence, which consumers must understand: **you observe state, not
//! transitions.** A sub-second halt can be replaced by a subsequent healthy
//! update and never seen. That is acceptable because every frame carries
//! complete state and the node's heartbeat makes any halt lasting longer than
//! one interval unmissable — but a consumer that accumulates transitions rather
//! than reading state will be wrong. If every transition matters, that is a
//! durable log, not a live socket.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use oracle_transport::{BroadcastSealer, os_rng};
use oracle_types::{FeedId, Symbol};
use oracle_wire::{Address, SignedUpdate};
use tokio::sync::Notify;

/// A signed update, serialized and sealed once and shared by every subscriber.
///
/// Signing, encoding and sealing happen once per update rather than once per
/// subscriber; with a few hundred subscribers that is the difference between a
/// fanout that scales and one that does not.
pub struct PreparedUpdate {
    /// The feed.
    pub feed_id: FeedId,
    /// The canonical symbol.
    pub symbol: Symbol,
    /// The 182-byte signed frame.
    binary: Bytes,
    /// `binary` sealed under the broadcast key: what every subscriber receives.
    sealed: Bytes,
    signed: SignedUpdate,
}

impl PreparedUpdate {
    /// Prepares a signed update for fanout, sealing it once.
    #[must_use]
    pub fn new(symbol: Symbol, signed: SignedUpdate, sealer: &BroadcastSealer) -> Self {
        let binary = Bytes::copy_from_slice(&signed.encode_frame());
        let sealed = Bytes::from(sealer.seal(&binary, &mut os_rng()));
        Self {
            feed_id: signed.update().feed_id,
            symbol,
            binary,
            sealed,
            signed,
        }
    }

    /// Returns the sealed frame, the same bytes for every subscriber.
    #[must_use]
    pub fn sealed(&self) -> Bytes {
        self.sealed.clone()
    }

    /// Returns the binary frame.
    #[must_use]
    pub fn binary(&self) -> Bytes {
        self.binary.clone()
    }

    /// Returns the signed update.
    #[must_use]
    pub const fn signed(&self) -> &SignedUpdate {
        &self.signed
    }
}

/// What a subscriber is listening to.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Selection {
    /// Every feed. Rate-capped separately: it is a trivial self-inflicted denial
    /// of service as the catalogue grows.
    Firehose,
    /// A specific set.
    Feeds(std::collections::HashSet<FeedId>),
}

impl Selection {
    fn wants(&self, feed_id: FeedId) -> bool {
        match self {
            Self::Firehose => true,
            Self::Feeds(feeds) => feeds.contains(&feed_id),
        }
    }
}

/// One subscriber's conflating mailbox.
pub struct Subscriber {
    id: u64,
    client: Address,
    selection: Mutex<Selection>,
    pending: Mutex<HashMap<FeedId, Arc<PreparedUpdate>>>,
    dropped: AtomicU64,
    lagged: AtomicBool,
    closed: AtomicBool,
    notify: Notify,
    max_pending: usize,
}

impl Subscriber {
    /// Returns the subscriber id.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the authenticated client's address.
    #[must_use]
    pub const fn client(&self) -> Address {
        self.client
    }

    /// Replaces the feed selection.
    pub fn select(&self, feeds: std::collections::HashSet<FeedId>) {
        if let Ok(mut selection) = self.selection.lock() {
            *selection = Selection::Feeds(feeds);
        }
    }

    /// Subscribes to every feed.
    pub fn select_firehose(&self) {
        if let Ok(mut selection) = self.selection.lock() {
            *selection = Selection::Firehose;
        }
    }

    /// Adds feeds to the selection.
    pub fn add(&self, feeds: impl IntoIterator<Item = FeedId>) {
        if let Ok(mut selection) = self.selection.lock()
            && let Selection::Feeds(set) = &mut *selection
        {
            set.extend(feeds);
        }
    }

    /// Removes feeds from the selection.
    pub fn remove(&self, feeds: impl IntoIterator<Item = FeedId>) {
        if let Ok(mut selection) = self.selection.lock()
            && let Selection::Feeds(set) = &mut *selection
        {
            for feed in feeds {
                set.remove(&feed);
            }
        }
    }

    /// Returns `true` if this subscriber wants `feed_id`.
    #[must_use]
    pub fn wants(&self, feed_id: FeedId) -> bool {
        self.selection
            .lock()
            .is_ok_and(|selection| selection.wants(feed_id))
    }

    /// Returns how many updates were conflated away.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Returns `true` if the subscriber fell too far behind.
    #[must_use]
    pub fn is_lagged(&self) -> bool {
        self.lagged.load(Ordering::Relaxed)
    }

    /// Returns `true` if the subscriber has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Closes the subscriber and wakes its writer.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    /// Offers an update, replacing any pending one for the same feed.
    fn offer(&self, update: &Arc<PreparedUpdate>) {
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        if pending.len() >= self.max_pending && !pending.contains_key(&update.feed_id) {
            // Too many distinct feeds outstanding: this subscriber is not
            // keeping up at all. Say so rather than quietly dropping data.
            self.lagged.store(true, Ordering::Relaxed);
            self.notify.notify_waiters();
            return;
        }
        if pending.insert(update.feed_id, Arc::clone(update)).is_some() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        drop(pending);
        self.notify.notify_waiters();
    }

    /// Takes everything pending, or waits until there is something.
    ///
    /// Returns an empty vector when the subscriber is closed or has lagged, so
    /// the caller can check [`Subscriber::is_lagged`] and report it.
    pub async fn drain(&self) -> Vec<Arc<PreparedUpdate>> {
        loop {
            if self.is_closed() || self.is_lagged() {
                return Vec::new();
            }
            {
                let Ok(mut pending) = self.pending.lock() else {
                    return Vec::new();
                };
                if !pending.is_empty() {
                    return pending.drain().map(|(_, update)| update).collect();
                }
            }
            self.notify.notified().await;
        }
    }
}

/// The publish-side registry of subscribers, plus the latest update per feed.
pub struct Hub {
    subscribers: Mutex<HashMap<u64, Arc<Subscriber>>>,
    latest: Mutex<HashMap<FeedId, Arc<PreparedUpdate>>>,
    next_id: AtomicU64,
    max_pending: usize,
    sealer: Arc<BroadcastSealer>,
}

impl Hub {
    /// Builds a hub.
    ///
    /// `max_pending` bounds how many distinct feeds may be outstanding for one
    /// subscriber before it is declared lagged. `sealer` seals each update once
    /// under the node's broadcast key.
    #[must_use]
    pub fn new(max_pending: usize, sealer: Arc<BroadcastSealer>) -> Self {
        Self {
            subscribers: Mutex::new(HashMap::new()),
            latest: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            max_pending: max_pending.max(1),
            sealer,
        }
    }

    /// Registers an authenticated subscriber.
    #[must_use]
    pub fn subscribe(&self, client: Address) -> Arc<Subscriber> {
        let subscriber = Arc::new(Subscriber {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            client,
            selection: Mutex::new(Selection::Feeds(std::collections::HashSet::new())),
            pending: Mutex::new(HashMap::new()),
            dropped: AtomicU64::new(0),
            lagged: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            notify: Notify::new(),
            max_pending: self.max_pending,
        });
        if let Ok(mut subscribers) = self.subscribers.lock() {
            subscribers.insert(subscriber.id, Arc::clone(&subscriber));
        }
        subscriber
    }

    /// Removes a subscriber.
    pub fn unsubscribe(&self, id: u64) {
        if let Ok(mut subscribers) = self.subscribers.lock()
            && let Some(subscriber) = subscribers.remove(&id)
        {
            subscriber.close();
        }
    }

    /// Returns the current subscriber count.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers
            .lock()
            .map_or(0, |subscribers| subscribers.len())
    }

    /// Publishes an update to every interested subscriber. This is the one place
    /// a frame is sealed, before any subscriber sees it.
    pub fn publish(&self, symbol: Symbol, signed: SignedUpdate) -> Arc<PreparedUpdate> {
        let prepared = Arc::new(PreparedUpdate::new(symbol, signed, &self.sealer));
        if let Ok(mut latest) = self.latest.lock() {
            latest.insert(prepared.feed_id, Arc::clone(&prepared));
        }
        if let Ok(subscribers) = self.subscribers.lock() {
            for subscriber in subscribers.values() {
                if !subscriber.is_closed() && subscriber.wants(prepared.feed_id) {
                    subscriber.offer(&prepared);
                }
            }
        }
        prepared
    }

    /// Returns the latest update for every feed.
    #[must_use]
    pub fn latest_all(&self) -> Vec<Arc<PreparedUpdate>> {
        self.latest
            .lock()
            .map_or_else(|_| Vec::new(), |latest| latest.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_transport::NodeKeySchedule;
    use oracle_types::{Flags, PriceUpdate, Venue, VenueSet};
    use oracle_wire::{Signer, feed_id};

    fn sealer() -> Arc<BroadcastSealer> {
        let schedule = NodeKeySchedule::new(
            oracle_wire::Address::from_bytes([0xA1; 20]),
            60,
            1_754_582_400,
            &mut os_rng(),
        );
        Arc::new(BroadcastSealer::new(Arc::clone(schedule.current())))
    }

    fn hub(max_pending: usize) -> Hub {
        Hub::new(max_pending, sealer())
    }

    fn symbol(text: &str) -> Symbol {
        text.parse().expect("valid symbol")
    }

    fn signed(symbol: &Symbol, seq: u64) -> SignedUpdate {
        let signer = Signer::from_secret_bytes([5; 32]).expect("valid key");
        signer.sign_update(&PriceUpdate {
            feed_id: feed_id(symbol),
            flags: Flags::NONE,
            price: 6_400_000_000_000,
            conf: 50_000_000,
            expo: -8,
            publish_time_ns: 1_754_582_400_000_000_000 + seq,
            observation_time_ns: 1_754_582_400_000_000_000,
            prev_publish_time_ns: 1_754_582_399_000_000_000,
            seq,
            num_sources: 5,
            sources: Venue::ALL.into_iter().collect::<VenueSet>(),
        })
    }

    #[tokio::test]
    async fn a_subscriber_receives_the_feeds_it_selected() {
        let hub = hub(64);
        let btc = symbol("CRYPTO.BTC/USD");
        let eth = symbol("CRYPTO.ETH/USD");

        let subscriber = hub.subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        subscriber.select([feed_id(&btc)].into_iter().collect());

        hub.publish(btc, signed(&btc, 1));
        hub.publish(eth, signed(&eth, 1));

        let drained = subscriber.drain().await;
        assert_eq!(drained.len(), 1, "only the selected feed should arrive");
        assert_eq!(
            drained.first().map(|update| update.feed_id),
            Some(feed_id(&btc))
        );
    }

    /// The defining behaviour: a slow subscriber gets the newest price, not a
    /// backlog of old ones.
    #[tokio::test]
    async fn a_slow_subscriber_gets_the_latest_not_a_backlog() {
        let hub = hub(64);
        let btc = symbol("CRYPTO.BTC/USD");
        let subscriber = hub.subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        subscriber.select([feed_id(&btc)].into_iter().collect());

        for seq in 1..=100 {
            hub.publish(btc, signed(&btc, seq));
        }

        let drained = subscriber.drain().await;
        assert_eq!(drained.len(), 1, "100 updates must conflate to one slot");
        assert_eq!(
            drained.first().map(|update| update.signed().update().seq),
            Some(100),
            "and it must be the newest"
        );
        assert_eq!(subscriber.dropped(), 99);
    }

    #[tokio::test]
    async fn conflation_is_per_feed_not_global() {
        let hub = hub(64);
        let btc = symbol("CRYPTO.BTC/USD");
        let eth = symbol("CRYPTO.ETH/USD");
        let subscriber = hub.subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        subscriber.select_firehose();

        for seq in 1..=10 {
            hub.publish(btc, signed(&btc, seq));
            hub.publish(eth, signed(&eth, seq));
        }

        let drained = subscriber.drain().await;
        assert_eq!(drained.len(), 2, "one slot per feed, both retained");
    }

    #[tokio::test]
    async fn a_subscriber_too_far_behind_is_marked_lagged() {
        // Room for two distinct feeds outstanding.
        let hub = hub(2);
        let subscriber = hub.subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        subscriber.select_firehose();

        for index in 0..5_u8 {
            let symbol = symbol(&format!("CRYPTO.A{index}/USD"));
            hub.publish(symbol, signed(&symbol, 1));
        }

        assert!(
            subscriber.is_lagged(),
            "must be flagged rather than silently dropping"
        );
        assert!(
            subscriber.drain().await.is_empty(),
            "a lagged subscriber stops receiving"
        );
    }

    #[tokio::test]
    async fn drain_waits_until_something_arrives() {
        let hub = Arc::new(hub(64));
        let btc = symbol("CRYPTO.BTC/USD");
        let subscriber = hub.subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        subscriber.select_firehose();

        let waiter = {
            let subscriber = Arc::clone(&subscriber);
            tokio::spawn(async move { subscriber.drain().await })
        };
        tokio::task::yield_now().await;

        hub.publish(btc, signed(&btc, 1));
        let drained = waiter.await.expect("joins");
        assert_eq!(drained.len(), 1);
    }

    #[tokio::test]
    async fn closing_wakes_a_waiting_subscriber() {
        let hub = Arc::new(hub(64));
        let subscriber = hub.subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        subscriber.select_firehose();

        let waiter = {
            let subscriber = Arc::clone(&subscriber);
            tokio::spawn(async move { subscriber.drain().await })
        };
        tokio::task::yield_now().await;

        hub.unsubscribe(subscriber.id());
        assert!(waiter.await.expect("joins").is_empty());
        assert_eq!(hub.subscriber_count(), 0);
    }

    #[test]
    fn the_latest_update_is_retained_for_health() {
        let hub = hub(64);
        let btc = symbol("CRYPTO.BTC/USD");
        hub.publish(btc, signed(&btc, 1));
        hub.publish(btc, signed(&btc, 2));

        let latest = hub.latest_all();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest.first().map(|u| u.signed().update().seq), Some(2));
    }

    /// Check 1: the publish path seals once per update, whatever the number of
    /// subscribers, and every subscriber gets the same bytes.
    #[tokio::test]
    async fn an_update_is_sealed_once_for_any_number_of_subscribers() {
        let sealer = sealer();
        let hub = Hub::new(64, Arc::clone(&sealer));
        let btc = symbol("CRYPTO.BTC/USD");
        for (round, count) in [(1_u64, 1_usize), (2, 10), (3, 1000)] {
            let subscribers: Vec<Arc<Subscriber>> = (0..count)
                .map(|_| {
                    let subscriber = hub.subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
                    subscriber.select_firehose();
                    subscriber
                })
                .collect();
            let before = sealer.seals();
            hub.publish(btc, signed(&btc, round));
            assert_eq!(sealer.seals() - before, 1, "{count} subscribers");
            let mut copies = Vec::with_capacity(count);
            for subscriber in &subscribers {
                let drained = subscriber.drain().await;
                let update = drained.first().expect("delivered");
                copies.push(update.sealed());
                hub.unsubscribe(subscriber.id());
            }
            assert!(copies.iter().all(|copy| Some(copy) == copies.first()));
        }
    }
}
