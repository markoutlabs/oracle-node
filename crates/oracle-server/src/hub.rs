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
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;
use oracle_types::{FeedId, Symbol};
use oracle_wire::SignedUpdate;
use tokio::sync::Notify;

use crate::protocol::{Encoding, JsonUpdate};

/// A signed update, serialized once and shared by every subscriber.
///
/// Signing and encoding happen once per update rather than once per subscriber —
/// with a few hundred subscribers that is the difference between a fanout that
/// scales and one that does not.
pub struct PreparedUpdate {
    /// The feed.
    pub feed_id: FeedId,
    /// The canonical symbol.
    pub symbol: Symbol,
    /// The 182-byte wire frame.
    binary: Bytes,
    /// The JSON view, built on first request and then shared.
    json: OnceLock<Bytes>,
    signed: SignedUpdate,
}

impl PreparedUpdate {
    /// Prepares a signed update for fanout.
    #[must_use]
    pub fn new(symbol: Symbol, signed: SignedUpdate) -> Self {
        Self {
            feed_id: signed.update().feed_id,
            symbol,
            binary: Bytes::copy_from_slice(&signed.encode_frame()),
            json: OnceLock::new(),
            signed,
        }
    }

    /// Returns the binary frame.
    #[must_use]
    pub fn binary(&self) -> Bytes {
        self.binary.clone()
    }

    /// Returns the JSON view, building it on first use.
    ///
    /// Lazy because most subscribers take binary, and serializing JSON for
    /// nobody is pure waste at a few thousand updates a second.
    #[must_use]
    pub fn json(&self) -> Bytes {
        self.json
            .get_or_init(|| {
                let view = JsonUpdate::new(&self.symbol, &self.signed);
                Bytes::from(serde_json::to_vec(&view).unwrap_or_else(|_| b"{}".to_vec()))
            })
            .clone()
    }

    /// Returns the encoded frame for a subscriber's chosen encoding.
    #[must_use]
    pub fn encoded(&self, encoding: Encoding) -> Bytes {
        match encoding {
            Encoding::Binary => self.binary(),
            Encoding::Json => self.json(),
        }
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
    /// Negotiated in the subscribe message, so it is settable after registration.
    encoding: Mutex<Encoding>,
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

    /// Returns the negotiated encoding.
    #[must_use]
    pub fn encoding(&self) -> Encoding {
        self.encoding
            .lock()
            .map_or(Encoding::Binary, |encoding| *encoding)
    }

    /// Sets the encoding, as negotiated in the subscribe message.
    pub fn set_encoding(&self, encoding: Encoding) {
        if let Ok(mut current) = self.encoding.lock() {
            *current = encoding;
        }
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
}

impl Hub {
    /// Builds a hub.
    ///
    /// `max_pending` bounds how many distinct feeds may be outstanding for one
    /// subscriber before it is declared lagged.
    #[must_use]
    pub fn new(max_pending: usize) -> Self {
        Self {
            subscribers: Mutex::new(HashMap::new()),
            latest: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            max_pending: max_pending.max(1),
        }
    }

    /// Registers a subscriber.
    #[must_use]
    pub fn subscribe(&self, encoding: Encoding) -> Arc<Subscriber> {
        let subscriber = Arc::new(Subscriber {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            encoding: Mutex::new(encoding),
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

    /// Publishes an update to every interested subscriber.
    pub fn publish(&self, symbol: Symbol, signed: SignedUpdate) -> Arc<PreparedUpdate> {
        let prepared = Arc::new(PreparedUpdate::new(symbol, signed));
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

    /// Returns the latest update for a feed.
    #[must_use]
    pub fn latest(&self, feed_id: FeedId) -> Option<Arc<PreparedUpdate>> {
        self.latest.lock().ok()?.get(&feed_id).cloned()
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
    use oracle_types::{Flags, PriceUpdate, Venue, VenueSet};
    use oracle_wire::{Signer, feed_id};

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
        let hub = Hub::new(64);
        let btc = symbol("CRYPTO.BTC/USD");
        let eth = symbol("CRYPTO.ETH/USD");

        let subscriber = hub.subscribe(Encoding::Binary);
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
        let hub = Hub::new(64);
        let btc = symbol("CRYPTO.BTC/USD");
        let subscriber = hub.subscribe(Encoding::Binary);
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
        let hub = Hub::new(64);
        let btc = symbol("CRYPTO.BTC/USD");
        let eth = symbol("CRYPTO.ETH/USD");
        let subscriber = hub.subscribe(Encoding::Binary);
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
        let hub = Hub::new(2);
        let subscriber = hub.subscribe(Encoding::Binary);
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
        let hub = Arc::new(Hub::new(64));
        let btc = symbol("CRYPTO.BTC/USD");
        let subscriber = hub.subscribe(Encoding::Binary);
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
        let hub = Arc::new(Hub::new(64));
        let subscriber = hub.subscribe(Encoding::Binary);
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
    fn the_latest_update_is_retained_for_rest_callers() {
        let hub = Hub::new(64);
        let btc = symbol("CRYPTO.BTC/USD");
        hub.publish(btc, signed(&btc, 1));
        hub.publish(btc, signed(&btc, 2));

        let latest = hub.latest(feed_id(&btc)).expect("present");
        assert_eq!(latest.signed().update().seq, 2);
        assert_eq!(hub.latest_all().len(), 1);
    }

    #[test]
    fn encoding_is_produced_once_and_shared() {
        let btc = symbol("CRYPTO.BTC/USD");
        let prepared = PreparedUpdate::new(btc, signed(&btc, 1));

        assert_eq!(prepared.binary().len(), oracle_wire::FRAME_SIZE);
        // The lazily-built JSON must be identical across calls, not rebuilt.
        assert_eq!(prepared.json(), prepared.json());
        assert_eq!(prepared.encoded(Encoding::Binary), prepared.binary());
        assert_eq!(prepared.encoded(Encoding::Json), prepared.json());
    }
}
