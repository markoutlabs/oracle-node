//! Fanout to web clients.
//!
//! Each message is serialized once and shared. A price or a venue report keeps
//! one slot per key, so a slow client gets the newest state, not a backlog. Book
//! messages queue, because a delta builds on the one before it. A queue that
//! fills is replaced by a fresh snapshot, so a slow client loses frames but
//! never holds a wrong book.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oracle_client::{AcceptedVenues, Book, ClientStats, Resolved};
use oracle_types::{BookLevel, FeedId, InstrumentId, Symbol, side_changes};
use oracle_wire::{Address, feed_id};
use tokio::sync::Notify;

use crate::protocol::{self, BookFrame, Topics};

/// A conflating slot: the newest message replaces the one waiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Slot {
    Price(FeedId),
    Venues(FeedId, Address),
}

/// Every lock here guards plain data that each write leaves whole.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
struct Selection {
    prices: HashSet<FeedId>,
    venues: HashSet<FeedId>,
    books: HashSet<InstrumentId>,
}

impl Selection {
    fn len(&self) -> usize {
        self.prices.len() + self.venues.len() + self.books.len()
    }
}

#[derive(Default)]
struct Outbox {
    replies: VecDeque<Arc<str>>,
    slots: HashMap<Slot, Arc<str>>,
    books: HashMap<InstrumentId, Vec<Arc<str>>>,
}

/// One web socket's subscriptions and waiting messages.
pub struct WebClient {
    id: u64,
    ip: IpAddr,
    selection: Mutex<Selection>,
    outbox: Mutex<Outbox>,
    notify: Notify,
    closed: AtomicBool,
    max_book_queue: usize,
}

impl WebClient {
    /// Returns the client id.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the client's address.
    #[must_use]
    pub const fn ip(&self) -> IpAddr {
        self.ip
    }

    /// Queues a reply ahead of any data.
    pub fn reply(&self, message: Arc<str>) {
        lock(&self.outbox).replies.push_back(message);
        self.notify.notify_one();
    }

    /// Marks the client closed and wakes its writer.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.notify.notify_one();
    }

    /// Returns `true` once the client is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Takes everything waiting, or waits for something. Once closed, it still
    /// returns what waits, such as a last error, and then nothing.
    pub async fn drain(&self) -> Vec<Arc<str>> {
        loop {
            {
                let mut outbox = lock(&self.outbox);
                let mut messages: Vec<Arc<str>> = outbox.replies.drain(..).collect();
                messages.extend(outbox.slots.drain().map(|(_, message)| message));
                for queue in outbox.books.values_mut() {
                    messages.append(queue);
                }
                if !messages.is_empty() {
                    return messages;
                }
            }
            if self.is_closed() {
                return Vec::new();
            }
            self.notify.notified().await;
        }
    }

    fn offer(&self, slot: Slot, message: &Arc<str>) {
        lock(&self.outbox).slots.insert(slot, Arc::clone(message));
        self.notify.notify_one();
    }

    /// Queues a book message. Past the limit, the queue becomes one snapshot.
    fn offer_book(
        &self,
        instrument: &InstrumentId,
        message: &Arc<str>,
        snapshot: &dyn Fn() -> Arc<str>,
    ) {
        let mut outbox = lock(&self.outbox);
        let queue = outbox.books.entry(instrument.clone()).or_default();
        if queue.len() >= self.max_book_queue {
            queue.clear();
            queue.push(snapshot());
        } else {
            queue.push(Arc::clone(message));
        }
        drop(outbox);
        self.notify.notify_one();
    }

    /// Replaces a book's queue with one snapshot.
    fn restart_book(&self, instrument: &InstrumentId, snapshot: Arc<str>) {
        let mut outbox = lock(&self.outbox);
        let queue = outbox.books.entry(instrument.clone()).or_default();
        queue.clear();
        queue.push(snapshot);
        drop(outbox);
        self.notify.notify_one();
    }
}

/// The book a web client holds, at the proxy's `seq` for it.
struct ServedBook {
    instrument: InstrumentId,
    source: Option<Book>,
    seq: u64,
    bids: BTreeMap<i64, u64>,
    asks: BTreeMap<i64, u64>,
}

impl ServedBook {
    fn snapshot(&self) -> Arc<str> {
        protocol::book_message(&BookFrame {
            instrument: &self.instrument,
            seq: self.seq,
            snapshot: true,
            available: self.source.is_some(),
            source: self.source.as_ref(),
            bids: levels(self.bids.iter().rev()),
            asks: levels(self.asks.iter()),
        })
    }
}

fn levels<'a>(side: impl Iterator<Item = (&'a i64, &'a u64)>) -> Vec<BookLevel> {
    side.map(|(price, qty)| BookLevel {
        price: *price,
        qty: *qty,
    })
    .collect()
}

/// The upstream client's state, for `/health`.
#[derive(Clone, Copy, Debug, Default)]
pub struct UpstreamStatus {
    /// The registry version the upstream client trusts.
    pub registry_version: u64,
    /// The upstream client's counters.
    pub stats: ClientStats,
}

/// Every web client, the latest messages, and the served books.
pub struct Hub {
    prices: HashMap<String, Symbol>,
    venues: HashMap<String, Symbol>,
    clients: Mutex<HashMap<u64, Arc<WebClient>>>,
    latest: Mutex<HashMap<Slot, Arc<str>>>,
    books: Mutex<HashMap<InstrumentId, ServedBook>>,
    upstream: Mutex<UpstreamStatus>,
    next_id: AtomicU64,
    max_subscriptions: usize,
    max_book_queue: usize,
}

impl Hub {
    /// Builds a hub that serves these prices and venue reports.
    #[must_use]
    pub fn new(
        prices: &[Symbol],
        venues: &[Symbol],
        max_subscriptions: usize,
        max_book_queue: usize,
    ) -> Self {
        let names = |symbols: &[Symbol]| {
            symbols
                .iter()
                .map(|symbol| (symbol.to_string(), *symbol))
                .collect()
        };
        Self {
            prices: names(prices),
            venues: names(venues),
            clients: Mutex::new(HashMap::new()),
            latest: Mutex::new(HashMap::new()),
            books: Mutex::new(HashMap::new()),
            upstream: Mutex::new(UpstreamStatus::default()),
            next_id: AtomicU64::new(1),
            max_subscriptions,
            max_book_queue: max_book_queue.max(1),
        }
    }

    /// Registers a web client.
    pub fn connect(&self, ip: IpAddr) -> Arc<WebClient> {
        let client = Arc::new(WebClient {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            ip,
            selection: Mutex::new(Selection::default()),
            outbox: Mutex::new(Outbox::default()),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
            max_book_queue: self.max_book_queue,
        });
        lock(&self.clients).insert(client.id, Arc::clone(&client));
        client
    }

    /// Removes a web client.
    pub fn disconnect(&self, id: u64) {
        if let Some(client) = lock(&self.clients).remove(&id) {
            client.close();
        }
    }

    /// Returns the number of web clients.
    #[must_use]
    pub fn client_count(&self) -> usize {
        lock(&self.clients).len()
    }

    /// Applies a subscribe request and returns the reply. All or nothing past
    /// the subscription limit.
    pub fn subscribe(&self, client: &WebClient, topics: &Topics) -> Arc<str> {
        let (accepted, prices, venues, books, unknown) = self.resolve(topics);
        let current = lock(&client.selection).len();
        if current.saturating_add(accepted.len()) > self.max_subscriptions {
            return protocol::error(
                "too_many_subscriptions",
                &format!("at most {} subscriptions", self.max_subscriptions),
            );
        }
        {
            // Under the lock that publishing takes, so no update falls between
            // the selection and the latest message.
            let latest = lock(&self.latest);
            let mut selection = lock(&client.selection);
            selection.prices.extend(prices.iter().copied());
            selection.venues.extend(venues.iter().copied());
            drop(selection);
            for (slot, message) in latest.iter() {
                let wanted = match slot {
                    Slot::Price(feed) => prices.contains(feed),
                    Slot::Venues(feed, _) => venues.contains(feed),
                };
                if wanted {
                    client.offer(*slot, message);
                }
            }
        }
        {
            let served = lock(&self.books);
            lock(&client.selection).books.extend(books.iter().cloned());
            for book in &books {
                if let Some(served) = served.get(book) {
                    client.restart_book(book, served.snapshot());
                }
            }
        }
        protocol::subscribed("subscribed", &accepted, &unknown)
    }

    /// Applies an unsubscribe request and returns the reply.
    pub fn unsubscribe(&self, client: &WebClient, topics: &Topics) -> Arc<str> {
        let (accepted, prices, venues, books, _) = self.resolve(topics);
        let mut selection = lock(&client.selection);
        for feed in &prices {
            selection.prices.remove(feed);
        }
        for feed in &venues {
            selection.venues.remove(feed);
        }
        for book in &books {
            selection.books.remove(book);
        }
        drop(selection);
        let mut outbox = lock(&client.outbox);
        outbox.slots.retain(|slot, _| match slot {
            Slot::Price(feed) => !prices.contains(feed),
            Slot::Venues(feed, _) => !venues.contains(feed),
        });
        for book in &books {
            outbox.books.remove(book);
        }
        drop(outbox);
        protocol::subscribed("unsubscribed", &accepted, &[])
    }

    /// Splits topics into the ones this proxy serves and the rest.
    fn resolve(
        &self,
        topics: &Topics,
    ) -> (
        Topics,
        HashSet<FeedId>,
        HashSet<FeedId>,
        Vec<InstrumentId>,
        Vec<String>,
    ) {
        let mut accepted = Topics::default();
        let mut unknown = Vec::new();
        let mut feeds =
            |names: &[String], served: &HashMap<String, Symbol>, out: &mut Vec<String>| {
                let mut ids = HashSet::new();
                for name in names {
                    match served.get(name) {
                        Some(symbol) => {
                            ids.insert(feed_id(symbol));
                            out.push(name.clone());
                        }
                        None => unknown.push(name.clone()),
                    }
                }
                ids
            };
        let prices = feeds(&topics.prices, &self.prices, &mut accepted.prices);
        let venues = feeds(&topics.venues, &self.venues, &mut accepted.venues);
        let served = lock(&self.books);
        let mut books = Vec::new();
        for name in &topics.books {
            match protocol::parse_book(name).filter(|book| served.contains_key(book)) {
                Some(book) => {
                    books.push(book);
                    accepted.books.push(name.clone());
                }
                None => unknown.push(name.clone()),
            }
        }
        (accepted, prices, venues, books, unknown)
    }

    /// Publishes a resolved price.
    pub fn publish_price(&self, resolved: &Resolved) {
        let Some(symbol) = self
            .prices
            .values()
            .find(|symbol| feed_id(symbol) == resolved.feed_id)
        else {
            return;
        };
        let message = protocol::price_message(symbol, resolved);
        self.publish(Slot::Price(resolved.feed_id), &message, |selection| {
            selection.prices.contains(&resolved.feed_id)
        });
    }

    /// Publishes one node's venue report.
    pub fn publish_venues(&self, accepted: &AcceptedVenues) {
        let feed = accepted.report.feed_id;
        let Some(symbol) = self.venues.values().find(|symbol| feed_id(symbol) == feed) else {
            return;
        };
        let message = protocol::venues_message(symbol, accepted);
        self.publish(Slot::Venues(feed, accepted.signer), &message, |selection| {
            selection.venues.contains(&feed)
        });
    }

    fn publish(&self, slot: Slot, message: &Arc<str>, wants: impl Fn(&Selection) -> bool) {
        let mut latest = lock(&self.latest);
        latest.insert(slot, Arc::clone(message));
        for client in lock(&self.clients).values() {
            if wants(&lock(&client.selection)) {
                client.offer(slot, message);
            }
        }
    }

    /// Moves a served book to the SDK's freshest valid book, `None` when there
    /// is none, and sends subscribers what changed.
    ///
    /// A change of node, or a book that comes back, is a snapshot: two nodes'
    /// books are not deltas of each other.
    pub fn update_book(&self, instrument: &InstrumentId, current: Option<&Book>) {
        let mut books = lock(&self.books);
        let served = books
            .entry(instrument.clone())
            .or_insert_with(|| ServedBook {
                instrument: instrument.clone(),
                source: None,
                seq: 0,
                bids: BTreeMap::new(),
                asks: BTreeMap::new(),
            });
        let message = match current {
            None if served.source.is_none() => return,
            None => {
                served.source = None;
                served.bids.clear();
                served.asks.clear();
                served.seq = served.seq.saturating_add(1);
                served.snapshot()
            }
            Some(book) => {
                let bids: BTreeMap<i64, u64> = book.bids().map(|l| (l.price, l.qty)).collect();
                let asks: BTreeMap<i64, u64> = book.asks().map(|l| (l.price, l.qty)).collect();
                let same_node = served.source.as_ref().is_some_and(|s| s.node == book.node);
                if same_node {
                    let changed_bids = side_changes(&served.bids, &bids);
                    let changed_asks = side_changes(&served.asks, &asks);
                    if changed_bids.is_empty() && changed_asks.is_empty() {
                        return;
                    }
                    served.seq = served.seq.saturating_add(1);
                    served.bids = bids;
                    served.asks = asks;
                    served.source = Some(book.clone());
                    protocol::book_message(&BookFrame {
                        instrument,
                        seq: served.seq,
                        snapshot: false,
                        available: true,
                        source: served.source.as_ref(),
                        bids: levels(changed_bids.iter().rev()),
                        asks: levels(changed_asks.iter()),
                    })
                } else {
                    served.seq = served.seq.saturating_add(1);
                    served.bids = bids;
                    served.asks = asks;
                    served.source = Some(book.clone());
                    served.snapshot()
                }
            }
        };
        let served: &ServedBook = served;
        let snapshot = || served.snapshot();
        for client in lock(&self.clients).values() {
            if lock(&client.selection).books.contains(instrument) {
                client.offer_book(instrument, &message, &snapshot);
            }
        }
    }

    /// The prices, venue feeds and books this proxy can serve now.
    #[must_use]
    pub fn catalog(&self) -> Topics {
        let names = |served: &HashMap<String, Symbol>| {
            let mut names: Vec<String> = served.keys().cloned().collect();
            names.sort();
            names
        };
        let mut books: Vec<String> = lock(&self.books).keys().map(ToString::to_string).collect();
        books.sort();
        Topics {
            prices: names(&self.prices),
            venues: names(&self.venues),
            books,
        }
    }

    /// Records the upstream client's state.
    pub fn set_upstream(&self, status: UpstreamStatus) {
        *lock(&self.upstream) = status;
    }

    /// Returns the upstream client's state.
    #[must_use]
    pub fn upstream(&self) -> UpstreamStatus {
        *lock(&self.upstream)
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "JSON fixtures of a known shape; a missing index is a failing test"
)]
mod tests {
    use super::*;
    use oracle_client::{Concern, Status};
    use oracle_types::{BookUpdate, Fixed, MarketKind, NANOS_PER_SEC, Venue};
    use std::net::Ipv4Addr;

    const NOW: u64 = 1_754_582_400 * NANOS_PER_SEC;

    fn btc() -> Symbol {
        "CRYPTO.BTC/USD".parse().expect("valid")
    }

    fn hub(max_book_queue: usize) -> Hub {
        Hub::new(&[btc()], &[btc()], 8, max_book_queue)
    }

    fn client(hub: &Hub) -> Arc<WebClient> {
        hub.connect(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    fn resolved(price: &str) -> Resolved {
        Resolved {
            feed_id: feed_id(&btc()),
            status: Status::Ok,
            price: Some(price.parse::<Fixed>().expect("decimal")),
            conf: Some(Fixed::ONE),
            nodes: 3,
            halted_nodes: 0,
            concerns: vec![Concern::NodeDivergence],
            publish_time_ns: NOW,
            spread_bps: None,
        }
    }

    fn instrument() -> InstrumentId {
        InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT")
    }

    fn book(node: u8, seq: u64, bids: &[(i64, u64)]) -> Book {
        let mut book = Book::new(Address::from_bytes([node; 20]), instrument());
        let levels = |levels: &[(i64, u64)]| -> Vec<BookLevel> {
            levels
                .iter()
                .map(|&(price, qty)| BookLevel { price, qty })
                .collect()
        };
        book.apply(&BookUpdate {
            venue: Venue::Binance,
            market: MarketKind::Spot,
            symbol: "BTCUSDT".to_owned(),
            publish_time_ns: NOW,
            seq,
            snapshot: true,
            exchange_time_ns: None,
            local_recv_ns: NOW,
            bids: levels(bids),
            asks: levels(&[(10_100_000_000, 100_000_000)]),
        });
        book
    }

    fn messages(texts: &[Arc<str>]) -> Vec<serde_json::Value> {
        texts
            .iter()
            .map(|text| serde_json::from_str(text).expect("json"))
            .collect()
    }

    fn topics(prices: &[&str], books: &[&str]) -> Topics {
        Topics {
            prices: prices.iter().map(|name| (*name).to_owned()).collect(),
            venues: Vec::new(),
            books: books.iter().map(|name| (*name).to_owned()).collect(),
        }
    }

    #[tokio::test]
    async fn a_subscriber_gets_the_latest_price_then_only_the_newest() {
        let hub = hub(64);
        hub.publish_price(&resolved("100"));
        let client = client(&hub);
        let reply = hub.subscribe(&client, &topics(&["CRYPTO.BTC/USD", "CRYPTO.X/USD"], &[]));
        client.reply(reply);
        let first = messages(&client.drain().await);
        assert_eq!(first[0]["type"], "subscribed");
        assert_eq!(first[0]["unknown"][0], "CRYPTO.X/USD");
        assert_eq!(first[1]["price"], "100");
        assert_eq!(first[1]["concerns"][0], "node_divergence");

        hub.publish_price(&resolved("101"));
        hub.publish_price(&resolved("102"));
        let next = messages(&client.drain().await);
        assert_eq!(next.len(), 1, "conflated");
        assert_eq!(next[0]["price"], "102");
    }

    #[tokio::test]
    async fn a_book_streams_snapshot_then_deltas_and_restarts_on_a_new_node() {
        let hub = hub(64);
        hub.update_book(&instrument(), Some(&book(1, 1, &[(10_000_000_000, 1)])));
        let client = client(&hub);
        let _ = hub.subscribe(&client, &topics(&[], &["binance:spot:BTCUSDT"]));
        let first = messages(&client.drain().await);
        assert_eq!(
            (first[0]["seq"].as_u64(), first[0]["snapshot"].as_bool()),
            (Some(1), Some(true))
        );
        assert_eq!(
            first[0]["bids"][0],
            serde_json::json!(["100", "0.00000001"])
        );

        hub.update_book(&instrument(), Some(&book(1, 2, &[(10_000_000_000, 2)])));
        hub.update_book(&instrument(), Some(&book(1, 3, &[(10_000_000_000, 2)])));
        let delta = messages(&client.drain().await);
        assert_eq!(delta.len(), 1, "an unchanged book sends nothing");
        assert_eq!(
            (delta[0]["seq"].as_u64(), delta[0]["snapshot"].as_bool()),
            (Some(2), Some(false))
        );

        hub.update_book(&instrument(), Some(&book(2, 9, &[(9_990_000_000, 5)])));
        let switched = messages(&client.drain().await);
        assert_eq!(
            switched[0]["snapshot"], true,
            "another node's book is a snapshot"
        );
        assert_eq!(switched[0]["seq"], 3);

        hub.update_book(&instrument(), None);
        let gone = messages(&client.drain().await);
        assert_eq!(gone[0]["available"], false);
        assert!(gone[0]["bids"].as_array().is_some_and(Vec::is_empty));
    }

    #[tokio::test]
    async fn a_full_book_queue_becomes_one_snapshot() {
        let hub = hub(2);
        hub.update_book(&instrument(), Some(&book(1, 1, &[(10_000_000_000, 1)])));
        let client = client(&hub);
        let _ = hub.subscribe(&client, &topics(&[], &["binance:spot:BTCUSDT"]));
        for qty in 2..=5 {
            hub.update_book(&instrument(), Some(&book(1, qty, &[(10_000_000_000, qty)])));
        }
        let queued = messages(&client.drain().await);
        assert_eq!(queued[0]["snapshot"], true);
        assert_eq!(
            queued.last().map(|m| m["seq"].clone()),
            Some(serde_json::json!(5))
        );
    }

    #[test]
    fn subscriptions_past_the_limit_are_refused_whole() {
        let hub = Hub::new(&[btc()], &[btc()], 1, 64);
        let client = client(&hub);
        let reply = hub.subscribe(
            &client,
            &Topics {
                prices: vec!["CRYPTO.BTC/USD".to_owned()],
                venues: vec!["CRYPTO.BTC/USD".to_owned()],
                books: Vec::new(),
            },
        );
        assert!(reply.contains("too_many_subscriptions"), "{reply}");
        assert_eq!(lock(&client.selection).len(), 0);
    }
}
