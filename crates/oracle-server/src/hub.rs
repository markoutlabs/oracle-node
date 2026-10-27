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

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use oracle_transport::{BroadcastSealer, os_rng};
use oracle_types::{FeedId, InstrumentId, Symbol};
use oracle_wire::{
    Address, SignedBookUpdate, SignedFundingUpdate, SignedUpdate, SignedVenueReport,
};
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

/// A venue report, serialized and sealed once and shared by every subscriber.
pub struct PreparedVenues {
    /// The feed.
    pub feed_id: FeedId,
    /// The canonical symbol.
    pub symbol: Symbol,
    sealed: Bytes,
    signed: SignedVenueReport,
}

impl PreparedVenues {
    /// Prepares a signed venue report for fanout, sealing it once.
    #[must_use]
    pub fn new(symbol: Symbol, signed: SignedVenueReport, sealer: &BroadcastSealer) -> Self {
        let sealed = Bytes::from(sealer.seal(&signed.encode_frame(), &mut os_rng()));
        Self {
            feed_id: signed.report().feed_id,
            symbol,
            sealed,
            signed,
        }
    }

    /// Returns the signed report.
    #[must_use]
    pub const fn signed(&self) -> &SignedVenueReport {
        &self.signed
    }
}

/// A book update, serialized and sealed once and shared by every subscriber.
pub struct PreparedBook {
    /// The venue instrument.
    pub instrument: InstrumentId,
    /// `true` for a snapshot.
    pub snapshot: bool,
    sealed: Bytes,
    signed: SignedBookUpdate,
}

impl PreparedBook {
    /// Prepares a signed book update for fanout, sealing it once.
    #[must_use]
    pub fn new(signed: SignedBookUpdate, sealer: &BroadcastSealer) -> Self {
        let update = signed.update();
        let instrument = InstrumentId::new(update.venue, update.market, update.symbol.as_str());
        let snapshot = update.snapshot;
        let sealed = Bytes::from(sealer.seal(&signed.encode_frame(), &mut os_rng()));
        Self {
            instrument,
            snapshot,
            sealed,
            signed,
        }
    }

    /// Returns the signed update.
    #[must_use]
    pub const fn signed(&self) -> &SignedBookUpdate {
        &self.signed
    }
}

/// A funding update, serialized and sealed once and shared by every subscriber.
pub struct PreparedFunding {
    /// The perpetual.
    pub instrument: InstrumentId,
    sealed: Bytes,
    signed: SignedFundingUpdate,
}

impl PreparedFunding {
    /// Prepares a signed funding update for fanout, sealing it once.
    #[must_use]
    pub fn new(signed: SignedFundingUpdate, sealer: &BroadcastSealer) -> Self {
        let update = signed.update();
        let instrument = InstrumentId::new(update.venue, update.market, update.symbol.as_str());
        let sealed = Bytes::from(sealer.seal(&signed.encode_frame(), &mut os_rng()));
        Self {
            instrument,
            sealed,
            signed,
        }
    }

    /// Returns the signed update.
    #[must_use]
    pub const fn signed(&self) -> &SignedFundingUpdate {
        &self.signed
    }
}

/// Which stream a frame belongs to. Prices and venue reports each have their
/// own slot per feed, so a venue report never replaces a price.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Channel {
    /// Price updates.
    Prices,
    /// Venue reports.
    Venues,
    /// Book snapshots and deltas.
    Books,
    /// Funding updates.
    Funding,
}

/// A frame that waits for one subscriber.
#[derive(Clone)]
pub enum Outgoing {
    /// A price update.
    Price(Arc<PreparedUpdate>),
    /// A venue report.
    Venues(Arc<PreparedVenues>),
    /// A book snapshot or delta.
    Book(Arc<PreparedBook>),
    /// A funding update.
    Funding(Arc<PreparedFunding>),
}

impl Outgoing {
    /// Returns the sealed frame, the same bytes for every subscriber.
    #[must_use]
    pub fn sealed(&self) -> Bytes {
        match self {
            Self::Price(update) => update.sealed(),
            Self::Venues(report) => report.sealed.clone(),
            Self::Book(update) => update.sealed.clone(),
            Self::Funding(update) => update.sealed.clone(),
        }
    }

    /// Returns the feed, or `None` for a book or funding, which belong to an
    /// instrument.
    #[must_use]
    pub fn feed_id(&self) -> Option<FeedId> {
        match self {
            Self::Price(update) => Some(update.feed_id),
            Self::Venues(report) => Some(report.feed_id),
            Self::Book(_) | Self::Funding(_) => None,
        }
    }

    /// Returns the stream.
    #[must_use]
    pub const fn channel(&self) -> Channel {
        match self {
            Self::Price(_) => Channel::Prices,
            Self::Venues(_) => Channel::Venues,
            Self::Book(_) => Channel::Books,
            Self::Funding(_) => Channel::Funding,
        }
    }
}

/// The most book frames one subscriber may have waiting for one book. A
/// snapshot follows each second, so a client within the cap never needs this.
const MAX_BOOK_QUEUE: usize = 64;

/// One subscriber's frames for one book. Deltas cannot replace one another, so
/// they queue behind the snapshot they build on.
#[derive(Default)]
struct BookMailbox {
    frames: Vec<Arc<PreparedBook>>,
    /// The queue overflowed. Deltas are useless until the next snapshot.
    awaiting_snapshot: bool,
}

/// Which perpetuals' funding a subscriber wants.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum FundingSelection {
    /// No perpetual.
    #[default]
    None,
    /// These perpetuals.
    Some(HashSet<InstrumentId>),
    /// Every perpetual: few, and each sends at most one frame a second.
    All,
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
    /// Feeds whose venue reports this subscriber wants. Never the firehose.
    venues: Mutex<HashSet<FeedId>>,
    /// Books this subscriber wants.
    books: Mutex<HashSet<InstrumentId>>,
    pending: Mutex<HashMap<(Channel, FeedId), Outgoing>>,
    book_queue: Mutex<HashMap<InstrumentId, BookMailbox>>,
    /// Perpetuals whose funding this subscriber wants.
    funding: Mutex<FundingSelection>,
    /// One slot per perpetual: each frame carries the whole state.
    funding_pending: Mutex<HashMap<InstrumentId, Arc<PreparedFunding>>>,
    dropped: AtomicU64,
    lagged: AtomicBool,
    closed: AtomicBool,
    notify: Notify,
    /// The hub's, shared, so a larger feed set raises it for every subscriber.
    max_pending: Arc<AtomicUsize>,
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

    /// Adds feeds whose venue reports to send.
    pub fn add_venues(&self, feeds: impl IntoIterator<Item = FeedId>) {
        if let Ok(mut venues) = self.venues.lock() {
            venues.extend(feeds);
        }
    }

    /// Stops the venue reports of these feeds.
    pub fn remove_venues(&self, feeds: impl IntoIterator<Item = FeedId>) {
        if let Ok(mut venues) = self.venues.lock() {
            for feed in feeds {
                venues.remove(&feed);
            }
        }
    }

    /// Adds books to send.
    pub fn add_books(&self, books: impl IntoIterator<Item = InstrumentId>) {
        if let Ok(mut selected) = self.books.lock() {
            selected.extend(books);
        }
    }

    /// Stops these books.
    pub fn remove_books(&self, books: &[InstrumentId]) {
        if let Ok(mut selected) = self.books.lock() {
            for book in books {
                selected.remove(book);
            }
        }
        if let Ok(mut queue) = self.book_queue.lock() {
            for book in books {
                queue.remove(book);
            }
        }
    }

    /// Returns `true` if this subscriber wants `book`.
    #[must_use]
    pub fn wants_book(&self, book: &InstrumentId) -> bool {
        self.books
            .lock()
            .is_ok_and(|selected| selected.contains(book))
    }

    /// Adds perpetuals whose funding to send.
    pub fn add_funding(&self, instruments: impl IntoIterator<Item = InstrumentId>) {
        if let Ok(mut selection) = self.funding.lock() {
            if let FundingSelection::Some(set) = &mut *selection {
                set.extend(instruments);
            } else if *selection == FundingSelection::None {
                *selection = FundingSelection::Some(instruments.into_iter().collect());
            }
        }
    }

    /// Sends the funding of every perpetual.
    pub fn add_all_funding(&self) {
        if let Ok(mut selection) = self.funding.lock() {
            *selection = FundingSelection::All;
        }
    }

    /// Stops the funding of these perpetuals, or of all with `all`.
    pub fn remove_funding(&self, instruments: &[InstrumentId], all: bool) {
        if let Ok(mut selection) = self.funding.lock() {
            if all {
                *selection = FundingSelection::None;
            } else if let FundingSelection::Some(set) = &mut *selection {
                for instrument in instruments {
                    set.remove(instrument);
                }
            }
        }
        if let Ok(mut pending) = self.funding_pending.lock() {
            pending.retain(|instrument, _| !all && !instruments.contains(instrument));
        }
    }

    /// Returns `true` if this subscriber wants the funding of `instrument`.
    #[must_use]
    pub fn wants_funding(&self, instrument: &InstrumentId) -> bool {
        self.funding
            .lock()
            .is_ok_and(|selection| match &*selection {
                FundingSelection::None => false,
                FundingSelection::Some(set) => set.contains(instrument),
                FundingSelection::All => true,
            })
    }

    /// Offers a funding frame, replacing any pending one for the perpetual.
    fn offer_funding(&self, frame: &Arc<PreparedFunding>) {
        let Ok(mut pending) = self.funding_pending.lock() else {
            return;
        };
        if pending
            .insert(frame.instrument.clone(), Arc::clone(frame))
            .is_some()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        drop(pending);
        self.notify.notify_waiters();
    }

    /// Queues a book frame behind the snapshot it builds on.
    fn offer_book(&self, frame: &Arc<PreparedBook>) {
        let Ok(mut queue) = self.book_queue.lock() else {
            return;
        };
        let mailbox = queue.entry(frame.instrument.clone()).or_default();
        if frame.snapshot {
            mailbox.frames.clear();
            mailbox.frames.push(Arc::clone(frame));
            mailbox.awaiting_snapshot = false;
        } else if mailbox.awaiting_snapshot {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        } else if mailbox.frames.len() >= MAX_BOOK_QUEUE {
            let lost = u64::try_from(mailbox.frames.len()).unwrap_or(u64::MAX);
            self.dropped
                .fetch_add(lost.saturating_add(1), Ordering::Relaxed);
            mailbox.frames.clear();
            mailbox.awaiting_snapshot = true;
            return;
        } else {
            mailbox.frames.push(Arc::clone(frame));
        }
        drop(queue);
        self.notify.notify_waiters();
    }

    /// Returns `true` if this subscriber wants `feed_id` on `channel`.
    #[must_use]
    pub fn wants(&self, channel: Channel, feed_id: FeedId) -> bool {
        match channel {
            Channel::Prices => self
                .selection
                .lock()
                .is_ok_and(|selection| selection.wants(feed_id)),
            Channel::Venues => self
                .venues
                .lock()
                .is_ok_and(|venues| venues.contains(&feed_id)),
            Channel::Books | Channel::Funding => false,
        }
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

    /// Offers a frame, replacing any pending one for the same feed and stream.
    fn offer(&self, frame: Outgoing) {
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        let Some(feed_id) = frame.feed_id() else {
            return;
        };
        let key = (frame.channel(), feed_id);
        if pending.len() >= self.max_pending.load(Ordering::Relaxed) && !pending.contains_key(&key)
        {
            // Too many distinct feeds outstanding: this subscriber is not
            // keeping up at all. Say so rather than quietly dropping data.
            self.lagged.store(true, Ordering::Relaxed);
            self.notify.notify_waiters();
            return;
        }
        if pending.insert(key, frame).is_some() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        drop(pending);
        self.notify.notify_waiters();
    }

    /// Takes everything pending, or waits until there is something.
    ///
    /// Returns an empty vector when the subscriber is closed or has lagged, so
    /// the caller can check [`Subscriber::is_lagged`] and report it.
    pub async fn drain(&self) -> Vec<Outgoing> {
        loop {
            if self.is_closed() || self.is_lagged() {
                return Vec::new();
            }
            let mut frames: Vec<Outgoing> = match self.pending.lock() {
                Ok(mut pending) => pending.drain().map(|(_, frame)| frame).collect(),
                Err(_) => return Vec::new(),
            };
            if let Ok(mut queue) = self.book_queue.lock() {
                for mailbox in queue.values_mut() {
                    frames.extend(mailbox.frames.drain(..).map(Outgoing::Book));
                }
            }
            if let Ok(mut pending) = self.funding_pending.lock() {
                frames.extend(pending.drain().map(|(_, frame)| Outgoing::Funding(frame)));
            }
            if !frames.is_empty() {
                return frames;
            }
            self.notify.notified().await;
        }
    }
}

/// The publish-side registry of subscribers, plus the latest update per feed.
pub struct Hub {
    subscribers: Mutex<HashMap<u64, Arc<Subscriber>>>,
    latest: Mutex<HashMap<FeedId, Arc<PreparedUpdate>>>,
    /// For each book, the latest snapshot and the deltas after it, for a
    /// subscriber that joins between snapshots.
    book_history: Mutex<HashMap<InstrumentId, Vec<Arc<PreparedBook>>>>,
    /// The latest funding frame of each perpetual, for a new subscriber.
    latest_funding: Mutex<HashMap<InstrumentId, Arc<PreparedFunding>>>,
    next_id: AtomicU64,
    max_pending: Arc<AtomicUsize>,
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
            book_history: Mutex::new(HashMap::new()),
            latest_funding: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            max_pending: Arc::new(AtomicUsize::new(max_pending.max(1))),
            sealer,
        }
    }

    /// Registers an authenticated subscriber.
    #[must_use]
    pub fn subscribe(&self, client: Address) -> Arc<Subscriber> {
        let subscriber = Arc::new(Subscriber {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            client,
            selection: Mutex::new(Selection::Feeds(HashSet::new())),
            venues: Mutex::new(HashSet::new()),
            books: Mutex::new(HashSet::new()),
            book_queue: Mutex::new(HashMap::new()),
            funding: Mutex::new(FundingSelection::None),
            funding_pending: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            dropped: AtomicU64::new(0),
            lagged: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            notify: Notify::new(),
            max_pending: Arc::clone(&self.max_pending),
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

    /// Returns `true` if an open subscriber wants `feed_id` on `channel`. The
    /// node skips signing what nobody wants.
    #[must_use]
    pub fn has_subscriber(&self, channel: Channel, feed_id: FeedId) -> bool {
        self.subscribers.lock().is_ok_and(|subscribers| {
            subscribers
                .values()
                .any(|subscriber| !subscriber.is_closed() && subscriber.wants(channel, feed_id))
        })
    }

    /// Returns `true` if an open subscriber wants `book`.
    #[must_use]
    pub fn has_book_subscriber(&self, book: &InstrumentId) -> bool {
        self.subscribers.lock().is_ok_and(|subscribers| {
            subscribers
                .values()
                .any(|subscriber| !subscriber.is_closed() && subscriber.wants_book(book))
        })
    }

    /// Sets every subscriber's bound on outstanding feeds, after the feed set changed size.
    pub fn set_max_pending(&self, max_pending: usize) {
        self.max_pending
            .store(max_pending.max(1), Ordering::Relaxed);
    }

    /// Drops the latest update of every feed outside `keep`, after a new feed set.
    pub fn forget_feeds(&self, keep: &HashSet<FeedId>) {
        if let Ok(mut latest) = self.latest.lock() {
            latest.retain(|feed, _| keep.contains(feed));
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
        self.offer(&Outgoing::Price(Arc::clone(&prepared)));
        prepared
    }

    /// Publishes a venue report to every subscriber that asked for it.
    pub fn publish_venues(&self, symbol: Symbol, signed: SignedVenueReport) -> Arc<PreparedVenues> {
        let prepared = Arc::new(PreparedVenues::new(symbol, signed, &self.sealer));
        self.offer(&Outgoing::Venues(Arc::clone(&prepared)));
        prepared
    }

    /// Publishes a book frame to every subscriber of that book.
    pub fn publish_book(&self, signed: SignedBookUpdate) -> Arc<PreparedBook> {
        let prepared = Arc::new(PreparedBook::new(signed, &self.sealer));
        if let Ok(mut history) = self.book_history.lock() {
            let frames = history.entry(prepared.instrument.clone()).or_default();
            if prepared.snapshot {
                frames.clear();
                frames.push(Arc::clone(&prepared));
            } else if frames.is_empty() || frames.len() >= MAX_BOOK_QUEUE {
                // No snapshot to build on: a joiner waits for the next one.
                frames.clear();
            } else {
                frames.push(Arc::clone(&prepared));
            }
        }
        if let Ok(subscribers) = self.subscribers.lock() {
            for subscriber in subscribers.values() {
                if !subscriber.is_closed() && subscriber.wants_book(&prepared.instrument) {
                    subscriber.offer_book(&prepared);
                }
            }
        }
        prepared
    }

    /// Sends a new subscriber of `books` the latest snapshot of each, and the
    /// deltas after it. Call it after [`Subscriber::add_books`], so no frame
    /// falls between the two.
    pub fn replay_books(&self, subscriber: &Subscriber, books: &[InstrumentId]) {
        let frames: Vec<Arc<PreparedBook>> = match self.book_history.lock() {
            Ok(history) => books
                .iter()
                .filter_map(|book| history.get(book))
                .flatten()
                .cloned()
                .collect(),
            Err(_) => return,
        };
        for frame in &frames {
            subscriber.offer_book(frame);
        }
    }

    /// Publishes a funding frame to every subscriber of that perpetual.
    pub fn publish_funding(&self, signed: SignedFundingUpdate) -> Arc<PreparedFunding> {
        let prepared = Arc::new(PreparedFunding::new(signed, &self.sealer));
        if let Ok(mut latest) = self.latest_funding.lock() {
            latest.insert(prepared.instrument.clone(), Arc::clone(&prepared));
        }
        if let Ok(subscribers) = self.subscribers.lock() {
            for subscriber in subscribers.values() {
                if !subscriber.is_closed() && subscriber.wants_funding(&prepared.instrument) {
                    subscriber.offer_funding(&prepared);
                }
            }
        }
        prepared
    }

    /// Sends a new subscriber the latest funding frame of each perpetual it
    /// now wants. Call it after [`Subscriber::add_funding`].
    pub fn replay_funding(&self, subscriber: &Subscriber) {
        let frames: Vec<Arc<PreparedFunding>> = match self.latest_funding.lock() {
            Ok(latest) => latest
                .values()
                .filter(|frame| subscriber.wants_funding(&frame.instrument))
                .cloned()
                .collect(),
            Err(_) => return,
        };
        for frame in &frames {
            subscriber.offer_funding(frame);
        }
    }

    fn offer(&self, frame: &Outgoing) {
        let (channel, Some(feed_id)) = (frame.channel(), frame.feed_id()) else {
            return;
        };
        if let Ok(subscribers) = self.subscribers.lock() {
            for subscriber in subscribers.values() {
                if !subscriber.is_closed() && subscriber.wants(channel, feed_id) {
                    subscriber.offer(frame.clone());
                }
            }
        }
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
            drained.first().and_then(Outgoing::feed_id),
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
            drained.first().and_then(|frame| match frame {
                Outgoing::Price(update) => Some(update.signed().update().seq),
                Outgoing::Venues(_) | Outgoing::Book(_) | Outgoing::Funding(_) => None,
            }),
            Some(100),
            "and it must be the newest"
        );
        assert_eq!(subscriber.dropped(), 99);
    }

    fn venues(symbol: &Symbol, seq: u64) -> SignedVenueReport {
        let signer = Signer::from_secret_bytes([5; 32]).expect("valid key");
        signer
            .sign_venue_report(&oracle_types::VenueReport {
                feed_id: feed_id(symbol),
                publish_time_ns: 1_754_582_400_000_000_000 + seq,
                seq,
                expo: -8,
                entries: Vec::new(),
            })
            .expect("signs")
    }

    #[tokio::test]
    async fn a_venue_report_has_its_own_selection_and_its_own_slot() {
        let hub = hub(64);
        let btc = symbol("CRYPTO.BTC/USD");
        let subscriber = hub.subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        subscriber.select([feed_id(&btc)].into_iter().collect());
        hub.publish_venues(btc, venues(&btc, 1));
        hub.publish(btc, signed(&btc, 1));
        assert_eq!(
            subscriber.drain().await.len(),
            1,
            "venue reports need their own subscription"
        );

        subscriber.add_venues([feed_id(&btc)]);
        hub.publish(btc, signed(&btc, 2));
        hub.publish_venues(btc, venues(&btc, 2));
        hub.publish_venues(btc, venues(&btc, 3));
        let drained = subscriber.drain().await;
        assert_eq!(drained.len(), 2, "a report never replaces a price");
        assert!(
            drained
                .iter()
                .any(|frame| frame.channel() == Channel::Venues)
        );
    }

    fn instrument() -> InstrumentId {
        InstrumentId::new(Venue::Binance, oracle_types::MarketKind::Spot, "BTCUSDT")
    }

    fn book(seq: u64, snapshot: bool) -> SignedBookUpdate {
        let signer = Signer::from_secret_bytes([5; 32]).expect("valid key");
        signer
            .sign_book_update(&oracle_types::BookUpdate {
                venue: Venue::Binance,
                market: oracle_types::MarketKind::Spot,
                symbol: "BTCUSDT".to_owned(),
                publish_time_ns: 1_754_582_400_000_000_000 + seq,
                seq,
                snapshot,
                exchange_time_ns: None,
                local_recv_ns: 0,
                venue_seq: None,
                bids: vec![oracle_types::BookLevel {
                    price: 100,
                    qty: u64::from(snapshot),
                }],
                asks: Vec::new(),
            })
            .expect("signs")
    }

    fn book_seqs(frames: &[Outgoing]) -> Vec<u64> {
        frames
            .iter()
            .filter_map(|frame| match frame {
                Outgoing::Book(update) => Some(update.signed().update().seq),
                Outgoing::Price(_) | Outgoing::Venues(_) | Outgoing::Funding(_) => None,
            })
            .collect()
    }

    fn funding(symbol: &str, seq: u64) -> SignedFundingUpdate {
        let signer = Signer::from_secret_bytes([5; 32]).expect("valid key");
        signer
            .sign_funding_update(&oracle_types::FundingUpdate {
                venue: oracle_types::Venue::Bybit,
                market: oracle_types::MarketKind::LinearPerp,
                symbol: symbol.to_owned(),
                publish_time_ns: seq,
                seq,
                basis: oracle_types::FundingBasis::Interval,
                rate: 100_000_000,
                predicted_rate: None,
                interval_ns: None,
                next_funding_time_ns: None,
                settled: None,
                open_interest: None,
                exchange_time_ns: None,
                local_recv_ns: seq,
            })
            .expect("signs")
    }

    fn funding_seqs(frames: &[Outgoing]) -> Vec<(String, u64)> {
        let mut seqs: Vec<(String, u64)> = frames
            .iter()
            .filter_map(|frame| match frame {
                Outgoing::Funding(update) => {
                    let update = update.signed().update();
                    Some((update.symbol.clone(), update.seq))
                }
                _ => None,
            })
            .collect();
        seqs.sort();
        seqs
    }

    #[tokio::test]
    async fn funding_conflates_per_perpetual_and_a_joiner_gets_the_latest() {
        let hub = hub(64);
        let btc = || {
            InstrumentId::new(
                oracle_types::Venue::Bybit,
                oracle_types::MarketKind::LinearPerp,
                "BTCUSDT",
            )
        };
        hub.publish_funding(funding("BTCUSDT", 1));
        hub.publish_funding(funding("ETHUSDT", 1));

        let one = hub.subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        one.add_funding([btc()]);
        hub.replay_funding(&one);
        assert_eq!(
            funding_seqs(&one.drain().await),
            vec![("BTCUSDT".to_owned(), 1)]
        );

        let all = hub.subscribe(oracle_wire::Address::from_bytes([0xC2; 20]));
        all.add_all_funding();
        hub.replay_funding(&all);
        for seq in 2..=4 {
            hub.publish_funding(funding("BTCUSDT", seq));
        }
        assert_eq!(
            funding_seqs(&one.drain().await),
            vec![("BTCUSDT".to_owned(), 4)]
        );
        assert_eq!(
            funding_seqs(&all.drain().await),
            vec![("BTCUSDT".to_owned(), 4), ("ETHUSDT".to_owned(), 1)]
        );

        all.remove_funding(&[], true);
        hub.publish_funding(funding("ETHUSDT", 2));
        assert!(!all.wants_funding(&btc()));
    }

    #[tokio::test]
    async fn a_late_subscriber_gets_the_snapshot_and_the_deltas_in_order() {
        let hub = hub(64);
        hub.publish_book(book(1, true));
        hub.publish_book(book(2, false));
        hub.publish_book(book(3, false));

        let subscriber = hub.subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        subscriber.add_books([instrument()]);
        hub.replay_books(&subscriber, &[instrument()]);
        assert_eq!(book_seqs(&subscriber.drain().await), vec![1, 2, 3]);

        hub.publish_book(book(4, false));
        hub.publish_book(book(5, false));
        assert_eq!(
            book_seqs(&subscriber.drain().await),
            vec![4, 5],
            "deltas never replace one another"
        );
    }

    #[tokio::test]
    async fn an_overflowing_book_queue_waits_for_the_next_snapshot() {
        let hub = hub(64);
        let subscriber = hub.subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        subscriber.add_books([instrument()]);
        hub.publish_book(book(1, true));
        for seq in 2..=80 {
            hub.publish_book(book(seq, false));
        }
        assert!(subscriber.dropped() > 0);
        hub.publish_book(book(81, true));
        assert_eq!(book_seqs(&subscriber.drain().await), vec![81]);
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
