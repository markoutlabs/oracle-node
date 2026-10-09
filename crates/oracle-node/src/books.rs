//! Book frames for subscribers: a snapshot of each local book every second, and
//! the levels that changed in between.
//!
//! A delta is the difference between the levels of the last frame and the
//! current ones. A client that applies it holds exactly the node's top levels,
//! whatever the venue's own delta format was.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use oracle_types::{
    BOOK_EXPO, BookDepth, BookLevel, BookUpdate, InstrumentId, MarketKind, ObsKind, Observation,
    Venue, side_changes,
};

/// How often each book sends a full snapshot. A client that missed a frame
/// waits at most this long.
pub const SNAPSHOT_EVERY: Duration = Duration::from_secs(1);

/// The rate cap for each book, as for a price.
pub const MIN_INTERVAL: Duration = Duration::from_millis(50);

/// One side of a book as mantissas at [`BOOK_EXPO`].
type Side = BTreeMap<i64, u64>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Levels {
    bids: Side,
    asks: Side,
}

impl Levels {
    /// Levels whose price or size does not fit the exponent are left out.
    fn of(depth: Option<&BookDepth>) -> Self {
        let side = |levels: &[oracle_types::Level]| -> Side {
            levels
                .iter()
                .filter_map(|level| {
                    Some((
                        level.price.to_scaled(BOOK_EXPO).ok()?,
                        level.qty.to_scaled_unsigned(BOOK_EXPO).ok()?,
                    ))
                })
                .filter(|(_, qty)| *qty > 0)
                .collect()
        };
        depth.map_or_else(Self::default, |depth| Self {
            bids: side(&depth.bids),
            asks: side(&depth.asks),
        })
    }
}

struct BookState {
    /// What subscribers hold: the levels of the last frame.
    sent: Levels,
    current: Option<Arc<BookDepth>>,
    exchange_time_ns: Option<u64>,
    local_recv_ns: u64,
    /// The venue's update id of the current book, where the venue sends one.
    venue_seq: Option<u64>,
    seq: u64,
    last_sent_ns: Option<u64>,
    last_snapshot_ns: Option<u64>,
    dirty: bool,
    /// The connection dropped: the next frame is a snapshot, empty until new
    /// data arrives.
    reset: bool,
}

/// Turns local books into snapshot and delta frames.
pub struct BookPublisher {
    books: HashMap<InstrumentId, BookState>,
    seq_floor: u64,
}

impl BookPublisher {
    /// Starts every book's sequence at `seq_floor`, as for prices.
    #[must_use]
    pub fn new(seq_floor: u64) -> Self {
        Self {
            books: HashMap::new(),
            seq_floor,
        }
    }

    /// Takes the latest depth of a book.
    pub fn observe(&mut self, observation: &Observation) {
        if observation.kind != ObsKind::Depth || observation.book.is_none() {
            return;
        }
        let seq_floor = self.seq_floor;
        let state = self
            .books
            .entry(observation.instrument.clone())
            .or_insert_with(|| BookState {
                sent: Levels::default(),
                current: None,
                exchange_time_ns: None,
                local_recv_ns: 0,
                venue_seq: None,
                seq: seq_floor,
                last_sent_ns: None,
                last_snapshot_ns: None,
                dirty: false,
                reset: false,
            });
        state.current.clone_from(&observation.book);
        state.exchange_time_ns = observation.exchange_time_ns;
        state.local_recv_ns = observation.local_recv_ns;
        state.venue_seq = observation.seq;
        state.dirty = true;
    }

    /// Empties every book of a connection that dropped. Subscribers get an empty
    /// snapshot, so nobody keeps a book that nothing updates.
    pub fn reset(&mut self, venue: Venue, market: MarketKind) {
        for (instrument, state) in &mut self.books {
            if instrument.venue == venue && instrument.market == market {
                state.current = None;
                // The empty snapshot shows no venue state.
                state.venue_seq = None;
                state.reset = true;
                state.dirty = true;
            }
        }
    }

    /// Returns the frames that are due.
    ///
    /// Snapshots go out whether or not anyone `wanted` the book, so the server
    /// always has one for the next subscriber. A delta nobody wants is not
    /// built and takes no `seq`: the next one builds on the last frame sent.
    pub fn poll(&mut self, now_ns: u64, wanted: impl Fn(&InstrumentId) -> bool) -> Vec<BookUpdate> {
        let min_interval = nanos(MIN_INTERVAL);
        let snapshot_every = nanos(SNAPSHOT_EVERY);
        let mut updates = Vec::new();
        for (instrument, state) in &mut self.books {
            if state
                .last_sent_ns
                .is_some_and(|last| now_ns.saturating_sub(last) < min_interval)
            {
                continue;
            }
            let snapshot = state.reset
                || state
                    .last_snapshot_ns
                    .is_none_or(|last| now_ns.saturating_sub(last) >= snapshot_every);
            if !snapshot && (!state.dirty || !wanted(instrument)) {
                continue;
            }
            let current = Levels::of(state.current.as_deref());
            let (bids, asks) = if snapshot {
                (
                    levels(current.bids.iter().rev()),
                    levels(current.asks.iter()),
                )
            } else {
                let (bids, asks) = changes(&state.sent, &current);
                (levels(bids.iter().rev()), levels(asks.iter()))
            };
            state.dirty = false;
            if !snapshot && bids.is_empty() && asks.is_empty() {
                continue;
            }
            state.seq = state.seq.saturating_add(1);
            state.last_sent_ns = Some(now_ns);
            if snapshot {
                state.last_snapshot_ns = Some(now_ns);
                state.reset = false;
            }
            updates.push(BookUpdate {
                venue: instrument.venue,
                market: instrument.market,
                symbol: instrument.symbol.to_string(),
                publish_time_ns: now_ns,
                seq: state.seq,
                snapshot,
                exchange_time_ns: state.exchange_time_ns,
                local_recv_ns: state.local_recv_ns.min(now_ns),
                venue_seq: state.venue_seq,
                bids,
                asks,
            });
            state.sent = current;
        }
        updates
    }
}

fn changes(sent: &Levels, current: &Levels) -> (Side, Side) {
    (
        side_changes(&sent.bids, &current.bids),
        side_changes(&sent.asks, &current.asks),
    )
}

fn levels<'a>(side: impl Iterator<Item = (&'a i64, &'a u64)>) -> Vec<BookLevel> {
    side.map(|(price, qty)| BookLevel {
        price: *price,
        qty: *qty,
    })
    .collect()
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_types::{Fixed, Level};

    const SECOND: u64 = 1_000_000_000;
    const START: u64 = 1_754_582_400 * SECOND;

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("valid decimal")
    }

    fn instrument() -> InstrumentId {
        InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT")
    }

    fn depth(bids: &[(&str, &str)], asks: &[(&str, &str)], at: u64) -> Observation {
        let side = |levels: &[(&str, &str)]| -> Vec<Level> {
            levels
                .iter()
                .map(|(price, qty)| Level {
                    price: fixed(price),
                    qty: fixed(qty),
                })
                .collect()
        };
        Observation {
            instrument: instrument(),
            kind: ObsKind::Depth,
            price: fixed("100"),
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            depth_notional_1bp: None,
            exchange_time_ns: None,
            local_recv_ns: at,
            seq: None,
            book: Some(Arc::new(BookDepth {
                bids: side(bids),
                asks: side(asks),
            })),
            funding: None,
        }
    }

    fn level(price: &str, qty: &str) -> BookLevel {
        BookLevel {
            price: fixed(price).to_scaled(BOOK_EXPO).expect("fits"),
            qty: fixed(qty).to_scaled_unsigned(BOOK_EXPO).expect("fits"),
        }
    }

    /// Applies frames as a client does.
    fn apply(book: &mut Levels, update: &BookUpdate) {
        if update.snapshot {
            *book = Levels::default();
        }
        for (side, levels) in [
            (&mut book.bids, &update.bids),
            (&mut book.asks, &update.asks),
        ] {
            for level in levels {
                if level.qty == 0 {
                    side.remove(&level.price);
                } else {
                    side.insert(level.price, level.qty);
                }
            }
        }
    }

    #[test]
    fn a_book_starts_with_a_snapshot_then_sends_only_what_changed() {
        let mut publisher = BookPublisher::new(100);
        publisher.observe(&depth(&[("100", "1"), ("99", "2")], &[("101", "1")], START));
        let first = publisher.poll(START, |_| true);
        let [snapshot] = first.as_slice() else {
            panic!("one book, one frame: {first:?}");
        };
        assert!(snapshot.snapshot);
        assert_eq!(snapshot.seq, 101);
        assert_eq!(snapshot.bids, vec![level("100", "1"), level("99", "2")]);

        let later = START + 100_000_000;
        publisher.observe(&depth(
            &[("100", "3")],
            &[("101", "1"), ("102", "4")],
            later,
        ));
        let second = publisher.poll(later, |_| true);
        let [delta] = second.as_slice() else {
            panic!("one delta: {second:?}");
        };
        assert!(!delta.snapshot);
        assert_eq!(delta.seq, 102);
        assert_eq!(delta.bids, vec![level("100", "3"), level("99", "0")]);
        assert_eq!(delta.asks, vec![level("102", "4")]);

        let mut client = Levels::default();
        apply(&mut client, snapshot);
        apply(&mut client, delta);
        assert_eq!(
            client,
            Levels::of(Some(&BookDepth {
                bids: vec![Level {
                    price: fixed("100"),
                    qty: fixed("3")
                }],
                asks: vec![
                    Level {
                        price: fixed("101"),
                        qty: fixed("1")
                    },
                    Level {
                        price: fixed("102"),
                        qty: fixed("4")
                    }
                ],
            })),
            "snapshot plus delta equals the node's book"
        );
    }

    #[test]
    fn frames_follow_the_cap_and_the_snapshot_interval() {
        let mut publisher = BookPublisher::new(0);
        publisher.observe(&depth(&[("100", "1")], &[("101", "1")], START));
        assert_eq!(publisher.poll(START, |_| true).len(), 1);

        let soon = START + 10_000_000;
        publisher.observe(&depth(&[("100", "2")], &[("101", "1")], soon));
        assert!(publisher.poll(soon, |_| true).is_empty(), "inside the cap");
        assert_eq!(
            publisher.poll(START + 50_000_000, |_| true).len(),
            1,
            "the cap expired"
        );
        assert!(
            publisher.poll(START + 500_000_000, |_| true).is_empty(),
            "nothing changed"
        );
        let refreshed = publisher.poll(START + SECOND, |_| true);
        assert!(refreshed.first().is_some_and(|update| update.snapshot));
    }

    #[test]
    fn a_book_nobody_wants_sends_only_snapshots_and_stays_contiguous() {
        let mut publisher = BookPublisher::new(0);
        publisher.observe(&depth(&[("100", "1")], &[("101", "1")], START));
        let snapshot = publisher.poll(START, |_| false);
        assert!(
            snapshot
                .first()
                .is_some_and(|update| update.snapshot && update.seq == 1)
        );

        let later = START + 100_000_000;
        publisher.observe(&depth(&[("100", "2")], &[("101", "1")], later));
        assert!(
            publisher.poll(later, |_| false).is_empty(),
            "no delta for nobody"
        );

        let joined = later + 100_000_000;
        let delta = publisher.poll(joined, |_| true);
        let [delta] = delta.as_slice() else {
            panic!("one delta: {delta:?}");
        };
        assert_eq!(delta.seq, 2, "no seq was spent on the skipped delta");
        assert_eq!(delta.bids, vec![level("100", "2")]);
    }

    #[test]
    fn each_frame_carries_the_venue_update_id_of_its_book() {
        let mut publisher = BookPublisher::new(0);
        let mut first = depth(&[("100", "1")], &[("101", "1")], START);
        first.seq = Some(73_514_215_042);
        publisher.observe(&first);
        let snapshot = publisher.poll(START, |_| true);
        assert_eq!(
            snapshot.first().and_then(|update| update.venue_seq),
            Some(73_514_215_042)
        );

        let later = START + 100_000_000;
        let mut next = depth(&[("100", "2")], &[("101", "1")], later);
        next.seq = Some(73_514_215_050);
        publisher.observe(&next);
        let delta = publisher.poll(later, |_| true);
        assert_eq!(
            delta.first().and_then(|update| update.venue_seq),
            Some(73_514_215_050)
        );

        // An empty snapshot after a drop shows no venue state.
        publisher.reset(Venue::Binance, MarketKind::Spot);
        let after = later + 100_000_000;
        let empty = publisher.poll(after, |_| true);
        assert_eq!(empty.first().map(|update| update.venue_seq), Some(None));
    }

    #[test]
    fn a_dropped_connection_sends_an_empty_snapshot() {
        let mut publisher = BookPublisher::new(0);
        publisher.observe(&depth(&[("100", "1")], &[("101", "1")], START));
        let _ = publisher.poll(START, |_| true);
        publisher.reset(Venue::Binance, MarketKind::Spot);
        let after = START + 100_000_000;
        let frames = publisher.poll(after, |_| true);
        let [empty] = frames.as_slice() else {
            panic!("one frame: {frames:?}");
        };
        assert!(empty.snapshot && empty.bids.is_empty() && empty.asks.is_empty());
    }
}
