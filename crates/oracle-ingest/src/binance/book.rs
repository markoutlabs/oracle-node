//! Binance's books: a REST snapshot, then the diff stream, joined by update ids.
//!
//! Binance's procedure: buffer the diffs until the snapshot arrives; drop the
//! ones it already covers; the first diff applied must straddle the snapshot's
//! id; after that each diff must follow the last. Spot chains `U` to the last
//! `u`; futures chains `pu`. Anything else is [`DecodeError::Resync`].

use std::collections::HashMap;

use oracle_types::Level;

use crate::DecodeError;
use crate::book::{Books, Side};

/// Diffs held while the snapshot is in flight. At ten a second that is minutes;
/// a snapshot that slow has failed.
const MAX_BUFFERED: usize = 4_096;

/// One diff-depth event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Diff {
    /// `U`: the first update id in the event.
    pub first: u64,
    /// `u`: the last update id in the event.
    pub last: u64,
    /// `pu`: futures only, the last update id of the previous event.
    pub previous: Option<u64>,
    pub bids: Vec<Level>,
    pub asks: Vec<Level>,
}

#[derive(Debug)]
enum Sync {
    /// No snapshot yet.
    Buffering(Vec<Diff>),
    /// A snapshot at this id; the next diff must straddle it.
    Bridging(u64),
    /// In step with the stream.
    Live,
}

/// What a diff did to its book.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Applied {
    /// Applied: the book changed.
    Changed,
    /// Held, or older than the book: nothing changed.
    Unchanged,
}

/// The books on one Binance connection, and how far each is in sync.
#[derive(Debug, Default)]
pub(crate) struct BinanceBooks {
    pub books: Books,
    sync: HashMap<String, Sync>,
}

impl BinanceBooks {
    /// Drops every book and its sync state.
    pub fn clear(&mut self) {
        self.books.clear();
        self.sync.clear();
    }

    /// Applies or holds one diff for `symbol`.
    pub fn on_diff(
        &mut self,
        symbol: &str,
        futures: bool,
        diff: Diff,
    ) -> Result<Applied, DecodeError> {
        let state = self
            .sync
            .entry(symbol.to_owned())
            .or_insert_with(|| Sync::Buffering(Vec::new()));
        if let Sync::Buffering(held) = state {
            if held.len() >= MAX_BUFFERED {
                return Err(DecodeError::Resync(format!(
                    "{symbol}: no snapshot arrived"
                )));
            }
            held.push(diff);
            return Ok(Applied::Unchanged);
        }
        self.apply(symbol, futures, diff)
    }

    /// Starts `symbol`'s book from a snapshot at `id`, then applies the diffs
    /// held while it was in flight.
    pub fn on_snapshot(
        &mut self,
        symbol: &str,
        futures: bool,
        id: u64,
        bids: Vec<Level>,
        asks: Vec<Level>,
    ) -> Result<Applied, DecodeError> {
        let held = match self.sync.insert(symbol.to_owned(), Sync::Bridging(id)) {
            Some(Sync::Buffering(held)) => held,
            _ => Vec::new(),
        };
        let book = self.books.book(symbol);
        book.clear();
        for (side, levels) in [(Side::Bid, bids), (Side::Ask, asks)] {
            for level in levels {
                book.set(side, level.price, level.qty);
            }
        }
        book.last_id = Some(id);
        for diff in held {
            self.apply(symbol, futures, diff)?;
        }
        Ok(Applied::Changed)
    }

    fn apply(&mut self, symbol: &str, futures: bool, diff: Diff) -> Result<Applied, DecodeError> {
        let book = self.books.book(symbol);
        let Some(last) = book.last_id else {
            return Err(DecodeError::Resync(format!(
                "{symbol}: a diff with no book"
            )));
        };
        let state = self.sync.get(symbol);
        // Older than the book: the snapshot or an earlier diff already holds it.
        let stale = if futures {
            diff.last < last
        } else {
            diff.last <= last
        };
        let follows = match state {
            Some(Sync::Bridging(id)) if futures => diff.first <= *id && *id <= diff.last,
            Some(Sync::Bridging(id)) => {
                diff.first <= id.saturating_add(1) && id.saturating_add(1) <= diff.last
            }
            _ if futures => diff.previous == Some(last),
            _ => diff.first == last.saturating_add(1),
        };
        if !follows {
            if stale {
                return Ok(Applied::Unchanged);
            }
            return Err(DecodeError::Resync(format!(
                "{symbol}: diff {}..{} does not follow {last}",
                diff.first, diff.last
            )));
        }
        for (side, levels) in [(Side::Bid, diff.bids), (Side::Ask, diff.asks)] {
            for level in levels {
                book.set(side, level.price, level.qty);
            }
        }
        book.last_id = Some(diff.last);
        self.sync.insert(symbol.to_owned(), Sync::Live);
        Ok(Applied::Changed)
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixed-shape books; an out-of-range index is a failing test"
)]
mod tests {
    use super::*;

    fn level(price: &str, qty: &str) -> Level {
        Level {
            price: price.parse().expect("valid"),
            qty: qty.parse().expect("valid"),
        }
    }

    fn diff(first: u64, last: u64, previous: Option<u64>, bid: &str) -> Diff {
        Diff {
            first,
            last,
            previous,
            bids: vec![level(bid, "1")],
            asks: Vec::new(),
        }
    }

    fn snapshot(books: &mut BinanceBooks, futures: bool, id: u64) -> Result<Applied, DecodeError> {
        books.on_snapshot(
            "BTCUSDT",
            futures,
            id,
            vec![level("100", "1")],
            vec![level("101", "1")],
        )
    }

    fn best_bid(books: &mut BinanceBooks) -> String {
        books.books.book("BTCUSDT").top(Side::Bid, 1)[0]
            .price
            .to_string()
    }

    /// Diffs that arrive before the snapshot wait for it; the ones it covers
    /// are dropped and the rest applied in order.
    #[test]
    fn spot_buffers_until_the_snapshot_then_bridges() {
        let mut books = BinanceBooks::default();
        for (first, last, bid) in [(90, 99, "99.1"), (100, 105, "99.2"), (106, 110, "100.5")] {
            assert_eq!(
                books.on_diff("BTCUSDT", false, diff(first, last, None, bid)),
                Ok(Applied::Unchanged)
            );
        }
        // Snapshot at 102: 90..99 is covered, 100..105 straddles 103, 106 follows.
        snapshot(&mut books, false, 102).expect("bridges");
        assert_eq!(best_bid(&mut books), "100.5");
        assert_eq!(
            books.on_diff("BTCUSDT", false, diff(111, 112, None, "100.6")),
            Ok(Applied::Changed)
        );
        assert!(matches!(
            books.on_diff("BTCUSDT", false, diff(114, 115, None, "100.7")),
            Err(DecodeError::Resync(_))
        ));
    }

    #[test]
    fn a_gap_between_snapshot_and_stream_asks_for_a_resync() {
        let mut books = BinanceBooks::default();
        books
            .on_diff("BTCUSDT", false, diff(110, 120, None, "100.5"))
            .expect("held");
        assert!(matches!(
            snapshot(&mut books, false, 102),
            Err(DecodeError::Resync(_))
        ));
    }

    /// Futures chain each event to the last by `pu`, not by `U`.
    #[test]
    fn futures_follow_the_previous_id() {
        let mut books = BinanceBooks::default();
        snapshot(&mut books, true, 100).expect("a book");
        assert_eq!(
            books.on_diff("BTCUSDT", true, diff(95, 103, Some(94), "100.2")),
            Ok(Applied::Changed),
            "straddles the snapshot"
        );
        assert_eq!(
            books.on_diff("BTCUSDT", true, diff(104, 108, Some(103), "100.3")),
            Ok(Applied::Changed)
        );
        assert!(matches!(
            books.on_diff("BTCUSDT", true, diff(110, 112, Some(109), "100.4")),
            Err(DecodeError::Resync(_))
        ));
    }

    #[test]
    fn a_snapshot_that_never_comes_asks_for_a_resync() {
        let mut books = BinanceBooks::default();
        let mut result = Ok(Applied::Unchanged);
        for id in 0..=u64::try_from(MAX_BUFFERED).expect("fits") {
            result = books.on_diff("BTCUSDT", false, diff(id, id, None, "100"));
        }
        assert!(matches!(result, Err(DecodeError::Resync(_))));
    }
}
