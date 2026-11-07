//! Binance's books: a REST snapshot, then the diff stream, joined by update ids.
//!
//! Binance's procedure: buffer the diffs until the snapshot arrives; drop the
//! ones it already covers; the first diff applied must straddle the snapshot's
//! id; after that each diff must follow the last. Spot chains `U` to the last
//! `u`; futures chains `pu`. Anything else is [`DecodeError::Resync`]. The
//! diffs arrive parsed whole, so a diff applies whole or not at all.

use std::collections::HashMap;
use std::sync::Arc;

use crate::DecodeError;
use crate::book::{BookKeeper, BookMsg};

/// Diffs held while the snapshot is in flight. At ten a second that is minutes;
/// a snapshot that slow has failed.
const MAX_BUFFERED: usize = 4_096;

/// One diff-depth event: `U`, and the levels with `u` as the id and, on
/// futures, `pu` as the id before.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Diff {
    /// `U`: the first update id in the event.
    pub first: u64,
    pub changes: BookMsg<'static>,
}

impl Diff {
    /// `u`: the last update id in the event.
    fn last(&self) -> u64 {
        self.changes.next_id.unwrap_or(self.first)
    }
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
    pub keeper: BookKeeper,
    sync: HashMap<Arc<str>, Sync>,
}

impl BinanceBooks {
    /// Drops every book and its sync state.
    pub fn clear(&mut self) {
        self.keeper.clear();
        self.sync.clear();
    }

    /// Applies or holds one diff for the book of `key`.
    pub fn on_diff(
        &mut self,
        key: &Arc<str>,
        futures: bool,
        diff: Diff,
    ) -> Result<Applied, DecodeError> {
        let state = self
            .sync
            .entry(Arc::clone(key))
            .or_insert_with(|| Sync::Buffering(Vec::new()));
        if let Sync::Buffering(held) = state {
            if held.len() >= MAX_BUFFERED {
                return Err(DecodeError::Resync(format!("{key}: no snapshot arrived")));
            }
            held.push(diff);
            return Ok(Applied::Unchanged);
        }
        self.apply(key, futures, diff)
    }

    /// Starts the book of `key` from a snapshot at `id`, then applies the diffs
    /// held while it was in flight.
    pub fn on_snapshot(
        &mut self,
        key: &Arc<str>,
        futures: bool,
        id: u64,
        snapshot: &BookMsg<'_>,
    ) -> Result<Applied, DecodeError> {
        let held = match self.sync.insert(Arc::clone(key), Sync::Bridging(id)) {
            Some(Sync::Buffering(held)) => held,
            _ => Vec::new(),
        };
        let book = self.keeper.book_mut(key);
        book.apply(snapshot);
        book.last_id = Some(id);
        for diff in held {
            self.apply(key, futures, diff)?;
        }
        Ok(Applied::Changed)
    }

    fn apply(&mut self, key: &Arc<str>, futures: bool, diff: Diff) -> Result<Applied, DecodeError> {
        let book = self.keeper.book_mut(key);
        let Some(last) = book.last_id else {
            return Err(DecodeError::Resync(format!("{key}: a diff with no book")));
        };
        let state = self.sync.get(key);
        let (first, final_id) = (diff.first, diff.last());
        // Older than the book: the snapshot or an earlier diff already holds it.
        let stale = if futures {
            final_id < last
        } else {
            final_id <= last
        };
        let follows = match state {
            Some(Sync::Bridging(id)) if futures => first <= *id && *id <= final_id,
            Some(Sync::Bridging(id)) => {
                first <= id.saturating_add(1) && id.saturating_add(1) <= final_id
            }
            _ if futures => diff.changes.prev_id == Some(last),
            _ => first == last.saturating_add(1),
        };
        if !follows {
            if stale {
                return Ok(Applied::Unchanged);
            }
            return Err(DecodeError::Resync(format!(
                "{key}: diff {first}..{final_id} does not follow {last}"
            )));
        }
        book.apply(&diff.changes);
        self.sync.insert(Arc::clone(key), Sync::Live);
        Ok(Applied::Changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InstrumentMap;
    use crate::book::{BookRule, Change, Continuity};
    use crate::instrument::InstrumentEntry;
    use crate::testing::{fixed, instrument};
    use oracle_types::{MarketKind, Observation, Venue};

    fn btc() -> InstrumentEntry {
        let spec = instrument("BTCUSDT", MarketKind::Spot);
        let map = InstrumentMap::new(Venue::Binance, MarketKind::Spot, &[spec]).expect("a map");
        map.lookup("BTCUSDT").cloned().expect("the instrument")
    }

    fn diff(first: u64, last: u64, previous: Option<u64>, bid: &str) -> Diff {
        Diff {
            first,
            changes: BookMsg {
                prev_id: previous,
                next_id: Some(last),
                bids: vec![Change::new(fixed(bid), fixed("1"))],
                ..BookMsg::default()
            },
        }
    }

    fn snapshot(books: &mut BinanceBooks, futures: bool, id: u64) -> Result<Applied, DecodeError> {
        let whole = BookMsg {
            snapshot: true,
            bids: vec![Change::new(fixed("100"), fixed("1"))],
            asks: vec![Change::new(fixed("101"), fixed("1"))],
            ..BookMsg::default()
        };
        books.on_snapshot(&btc().instrument.symbol, futures, id, &whole)
    }

    fn on_diff(
        books: &mut BinanceBooks,
        futures: bool,
        diff: Diff,
    ) -> Result<Applied, DecodeError> {
        books.on_diff(&btc().instrument.symbol, futures, diff)
    }

    /// The best bid that the book emits now.
    fn best_bid(books: &mut BinanceBooks) -> String {
        let mut out: Vec<Observation> = Vec::new();
        books
            .keeper
            .emit(
                BookRule::new(Continuity::UpdateId),
                &btc(),
                None,
                1,
                &mut out,
            )
            .expect("a book");
        out.first()
            .and_then(|top| top.bid)
            .expect("a bid")
            .to_string()
    }

    /// Diffs that arrive before the snapshot wait for it; the ones it covers
    /// are dropped and the rest applied in order.
    #[test]
    fn spot_buffers_until_the_snapshot_then_bridges() {
        let mut books = BinanceBooks::default();
        for (first, last, bid) in [(90, 99, "99.1"), (100, 105, "99.2"), (106, 110, "100.5")] {
            assert_eq!(
                on_diff(&mut books, false, diff(first, last, None, bid)),
                Ok(Applied::Unchanged)
            );
        }
        // Snapshot at 102: 90..99 is covered, 100..105 straddles 103, 106 follows.
        snapshot(&mut books, false, 102).expect("bridges");
        assert_eq!(best_bid(&mut books), "100.5");
        assert_eq!(
            on_diff(&mut books, false, diff(111, 112, None, "100.6")),
            Ok(Applied::Changed)
        );
        assert!(matches!(
            on_diff(&mut books, false, diff(114, 115, None, "100.7")),
            Err(DecodeError::Resync(_))
        ));
    }

    #[test]
    fn a_gap_between_snapshot_and_stream_asks_for_a_resync() {
        let mut books = BinanceBooks::default();
        on_diff(&mut books, false, diff(110, 120, None, "100.5")).expect("held");
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
            on_diff(&mut books, true, diff(95, 103, Some(94), "100.2")),
            Ok(Applied::Changed),
            "straddles the snapshot"
        );
        assert_eq!(
            on_diff(&mut books, true, diff(104, 108, Some(103), "100.3")),
            Ok(Applied::Changed)
        );
        assert!(matches!(
            on_diff(&mut books, true, diff(110, 112, Some(109), "100.4")),
            Err(DecodeError::Resync(_))
        ));
    }

    #[test]
    fn a_snapshot_that_never_comes_asks_for_a_resync() {
        let mut books = BinanceBooks::default();
        let mut result = Ok(Applied::Unchanged);
        for id in 0..=u64::try_from(MAX_BUFFERED).expect("fits") {
            result = on_diff(&mut books, false, diff(id, id, None, "100"));
        }
        assert!(matches!(result, Err(DecodeError::Resync(_))));
    }
}
