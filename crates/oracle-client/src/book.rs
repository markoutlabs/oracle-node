//! One node's view of one venue book, built from its snapshots and deltas.

use std::collections::BTreeMap;

use oracle_types::{BOOK_EXPO, BookLevel, BookUpdate, Fixed, FixedError, InstrumentId};
use oracle_wire::Address;

/// A venue book as one node sent it.
///
/// Prices and sizes are mantissas at [`BOOK_EXPO`]; [`Book::level_fixed`]
/// converts a level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Book {
    /// The node whose frames built this book.
    pub node: Address,
    /// The venue instrument.
    pub instrument: InstrumentId,
    /// The `seq` of the last frame applied.
    pub seq: u64,
    /// When the node signed the last frame.
    pub publish_time_ns: u64,
    /// The node's receipt time of the newest book data.
    pub local_recv_ns: u64,
    /// The venue's own timestamp on the newest book data.
    pub exchange_time_ns: Option<u64>,
    bids: BTreeMap<i64, u64>,
    asks: BTreeMap<i64, u64>,
    valid: bool,
}

impl Book {
    /// An empty book that waits for its first snapshot.
    #[must_use]
    pub const fn new(node: Address, instrument: InstrumentId) -> Self {
        Self {
            node,
            instrument,
            seq: 0,
            publish_time_ns: 0,
            local_recv_ns: 0,
            exchange_time_ns: None,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            valid: false,
        }
    }

    /// Applies one verified frame and returns whether the book is now valid.
    ///
    /// A snapshot replaces the book. A delta applies only on top of the frame
    /// before it: after a gap, the book is unknown until the next snapshot.
    pub fn apply(&mut self, update: &BookUpdate) -> bool {
        if update.snapshot {
            self.bids.clear();
            self.asks.clear();
            self.valid = true;
        } else if update.seq != self.seq.saturating_add(1) {
            self.valid = false;
        }
        self.seq = update.seq;
        self.publish_time_ns = update.publish_time_ns;
        self.local_recv_ns = update.local_recv_ns;
        self.exchange_time_ns = update.exchange_time_ns;
        if !self.valid {
            return false;
        }
        for (side, levels) in [
            (&mut self.bids, &update.bids),
            (&mut self.asks, &update.asks),
        ] {
            for level in levels {
                if level.qty == 0 {
                    side.remove(&level.price);
                } else {
                    side.insert(level.price, level.qty);
                }
            }
        }
        true
    }

    /// Returns `true` once a snapshot arrived and no frame was missed after it.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.valid
    }

    /// The bids, highest price first.
    pub fn bids(&self) -> impl Iterator<Item = BookLevel> + '_ {
        self.bids.iter().rev().map(level)
    }

    /// The asks, lowest price first.
    pub fn asks(&self) -> impl Iterator<Item = BookLevel> + '_ {
        self.asks.iter().map(level)
    }

    /// The best bid.
    #[must_use]
    pub fn best_bid(&self) -> Option<BookLevel> {
        self.bids.last_key_value().map(level)
    }

    /// The best ask.
    #[must_use]
    pub fn best_ask(&self) -> Option<BookLevel> {
        self.asks.first_key_value().map(level)
    }

    /// Converts a level to a price and a size.
    ///
    /// # Errors
    ///
    /// Returns [`FixedError`] if a mantissa does not fit the fixed-point range.
    pub fn level_fixed(level: BookLevel) -> Result<(Fixed, Fixed), FixedError> {
        let qty = i64::try_from(level.qty).map_err(|_| FixedError::Overflow)?;
        Ok((
            Fixed::from_scaled(level.price, BOOK_EXPO)?,
            Fixed::from_scaled(qty, BOOK_EXPO)?,
        ))
    }
}

fn level((price, qty): (&i64, &u64)) -> BookLevel {
    BookLevel {
        price: *price,
        qty: *qty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_types::{MarketKind, Venue};

    fn update(seq: u64, snapshot: bool, bids: &[(i64, u64)], asks: &[(i64, u64)]) -> BookUpdate {
        let side = |levels: &[(i64, u64)]| -> Vec<BookLevel> {
            levels
                .iter()
                .map(|&(price, qty)| BookLevel { price, qty })
                .collect()
        };
        BookUpdate {
            venue: Venue::Binance,
            market: MarketKind::Spot,
            symbol: "BTCUSDT".to_owned(),
            publish_time_ns: seq,
            seq,
            snapshot,
            exchange_time_ns: None,
            local_recv_ns: 0,
            bids: side(bids),
            asks: side(asks),
        }
    }

    fn book() -> Book {
        Book::new(
            Address::from_bytes([1; 20]),
            InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT"),
        )
    }

    #[test]
    fn deltas_build_on_the_snapshot() {
        let mut book = book();
        assert!(
            !book.apply(&update(5, false, &[(100, 1)], &[])),
            "no snapshot yet"
        );
        assert!(book.apply(&update(6, true, &[(100, 1), (99, 2)], &[(101, 1)])));
        assert!(book.apply(&update(7, false, &[(100, 0), (98, 4)], &[(102, 3)])));
        let bids: Vec<i64> = book.bids().map(|level| level.price).collect();
        assert_eq!(bids, vec![99, 98]);
        assert_eq!(book.best_ask().map(|level| level.price), Some(101));
        assert_eq!(book.asks().count(), 2);
    }

    #[test]
    fn a_gap_invalidates_the_book_until_the_next_snapshot() {
        let mut book = book();
        assert!(book.apply(&update(1, true, &[(100, 1)], &[(101, 1)])));
        assert!(
            !book.apply(&update(3, false, &[(100, 2)], &[])),
            "seq 2 is missing"
        );
        assert!(!book.is_valid());
        assert!(!book.apply(&update(4, false, &[(100, 3)], &[])));
        assert!(book.apply(&update(5, true, &[(100, 5)], &[(101, 1)])));
        assert_eq!(book.best_bid().map(|level| level.qty), Some(5));
    }
}
