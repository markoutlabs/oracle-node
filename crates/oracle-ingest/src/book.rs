//! Local order books, kept from a venue's snapshot and the deltas after it.
//!
//! A book is only as good as the last delta applied to it. Each venue proves
//! continuity its own way (a checksum, an update id, a sequence number), and a
//! failed proof is [`DecodeError::Resync`]: the session drops the connection,
//! the reconnect resubscribes, and the venue sends a fresh snapshot. A book the
//! node cannot prove correct never prices anything.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use oracle_types::{BookDepth, Fixed, InstrumentId, Level, ObsKind, Observation};

use crate::DecodeError;

/// Levels per side carried in each depth observation.
pub const DEPTH_LEVELS: usize = 50;

/// Which side of the book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Bids.
    Bid,
    /// Asks.
    Ask,
}

/// One resting level. The venue's own text is kept where a checksum is
/// computed over it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Resting {
    qty: Fixed,
    text: Option<(Box<str>, Box<str>)>,
}

/// One instrument's book.
#[derive(Clone, Debug, Default)]
pub struct LocalBook {
    bids: BTreeMap<Fixed, Resting>,
    asks: BTreeMap<Fixed, Resting>,
    /// The venue's last update id or sequence number, for continuity checks.
    pub last_id: Option<u64>,
}

impl LocalBook {
    /// Empties the book, ahead of a snapshot.
    pub fn clear(&mut self) {
        self.bids.clear();
        self.asks.clear();
        self.last_id = None;
    }

    /// Sets a level. A zero size removes it.
    pub fn set(&mut self, side: Side, price: Fixed, qty: Fixed) {
        self.set_with_text(side, price, qty, None);
    }

    /// Sets a level and keeps the venue's text for it.
    pub fn set_with_text(
        &mut self,
        side: Side,
        price: Fixed,
        qty: Fixed,
        text: Option<(&str, &str)>,
    ) {
        let levels = self.side_mut(side);
        if qty.is_positive() {
            let text = text.map(|(price, qty)| (price.into(), qty.into()));
            levels.insert(price, Resting { qty, text });
        } else {
            levels.remove(&price);
        }
    }

    /// Keeps only the best `depth` levels on each side. Venues that publish a
    /// fixed depth stop sending levels that fall out of it.
    pub fn truncate(&mut self, depth: usize) {
        while self.bids.len() > depth {
            self.bids.pop_first();
        }
        while self.asks.len() > depth {
            self.asks.pop_last();
        }
    }

    /// The best `n` levels of one side, best first.
    #[must_use]
    pub fn top(&self, side: Side, n: usize) -> Vec<Level> {
        let level = |(price, resting): (&Fixed, &Resting)| Level {
            price: *price,
            qty: resting.qty,
        };
        match side {
            Side::Bid => self.bids.iter().rev().take(n).map(level).collect(),
            Side::Ask => self.asks.iter().take(n).map(level).collect(),
        }
    }

    /// The venue's text for the best `n` levels of one side, best first.
    /// `None` if any of them was set without text.
    #[must_use]
    pub fn top_text(&self, side: Side, n: usize) -> Option<Vec<(&str, &str)>> {
        fn text(resting: &Resting) -> Option<(&str, &str)> {
            resting
                .text
                .as_ref()
                .map(|(price, qty)| (price.as_ref(), qty.as_ref()))
        }
        match side {
            Side::Bid => self.bids.values().rev().take(n).map(text).collect(),
            Side::Ask => self.asks.values().take(n).map(text).collect(),
        }
    }

    /// `true` if the best bid is above the best ask.
    #[must_use]
    pub fn is_crossed(&self) -> bool {
        matches!(
            (self.bids.last_key_value(), self.asks.first_key_value()),
            (Some((bid, _)), Some((ask, _))) if bid > ask
        )
    }

    fn side_mut(&mut self, side: Side) -> &mut BTreeMap<Fixed, Resting> {
        match side {
            Side::Bid => &mut self.bids,
            Side::Ask => &mut self.asks,
        }
    }
}

/// The last funding fields of one instrument, for a venue whose messages
/// carry only the fields that changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LastFunding {
    /// The funding rate.
    pub rate: Option<Fixed>,
    /// The funding period, in nanoseconds.
    pub interval_ns: Option<u64>,
    /// The next funding time, in unix nanoseconds.
    pub next_funding_time_ns: Option<u64>,
    /// The venue's prediction of the next rate.
    pub predicted: Option<Fixed>,
    /// The last rate that the venue settled, and when.
    pub settled: Option<(Fixed, u64)>,
    /// The open interest, in the venue's unit.
    pub open_interest: Option<Fixed>,
}

/// Every book on one connection, by venue symbol. Emptied on each connect, so
/// nothing from before a gap survives it.
#[derive(Clone, Debug, Default)]
pub struct Books {
    by_symbol: HashMap<String, LocalBook>,
    /// The last sequence number on the connection, for venues that number
    /// every message rather than each book.
    pub sequence: Option<u64>,
    funding: HashMap<String, LastFunding>,
}

impl Books {
    /// Drops every book and every funding state.
    pub fn clear(&mut self) {
        self.by_symbol.clear();
        self.sequence = None;
        self.funding.clear();
    }

    /// The last funding fields for a venue symbol, created empty.
    pub fn funding(&mut self, symbol: &str) -> &mut LastFunding {
        self.funding.entry(symbol.to_owned()).or_default()
    }

    /// The book for a venue symbol, created empty.
    pub fn book(&mut self, symbol: &str) -> &mut LocalBook {
        self.by_symbol.entry(symbol.to_owned()).or_default()
    }

    /// Emits the book's top levels as a depth observation.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Resync`] for a crossed book: deltas were missed or
    /// misapplied, and nothing it says can be trusted.
    pub fn emit(
        &self,
        symbol: &str,
        instrument: InstrumentId,
        exchange_time_ns: Option<u64>,
        local_recv_ns: u64,
        out: &mut Vec<Observation>,
    ) -> Result<(), DecodeError> {
        self.emit_as(
            ObsKind::Depth,
            symbol,
            instrument,
            exchange_time_ns,
            local_recv_ns,
            out,
        )
    }

    /// Emits only the best bid and ask, for an instrument that wants no depth.
    ///
    /// # Errors
    ///
    /// As [`Books::emit`].
    pub fn emit_top(
        &self,
        symbol: &str,
        instrument: InstrumentId,
        exchange_time_ns: Option<u64>,
        local_recv_ns: u64,
        out: &mut Vec<Observation>,
    ) -> Result<(), DecodeError> {
        self.emit_as(
            ObsKind::BookTop,
            symbol,
            instrument,
            exchange_time_ns,
            local_recv_ns,
            out,
        )
    }

    fn emit_as(
        &self,
        kind: ObsKind,
        symbol: &str,
        instrument: InstrumentId,
        exchange_time_ns: Option<u64>,
        local_recv_ns: u64,
        out: &mut Vec<Observation>,
    ) -> Result<(), DecodeError> {
        let Some(book) = self.by_symbol.get(symbol) else {
            return Ok(());
        };
        if book.is_crossed() {
            return Err(DecodeError::Resync(format!(
                "{symbol}: the book is crossed"
            )));
        }
        let depth = kind == ObsKind::Depth;
        let levels = if depth { DEPTH_LEVELS } else { 1 };
        let (bids, asks) = (book.top(Side::Bid, levels), book.top(Side::Ask, levels));
        let (Some(best_bid), Some(best_ask)) = (bids.first().copied(), asks.first().copied())
        else {
            return Ok(());
        };
        let mid = best_bid
            .price
            .checked_add(best_ask.price)
            .and_then(|sum| sum.checked_div(Fixed::from_int(2).ok()?))
            .unwrap_or(best_bid.price);
        out.push(Observation {
            instrument,
            kind,
            price: mid,
            bid: Some(best_bid.price),
            ask: Some(best_ask.price),
            bid_qty: Some(best_bid.qty),
            ask_qty: Some(best_ask.qty),
            depth_notional_1bp: None,
            exchange_time_ns,
            local_recv_ns,
            seq: book.last_id,
            book: depth.then(|| Arc::new(BookDepth { bids, asks })),
            funding: None,
        });
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixed-shape books; an out-of-range index is a failing test"
)]
mod tests {
    use super::*;

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("valid decimal")
    }

    #[test]
    fn levels_are_set_removed_and_ordered_best_first() {
        let mut book = LocalBook::default();
        book.set(Side::Bid, fixed("99"), fixed("1"));
        book.set(Side::Bid, fixed("100"), fixed("2"));
        book.set(Side::Ask, fixed("102"), fixed("1"));
        book.set(Side::Ask, fixed("101"), fixed("3"));
        assert_eq!(book.top(Side::Bid, 1)[0].price, fixed("100"));
        assert_eq!(book.top(Side::Ask, 1)[0].price, fixed("101"));

        book.set(Side::Bid, fixed("100"), Fixed::ZERO);
        assert_eq!(book.top(Side::Bid, 5).len(), 1);
        assert_eq!(book.top(Side::Bid, 1)[0].price, fixed("99"));
    }

    #[test]
    fn truncate_drops_the_worst_levels() {
        let mut book = LocalBook::default();
        for price in ["97", "98", "99"] {
            book.set(Side::Bid, fixed(price), fixed("1"));
        }
        for price in ["101", "102", "103"] {
            book.set(Side::Ask, fixed(price), fixed("1"));
        }
        book.truncate(2);
        let prices = |side| -> Vec<Fixed> { book.top(side, 5).iter().map(|l| l.price).collect() };
        assert_eq!(prices(Side::Bid), [fixed("99"), fixed("98")]);
        assert_eq!(prices(Side::Ask), [fixed("101"), fixed("102")]);
    }

    #[test]
    fn a_crossed_book_asks_for_a_resync() {
        let mut books = Books::default();
        let book = books.book("BTCUSDT");
        book.set(Side::Bid, fixed("101"), fixed("1"));
        book.set(Side::Ask, fixed("100"), fixed("1"));
        let instrument = InstrumentId::new(
            oracle_types::Venue::Kraken,
            oracle_types::MarketKind::Spot,
            "BTC/USD",
        );
        let mut out = Vec::new();
        assert!(matches!(
            books.emit("BTCUSDT", instrument, None, 1, &mut out),
            Err(DecodeError::Resync(_))
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn text_is_kept_only_where_given() {
        let mut book = LocalBook::default();
        book.set_with_text(Side::Ask, fixed("101"), fixed("1"), Some(("101.0", "1.00")));
        assert_eq!(book.top_text(Side::Ask, 1), Some(vec![("101.0", "1.00")]));
        book.set(Side::Ask, fixed("100"), fixed("1"));
        assert_eq!(book.top_text(Side::Ask, 2), None);
    }
}
