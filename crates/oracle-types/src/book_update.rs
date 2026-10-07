//! One frame of a venue's order book, as a node keeps it: a snapshot of the top
//! levels, or the levels that changed since the previous frame.
//!
//! A client that applies a snapshot and then every delta in `seq` order holds
//! exactly the node's top levels. A gap in `seq` makes the book unknown until
//! the next snapshot.

use crate::{MarketKind, Venue};

/// The exponent of every price and size in a book update.
pub const BOOK_EXPO: i32 = -8;

/// The most levels one side of a book update carries. A delta of a 50-level
/// window changes at most 100 levels on a side.
pub const MAX_BOOK_LEVELS: usize = 128;

/// The longest venue symbol a book update carries.
pub const MAX_BOOK_SYMBOL: usize = 32;

/// One price level: a price and the size resting there, both at the update's
/// exponents. In a delta, a size of zero removes the level.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct BookLevel {
    /// The price mantissa.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub price: i64,
    /// The size mantissa, in base units.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub qty: u64,
}

/// A snapshot or a delta of one venue instrument's book, signed by one node.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct BookUpdate {
    /// The venue.
    pub venue: Venue,
    /// Spot or perpetual.
    pub market: MarketKind,
    /// The venue's own symbol for the instrument, such as `BTCUSDT`.
    pub symbol: String,
    /// When the node signed this update, in unix nanoseconds.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub publish_time_ns: u64,
    /// Monotonic per `(node, book)`. A delta applies to the frame with
    /// `seq - 1`.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub seq: u64,
    /// `true` for the full top of the book, `false` for the changes since the
    /// previous frame.
    pub snapshot: bool,
    /// The venue's own timestamp on the newest book data, if it sends one.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub exchange_time_ns: Option<u64>,
    /// Our receipt time of the newest book data, or `0` with none.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub local_recv_ns: u64,
    /// Bids, highest price first.
    pub bids: Vec<BookLevel>,
    /// Asks, lowest price first.
    pub asks: Vec<BookLevel>,
}

impl BookUpdate {
    /// Returns `true` if the book data is not dated after the signature.
    #[must_use]
    pub const fn timestamps_coherent(&self) -> bool {
        self.local_recv_ns <= self.publish_time_ns
    }
}
