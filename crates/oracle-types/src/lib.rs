//! Core domain types for the price oracle.
//!
//! This crate is pure data: no I/O, no clock, no cryptography. It defines the
//! vocabulary that the ingest, aggregation, and wire layers all share.
//!
//! The three things worth understanding before using anything else here:
//!
//! - [`Fixed`] is the internal arithmetic type: `i128` scaled by `10^-12`.
//!   Prices never touch floating point, so a recorded observation set always
//!   replays to a bit-identical published price.
//! - [`Symbol`] is a parsed, canonical feed name. It cannot be constructed in a
//!   non-canonical form, which is what makes [`FeedId`] derivation safe.
//! - [`PriceUpdate`] is the logical payload that gets signed. Its byte encoding
//!   lives in `oracle-wire`, not here, so this crate stays free of crypto deps.

mod book_update;
mod fixed;
mod flags;
mod observation;
mod symbol;
mod update;
mod venue;
mod venue_report;

pub use book_update::{
    BOOK_EXPO, BookLevel, BookUpdate, MAX_BOOK_LEVELS, MAX_BOOK_SYMBOL, side_changes,
};
pub use fixed::{Fixed, FixedError};
pub use flags::Flags;
pub use observation::{BookDepth, Impact, Level, ObsKind, ObsKindError, Observation};
pub use symbol::{AssetClass, AssetCode, FeedId, FeedKind, Symbol, SymbolError};
pub use update::PriceUpdate;
#[cfg(feature = "serde")]
pub use update::{num_str, opt_num_str};
pub use venue::{InstrumentId, MarketKind, Venue, VenueError, VenueSet};
pub use venue_report::{
    MAX_VENUE_ENTRIES, QTY_EXPO, RATE_EXPO, SourceStatus, VenueEntry, VenueReport,
};

/// Nanoseconds in one second, as `u64`.
pub const NANOS_PER_SEC: u64 = 1_000_000_000;
