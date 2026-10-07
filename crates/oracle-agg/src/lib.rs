//! Aggregation: many venues' observations into one price and confidence.
//!
//! # A pure function, deliberately
//!
//! [`Aggregator`] holds no clock, opens no socket, and spawns nothing. Time
//! arrives as a `now_ns` argument and results are returned rather than sent.
//!
//! That constraint is the point. It means a recorded observation sequence
//! replayed through this crate reproduces its prices bit-for-bit, months later,
//! on a different machine — so every production incident becomes a unit test
//! instead of an argument. It is also why [`oracle_types::Fixed`] exists: with
//! floating point, reproducibility would depend on evaluation order and compiler
//! flags, which is exactly the "only happens in production" class of bug this
//! design is trying to eliminate.
//!
//! # The governing bias
//!
//! **Degrade loudly, halt rarely, never silently narrow.** An oracle that goes
//! dark breaks its consumers; one that publishes a confident wrong number
//! liquidates them. Widening the confidence interval is the pressure-release
//! valve, and nearly every failure path reaches for it before reaching for a
//! halt. Halting is reserved for the cases where there is no honest price to
//! widen around: too few live sources, or a price outside the sanity band.
//!
//! # What confidence means
//!
//! `conf` is the widest of three floors — how much the venues disagree, how tight
//! their books actually are, and an absolute minimum. It is not decoration. It is
//! how the oracle says "markets are dislocated" without either lying about the
//! price or going dark, and it is the number a consumer should key off.
//!
//! # Pipeline
//!
//! ```text
//!   observations ──▶ per-venue quote      (microprice, staleness, crossed books)
//!                ──▶ outlier rejection    (MAD, never below quorum)
//!                ──▶ weighted median      (one venue cannot move it, at any weight)
//!                ──▶ confidence           (disagreement ∨ spread ∨ floor)
//!                ──▶ circuit breakers     (jump corroboration, sanity band)
//!                ──▶ publication policy   (rate cap, then deviation ∨ heartbeat)
//! ```

pub mod aggregate;
pub mod config;
pub mod quote;
pub mod state;
pub mod stats;

pub use aggregate::{Aggregation, Outcome, Reasons};
pub use config::{ConfigError, FeedConfig, SourceConfig};
pub use quote::SourceQuote;
pub use state::{AggError, Aggregator, Cause, FeedStats, Trigger};
