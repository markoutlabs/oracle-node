//! An oracle node: ingest, aggregate, sign, serve.
//!
//! ```text
//!   exchanges ──▶ oracle-ingest ──▶ Pipeline ──▶ oracle-server ──▶ subscribers
//!                                      │
//!                                 oracle-agg + oracle-wire
//! ```
//!
//! The whole node is one config file. Ingest subscriptions are **derived** from
//! the feed definitions rather than listed separately — two lists would drift,
//! and the failure mode of that drift is a feed that quietly loses a venue.
//!
//! [`Pipeline`] is deliberately synchronous and owned by a single task. The
//! ordering guarantee that `oracle-ingest` provides — a disconnect notice
//! reaching the aggregator before any post-reconnect quote — only means
//! something if nothing downstream reorders it.

pub mod adapters;
pub mod config;
pub mod init;
pub mod keyfile;
pub mod pipeline;

pub use adapters::build_adapters;
pub use config::{ConfigError, NodeConfig, ResolvedConfig};
pub use init::{InitError, InitOptions, NodeKeys, Rotation, candid_call};
pub use keyfile::{KeyFileError, PassphraseSource};
pub use pipeline::{Pipeline, PipelineStats};
