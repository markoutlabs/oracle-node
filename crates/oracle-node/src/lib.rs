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
pub mod books;
pub mod config;
pub mod init;
pub mod keyfile;
pub mod logging;
pub mod pipeline;
pub mod seed;

pub use adapters::{Adapters, build_adapters};
pub use config::{ConfigError, NodeConfig, ResolvedConfig};
pub use init::{
    CanisterId, Endpoint, Gateway, InitError, NodeKey, NodeSetup, RegistrySource, RootKey,
    Rotation, ServiceUnit, Unlock, Written, candid_call, generate_passphrase, resolve_path,
};
pub use keyfile::{KeyFileError, PassphraseSource};
pub use logging::LogFormat;
pub use pipeline::{Pipeline, PipelineStats};
pub use seed::{NodeKeys, Seed, SeedError};
