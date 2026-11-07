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
pub mod catalog;
pub mod config;
pub mod embed;
pub mod feed_set;
pub mod funding;
pub mod ingest;
#[cfg(feature = "cli")]
pub mod init;
#[cfg(feature = "serve")]
pub mod keyfile;
#[cfg(feature = "cli")]
pub mod logging;
pub mod pipeline;
#[cfg(feature = "serve")]
pub mod publish;
pub mod run;
pub mod seed;

pub use adapters::{Adapter, build_adapters, build_venue_adapters};
#[cfg(feature = "serve")]
pub use config::NodeConfig;
pub use config::{ConfigError, ResolvedConfig};
#[cfg(feature = "cli")]
pub use init::{
    CanisterId, Endpoint, FeedUpdate, Gateway, InitError, NodeKey, NodeSetup, RegistrySource,
    RootKey, Rotation, ServiceUnit, Unlock, Written, candid_call, generate_passphrase,
    resolve_path, update_feeds,
};
#[cfg(feature = "serve")]
pub use keyfile::{KeyFileError, PassphraseSource};
#[cfg(feature = "cli")]
pub use logging::LogFormat;
pub use pipeline::{Pipeline, PipelineStats};
pub use seed::{NodeKeys, Seed, SeedError};
