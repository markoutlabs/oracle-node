//! Node configuration.
//!
//! One file describes the whole node. The ingest subscriptions are **derived**
//! from the feed definitions rather than listed separately: every source of every
//! feed is, by definition, an instrument to stream. Two lists would drift, and
//! the failure mode of that drift is a feed that silently loses a venue.
//!
//! - `settings`: the serde types of the file.
//! - `resolve`: the feeds to a [`ResolvedConfig`].
//! - `load`: the key and the signed documents that the config names.

use std::path::PathBuf;

mod load;
mod resolve;
mod settings;

pub use resolve::{ResolvedConfig, VenueConnection, resolve_feeds};
pub use settings::{
    ClientsSettings, DEFAULT_TICK_MS, EndpointSettings, FeedSettings, NetworkFeedsSettings,
    NodeConfig, PublishSettings, RegistrySettings, ServerSettings, SigningSettings, SourceSettings,
    max_pending,
};

/// Anything that stops the node starting.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The path attempted.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The file was not valid TOML, or did not match the schema.
    #[error("cannot parse {path}: {source}")]
    Parse {
        /// The path attempted.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: toml::de::Error,
    },

    /// A field held a value this node cannot use.
    #[error("invalid configuration: {0}")]
    Invalid(String),

    /// The signing key could not be loaded.
    #[error("cannot load the signing key: {0}")]
    SigningKey(String),

    /// The client list could not be loaded.
    #[error("cannot load the client list: {0}")]
    Clients(String),

    /// The registry could not be loaded or verified.
    #[error("cannot load the registry: {0}")]
    Registry(String),

    /// The network's feed set could not be fetched.
    #[error("cannot load the network feed set: {0}")]
    FeedSet(String),
}

impl ConfigError {
    /// Returns `true` if only an edit fixes this. A failed fetch may pass on a retry.
    #[must_use]
    pub const fn is_permanent(&self) -> bool {
        !matches!(
            self,
            Self::Registry(_) | Self::Clients(_) | Self::FeedSet(_)
        )
    }
}

#[cfg(test)]
mod fixture;
