//! The proxy config file.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use oracle_types::Symbol;
use oracle_wire::Address;
use serde::Deserialize;

/// A config the proxy cannot run with.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
    /// The file is not a valid config.
    #[error("{path} is not a valid proxy config: {source}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: toml::de::Error,
    },
    /// A value is out of range.
    #[error("{0}")]
    Invalid(String),
}

/// The proxy config.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Where web clients connect. Keep it on loopback, behind a reverse proxy
    /// that terminates TLS.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// The nodes and the trust root.
    pub upstream: UpstreamConfig,
    /// What the proxy serves.
    pub feeds: FeedsConfig,
    /// Limits on web clients.
    #[serde(default)]
    pub limits: Limits,
}

/// How the proxy reaches the nodes, as one listed client.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// The registry canister. Mainnet's when absent.
    pub canister_id: Option<String>,
    /// The registry document's URL, for a local network. Mainnet's when absent.
    pub registry_url: Option<String>,
    /// The network's root key in hex, for a local network. Mainnet's when absent.
    pub root_key: Option<String>,
    /// The pinned governance address. Mainnet's when absent.
    pub governance: Option<Address>,
    /// A file with this proxy's client API key in hex. Governance lists its
    /// address with `add_client`.
    pub client_key_file: PathBuf,
    /// Nodes that must agree on a price.
    #[serde(default = "default_quorum")]
    pub quorum: usize,
    /// Allows a quorum below three. One node proves who is talking, not that
    /// the price is right.
    #[serde(default)]
    pub allow_low_quorum: bool,
}

/// The feeds the proxy pulls from the nodes and serves.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedsConfig {
    /// Feeds whose prices to serve.
    #[serde(default)]
    pub prices: Vec<Symbol>,
    /// Feeds whose venue reports to serve.
    #[serde(default)]
    pub venues: Vec<Symbol>,
    /// Feeds whose sources' books to serve.
    #[serde(default)]
    pub books: Vec<Symbol>,
}

/// Limits on web clients. The socket is open to anyone, so these are the
/// whole defence against a client that asks for too much.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Open sockets, in total.
    pub max_connections: usize,
    /// Open sockets from one IP address.
    pub connections_per_ip: usize,
    /// New sockets from one IP address each minute.
    pub connects_per_minute: u32,
    /// Control messages from one socket each second.
    pub messages_per_second: u32,
    /// Prices, venue feeds and books one socket may hold.
    pub max_subscriptions: usize,
    /// Book messages one socket may have waiting for one book. Past this, the
    /// socket gets a fresh snapshot instead.
    pub max_book_queue: usize,
    /// How often books are compared and their changes sent, in milliseconds.
    pub book_interval_ms: u64,
    /// Takes the client address from the last `X-Forwarded-For` entry, the one
    /// the reverse proxy adds. Set it only behind a reverse proxy that sets it.
    pub trust_forwarded_for: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 1_024,
            connections_per_ip: 8,
            connects_per_minute: 30,
            messages_per_second: 10,
            max_subscriptions: 256,
            max_book_queue: 64,
            book_interval_ms: 100,
            trust_forwarded_for: false,
        }
    }
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8792))
}

const fn default_quorum() -> usize {
    3
}

impl ProxyConfig {
    /// Reads and checks a config file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be read or parsed, or a value
    /// is out of range.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let config: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Checks the values that parse but cannot work.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] with the reason.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |reason: &str| Err(ConfigError::Invalid(reason.to_owned()));
        let feeds = &self.feeds;
        if feeds.prices.is_empty() && feeds.venues.is_empty() && feeds.books.is_empty() {
            return invalid("[feeds] lists nothing to serve");
        }
        if self.upstream.quorum == 0 {
            return invalid("upstream.quorum must be at least 1");
        }
        if self.upstream.quorum < 3 && !self.upstream.allow_low_quorum {
            return invalid(
                "upstream.quorum below 3 needs allow_low_quorum = true: \
                 one node proves who is talking, not that the price is right",
            );
        }
        if self.upstream.registry_url.is_some() != self.upstream.root_key.is_some() {
            return invalid("upstream.registry_url and upstream.root_key go together");
        }
        let limits = &self.limits;
        if limits.max_connections == 0
            || limits.connections_per_ip == 0
            || limits.connects_per_minute == 0
            || limits.messages_per_second == 0
            || limits.max_subscriptions == 0
            || limits.max_book_queue == 0
            || limits.book_interval_ms == 0
        {
            return invalid("every [limits] value must be above zero");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<ProxyConfig, ConfigError> {
        let config: ProxyConfig = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: PathBuf::from("test.toml"),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    const MINIMAL: &str = r#"
[upstream]
client_key_file = "proxy.key"

[feeds]
prices = ["CRYPTO.BTC/USD"]
"#;

    #[test]
    fn a_minimal_config_takes_mainnet_and_the_defaults() {
        let config = parse(MINIMAL).expect("valid");
        assert_eq!(config.listen, default_listen());
        assert_eq!(config.upstream.quorum, 3);
        assert!(config.upstream.canister_id.is_none());
        assert_eq!(config.limits, Limits::default());
    }

    #[test]
    fn the_example_config_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proxy/proxy.toml");
        let config = ProxyConfig::load(&path).expect("proxy/proxy.toml is valid");
        assert!(config.limits.trust_forwarded_for);
    }

    #[test]
    fn a_low_quorum_needs_the_acknowledgement() {
        let low = MINIMAL.replace(
            "client_key_file = \"proxy.key\"",
            "client_key_file = \"proxy.key\"\nquorum = 1",
        );
        assert!(parse(&low).is_err());
        let acknowledged = low.replace("quorum = 1", "quorum = 1\nallow_low_quorum = true");
        assert!(parse(&acknowledged).is_ok());
    }

    #[test]
    fn nothing_to_serve_and_bad_symbols_are_refused() {
        let empty = MINIMAL.replace("prices = [\"CRYPTO.BTC/USD\"]", "");
        assert!(parse(&empty).is_err());
        let bad = MINIMAL.replace("CRYPTO.BTC/USD", "not a symbol");
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn a_local_registry_needs_its_root_key() {
        let local = MINIMAL.replace(
            "client_key_file = \"proxy.key\"",
            "client_key_file = \"proxy.key\"\nregistry_url = \"http://127.0.0.1:8000/registry.json\"",
        );
        assert!(parse(&local).is_err());
    }
}
