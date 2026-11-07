//! The serde types of the config file, and their defaults.

#[cfg(feature = "serve")]
use std::path::PathBuf;

use serde::Deserialize;

/// The whole node configuration.
#[cfg(feature = "serve")]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Subscriber-facing server settings.
    pub server: ServerSettings,
    /// Where to find the signing key.
    pub signing: SigningSettings,
    /// Where to find the registry this node publishes as a hint.
    pub registry: RegistrySettings,
    /// Where the client list comes from. `start` requires it; it is optional
    /// here so tools that only read the feeds, such as replay, can share configs.
    #[serde(default)]
    pub clients: Option<ClientsSettings>,
    /// How often every feed is re-evaluated, in milliseconds. A price move is
    /// evaluated when it arrives; this timer catches what changes with no
    /// input: heartbeats and stale venues.
    #[serde(default = "default_tick_ms")]
    pub tick_interval_ms: u64,
    /// The feeds this node publishes.
    pub feeds: Vec<FeedSettings>,
    /// Venue endpoints in place of the built-in ones.
    #[serde(default)]
    pub endpoints: Vec<EndpointSettings>,
    /// Pushes to the registry canister, which resolves the median on-chain.
    /// No section, no pushes.
    #[serde(default)]
    pub publish: Option<PublishSettings>,
    /// The network's feed set, which replaces `feeds` once it verifies.
    #[serde(default)]
    pub network_feeds: Option<NetworkFeedsSettings>,
}

/// The canister's certified `/feeds.json`, checked against `registry.governance_address`.
#[cfg(feature = "serve")]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkFeedsSettings {
    /// URL of the canister's `/feeds.json`.
    pub url: String,
    /// Seconds between polls; keep it well below `lead_secs`, so every node sees a set before the first slot.
    #[serde(default = "default_network_feeds_poll_secs")]
    pub poll_secs: u64,
    /// Seconds from a publish to the first node's change; the same on every node of a network.
    #[serde(default = "default_network_feeds_lead_secs")]
    pub lead_secs: u64,
    /// Seconds between two nodes' changes. The same on every node, as `lead_secs`.
    #[serde(default = "default_network_feeds_slot_secs")]
    pub slot_secs: u64,
}

#[cfg(feature = "serve")]
impl NetworkFeedsSettings {
    /// The default `poll_secs`, which `init` writes too.
    pub const POLL_SECS: u64 = 30;

    /// The nodes' change slots.
    #[must_use]
    pub const fn slots(&self) -> oracle_wire::Slots {
        oracle_wire::Slots {
            lead_secs: self.lead_secs,
            slot_secs: self.slot_secs,
        }
    }
}

#[cfg(feature = "serve")]
const fn default_network_feeds_poll_secs() -> u64 {
    NetworkFeedsSettings::POLL_SECS
}

#[cfg(feature = "serve")]
const fn default_network_feeds_lead_secs() -> u64 {
    oracle_wire::SLOT_LEAD_SECS
}

#[cfg(feature = "serve")]
const fn default_network_feeds_slot_secs() -> u64 {
    oracle_wire::SLOT_SECS
}

/// When the node pushes its frames to the registry canister.
#[cfg(feature = "serve")]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishSettings {
    /// The Internet Computer API that takes the pushes. Mainnet's by default.
    #[serde(default = "default_publish_gateway")]
    pub gateway: String,
    /// Seconds after which a feed is pushed even when its price did not move.
    /// At most 60, and less than half the canister's price window
    /// (`get_price_window`), or a quiet feed drops out of its quorum.
    #[serde(default = "default_publish_heartbeat_secs")]
    pub heartbeat_secs: u64,
    /// A price move this large since the last push, in basis points, pushes
    /// the feed at once.
    #[serde(default = "default_publish_deviation_bps")]
    pub deviation_bps: u32,
    /// Seconds between two pushes, at least. Each push costs the canister cycles.
    #[serde(default = "default_publish_min_interval_secs")]
    pub min_interval_secs: u64,
}

#[cfg(feature = "serve")]
fn default_publish_gateway() -> String {
    "https://icp-api.io".to_owned()
}

#[cfg(feature = "serve")]
const fn default_publish_heartbeat_secs() -> u64 {
    30
}

#[cfg(feature = "serve")]
const fn default_publish_deviation_bps() -> u32 {
    10
}

#[cfg(feature = "serve")]
const fn default_publish_min_interval_secs() -> u64 {
    5
}

/// Subscriber-facing server settings.
#[cfg(feature = "serve")]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    /// Address to listen on.
    pub listen: String,
    /// Distinct feeds a subscriber may have outstanding before it is disconnected.
    #[serde(default = "default_max_pending")]
    pub max_pending_feeds: usize,
    /// What one peer can cost the node: sockets, handshakes, requests, messages.
    #[serde(default)]
    pub limits: oracle_server::Limits,
}

/// Where the hot signing key comes from.
///
/// A file, never a command-line argument: arguments are visible in `ps` to
/// every user on the box.
#[cfg(feature = "serve")]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningSettings {
    /// File containing the key: an `age` file as written by `init`, or plaintext
    /// hex for a local playground. Read once at startup.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// File containing the passphrase that opens an encrypted `key_file`,
    /// readable only by the operator. Without it the node prompts at startup,
    /// and refuses to start when there is no terminal.
    #[serde(default)]
    pub passphrase_file: Option<PathBuf>,
    /// Environment variable holding the key as plaintext hex.
    ///
    /// Only a build with the `dev-key-env` feature reads it, for local
    /// playgrounds with seeded keys. A real key never goes in an environment
    /// variable (SPEC §9.2).
    #[serde(default)]
    pub key_env: Option<String>,
}

/// Where the client list comes from. Exactly one of `path` and `url`. It is
/// verified against `registry.governance_address`, and a `url` response
/// against the certificate of `registry.canister_id`.
#[cfg(feature = "serve")]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientsSettings {
    /// Path to a signed client list JSON file. Read once; for local runs.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// URL of the canister's `/clients.json`, polled every `poll_secs`.
    #[serde(default)]
    pub url: Option<String>,
    /// Seconds between polls. Bounds how long a revocation takes to land.
    #[serde(default = "default_clients_poll_secs")]
    pub poll_secs: u64,
}

#[cfg(feature = "serve")]
const fn default_clients_poll_secs() -> u64 {
    30
}

/// Where the registry comes from. Exactly one of `path` and `url`.
#[cfg(feature = "serve")]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySettings {
    /// Path to a signed registry JSON file.
    ///
    /// A file is pinned until the node restarts. Fine for a local run; a
    /// deployed node should fetch from the registry canister instead.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// URL of the registry canister's `/registry.json` (SPEC §3.6). Fetched
    /// at startup.
    ///
    /// The response must carry the canister's certificate, and the document
    /// must carry the governance signature.
    #[serde(default)]
    pub url: Option<String>,
    /// The registry canister, whose certificate every fetched document must carry.
    #[serde(default)]
    pub canister_id: Option<String>,
    /// The root key of the canister's network, DER in hex. Mainnet if not set.
    #[serde(default)]
    pub root_key: Option<String>,
    /// Governance address to verify it against, `0x`-hex.
    ///
    /// Pinned here rather than taken from the registry itself, which would let
    /// the document vouch for its own author.
    pub governance_address: String,
}

// The feed set is a signed document too, so its types live with the encoding.
pub use oracle_wire::{FeedSettings, SourceSettings};

/// One venue market's WebSocket endpoint in place of the built-in one: a
/// regional host, a proxy, or a local feed for tests.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointSettings {
    /// Venue name, as in `oracle_types::Venue`.
    pub venue: String,
    /// `spot` or `linear_perp`.
    pub market: String,
    /// A `ws://` or `wss://` URL. For binance it is the combined-stream base,
    /// and the node appends `?streams=…`.
    pub url: String,
}

#[cfg(feature = "serve")]
const fn default_tick_ms() -> u64 {
    DEFAULT_TICK_MS
}

#[cfg(feature = "serve")]
const fn default_max_pending() -> usize {
    512
}

/// The bound below which [`max_pending`] never goes.
const MIN_PENDING: usize = 512;

/// The `server.max_pending_feeds` that `init` writes for `count` feeds.
#[must_use]
pub fn max_pending(count: usize) -> usize {
    // A slow subscriber can owe a price and a venue report for each feed.
    count.saturating_mul(2).next_power_of_two().max(MIN_PENDING)
}

/// The default of `tick_interval_ms`.
pub const DEFAULT_TICK_MS: u64 = 25;

#[cfg(feature = "serve")]
impl NodeConfig {
    /// The config's `max_pending_feeds`, raised for a larger set of `feeds` feeds.
    #[must_use]
    pub fn max_pending_for(&self, feeds: usize) -> usize {
        max_pending(feeds).max(self.server.max_pending_feeds)
    }
}

#[cfg(all(test, feature = "serve"))]
mod tests {
    use crate::config::fixture::{btc, config};

    #[test]
    fn the_server_limits_have_defaults_and_refuse_zero_and_unknown_keys() {
        assert_eq!(
            config().parse().server.limits,
            oracle_server::Limits::default()
        );
        let limits = |line: &str| {
            config()
                .section(&format!("[server.limits]\n{line}"))
                .try_parse()
        };
        let set = limits("sockets_per_ip = 4").expect("parses");
        assert_eq!(set.server.limits.sockets_per_ip.get(), 4);
        for bad in ["sockets_per_ip = 0", "sockets_per_hour = 4"] {
            assert!(limits(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_heartbeat_and_the_class_are_not_settings() {
        for (key, value) in [
            ("heartbeat_ms", toml::Value::from(500)),
            ("slow", true.into()),
        ] {
            assert!(
                config().feed(btc().set(key, value)).try_parse().is_err(),
                "{key} must be refused"
            );
        }
    }

    /// A typo in a config field is a silent misconfiguration otherwise.
    #[test]
    fn unknown_fields_are_refused_rather_than_ignored() {
        let typo = config().feed(btc().set("min_sourcs", 1));
        assert!(typo.try_parse().is_err(), "{}", typo.toml());
    }
}
