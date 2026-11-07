//! The network's built-in feed files, as text. `init` writes them into a node
//! config, and an app that embeds the node picks its feeds from them.

/// The hand-written feeds, below the settings of a local test node.
pub const ALL_FEEDS_TOML: &str = include_str!("../../../node/all-feeds.toml");

/// The most traded assets, from `scripts/asset-feeds.py`.
pub const ASSETS_TOML: &str = include_str!("../../../node/assets.toml");
