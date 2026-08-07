//! Node configuration.
//!
//! One file describes the whole node. The ingest subscriptions are **derived**
//! from the feed definitions rather than listed separately: every source of every
//! feed is, by definition, an instrument to stream. Two lists would drift, and
//! the failure mode of that drift is a feed that silently loses a venue.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use oracle_agg::FeedConfig;
use oracle_agg::config::SourceConfig;
use oracle_ingest::InstrumentSpec;
use oracle_ingest::binance::BinanceConfig;
use oracle_types::{Fixed, InstrumentId, MarketKind, ObsKind, Symbol, Venue};
use oracle_wire::feed_id;
use serde::Deserialize;

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

    /// The registry could not be loaded or verified.
    #[error("cannot load the registry: {0}")]
    Registry(String),
}

/// The whole node configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// This node's identifier, which must match its registry entry.
    pub node_id: String,
    /// Subscriber-facing server settings.
    pub server: ServerSettings,
    /// Where to find the signing key.
    pub signing: SigningSettings,
    /// Where to find the registry this node publishes as a hint.
    pub registry: RegistrySettings,
    /// How often to evaluate every feed, in milliseconds.
    ///
    /// Must be at or below the tightest feed's rate cap, or the cap becomes the
    /// tick rate and the deviation trigger never fires early.
    #[serde(default = "default_tick_ms")]
    pub tick_interval_ms: u64,
    /// The feeds this node publishes.
    pub feeds: Vec<FeedSettings>,
}

/// Subscriber-facing server settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    /// Address to listen on.
    pub listen: String,
    /// Distinct feeds a subscriber may have outstanding before it is disconnected.
    #[serde(default = "default_max_pending")]
    pub max_pending_feeds: usize,
}

/// Where the hot signing key comes from.
///
/// A path or an environment variable, never a command-line argument: arguments
/// are visible in `ps` to every user on the box.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningSettings {
    /// File containing the key as hex. Read once at startup.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// Environment variable holding the key as hex.
    #[serde(default)]
    pub key_env: Option<String>,
}

/// Where the registry comes from.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySettings {
    /// Path to the signed registry JSON.
    pub path: PathBuf,
    /// Governance address to verify it against, `0x`-hex.
    ///
    /// Pinned here rather than taken from the registry itself, which would let
    /// the document vouch for its own author.
    pub governance_address: String,
}

/// One feed.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedSettings {
    /// Canonical symbol.
    pub symbol: String,
    /// Surviving venues required before the feed publishes a usable price.
    #[serde(default)]
    pub min_sources: Option<u32>,
    /// Treat this as a slow-moving quantity: funding rates, open interest.
    #[serde(default)]
    pub slow: bool,
    /// Contributing venues.
    pub sources: Vec<SourceSettings>,
}

/// One venue's contribution to a feed.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSettings {
    /// Venue name, as in `oracle_types::Venue`.
    pub venue: String,
    /// `spot` or `linear_perp`.
    pub market: String,
    /// The venue's own symbol.
    pub symbol: String,
    /// Observation kinds in preference order; `["book_top", "trade"]` by default.
    #[serde(default)]
    pub kinds: Option<Vec<String>>,
    /// Static trust weight as a decimal string; `1` by default.
    #[serde(default)]
    pub weight: Option<String>,
}

const fn default_tick_ms() -> u64 {
    25
}

const fn default_max_pending() -> usize {
    512
}

/// Everything the node needs to start, derived from the config.
pub struct ResolvedConfig {
    /// Aggregation configuration, one entry per feed.
    pub feeds: Vec<FeedConfig>,
    /// The canonical symbols this node serves.
    pub symbols: Vec<Symbol>,
    /// Binance ingest configuration, derived from the feed sources.
    pub binance: BinanceConfig,
    /// How often to evaluate feeds.
    pub tick_interval: Duration,
}

impl NodeConfig {
    /// Loads a config file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] or [`ConfigError::Parse`].
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })
    }

    /// Loads the signing key from the configured source.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::SigningKey`] if no source is configured, the source
    /// cannot be read, or the value is not a valid key.
    pub fn load_signing_key(&self) -> Result<oracle_wire::Signer, ConfigError> {
        let hex = match (&self.signing.key_file, &self.signing.key_env) {
            (Some(path), _) => std::fs::read_to_string(path)
                .map_err(|e| ConfigError::SigningKey(format!("{}: {e}", path.display())))?,
            (None, Some(var)) => std::env::var(var)
                .map_err(|_| ConfigError::SigningKey(format!("${var} is not set")))?,
            (None, None) => {
                return Err(ConfigError::SigningKey(
                    "set either signing.key_file or signing.key_env".to_owned(),
                ));
            }
        };
        oracle_wire::Signer::from_hex(hex.trim())
            .map_err(|e| ConfigError::SigningKey(e.to_string()))
    }

    /// Loads and verifies the registry against the pinned governance address.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Registry`] if the file is unreadable, malformed, or
    /// not signed by the pinned key.
    pub fn load_registry(&self) -> Result<oracle_wire::Registry, ConfigError> {
        let path = &self.registry.path;
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Registry(format!("{}: {e}", path.display())))?;
        let registry: oracle_wire::Registry = serde_json::from_str(&text)
            .map_err(|e| ConfigError::Registry(format!("{}: {e}", path.display())))?;

        let governance: oracle_wire::Address = self
            .registry
            .governance_address
            .parse()
            .map_err(|e| ConfigError::Registry(format!("bad governance address: {e}")))?;
        registry
            .verify(governance, 0)
            .map_err(|e| ConfigError::Registry(e.to_string()))?;
        Ok(registry)
    }

    /// Resolves the config into everything the node needs to run.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] for an unparseable symbol, venue, market,
    /// or observation kind, or for a feed that could never publish.
    pub fn resolve(&self) -> Result<ResolvedConfig, ConfigError> {
        if self.feeds.is_empty() {
            return Err(ConfigError::Invalid("no feeds configured".to_owned()));
        }

        let mut feeds = Vec::with_capacity(self.feeds.len());
        let mut symbols = Vec::with_capacity(self.feeds.len());
        // Deduplicated because several feeds may read the same instrument, and
        // subscribing twice would double the message rate for no benefit.
        let mut instruments: BTreeMap<(Venue, MarketKind, String), InstrumentSpec> =
            BTreeMap::new();

        for feed in &self.feeds {
            let symbol: Symbol = feed
                .symbol
                .parse()
                .map_err(|e| ConfigError::Invalid(format!("feed `{}`: {e}", feed.symbol)))?;
            symbols.push(symbol);

            let mut sources = Vec::with_capacity(feed.sources.len());
            for source in &feed.sources {
                let venue: Venue = source
                    .venue
                    .parse()
                    .map_err(|e| ConfigError::Invalid(format!("feed `{}`: {e}", feed.symbol)))?;
                let market: MarketKind = source
                    .market
                    .parse()
                    .map_err(|e| ConfigError::Invalid(format!("feed `{}`: {e}", feed.symbol)))?;
                let kinds = match &source.kinds {
                    Some(names) => names
                        .iter()
                        .map(|name| {
                            name.parse::<ObsKind>().map_err(|e| {
                                ConfigError::Invalid(format!("feed `{}`: {e}", feed.symbol))
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    None => vec![ObsKind::BookTop, ObsKind::Trade],
                };

                let instrument = InstrumentId::new(venue, market, source.symbol.as_str());
                let mut config = SourceConfig::new(instrument, kinds);
                if let Some(weight) = &source.weight {
                    let weight: Fixed = weight.parse().map_err(|e| {
                        ConfigError::Invalid(format!("feed `{}`: bad weight: {e}", feed.symbol))
                    })?;
                    config = config.with_weight(weight);
                }
                sources.push(config);

                instruments
                    .entry((venue, market, source.symbol.clone()))
                    .or_insert_with(|| InstrumentSpec {
                        venue_symbol: source.symbol.clone(),
                        market,
                        canonical: symbol,
                    });
            }

            let id = feed_id(&symbol);
            let mut config = if feed.slow {
                FeedConfig::slow(symbol, id, sources)
            } else {
                FeedConfig::spot(symbol, id, sources)
            };
            if let Some(min_sources) = feed.min_sources {
                config.min_sources = min_sources;
            }
            config
                .validate()
                .map_err(|e| ConfigError::Invalid(e.to_string()))?;
            feeds.push(config);
        }

        let mut binance = BinanceConfig::default();
        for ((venue, market, _), spec) in instruments {
            if venue != Venue::Binance {
                return Err(ConfigError::Invalid(format!(
                    "venue `{venue}` has no adapter yet; only binance is implemented"
                )));
            }
            match market {
                MarketKind::Spot => binance.spot.push(spec),
                MarketKind::LinearPerp => binance.perp.push(spec),
            }
        }

        Ok(ResolvedConfig {
            feeds,
            symbols,
            binance,
            tick_interval: Duration::from_millis(self.tick_interval_ms.max(1)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
node_id = "oracle-eu-1"

[server]
listen = "127.0.0.1:8080"

[signing]
key_env = "ORACLE_SIGNING_KEY"

[registry]
path = "registry.json"
governance_address = "0x0000000000000000000000000000000000000001"

[[feeds]]
symbol = "CRYPTO.BTC/USDT"
min_sources = 1
sources = [
  { venue = "binance", market = "spot", symbol = "BTCUSDT" },
]

[[feeds]]
symbol = "CRYPTO.BTC/USDT.PERP_MARK"
min_sources = 1
sources = [
  { venue = "binance", market = "linear_perp", symbol = "BTCUSDT", kinds = ["mark_price"] },
]
"#;

    fn parse(text: &str) -> NodeConfig {
        toml::from_str(text).expect("parses")
    }

    #[test]
    fn a_complete_config_resolves() {
        let resolved = parse(SAMPLE).resolve().expect("resolves");
        assert_eq!(resolved.feeds.len(), 2);
        assert_eq!(resolved.symbols.len(), 2);
        assert_eq!(resolved.tick_interval, Duration::from_millis(25));
    }

    /// The point of deriving subscriptions from feeds: they cannot drift apart.
    #[test]
    fn ingest_subscriptions_are_derived_from_the_feed_sources() {
        let resolved = parse(SAMPLE).resolve().expect("resolves");
        assert_eq!(resolved.binance.spot.len(), 1);
        assert_eq!(resolved.binance.perp.len(), 1);
        assert_eq!(
            resolved
                .binance
                .spot
                .first()
                .map(|spec| spec.venue_symbol.as_str()),
            Some("BTCUSDT")
        );
        assert_eq!(
            resolved.binance.perp.first().map(|spec| spec.market),
            Some(MarketKind::LinearPerp)
        );
    }

    #[test]
    fn an_instrument_shared_by_two_feeds_is_subscribed_once() {
        let text = SAMPLE.replace(
            r#"symbol = "CRYPTO.BTC/USDT.PERP_MARK""#,
            r#"symbol = "CRYPTO.BTC/USD""#,
        )
        .replace(
            r#"{ venue = "binance", market = "linear_perp", symbol = "BTCUSDT", kinds = ["mark_price"] },"#,
            r#"{ venue = "binance", market = "spot", symbol = "BTCUSDT" },"#,
        );
        let resolved = parse(&text).resolve().expect("resolves");
        assert_eq!(resolved.feeds.len(), 2, "both feeds exist");
        assert_eq!(
            resolved.binance.spot.len(),
            1,
            "but the instrument is streamed once"
        );
    }

    #[test]
    fn observation_kinds_default_to_book_then_trade() {
        let resolved = parse(SAMPLE).resolve().expect("resolves");
        let spot = resolved.feeds.first().expect("a feed");
        assert_eq!(
            spot.sources.first().map(|source| source.kinds.clone()),
            Some(vec![ObsKind::BookTop, ObsKind::Trade])
        );
    }

    #[test]
    fn slow_feeds_use_the_relaxed_policy() {
        let text = SAMPLE.replace(
            r#"symbol = "CRYPTO.BTC/USDT.PERP_MARK""#,
            "symbol = \"CRYPTO.BTC/USDT.FUNDING_8H\"\nslow = true",
        );
        let resolved = parse(&text).resolve().expect("resolves");
        let funding = resolved.feeds.get(1).expect("a second feed");
        assert_eq!(funding.max_age, Duration::from_secs(90));
        assert_eq!(funding.expo, -9);
    }

    #[test]
    fn unknown_fields_are_refused_rather_than_ignored() {
        // A typo in a config field is a silent misconfiguration otherwise.
        let text = SAMPLE.replace("min_sources = 1", "min_sourcs = 1");
        assert!(toml::from_str::<NodeConfig>(&text).is_err());
    }

    #[test]
    fn bad_symbols_venues_and_kinds_are_reported_at_startup() {
        for (from, to) in [
            (
                r#"symbol = "CRYPTO.BTC/USDT""#,
                r#"symbol = "not a symbol""#,
            ),
            (r#"venue = "binance""#, r#"venue = "ftx""#),
            (r#"market = "spot""#, r#"market = "futures""#),
            (r#"kinds = ["mark_price"]"#, r#"kinds = ["nonsense"]"#),
        ] {
            let text = SAMPLE.replacen(from, to, 1);
            let parsed = toml::from_str::<NodeConfig>(&text);
            let failed = match parsed {
                Ok(config) => config.resolve().is_err(),
                Err(_) => true,
            };
            assert!(failed, "`{to}` should have been rejected");
        }
    }

    #[test]
    fn a_feed_with_no_sources_is_refused() {
        let text = SAMPLE.replace(
            r#"  { venue = "binance", market = "spot", symbol = "BTCUSDT" },
"#,
            "",
        );
        assert!(parse(&text).resolve().is_err());
    }

    #[test]
    fn venues_without_an_adapter_are_refused_at_startup() {
        let text = SAMPLE.replacen(r#"venue = "binance""#, r#"venue = "kraken""#, 1);
        let error = parse(&text).resolve().err().expect("must refuse");
        assert!(error.to_string().contains("no adapter"), "got {error}");
    }

    #[test]
    fn a_missing_signing_key_source_is_an_error_not_a_default() {
        let text = SAMPLE.replace(r#"key_env = "ORACLE_SIGNING_KEY""#, "");
        let config = parse(&text);
        assert!(matches!(
            config.load_signing_key(),
            Err(ConfigError::SigningKey(_))
        ));
    }
}
