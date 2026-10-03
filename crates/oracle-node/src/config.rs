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
use oracle_agg::config::{QuoteConversion, SourceConfig};
use oracle_ingest::InstrumentSpec;
use oracle_ingest::binance::BinanceConfig;
use oracle_ingest::venues::{
    DecodeFn, VenueSpec, bybit, coinbase, deribit, kraken, kraken_futures, okx,
};
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
    /// The peg feed converted sources are priced through, such as `CRYPTO.USDT/USD`.
    #[serde(default)]
    pub peg: Option<String>,
    /// Peg confidence above which this feed degrades, in basis points.
    #[serde(default)]
    pub max_peg_conf_bps: Option<String>,
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

    /// This source is quoted in the feed's peg asset and must be converted.
    ///
    /// Set on every USDT-quoted source of a `/USD` feed. Publishing those
    /// unconverted is a lie that costs money the day the peg breaks — and a
    /// silent one, because on an ordinary day the two agree to a basis point.
    #[serde(default)]
    pub converted: bool,
}

const fn default_tick_ms() -> u64 {
    25
}

const fn default_max_pending() -> usize {
    512
}

/// Peg confidence above which dependent feeds degrade, from SPEC.md §5.3.
const DEFAULT_MAX_PEG_CONF_BPS: Fixed = Fixed::from_raw(50 * 1_000_000_000_000);

/// Idle timeout for the socket-subscribing venues.
const VENUE_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Session recycle age for the socket-subscribing venues.
const VENUE_MAX_SESSION: Duration = Duration::from_secs(23 * 3_600);
/// Subscription arguments per frame.
const VENUE_CHUNK: usize = 100;

/// One non-Binance venue connection and the instruments it carries.
pub struct VenueConnection {
    /// How to connect, subscribe, and keep alive.
    pub spec: VenueSpec,
    /// The instruments on that connection.
    pub instruments: Vec<InstrumentSpec>,
}

/// Everything the node needs to start, derived from the config.
pub struct ResolvedConfig {
    /// Aggregation configuration, one entry per feed.
    pub feeds: Vec<FeedConfig>,
    /// The canonical symbols this node serves.
    pub symbols: Vec<Symbol>,
    /// Binance ingest configuration, derived from the feed sources.
    pub binance: BinanceConfig,
    /// Connections for the venues that subscribe over the socket.
    pub venues: Vec<(Venue, Vec<VenueConnection>)>,
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
                if source.converted {
                    config = config.converted();
                }
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
            if let Some(peg) = &feed.peg {
                let peg_symbol: Symbol = peg.parse().map_err(|e| {
                    ConfigError::Invalid(format!("feed `{}`: bad peg symbol: {e}", feed.symbol))
                })?;
                let max_peg_conf_bps = match &feed.max_peg_conf_bps {
                    Some(text) => text.parse::<Fixed>().map_err(|e| {
                        ConfigError::Invalid(format!(
                            "feed `{}`: bad max_peg_conf_bps: {e}",
                            feed.symbol
                        ))
                    })?,
                    None => DEFAULT_MAX_PEG_CONF_BPS,
                };
                config = config.with_conversion(QuoteConversion {
                    peg_feed: feed_id(&peg_symbol),
                    max_peg_conf_bps,
                });
            }
            config
                .validate()
                .map_err(|e| ConfigError::Invalid(e.to_string()))?;
            feeds.push(config);
        }

        let mut binance = BinanceConfig::default();
        let mut by_venue: BTreeMap<(Venue, MarketKind), Vec<InstrumentSpec>> = BTreeMap::new();
        for ((venue, market, _), spec) in instruments {
            match venue {
                Venue::Binance => match market {
                    MarketKind::Spot => binance.spot.push(spec),
                    MarketKind::LinearPerp => binance.perp.push(spec),
                    MarketKind::InversePerp => {
                        return Err(ConfigError::Invalid(
                            "binance coin-margined futures are not served by this build; \
                             they live on a different host with their own contract catalogue"
                                .to_owned(),
                        ));
                    }
                },
                other => by_venue.entry((other, market)).or_default().push(spec),
            }
        }

        let mut venues: BTreeMap<Venue, Vec<VenueConnection>> = BTreeMap::new();
        for ((venue, market), instruments) in by_venue {
            let connection = venue_connection(venue, market, &instruments)?;
            venues.entry(venue).or_default().push(connection);
        }

        Ok(ResolvedConfig {
            feeds,
            symbols,
            binance,
            venues: venues.into_iter().collect(),
            tick_interval: Duration::from_millis(self.tick_interval_ms.max(1)),
        })
    }
}

/// Builds one venue connection from its instruments.
fn venue_connection(
    venue: Venue,
    market: MarketKind,
    instruments: &[InstrumentSpec],
) -> Result<VenueConnection, ConfigError> {
    let symbols = || instruments.iter().map(|spec| spec.venue_symbol.as_str());

    // Annotated so each arm's function item coerces to the shared pointer type;
    // an `as` cast per arm would do the same but reads as a reinterpretation.
    type Connection = (String, Vec<String>, Option<(Duration, String)>, DecodeFn);
    let (url, subscribe, keepalive, decode): Connection = match venue {
        Venue::Bybit => (
            bybit::url(market).to_owned(),
            bybit::subscribe_frames(symbols(), market, VENUE_CHUNK),
            Some((bybit::KEEPALIVE, bybit::KEEPALIVE_PAYLOAD.to_owned())),
            bybit::decode_payload,
        ),
        Venue::Okx => (
            okx::URL.to_owned(),
            okx::subscribe_frames(symbols(), VENUE_CHUNK),
            Some((okx::KEEPALIVE, okx::KEEPALIVE_PAYLOAD.to_owned())),
            okx::decode_payload,
        ),
        // Coinbase's public feed is spot only. Its perpetuals live on Coinbase
        // International, whose market-data socket authenticates every
        // subscription — a credential path this build does not have.
        Venue::Coinbase if market.is_perp() => {
            return Err(ConfigError::Invalid(
                "coinbase perpetuals are on Coinbase International, whose market-data \
                 feed requires API credentials this build cannot supply"
                    .to_owned(),
            ));
        }
        Venue::Coinbase => (
            coinbase::URL.to_owned(),
            vec![coinbase::subscribe_frame(symbols())],
            None,
            coinbase::decode_payload,
        ),
        // Kraken spot and Kraken Futures share a brand and nothing else.
        Venue::Kraken if market.is_perp() => (
            kraken_futures::URL.to_owned(),
            vec![kraken_futures::subscribe_frame(symbols())],
            None,
            kraken_futures::decode_payload,
        ),
        Venue::Kraken => (
            kraken::URL.to_owned(),
            vec![kraken::subscribe_frame(symbols())],
            None,
            kraken::decode_payload,
        ),
        // Deribit is a derivatives venue; its spot book is not worth pricing from.
        Venue::Deribit if !market.is_perp() => {
            return Err(ConfigError::Invalid(
                "deribit serves perpetuals only; use market = \"linear_perp\" or \
                 \"inverse_perp\""
                    .to_owned(),
            ));
        }
        Venue::Deribit => (
            deribit::URL.to_owned(),
            deribit::subscribe_frames(symbols(), VENUE_CHUNK),
            // None: the ticker channel pushes every 100ms whether or not the
            // market moves, so the socket is never idle and `idle_timeout`
            // catches a half-open one. Deribit's own heartbeat needs a reply to
            // each `test_request`, which this transport has no way to send.
            None,
            deribit::decode_payload,
        ),
        Venue::Binance => {
            return Err(ConfigError::Invalid(
                "binance is configured through its own adapter".to_owned(),
            ));
        }
        // `Venue` is non-exhaustive so adding one stays additive for consumers.
        // Here it must be a startup failure: a venue with no adapter would
        // otherwise be configured, accepted, and silently never stream.
        other => {
            return Err(ConfigError::Invalid(format!(
                "venue `{other}` has no adapter in this build"
            )));
        }
    };

    Ok(VenueConnection {
        spec: VenueSpec {
            venue,
            market,
            url,
            subscribe,
            keepalive,
            idle_timeout: VENUE_IDLE_TIMEOUT,
            max_session: VENUE_MAX_SESSION,
            // Distinct per venue and market, so sibling connections do not draw
            // the same jitter and re-synchronise after a shared outage.
            backoff_seed: u64::from(venue.index()).wrapping_mul(0x9E37_79B9_7F4A_7C15)
                ^ market_seed(market),
            decode,
        },
        instruments: instruments.to_vec(),
    })
}

/// Distinguishes a market within a venue's backoff seed.
///
/// Sibling connections must not draw the same jitter, or they re-synchronise
/// after a shared outage and reconnect in lockstep.
const fn market_seed(market: MarketKind) -> u64 {
    match market {
        MarketKind::Spot => 0,
        MarketKind::LinearPerp => 1,
        MarketKind::InversePerp => 2,
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

    /// The USDT-to-USD path, end to end through configuration.
    #[test]
    fn a_usd_feed_can_mix_native_and_converted_sources() {
        let text = r#"
node_id = "oracle-eu-1"

[server]
listen = "127.0.0.1:8080"

[signing]
key_env = "ORACLE_SIGNING_KEY"

[registry]
path = "registry.json"
governance_address = "0x0000000000000000000000000000000000000001"

[[feeds]]
symbol = "CRYPTO.USDT/USD"
min_sources = 1
sources = [
  { venue = "coinbase", market = "spot", symbol = "USDT-USD" },
  { venue = "kraken", market = "spot", symbol = "USDTUSD" },
]

[[feeds]]
symbol = "CRYPTO.BTC/USD"
min_sources = 2
peg = "CRYPTO.USDT/USD"
max_peg_conf_bps = "50"
sources = [
  { venue = "coinbase", market = "spot", symbol = "BTC-USD" },
  { venue = "binance", market = "spot", symbol = "BTCUSDT", converted = true },
  { venue = "bybit", market = "spot", symbol = "BTCUSDT", converted = true },
  { venue = "okx", market = "spot", symbol = "BTC-USDT", converted = true },
]
"#;
        let resolved = parse(text).resolve().expect("resolves");
        let btc = resolved
            .feeds
            .iter()
            .find(|feed| feed.symbol.to_string() == "CRYPTO.BTC/USD")
            .expect("btc feed");
        assert!(btc.needs_conversion());
        assert_eq!(
            btc.sources
                .iter()
                .filter(|source| source.convert_quote)
                .count(),
            3,
            "the three stablecoin venues convert"
        );
        assert_eq!(
            btc.sources
                .iter()
                .filter(|source| !source.convert_quote)
                .count(),
            1,
            "the native-USD venue does not"
        );

        // And the aggregator accepts the pair, peg included.
        assert!(oracle_agg::Aggregator::new(resolved.feeds).is_ok());
    }

    #[test]
    fn every_configured_venue_gets_a_connection() {
        let text = SAMPLE.replacen(r#"venue = "binance""#, r#"venue = "kraken""#, 1);
        let resolved = parse(&text).resolve().expect("resolves");
        assert_eq!(
            resolved.binance.spot.len(),
            0,
            "the spot feed moved to kraken"
        );
        let venues: Vec<Venue> = resolved.venues.iter().map(|(venue, _)| *venue).collect();
        assert_eq!(venues, [Venue::Kraken]);
    }

    #[test]
    fn each_venue_connection_carries_its_own_subscribe_and_keepalive() {
        let text = SAMPLE
            .replacen(
                r#"venue = "binance", market = "spot""#,
                r#"venue = "okx", market = "spot""#,
                1,
            )
            .replacen(r#"symbol = "BTCUSDT" }"#, r#"symbol = "BTC-USDT" }"#, 1);
        let resolved = parse(&text).resolve().expect("resolves");
        let (_, connections) = resolved
            .venues
            .iter()
            .find(|(venue, _)| *venue == Venue::Okx)
            .expect("okx configured");
        let spec = &connections.first().expect("one connection").spec;
        assert!(
            spec.subscribe
                .first()
                .is_some_and(|f| f.contains("bbo-tbt"))
        );
        // OKX drops a connection idle for 30s and wants a plain-text ping.
        let (period, payload) = spec.keepalive.clone().expect("okx needs a keepalive");
        assert_eq!(payload, "ping");
        assert!(period < Duration::from_secs(30));
    }

    /// Builds a config with one feed sourced from a single venue and market.
    fn one_source(venue: &str, market: &str, symbol: &str) -> Result<ResolvedConfig, ConfigError> {
        let text = format!(
            r#"
node_id = "n"
[server]
listen = "127.0.0.1:1"
[signing]
key_env = "K"
[registry]
path = "r.json"
governance_address = "0x0000000000000000000000000000000000000000"
[[feeds]]
symbol = "CRYPTO.BTC/USD.PERP_MARK"
min_sources = 1
sources = [
  {{ venue = "{venue}", market = "{market}", symbol = "{symbol}", kinds = ["mark_price"] }},
]
"#
        );
        parse(&text).resolve()
    }

    fn spec_for(resolved: &ResolvedConfig, venue: Venue) -> &VenueSpec {
        &resolved
            .venues
            .iter()
            .find(|(v, _)| *v == venue)
            .expect("venue configured")
            .1
            .first()
            .expect("one connection")
            .spec
    }

    /// Kraken spot and Kraken Futures are different hosts speaking different
    /// protocols. Routing a perp to the spot endpoint would connect happily and
    /// then decode nothing.
    #[test]
    fn kraken_perps_route_to_the_futures_endpoint() {
        let resolved = one_source("kraken", "linear_perp", "PF_XBTUSD").expect("resolves");
        let spec = spec_for(&resolved, Venue::Kraken);
        assert!(spec.url.contains("futures.kraken.com"), "{}", spec.url);
        assert!(
            spec.subscribe
                .first()
                .is_some_and(|f| f.contains(r#""feed":"ticker""#))
        );

        let spot = one_source("kraken", "spot", "BTC/USD").expect("resolves");
        let spot_spec = spec_for(&spot, Venue::Kraken);
        assert!(spot_spec.url.contains("ws.kraken.com"), "{}", spot_spec.url);
        assert_ne!(spec.url, spot_spec.url);
    }

    #[test]
    fn deribit_perps_subscribe_to_the_ticker_channel() {
        for market in ["linear_perp", "inverse_perp"] {
            let symbol = if market == "inverse_perp" {
                "BTC-PERPETUAL"
            } else {
                "BTC_USDC-PERPETUAL"
            };
            let resolved = one_source("deribit", market, symbol).expect("resolves");
            let spec = spec_for(&resolved, Venue::Deribit);
            assert!(spec.url.contains("deribit.com"), "{}", spec.url);
            assert!(
                spec.subscribe
                    .first()
                    .is_some_and(|f| f.contains("public/subscribe") && f.contains(symbol)),
                "{:?}",
                spec.subscribe
            );
        }
    }

    /// Deribit has no spot book worth pricing from, so asking for one is a
    /// configuration error rather than a connection that streams nothing.
    #[test]
    fn deribit_spot_is_refused() {
        let error = one_source("deribit", "spot", "BTC-PERPETUAL")
            .err()
            .expect("must refuse");
        assert!(
            matches!(&error, ConfigError::Invalid(m) if m.contains("perpetuals only")),
            "got {error:?}"
        );
    }

    /// Coinbase's public feed is spot only; its perps need credentials this
    /// build has no way to supply. Better to say so at startup than to open a
    /// socket that is disconnected three seconds later.
    #[test]
    fn coinbase_perps_are_refused_with_the_reason() {
        let error = one_source("coinbase", "linear_perp", "BTC-PERP")
            .err()
            .expect("must refuse");
        assert!(
            matches!(&error, ConfigError::Invalid(m) if m.contains("credentials")),
            "got {error:?}"
        );
    }

    #[test]
    fn binance_coin_margined_futures_are_refused() {
        let error = one_source("binance", "inverse_perp", "BTCUSD_PERP")
            .err()
            .expect("must refuse");
        assert!(
            matches!(&error, ConfigError::Invalid(m) if m.contains("coin-margined")),
            "got {error:?}"
        );
    }

    /// Sibling connections must not draw the same jitter, or they reconnect in
    /// lockstep after a shared outage.
    #[test]
    fn every_market_of_a_venue_gets_a_distinct_backoff_seed() {
        let seeds: std::collections::HashSet<u64> = MarketKind::ALL
            .into_iter()
            .map(|market| {
                u64::from(Venue::Deribit.index()).wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    ^ market_seed(market)
            })
            .collect();
        assert_eq!(seeds.len(), MarketKind::ALL.len());
    }

    #[test]
    fn sibling_venue_connections_get_different_jitter_seeds() {
        let text = r#"
node_id = "n"

[server]
listen = "127.0.0.1:8080"

[signing]
key_env = "K"

[registry]
path = "r.json"
governance_address = "0x0000000000000000000000000000000000000001"

[[feeds]]
symbol = "CRYPTO.BTC/USDT"
min_sources = 1
sources = [
  { venue = "bybit", market = "spot", symbol = "BTCUSDT" },
  { venue = "okx", market = "spot", symbol = "BTC-USDT" },
]
"#;
        let resolved = parse(text).resolve().expect("resolves");
        let seeds: std::collections::HashSet<u64> = resolved
            .venues
            .iter()
            .flat_map(|(_, connections)| connections.iter().map(|c| c.spec.backoff_seed))
            .collect();
        assert_eq!(seeds.len(), 2, "connections must not share a jitter seed");
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
