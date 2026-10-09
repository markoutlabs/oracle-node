//! Node configuration.
//!
//! One file describes the whole node. The ingest subscriptions are **derived**
//! from the feed definitions rather than listed separately: every source of every
//! feed is, by definition, an instrument to stream. Two lists would drift, and
//! the failure mode of that drift is a feed that silently loses a venue.

use std::collections::{BTreeMap, BTreeSet};
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
use oracle_wire::{check_endpoint, feed_id};
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

    /// The client list could not be loaded.
    #[error("cannot load the client list: {0}")]
    Clients(String),

    /// The registry could not be loaded or verified.
    #[error("cannot load the registry: {0}")]
    Registry(String),
}

impl ConfigError {
    /// Returns `true` if only an edit fixes this. A failed fetch may pass on a retry.
    #[must_use]
    pub const fn is_permanent(&self) -> bool {
        !matches!(self, Self::Registry(_) | Self::Clients(_))
    }
}

/// The whole node configuration.
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
    /// For local playgrounds with seeded keys only. A real key never goes in an
    /// environment variable (SPEC §9.2).
    #[serde(default)]
    pub key_env: Option<String>,
}

/// Where the client list comes from. Exactly one of `path` and `url`. It is
/// verified against `registry.governance_address`, and a `url` response
/// against the certificate of `registry.canister_id`.
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

const fn default_clients_poll_secs() -> u64 {
    30
}

/// Where the registry comes from. Exactly one of `path` and `url`.
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
    /// Publish on a move of at least this many basis points, as a decimal string.
    #[serde(default)]
    pub deviation_bps: Option<String>,
    /// Never publish more often than this, in milliseconds.
    #[serde(default)]
    pub min_interval_ms: Option<u64>,
    /// Price each venue at the average fill for this notional, in quote units,
    /// from depth snapshots, as a decimal string. Subscribes to depth where the
    /// venue offers it.
    #[serde(default)]
    pub impact_notional: Option<String>,
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
    /// Base units per contract, as a decimal string, for a venue that sizes in
    /// contracts: OKX swaps (`ctVal` on OKX's instruments endpoint).
    #[serde(default)]
    pub contract_size: Option<String>,
}

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
    /// How often to re-evaluate every feed for heartbeats and stale venues.
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

    /// Loads the secp256k1 signing key from the configured source.
    ///
    /// # Errors
    ///
    /// As [`Self::load_node_keys`].
    pub fn load_signing_key(&self) -> Result<oracle_wire::Signer, ConfigError> {
        self.load_node_keys().map(|keys| keys.signing)
    }

    /// Loads the node's keys from the configured source.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::SigningKey`] if no source is configured, the source
    /// cannot be read, or the value is not a seed or a key.
    pub fn load_node_keys(&self) -> Result<crate::NodeKeys, ConfigError> {
        let failed = |e: &dyn std::fmt::Display| ConfigError::SigningKey(e.to_string());
        match (&self.signing.key_file, &self.signing.key_env) {
            (Some(path), _) => {
                // The passphrase is read only for an encrypted file, so a
                // plaintext playground key never prompts.
                let passphrase =
                    if crate::keyfile::file_is_encrypted(path).map_err(|e| failed(&e))? {
                        let source = crate::keyfile::PassphraseSource::from_file(
                            self.signing.passphrase_file.clone(),
                        );
                        Some(
                            source
                                .read(&path.display().to_string(), false)
                                .map_err(|e| failed(&e))?,
                        )
                    } else {
                        None
                    };
                crate::keyfile::load_keys(path, passphrase.as_ref()).map_err(|e| failed(&e))
            }
            (None, Some(var)) => {
                // Wiped on drop. The value is a seed or a bare key.
                let text = zeroize::Zeroizing::new(
                    std::env::var(var)
                        .map_err(|_| ConfigError::SigningKey(format!("${var} is not set")))?,
                );
                crate::NodeKeys::from_text(&text).map_err(|e| failed(&e))
            }
            (None, None) => Err(ConfigError::SigningKey(
                "set either signing.key_file or signing.key_env".to_owned(),
            )),
        }
    }

    /// Fetches the registry from its configured source and verifies it against
    /// the pinned governance address.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Registry`] if not exactly one of `registry.path`
    /// and `registry.url` is set, if the document cannot be read or fetched, or
    /// if it is not signed by the pinned key.
    pub async fn fetch_registry(&self) -> Result<oracle_wire::Registry, ConfigError> {
        let registry: oracle_wire::Registry = self
            .load_document(
                "registry",
                self.registry.path.as_deref(),
                self.registry.url.as_deref(),
            )
            .await
            .map_err(ConfigError::Registry)?;
        registry
            .verify(self.governance()?, 0)
            .map_err(|e| ConfigError::Registry(e.to_string()))?;
        Ok(registry)
    }

    /// Returns the pinned governance address.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if it does not parse or is the zero
    /// placeholder.
    pub fn governance(&self) -> Result<oracle_wire::Address, ConfigError> {
        let address: oracle_wire::Address = self
            .registry
            .governance_address
            .parse()
            .map_err(|e| ConfigError::Invalid(format!("registry.governance_address: {e}")))?;
        if address == oracle_wire::Address::default() {
            return Err(ConfigError::Invalid(
                "registry.governance_address is the placeholder init wrote; set it to the \
                 address governance gave you"
                    .to_owned(),
            ));
        }
        Ok(address)
    }

    /// Fetches the client list, unverified, or `None` without a `[clients]`
    /// section. Verifying it against the governance address is the caller's job.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Clients`] if not exactly one of `path` and `url`
    /// is set, or the document cannot be read or fetched.
    pub async fn fetch_client_list(&self) -> Result<Option<oracle_wire::ClientList>, ConfigError> {
        let Some(clients) = &self.clients else {
            return Ok(None);
        };
        self.load_document("clients", clients.path.as_deref(), clients.url.as_deref())
            .await
            .map(Some)
            .map_err(ConfigError::Clients)
    }

    /// Reads a signed document from a file, or fetches it from the canister
    /// with its certificate checked. The governance signature is unchecked.
    async fn load_document<T: serde::de::DeserializeOwned>(
        &self,
        section: &str,
        path: Option<&std::path::Path>,
        url: Option<&str>,
    ) -> Result<T, String> {
        match (path, url) {
            (Some(path), None) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
            }
            (None, Some(url)) => {
                let canister_id = self.registry.canister_id.as_deref().ok_or(
                    "set registry.canister_id: a fetched document must carry its certificate",
                )?;
                let certification = match &self.registry.root_key {
                    Some(root_key) => oracle_client::Certification::new(canister_id, root_key),
                    None => oracle_client::Certification::mainnet(canister_id),
                }
                .map_err(|e| e.to_string())?;
                oracle_client::HttpDocumentSource::new(url, certification)
                    .map_err(|e| e.to_string())?
                    .fetch()
                    .await
                    .map_err(|e| format!("{url}: {e}"))
            }
            _ => Err(format!(
                "set exactly one of {section}.path and {section}.url"
            )),
        }
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
                // Depth replaces a top-of-book price, so only a book source needs it.
                let depth = feed.impact_notional.is_some() && kinds.contains(&ObsKind::BookTop);
                let contract_size = match &source.contract_size {
                    Some(text) => Some(text.parse::<Fixed>().map_err(|e| {
                        ConfigError::Invalid(format!(
                            "feed `{}`: bad contract_size: {e}",
                            feed.symbol
                        ))
                    })?),
                    None => None,
                };
                if contract_size.is_some_and(|size| !size.is_positive()) {
                    return Err(ConfigError::Invalid(format!(
                        "feed `{}`: contract_size must be above zero",
                        feed.symbol
                    )));
                }
                // An OKX swap's book is in contracts: priced without the size,
                // its depth would read a hundred times too deep or too thin.
                if depth && venue == Venue::Okx && market.is_perp() && contract_size.is_none() {
                    return Err(ConfigError::Invalid(format!(
                        "feed `{}`: OKX swap {} needs contract_size (`ctVal` on OKX's \
                         instruments endpoint) to read its book",
                        feed.symbol, source.symbol
                    )));
                }
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
                    .and_modify(|spec| {
                        spec.depth |= depth;
                        spec.contract_size = spec.contract_size.or(contract_size);
                    })
                    .or_insert_with(|| InstrumentSpec {
                        venue_symbol: source.symbol.clone(),
                        market,
                        canonical: symbol,
                        depth,
                        contract_size,
                    });
            }

            let id = feed_id(&symbol);
            // The symbol's kind fixes the class and its heartbeat, the same in
            // every node, because consumers rely on that heartbeat.
            let mut config = FeedConfig::for_symbol(symbol, id, sources);
            if let Some(min_sources) = feed.min_sources {
                config.min_sources = min_sources;
            }
            if let Some(text) = &feed.deviation_bps {
                config.deviation_bps = text.parse().map_err(|e| {
                    ConfigError::Invalid(format!("feed `{}`: bad deviation_bps: {e}", feed.symbol))
                })?;
            }
            if let Some(ms) = feed.min_interval_ms {
                config.min_interval = Duration::from_millis(ms);
            }
            if let Some(text) = &feed.impact_notional {
                config.impact_notional = Some(text.parse().map_err(|e| {
                    ConfigError::Invalid(format!(
                        "feed `{}`: bad impact_notional: {e}",
                        feed.symbol
                    ))
                })?);
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
            if let Some(book) = book_connection(venue, market, &instruments) {
                venues.entry(venue).or_default().push(book);
            }
        }
        apply_endpoints(&self.endpoints, &mut binance, &mut venues)?;

        Ok(ResolvedConfig {
            feeds,
            symbols,
            binance,
            venues: venues.into_iter().collect(),
            tick_interval: Duration::from_millis(self.tick_interval_ms.max(1)),
        })
    }
}

/// Puts each configured endpoint in place of the built-in URL.
///
/// An endpoint that no feed reads is refused: it is a typo or a leftover, and
/// the node would otherwise ignore it without a word.
fn apply_endpoints(
    endpoints: &[EndpointSettings],
    binance: &mut BinanceConfig,
    venues: &mut BTreeMap<Venue, Vec<VenueConnection>>,
) -> Result<(), ConfigError> {
    let mut seen = BTreeSet::new();
    for endpoint in endpoints {
        let invalid = |reason: String| {
            ConfigError::Invalid(format!(
                "endpoint for {} {}: {reason}",
                endpoint.venue, endpoint.market
            ))
        };
        let venue: Venue = endpoint
            .venue
            .parse()
            .map_err(|e| invalid(format!("{e}")))?;
        let market: MarketKind = endpoint
            .market
            .parse()
            .map_err(|e| invalid(format!("{e}")))?;
        // The rule the registry applies to node endpoints.
        check_endpoint(&endpoint.url).map_err(|e| invalid(e.to_string()))?;
        if !seen.insert((venue, market)) {
            return Err(invalid("set more than once".to_owned()));
        }
        let url = match (venue, market) {
            (Venue::Binance, MarketKind::Spot) if !binance.spot.is_empty() => {
                Some(&mut binance.spot_base_url)
            }
            (Venue::Binance, MarketKind::LinearPerp) if !binance.perp.is_empty() => {
                // One override serves both futures routes.
                binance.perp_market_url.clone_from(&endpoint.url);
                Some(&mut binance.perp_base_url)
            }
            (Venue::Binance, _) => None,
            _ => venues
                .get_mut(&venue)
                .and_then(|connections| {
                    connections
                        .iter_mut()
                        .find(|connection| connection.spec.market == market)
                })
                .map(|connection| &mut connection.spec.url),
        };
        *url.ok_or_else(|| invalid("no feed reads this market".to_owned()))? = endpoint.url.clone();
    }
    Ok(())
}

/// A second connection for venues whose book lives on another endpoint:
/// Coinbase's, on Advanced Trade. Only the instruments that want depth.
fn book_connection(
    venue: Venue,
    market: MarketKind,
    instruments: &[InstrumentSpec],
) -> Option<VenueConnection> {
    if venue != Venue::Coinbase {
        return None;
    }
    let books: Vec<InstrumentSpec> = instruments
        .iter()
        .filter(|spec| spec.depth)
        .cloned()
        .collect();
    if books.is_empty() {
        return None;
    }
    let product_ids = books.iter().map(|spec| spec.venue_symbol.as_str());
    Some(VenueConnection {
        spec: VenueSpec {
            venue,
            market,
            url: coinbase::BOOK_URL.to_owned(),
            subscribe: coinbase::book_subscribe_frames(product_ids),
            keepalive: None,
            idle_timeout: VENUE_IDLE_TIMEOUT,
            max_session: VENUE_MAX_SESSION,
            decode: coinbase::decode_book,
        },
        instruments: books,
    })
}

/// Builds one venue connection from its instruments.
fn venue_connection(
    venue: Venue,
    market: MarketKind,
    instruments: &[InstrumentSpec],
) -> Result<VenueConnection, ConfigError> {
    let symbols = || instruments.iter().map(|spec| spec.venue_symbol.as_str());
    let with_depth = || {
        instruments
            .iter()
            .map(|spec| (spec.venue_symbol.as_str(), spec.depth))
    };

    // Annotated so each arm's function item coerces to the shared pointer type;
    // an `as` cast per arm would do the same but reads as a reinterpretation.
    type Connection = (String, Vec<String>, Option<(Duration, String)>, DecodeFn);
    let (url, subscribe, keepalive, decode): Connection = match venue {
        Venue::Bybit => (
            bybit::url(market).to_owned(),
            bybit::subscribe_frames(with_depth(), market, VENUE_CHUNK),
            Some((bybit::KEEPALIVE, bybit::KEEPALIVE_PAYLOAD.to_owned())),
            bybit::decode,
        ),
        Venue::Okx => (
            okx::URL.to_owned(),
            okx::subscribe_frames(with_depth(), VENUE_CHUNK),
            Some((okx::KEEPALIVE, okx::KEEPALIVE_PAYLOAD.to_owned())),
            okx::decode,
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
            coinbase::decode,
        ),
        // Kraken spot and Kraken Futures share a brand and nothing else.
        Venue::Kraken if market.is_perp() => (
            kraken_futures::URL.to_owned(),
            vec![kraken_futures::subscribe_frame(symbols())],
            None,
            kraken_futures::decode,
        ),
        Venue::Kraken => (
            kraken::URL.to_owned(),
            kraken::subscribe_frames(with_depth()),
            None,
            kraken::decode,
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
            deribit::subscribe_frames(with_depth(), VENUE_CHUNK),
            // None: the ticker channel pushes every 100ms whether or not the
            // market moves, so the socket is never idle and `idle_timeout`
            // catches a half-open one. Deribit's own heartbeat needs a reply to
            // each `test_request`, which this transport has no way to send.
            None,
            deribit::decode,
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
            decode,
        },
        instruments: instruments.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_types::{PRICE_HEARTBEAT, SLOW_HEARTBEAT};

    const SAMPLE: &str = r#"
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

    /// The playground config shows every feed kind this build serves; it must
    /// keep resolving.
    #[test]
    fn the_all_feeds_playground_resolves() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../node/all-feeds.toml");
        let text = std::fs::read_to_string(path).expect("node/all-feeds.toml");
        let resolved = parse(&text).resolve().expect("resolves");
        let perp_mid = resolved
            .feeds
            .iter()
            .find(|feed| feed.symbol.to_string() == "CRYPTO.BTC/USDT.PERP_MID")
            .expect("a perp mid feed");
        assert!(perp_mid.impact_notional.is_some());
        assert!(resolved.binance.perp.iter().any(|spec| spec.depth));
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
    fn a_funding_feed_is_slow_by_its_kind() {
        let text = SAMPLE.replace(
            r#"symbol = "CRYPTO.BTC/USDT.PERP_MARK""#,
            r#"symbol = "CRYPTO.BTC/USDT.FUNDING_8H""#,
        );
        let resolved = parse(&text).resolve().expect("resolves");
        let price = resolved.feeds.first().expect("a feed");
        assert_eq!(price.heartbeat, PRICE_HEARTBEAT);
        let funding = resolved.feeds.get(1).expect("a second feed");
        assert_eq!(funding.heartbeat, SLOW_HEARTBEAT);
        assert_eq!(funding.max_age, Duration::from_secs(90));
        assert_eq!(funding.expo, -9);
    }

    #[test]
    fn the_heartbeat_and_the_class_are_not_settings() {
        for setting in ["heartbeat_ms = 500", "slow = true"] {
            let text = SAMPLE.replacen(
                "min_sources = 1\n",
                &format!("min_sources = 1\n{setting}\n"),
                1,
            );
            assert!(
                toml::from_str::<NodeConfig>(&text).is_err(),
                "{setting} must be refused"
            );
        }
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

    fn with_endpoints(text: &str, endpoints: &str) -> Result<ResolvedConfig, ConfigError> {
        parse(&format!("{text}\n{endpoints}")).resolve()
    }

    #[test]
    fn a_feed_sets_its_own_publication_policy() {
        let text = SAMPLE.replacen(
            "min_sources = 1\n",
            "min_sources = 1\ndeviation_bps = \"0.5\"\nmin_interval_ms = 10\n",
            1,
        );
        let resolved = parse(&text).resolve().expect("resolves");
        let feed = resolved.feeds.first().expect("a feed");
        assert_eq!(feed.deviation_bps.to_string(), "0.5");
        assert_eq!(feed.min_interval, Duration::from_millis(10));
        let other = resolved.feeds.get(1).expect("a second feed");
        assert_eq!(other.deviation_bps.to_string(), "1", "the default");

        for (settings, why) in [
            ("impact_notional = \"0\"", "impact_notional"),
            ("impact_notional = \"much\"", "impact_notional"),
            ("min_interval_ms = 0", "min_interval"),
            // Above the fixed one-second heartbeat, which could then never fire.
            ("min_interval_ms = 2000", "heartbeat"),
            ("deviation_bps = \"-1\"", "deviation_bps"),
            ("deviation_bps = \"lots\"", "deviation_bps"),
        ] {
            let text = SAMPLE.replacen(
                "min_sources = 1\n",
                &format!("min_sources = 1\n{settings}\n"),
                1,
            );
            let Err(error) = parse(&text).resolve() else {
                panic!("{settings} must be refused");
            };
            let error = error.to_string();
            assert!(error.contains(why), "{settings}: {error}");
        }
    }

    /// A feed that prices from depth subscribes to it for every instrument it
    /// reads, and only for those.
    #[test]
    fn impact_notional_turns_on_depth_for_its_instruments() {
        let text = SAMPLE.replacen(
            "min_sources = 1\n",
            "min_sources = 1\nimpact_notional = \"20000\"\n",
            1,
        );
        let resolved = parse(&text).resolve().expect("resolves");
        let feed = resolved.feeds.first().expect("a feed");
        assert_eq!(
            feed.impact_notional.map(|n| n.to_string()),
            Some("20000".to_owned())
        );
        assert!(resolved.binance.spot.iter().all(|spec| spec.depth));
        assert!(resolved.binance.perp.iter().all(|spec| !spec.depth));
    }

    /// An OKX swap's book is in contracts; without the contract size its depth
    /// would be wrong by the contract's factor, so the config is refused.
    #[test]
    fn an_okx_swap_book_needs_its_contract_size() {
        let feed = |extra: &str| {
            format!(
                r#"{SAMPLE}
[[feeds]]
symbol = "CRYPTO.BTC/USDT.PERP_MID"
min_sources = 1
impact_notional = "20000"
sources = [
  {{ venue = "okx", market = "linear_perp", symbol = "BTC-USDT-SWAP"{extra} }},
]
"#
            )
        };
        let Err(error) = parse(&feed("")).resolve() else {
            panic!("a swap book without a contract size must be refused");
        };
        assert!(error.to_string().contains("contract_size"), "{error}");
        assert!(
            parse(&feed(r#", contract_size = "0.01""#))
                .resolve()
                .is_ok()
        );
    }

    #[test]
    fn an_endpoint_replaces_the_built_in_url() {
        let resolved = with_endpoints(
            SAMPLE,
            r#"[[endpoints]]
venue = "binance"
market = "spot"
url = "ws://127.0.0.1:9000/stream""#,
        )
        .expect("resolves");
        assert_eq!(resolved.binance.spot_base_url, "ws://127.0.0.1:9000/stream");
        assert_eq!(
            resolved.binance.perp_base_url,
            BinanceConfig::default().perp_base_url
        );

        let okx = SAMPLE
            .replacen(
                r#"venue = "binance", market = "spot""#,
                r#"venue = "okx", market = "spot""#,
                1,
            )
            .replacen(r#"symbol = "BTCUSDT" }"#, r#"symbol = "BTC-USDT" }"#, 1);
        let resolved = with_endpoints(
            &okx,
            r#"[[endpoints]]
venue = "okx"
market = "spot"
url = "wss://wsaws.okx.com:8443/ws/v5/public""#,
        )
        .expect("resolves");
        assert_eq!(
            spec_for(&resolved, Venue::Okx).url,
            "wss://wsaws.okx.com:8443/ws/v5/public"
        );
    }

    #[test]
    fn an_endpoint_nothing_reads_or_that_is_not_a_socket_is_refused() {
        let endpoint = |venue: &str, market: &str, url: &str| {
            format!("[[endpoints]]\nvenue = \"{venue}\"\nmarket = \"{market}\"\nurl = \"{url}\"\n")
        };
        for (endpoints, expected) in [
            (endpoint("okx", "spot", "wss://x/ws"), "no feed reads"),
            (
                endpoint("binance", "spot", "https://x/stream"),
                "not a ws://",
            ),
            (
                [
                    endpoint("binance", "spot", "ws://a/s"),
                    endpoint("binance", "spot", "ws://b/s"),
                ]
                .concat(),
                "more than once",
            ),
        ] {
            let error = with_endpoints(SAMPLE, &endpoints)
                .err()
                .expect("refused")
                .to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    /// Builds a config with one feed sourced from a single venue and market.
    fn one_source(venue: &str, market: &str, symbol: &str) -> Result<ResolvedConfig, ConfigError> {
        let text = format!(
            r#"
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

    fn registry_section(body: &str) -> NodeConfig {
        let text = SAMPLE.replace(
            "[registry]\npath = \"registry.json\"\n\
             governance_address = \"0x0000000000000000000000000000000000000001\"",
            &format!("[registry]\n{body}"),
        );
        assert_ne!(text, SAMPLE, "the sample registry section must be replaced");
        parse(&text)
    }

    #[tokio::test]
    async fn the_clients_section_is_optional_and_exactly_one_source() {
        let none = parse(SAMPLE);
        assert!(none.clients.is_none());
        assert!(
            none.fetch_client_list()
                .await
                .expect("no section")
                .is_none()
        );

        let with = |body: &str| parse(&format!("{SAMPLE}\n[clients]\n{body}\n"));
        let url = with("url = \"http://127.0.0.1:1/clients.json\"");
        assert_eq!(url.clients.as_ref().map(|c| c.poll_secs), Some(30));
        for bad in [
            with("poll_secs = 5"),
            with("path = \"c.json\"\nurl = \"http://127.0.0.1:1/clients.json\""),
        ] {
            let error = bad.fetch_client_list().await.expect_err("must refuse");
            assert!(error.to_string().contains("exactly one"), "{error}");
        }
    }

    #[tokio::test]
    async fn the_registry_source_is_exactly_one_of_path_and_url() {
        let neither =
            registry_section("governance_address = \"0x0000000000000000000000000000000000000001\"");
        let error = neither.fetch_registry().await.expect_err("must refuse");
        assert!(error.to_string().contains("exactly one"), "{error}");

        let both = registry_section(
            "path = \"r.json\"\nurl = \"http://127.0.0.1:1/registry.json\"\n\
             governance_address = \"0x0000000000000000000000000000000000000001\"",
        );
        let error = both.fetch_registry().await.expect_err("must refuse");
        assert!(error.to_string().contains("exactly one"), "{error}");
    }

    /// A validly signed registry from a plain server is refused: only the
    /// canister's certificate proves that it is the latest version.
    #[tokio::test]
    async fn a_registry_url_needs_the_canister_certificate() {
        use oracle_client::testing::{governance, signed_registry};

        let registry = signed_registry(3, Vec::new());
        let json = serde_json::to_string(&registry).expect("serialises");
        let app = axum::Router::new().route(
            "/registry.json",
            axum::routing::get(move || std::future::ready(json.clone())),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serves");
        });

        let section = |extra: &str| {
            registry_section(&format!(
                "url = \"http://{address}/registry.json\"\n{extra}governance_address = \"{}\"",
                governance().address()
            ))
        };
        let error = section("").fetch_registry().await.expect_err("no canister");
        assert!(error.to_string().contains("canister_id"), "{error}");
        let error = section("canister_id = \"aaaaa-aa\"\n")
            .fetch_registry()
            .await
            .expect_err("uncertified");
        assert!(error.to_string().contains("not certified"), "{error}");
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
