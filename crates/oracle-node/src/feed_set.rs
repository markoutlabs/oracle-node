//! The network's feed set: the checks a set passes before the node uses it,
//! the choice between the cached and the fetched copy, and when each node
//! applies a new set.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use oracle_ingest::InstrumentSpec;
use oracle_ingest::clock::MonotonicClock;
use oracle_ingest::transport::WebSocketConnector;
use oracle_types::Venue;
use oracle_wire::{Address, FeedSet, FeedSettings, VerifiedFeedSet};

use crate::config::{
    ConfigError, DEFAULT_TICK_MS, EndpointSettings, NodeConfig, ResolvedConfig, resolve_feeds,
};

/// This node's version, which a feed set may require.
pub const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A feed set that passed every check, with the config it resolves to.
pub struct CheckedFeeds {
    /// The node's config with the set's feeds, and every `[[endpoints]]` override kept for a later set.
    pub config: NodeConfig,
    /// What the node runs.
    pub resolved: ResolvedConfig,
    /// The overrides, as `venue:market`, for markets that the set does not read.
    pub dropped_endpoints: Vec<String>,
}

/// Runs every check of the node's start on `feeds`: resolve, aggregator, and venue adapters.
///
/// # Errors
///
/// Returns [`ConfigError::Invalid`] with the first problem.
pub fn check_feeds(base: &NodeConfig, feeds: &[FeedSettings]) -> Result<CheckedFeeds, ConfigError> {
    let mut config = base.clone();
    config.feeds = feeds.to_vec();
    let read: BTreeSet<(&str, &str)> = feeds
        .iter()
        .flat_map(|feed| feed.sources.iter())
        .map(|source| (source.venue.as_str(), source.market.as_str()))
        .collect();
    let (endpoints, dropped): (Vec<EndpointSettings>, Vec<EndpointSettings>) =
        config.endpoints.iter().cloned().partition(|endpoint| {
            read.contains(&(endpoint.venue.as_str(), endpoint.market.as_str()))
        });
    let dropped_endpoints = dropped
        .iter()
        .map(|endpoint| format!("{}:{}", endpoint.venue, endpoint.market))
        .collect();
    let resolved = check(&config.feeds, &endpoints, config.tick_interval_ms)?;
    Ok(CheckedFeeds {
        config,
        resolved,
        dropped_endpoints,
    })
}

/// The checks of [`check_feeds`] on a feed list alone, for `oracle-node export-feeds`.
///
/// # Errors
///
/// Returns [`ConfigError::Invalid`] with the first problem.
pub fn check_feed_list(feeds: &[FeedSettings]) -> Result<ResolvedConfig, ConfigError> {
    check(feeds, &[], DEFAULT_TICK_MS)
}

fn check(
    feeds: &[FeedSettings],
    endpoints: &[EndpointSettings],
    tick_interval_ms: u64,
) -> Result<ResolvedConfig, ConfigError> {
    let resolved = resolve_feeds(feeds, endpoints, tick_interval_ms)?;
    oracle_agg::Aggregator::new(resolved.feeds.clone())
        .map_err(|error| ConfigError::Invalid(error.to_string()))?;
    // Resolving is pure, so a second copy feeds the dry run. The adapters log
    // each endpoint as they are built, which would read as a connection.
    let trial = resolve_feeds(feeds, endpoints, tick_interval_ms)?;
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        crate::adapters::build_adapters(
            trial.binance,
            trial.venues,
            WebSocketConnector,
            MonotonicClock::new(),
        )
    })
    .map_err(|error| ConfigError::Invalid(error.to_string()))?;
    Ok(resolved)
}

/// The instruments of each venue's adapter, from a resolved config.
pub type Subscriptions = BTreeMap<Venue, Vec<InstrumentSpec>>;

/// What each venue's adapter takes: equal instruments build equal adapters, so that venue needs no reconnect.
#[must_use]
pub fn subscriptions(resolved: &ResolvedConfig) -> Subscriptions {
    let mut subscriptions = Subscriptions::new();
    let binance = &resolved.binance;
    if !binance.spot.is_empty() || !binance.perp.is_empty() {
        let instruments = binance.spot.iter().chain(&binance.perp).cloned().collect();
        subscriptions.insert(Venue::Binance, instruments);
    }
    for (venue, connections) in &resolved.venues {
        let instruments = connections
            .iter()
            .flat_map(|connection| connection.instruments.iter().cloned())
            .collect();
        subscriptions.insert(*venue, instruments);
    }
    subscriptions
}

/// The venues whose adapters differ between two sets, in venue order.
#[must_use]
pub fn changed_venues(old: &Subscriptions, new: &Subscriptions) -> Vec<Venue> {
    old.keys()
        .chain(new.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|venue| old.get(*venue) != new.get(*venue))
        .copied()
        .collect()
}

/// The cached feed set sits next to the node's config.
#[must_use]
pub fn cache_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name("network-feeds.json")
}

/// Reads the cached feed set, unchecked; `None` when there is none or it does not parse.
#[must_use]
pub fn read_cache(path: &Path) -> Option<FeedSet> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Writes the feed set to the cache through a temporary file, so a crash never leaves half of one.
///
/// # Errors
///
/// Returns the I/O error, for example when the unit does not let the node
/// write its directory.
pub fn write_cache(path: &Path, set: &FeedSet) -> std::io::Result<()> {
    let next = path.with_extension("json.next");
    let text = serde_json::to_string(set).map_err(std::io::Error::other)?;
    std::fs::write(&next, text)?;
    std::fs::rename(&next, path)
}

/// A feed set that verified and passed every check.
pub struct Chosen {
    /// The set.
    pub set: VerifiedFeedSet,
    /// What it resolves to.
    pub checked: CheckedFeeds,
}

/// Checks a set newer than `min_version`: its signature, its node version and [`check_feeds`].
///
/// # Errors
///
/// Returns why the set cannot be used.
pub fn accept(
    base: &NodeConfig,
    set: &FeedSet,
    governance: Address,
    min_version: u64,
) -> Result<Chosen, String> {
    let verified = set
        .verify(governance, min_version)
        .map_err(|error| error.to_string())?;
    if !verified.serves(NODE_VERSION) {
        return Err(format!(
            "it needs oracle-node {} or newer, and this is {NODE_VERSION}",
            verified.min_node_version()
        ));
    }
    let checked = check_feeds(base, verified.feeds()).map_err(|error| error.to_string())?;
    Ok(Chosen {
        set: verified,
        checked,
    })
}

/// Picks the newest set that [`accept`] takes, with the reason each newer one failed.
#[must_use]
pub fn choose(
    base: &NodeConfig,
    candidates: Vec<(&'static str, FeedSet)>,
    governance: Address,
) -> (Option<Chosen>, Vec<String>) {
    let mut candidates = candidates;
    candidates.sort_by(|a, b| b.1.version.cmp(&a.1.version));
    let mut refused = Vec::new();
    for (origin, set) in candidates {
        match accept(base, &set, governance, 0) {
            Ok(chosen) => return (Some(chosen), refused),
            Err(reason) => {
                refused.push(format!("the {origin} feed set v{}: {reason}", set.version))
            }
        }
    }
    (None, refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(venue: &str, symbol: &str) -> oracle_wire::SourceSettings {
        oracle_wire::SourceSettings {
            venue: venue.to_owned(),
            market: "spot".to_owned(),
            symbol: symbol.to_owned(),
            ..oracle_wire::SourceSettings::default()
        }
    }

    fn feed(symbol: &str, sources: Vec<oracle_wire::SourceSettings>) -> FeedSettings {
        FeedSettings {
            symbol: symbol.to_owned(),
            sources,
            ..FeedSettings::default()
        }
    }

    #[test]
    fn only_the_venues_whose_instruments_change_reconnect() {
        let subscribed = |feeds: &[FeedSettings]| {
            subscriptions(&resolve_feeds(feeds, &[], DEFAULT_TICK_MS).expect("resolves"))
        };
        let old = vec![feed(
            "CRYPTO.ETH/BTC",
            vec![source("binance", "ETHBTC"), source("okx", "ETH-BTC")],
        )];
        let before = subscribed(&old);
        let mut new = old.clone();
        new.push(FeedSettings {
            min_sources: Some(1),
            ..feed("CRYPTO.SOL/BTC", vec![source("okx", "SOL-BTC")])
        });
        assert_eq!(changed_venues(&before, &subscribed(&new)), [Venue::Okx]);
        // A new weight or kind changes the price, not the subscription.
        let mut weighted = old.clone();
        if let Some(first) = weighted.first_mut().and_then(|f| f.sources.first_mut()) {
            first.weight = Some("2".to_owned());
            first.kinds = Some(vec!["trade".to_owned()]);
        }
        assert!(changed_venues(&before, &subscribed(&weighted)).is_empty());
        // Depth is a subscription.
        let mut deep = old.clone();
        if let Some(first) = deep.first_mut() {
            first.impact_notional = Some("1000".to_owned());
        }
        assert_eq!(
            changed_venues(&before, &subscribed(&deep)),
            [Venue::Binance, Venue::Okx]
        );
        assert_eq!(
            changed_venues(&before, &Subscriptions::new()),
            [Venue::Binance, Venue::Okx]
        );
    }

    #[test]
    fn the_network_feed_files_pass_every_check_and_a_missing_peg_does_not() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../node/");
        let all = std::fs::read_to_string(format!("{root}all-feeds.toml")).expect("all-feeds");
        let assets = std::fs::read_to_string(format!("{root}assets.toml")).expect("assets");
        let config: NodeConfig = toml::from_str(&format!("{all}\n{assets}")).expect("parses");
        let checked = check_feeds(&config, &config.feeds).expect("passes");
        assert_eq!(checked.resolved.feeds.len(), config.feeds.len());
        assert!(checked.dropped_endpoints.is_empty());
        // A peg that is not in the set.
        let mut feeds = config.feeds.clone();
        let pegged = feeds
            .iter_mut()
            .find(|feed| feed.peg.is_some())
            .expect("a pegged feed");
        pegged.peg = Some("CRYPTO.DAI/USD".to_owned());
        let symbol = pegged.symbol.clone();
        let error = check_feeds(&config, &feeds).err().expect("refused");
        assert!(error.to_string().contains(&symbol), "{error}");
    }

    #[test]
    fn an_override_for_a_market_the_set_drops_is_kept_for_a_later_set() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../node/");
        let all = std::fs::read_to_string(format!("{root}all-feeds.toml")).expect("all-feeds");
        let mut config: NodeConfig = toml::from_str(&all).expect("parses");
        config.endpoints.push(crate::config::EndpointSettings {
            venue: "okx".to_owned(),
            market: "spot".to_owned(),
            url: "wss://okx.example/ws".to_owned(),
        });
        let one_source = |sources| FeedSettings {
            min_sources: Some(1),
            ..feed("CRYPTO.ETH/BTC", sources)
        };
        let binance_only = vec![one_source(vec![source("binance", "ETHBTC")])];
        let checked = check_feeds(&config, &binance_only).expect("passes");
        assert_eq!(checked.dropped_endpoints, ["okx:spot"]);
        assert_eq!(checked.config.endpoints.len(), 1, "the override stays");
        // A later set that reads OKX spot again uses it.
        let with_okx = vec![one_source(vec![
            source("binance", "ETHBTC"),
            source("okx", "ETH-BTC"),
        ])];
        let again = check_feeds(&checked.config, &with_okx).expect("passes");
        assert!(again.dropped_endpoints.is_empty());
    }

    #[test]
    fn the_cache_round_trips_and_a_bad_file_reads_as_none() {
        let dir = std::env::temp_dir().join(format!("network-feeds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = cache_path(&dir.join("config.toml"));
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some("network-feeds.json")
        );
        assert!(read_cache(&path).is_none());
        let governance = oracle_wire::Signer::from_secret_bytes([0x33; 32]).expect("a key");
        let set = FeedSet::sign(
            &governance,
            3,
            1_000,
            String::new(),
            None,
            vec![feed("CRYPTO.ETH/BTC", vec![source("binance", "ETHBTC")])],
        )
        .expect("signs");
        write_cache(&path, &set).expect("writes");
        assert_eq!(read_cache(&path), Some(set));
        std::fs::write(&path, "{").expect("writes");
        assert!(read_cache(&path).is_none());
        std::fs::remove_dir_all(&dir).expect("cleans up");
    }
}
