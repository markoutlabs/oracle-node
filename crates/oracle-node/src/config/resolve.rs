//! The config's feeds to a [`ResolvedConfig`]: the aggregator's feeds, and
//! the venue connections that the feed sources imply.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use oracle_agg::FeedConfig;
use oracle_agg::config::{QuoteConversion, SourceConfig};
use oracle_ingest::InstrumentSpec;
use oracle_ingest::binance::BinanceConfig;
use oracle_ingest::venues::{
    DecodeFn, VenueSpec, bitfinex, bitget, bitstamp, bybit, coinbase, deribit, dydx, gate,
    hyperliquid, kraken, kraken_futures, kucoin, lighter, mexc, okx, toobit,
};
use oracle_types::{Fixed, InstrumentId, MarketKind, ObsKind, Symbol, Venue};
use oracle_wire::{check_endpoint, feed_id};

#[cfg(feature = "serve")]
use super::NodeConfig;
use super::{ConfigError, EndpointSettings, FeedSettings};

/// Peg confidence above which dependent feeds degrade, from SPEC.md §5.3.
const DEFAULT_MAX_PEG_CONF_BPS: Fixed = Fixed::from_raw(50 * 1_000_000_000_000);

/// Idle timeout for the socket-subscribing venues. The session probes a quiet
/// connection every second, so a healthy one never stays silent this long.
const VENUE_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Session recycle age for the socket-subscribing venues.
const VENUE_MAX_SESSION: Duration = Duration::from_secs(23 * 3_600);
/// A book, mark or index silent this long inside a live connection makes it
/// reconnect, which subscribes again.
const VENUE_RESUBSCRIBE_AFTER: Duration = Duration::from_secs(15 * 60);
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

#[cfg(feature = "serve")]
impl NodeConfig {
    /// Resolves the config into everything the node needs to run.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] for an unparseable symbol, venue, market,
    /// or observation kind, or for a feed that could never publish.
    pub fn resolve(&self) -> Result<ResolvedConfig, ConfigError> {
        resolve_feeds(&self.feeds, &self.endpoints, self.tick_interval_ms)
    }
}

/// Resolves feeds, endpoint overrides and the tick, so a feed list alone resolves as a config does.
///
/// # Errors
///
/// Returns [`ConfigError::Invalid`] as [`NodeConfig::resolve`] does.
pub fn resolve_feeds(
    settings: &[FeedSettings],
    endpoints: &[EndpointSettings],
    tick_interval_ms: u64,
) -> Result<ResolvedConfig, ConfigError> {
    if settings.is_empty() {
        return Err(ConfigError::Invalid("no feeds configured".to_owned()));
    }

    let mut feeds = Vec::with_capacity(settings.len());
    let mut symbols = Vec::with_capacity(settings.len());
    // Deduplicated because several feeds may read the same instrument, and
    // subscribing twice would double the message rate for no benefit.
    let mut instruments: BTreeMap<(Venue, MarketKind, String), InstrumentSpec> = BTreeMap::new();

    for feed in settings {
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
                    ConfigError::Invalid(format!("feed `{}`: bad contract_size: {e}", feed.symbol))
                })?),
                None => None,
            };
            if contract_size.is_some_and(|size| !size.is_positive()) {
                return Err(ConfigError::Invalid(format!(
                    "feed `{}`: contract_size must be above zero",
                    feed.symbol
                )));
            }
            // These perpetuals count in contracts, and venue reports count in coins.
            // Without the size, a book would also read a hundred times too deep or too thin.
            if let Some(field) = contract_size_field(venue)
                && market.is_perp()
                && contract_size.is_none()
            {
                return Err(ConfigError::Invalid(format!(
                    "feed `{}`: the {venue} perpetual {} needs contract_size ({field}); \
                     `oracle-node update-feeds` writes the network's feeds with it",
                    feed.symbol, source.symbol
                )));
            }
            let mut config = SourceConfig::new(instrument, kinds);
            if source.converted {
                config = config.converted();
            }
            if source.quote_only {
                config = config.quote_only();
            }
            if let Some(weight) = &source.weight {
                let weight: Fixed = weight.parse().map_err(|e| {
                    ConfigError::Invalid(format!("feed `{}`: bad weight: {e}", feed.symbol))
                })?;
                config = config.with_weight(weight);
            }
            sources.push(config);

            let spec = instruments
                .entry((venue, market, source.symbol.clone()))
                .or_insert_with(|| InstrumentSpec {
                    venue_symbol: source.symbol.clone(),
                    market,
                    canonical: symbol,
                    depth,
                    contract_size,
                });
            // One subscription serves every feed of the instrument, so its sizes
            // convert one way.
            if spec.contract_size != contract_size {
                return Err(ConfigError::Invalid(format!(
                    "feed `{}`: {} has another contract_size in an earlier feed",
                    feed.symbol, source.symbol
                )));
            }
            spec.depth |= depth;
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
        if let Some(ms) = feed.max_age_ms {
            if ms == 0 {
                return Err(ConfigError::Invalid(format!(
                    "feed `{}`: max_age_ms must be above zero",
                    feed.symbol
                )));
            }
            config.max_age = Duration::from_millis(ms);
        }
        if let Some(text) = &feed.impact_notional {
            config.impact_notional = Some(text.parse().map_err(|e| {
                ConfigError::Invalid(format!("feed `{}`: bad impact_notional: {e}", feed.symbol))
            })?);
        }
        if let Some([low, high]) = &feed.sanity_band {
            if !config.sanity_band_enabled() {
                return Err(ConfigError::Invalid(format!(
                    "feed `{}`: a slow feed has no sanity_band",
                    feed.symbol
                )));
            }
            let bound = |text: &String| {
                text.parse::<Fixed>().map_err(|e| {
                    ConfigError::Invalid(format!("feed `{}`: bad sanity_band: {e}", feed.symbol))
                })
            };
            let (low, high) = (bound(low)?, bound(high)?);
            if !(low.is_positive() && low < Fixed::ONE && high > Fixed::ONE) {
                return Err(ConfigError::Invalid(format!(
                    "feed `{}`: sanity_band must be [low, high] with 0 < low < 1 < high",
                    feed.symbol
                )));
            }
            config.sanity_band = (low, high);
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
        for chunk in instruments.chunks(markets_per_connection(venue, market)) {
            let connection = venue_connection(venue, market, chunk)?;
            venues.entry(venue).or_default().push(connection);
        }
        venues
            .entry(venue)
            .or_default()
            .extend(book_connections(venue, market, &instruments));
    }
    apply_endpoints(endpoints, &mut binance, &mut venues)?;

    Ok(ResolvedConfig {
        feeds,
        symbols,
        binance,
        venues: venues.into_iter().collect(),
        tick_interval: Duration::from_millis(tick_interval_ms.max(1)),
    })
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
                // One override serves both futures routes. It names no REST host,
                // so the node does not ask the real Binance for the intervals.
                binance.perp_market_url.clone_from(&endpoint.url);
                binance.perp_funding_info_url.clear();
                binance.perp_open_interest_url.clear();
                Some(&mut binance.perp_base_url)
            }
            (Venue::Binance, _) => None,
            _ => {
                // A market split over several connections moves whole. A
                // connection keeps its own query, such as MEXC's `?contracts=`.
                let mut moved = 0;
                for connection in venues.get_mut(&venue).into_iter().flatten() {
                    if connection.spec.market != market {
                        continue;
                    }
                    let query = connection
                        .spec
                        .url
                        .split_once('?')
                        .map(|(_, q)| q.to_owned());
                    connection.spec.url = match query {
                        Some(query) => format!("{}?{query}", endpoint.url),
                        None => endpoint.url.clone(),
                    };
                    moved += 1;
                }
                if moved == 0 {
                    return Err(invalid("no feed reads this market".to_owned()));
                }
                continue;
            }
        };
        *url.ok_or_else(|| invalid("no feed reads this market".to_owned()))? = endpoint.url.clone();
    }
    Ok(())
}

/// More connections for venues whose book lives on another endpoint:
/// Coinbase's, on Advanced Trade. Every instrument needs one, because the book
/// gives the top of book.
fn book_connections(
    venue: Venue,
    market: MarketKind,
    instruments: &[InstrumentSpec],
) -> Vec<VenueConnection> {
    if venue != Venue::Coinbase {
        return Vec::new();
    }
    instruments
        .chunks(coinbase::BOOK_PRODUCTS)
        .map(|books| {
            let product_ids = books.iter().map(|spec| spec.venue_symbol.as_str());
            VenueConnection {
                spec: VenueSpec {
                    venue,
                    market,
                    url: coinbase::BOOK_URL.to_owned(),
                    subscribe: coinbase::book_subscribe_frames(product_ids),
                    keepalive: None,
                    idle_timeout: VENUE_IDLE_TIMEOUT,
                    resubscribe_after: Some(VENUE_RESUBSCRIBE_AFTER),
                    max_session: VENUE_MAX_SESSION,
                    decode: coinbase::decode_book,
                },
                instruments: books.to_vec(),
            }
        })
        .collect()
}

/// The most markets on one connection of a venue. A venue that refuses more
/// channels than a limit gets its markets split over several connections.
const fn markets_per_connection(venue: Venue, market: MarketKind) -> usize {
    match (venue, market) {
        (Venue::Bitfinex, _) => bitfinex::MARKETS_PER_CONNECTION,
        (Venue::Bitstamp, _) => bitstamp::MARKETS_PER_CONNECTION,
        (Venue::Bitget, MarketKind::Spot) => bitget::SPOT_MARKETS_PER_CONNECTION,
        (Venue::Bitget, _) => bitget::FUTURES_MARKETS_PER_CONNECTION,
        (Venue::Gate, _) => gate::MARKETS_PER_CONNECTION,
        (Venue::Lighter, _) => lighter::MARKETS_PER_CONNECTION,
        (Venue::Dydx, _) => dydx::MARKETS_PER_CONNECTION,
        (Venue::Kucoin, _) => kucoin::MARKETS_PER_CONNECTION,
        (Venue::Mexc, MarketKind::Spot) => mexc::SPOT_MARKETS_PER_CONNECTION,
        (Venue::Mexc, _) => mexc::FUTURES_MARKETS_PER_CONNECTION,
        (Venue::Toobit, _) => toobit::MARKETS_PER_CONNECTION,
        _ => usize::MAX,
    }
}

/// Where a venue whose perpetuals count in contracts states the coins in one.
const fn contract_size_field(venue: Venue) -> Option<&'static str> {
    match venue {
        Venue::Okx => Some("`ctVal` on OKX's instruments endpoint"),
        Venue::Kucoin => Some("`multiplier` on KuCoin's contracts endpoint"),
        Venue::Mexc => Some("`contractSize` on MEXC's contract detail endpoint"),
        Venue::Gate => Some("`quanto_multiplier` on Gate's contracts endpoint"),
        _ => None,
    }
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
            // Deribit closes a connection that sends no request for 10 minutes.
            // Its own heartbeat needs a reply to each `test_request`, which this
            // transport cannot send; a plain request every 30 s suffices.
            Some((deribit::KEEPALIVE_EVERY, deribit::KEEPALIVE.to_owned())),
            deribit::decode,
        ),
        // One socket serves perpetuals and spot; a perpetual also takes its
        // context channel, so the market decides the frames.
        Venue::Hyperliquid => (
            hyperliquid::URL.to_owned(),
            hyperliquid::subscribe_frames(with_depth(), market.is_perp()),
            Some((
                hyperliquid::KEEPALIVE_EVERY,
                hyperliquid::KEEPALIVE.to_owned(),
            )),
            hyperliquid::decode,
        ),

        Venue::Kucoin | Venue::Mexc | Venue::Gate if market == MarketKind::InversePerp => {
            return Err(ConfigError::Invalid(format!(
                "{venue} inverse perpetuals are not supported; use the USDT-margined ones"
            )));
        }
        Venue::Mexc if market.is_perp() => (
            mexc::futures_url(symbols()),
            mexc::futures_frames(with_depth()),
            Some((mexc::KEEPALIVE_EVERY, mexc::FUTURES_KEEPALIVE.to_owned())),
            mexc::decode_futures,
        ),
        Venue::Mexc => (
            mexc::SPOT_URL.to_owned(),
            mexc::spot_frames(with_depth()),
            Some((mexc::KEEPALIVE_EVERY, mexc::SPOT_KEEPALIVE.to_owned())),
            mexc::decode_spot,
        ),
        Venue::Kucoin if market.is_perp() => (
            kucoin::futures_url(symbols()),
            kucoin::futures_frames(with_depth()),
            Some((kucoin::KEEPALIVE_EVERY, kucoin::KEEPALIVE.to_owned())),
            kucoin::decode_futures,
        ),
        Venue::Kucoin => (
            kucoin::SPOT_TOKEN.to_owned(),
            kucoin::spot_frames(with_depth()),
            Some((kucoin::KEEPALIVE_EVERY, kucoin::KEEPALIVE.to_owned())),
            kucoin::decode_spot,
        ),
        Venue::Bitfinex => (
            bitfinex::URL.to_owned(),
            bitfinex::subscribe_frames(with_depth(), market.is_perp()),
            Some((bitfinex::KEEPALIVE_EVERY, bitfinex::KEEPALIVE.to_owned())),
            bitfinex::decode,
        ),
        // Bitstamp's perpetuals serve EU investors only, and their mark is not on the socket.
        Venue::Bitstamp if market.is_perp() => {
            return Err(ConfigError::Invalid(
                "bitstamp serves spot only in this build; use market = \"spot\"".to_owned(),
            ));
        }
        Venue::Bitstamp => (
            bitstamp::URL.to_owned(),
            bitstamp::frames(symbols()),
            Some((bitstamp::KEEPALIVE_EVERY, bitstamp::KEEPALIVE.to_owned())),
            bitstamp::decode,
        ),
        Venue::Gate if market.is_perp() => (
            gate::FUTURES_URL.to_owned(),
            gate::futures_frames(with_depth()),
            Some((gate::KEEPALIVE_EVERY, gate::FUTURES_KEEPALIVE.to_owned())),
            gate::decode,
        ),
        Venue::Gate => (
            gate::SPOT_URL.to_owned(),
            gate::spot_frames(with_depth()),
            Some((gate::KEEPALIVE_EVERY, gate::SPOT_KEEPALIVE.to_owned())),
            gate::decode,
        ),
        // Lighter's spot books are thin, and it has no inverse perpetuals.
        Venue::Lighter if market != MarketKind::LinearPerp => {
            return Err(ConfigError::Invalid(
                "lighter serves its USDC perpetuals only in this build; use market = \"linear_perp\""
                    .to_owned(),
            ));
        }
        Venue::Lighter => (
            lighter::URL.to_owned(),
            lighter::frames(with_depth()),
            Some((lighter::KEEPALIVE_EVERY, lighter::KEEPALIVE.to_owned())),
            lighter::decode,
        ),
        Venue::Dydx if market != MarketKind::LinearPerp => {
            return Err(ConfigError::Invalid(
                "dydx serves its USDC perpetuals only; use market = \"linear_perp\"".to_owned(),
            ));
        }
        // The venue pings and the transport answers, so no keepalive is sent.
        Venue::Dydx => (
            dydx::URL.to_owned(),
            dydx::frames(symbols()),
            None,
            dydx::decode,
        ),
        // One socket serves every market; the frames name each market's kind.
        Venue::Bitget => (
            bitget::URL.to_owned(),
            bitget::frames(with_depth(), market),
            Some((bitget::KEEPALIVE_EVERY, bitget::KEEPALIVE.to_owned())),
            bitget::decode,
        ),
        Venue::Toobit if market.is_perp() => {
            return Err(ConfigError::Invalid(
                "toobit serves spot only in this build; use market = \"spot\"".to_owned(),
            ));
        }
        // No socket, so nothing to subscribe or keep alive. Each book's good read
        // comes about each second, so the idle timeout ends only a connection
        // whose reads all fail.
        Venue::Toobit => (toobit::url(symbols()), Vec::new(), None, toobit::decode),
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
            // Coinbase's `ticker` moves only on a trade: its silence is a quiet coin.
            resubscribe_after: (venue != Venue::Coinbase).then_some(VENUE_RESUBSCRIBE_AFTER),
            max_session: VENUE_MAX_SESSION,
            decode,
        },
        instruments: instruments.to_vec(),
    })
}

#[cfg(all(test, feature = "serve"))]
mod tests;
