use std::time::Duration;

use oracle_ingest::binance::BinanceConfig;
use oracle_ingest::venues::{VenueSpec, bitget, bitstamp, coinbase, dydx, gate, kucoin, lighter};
use oracle_types::{MarketKind, ObsKind, PRICE_HEARTBEAT, SLOW_HEARTBEAT, Venue};

use super::*;
use crate::config::DEFAULT_TICK_MS;
use crate::config::fixture::{
    BTC, BTC_MARK, Source, btc, btc_mark, config, feed, perp, source, spot,
};

fn playground(files: &[&str]) -> NodeConfig {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../node/");
    let text: Vec<String> = files
        .iter()
        .map(|file| std::fs::read_to_string(format!("{root}{file}")).expect(file))
        .collect();
    toml::from_str(&text.join("\n")).expect("parses")
}

/// A config with one mark-price feed from a single venue and market.
fn one_source(venue: &str, market: &str, symbol: &str) -> Result<ResolvedConfig, ConfigError> {
    config()
        .feed(feed("CRYPTO.BTC/USD.PERP_MARK").source(source(venue, market, symbol).mark()))
        .resolve()
}

fn connections_of(resolved: &ResolvedConfig, venue: Venue) -> &[VenueConnection] {
    &resolved
        .venues
        .iter()
        .find(|(v, _)| *v == venue)
        .unwrap_or_else(|| panic!("{venue} configured"))
        .1
}

fn spec_for(resolved: &ResolvedConfig, venue: Venue) -> &VenueSpec {
    &connections_of(resolved, venue)
        .first()
        .expect("one connection")
        .spec
}

/// The playground config shows every feed kind this build serves; it must
/// keep resolving.
#[test]
fn the_all_feeds_playground_resolves() {
    let resolved = playground(&["all-feeds.toml"]).resolve().expect("resolves");
    let perp_mid = resolved
        .feeds
        .iter()
        .find(|feed| feed.symbol.to_string() == "CRYPTO.BTC/USDT.PERP_MID")
        .expect("a perp mid feed");
    assert!(perp_mid.impact_notional.is_some());
    assert!(resolved.binance.perp.iter().any(|spec| spec.depth));
}

/// scripts/asset-feeds.py writes feeds only; with the playground they make
/// one config, and every venue symbol in it must resolve.
#[test]
fn the_generated_asset_feeds_resolve_with_the_playground() {
    let resolved = playground(&["all-feeds.toml", "assets.toml"])
        .resolve()
        .expect("resolves");
    assert!(resolved.feeds.len() > 100, "{} feeds", resolved.feeds.len());
}

#[test]
fn a_complete_config_resolves() {
    let resolved = config()
        .feed(btc())
        .feed(btc_mark())
        .resolve()
        .expect("resolves");
    assert_eq!(resolved.feeds.len(), 2);
    assert_eq!(resolved.symbols.len(), 2);
    assert_eq!(
        resolved.tick_interval,
        Duration::from_millis(DEFAULT_TICK_MS)
    );
}

/// The point of deriving subscriptions from feeds: they cannot drift apart.
#[test]
fn ingest_subscriptions_are_derived_from_the_feed_sources() {
    let resolved = config()
        .feed(btc())
        .feed(btc_mark())
        .resolve()
        .expect("resolves");
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
    let resolved = config()
        .feed(btc())
        .feed(feed("CRYPTO.BTC/USD").source(spot("binance", "BTCUSDT")))
        .resolve()
        .expect("resolves");
    assert_eq!(resolved.feeds.len(), 2, "both feeds exist");
    assert_eq!(
        resolved.binance.spot.len(),
        1,
        "but the instrument is streamed once"
    );
}

#[test]
fn observation_kinds_default_to_book_then_trade() {
    let resolved = config().feed(btc()).resolve().expect("resolves");
    let spot = resolved.feeds.first().expect("a feed");
    assert_eq!(
        spot.sources.first().map(|source| source.kinds.clone()),
        Some(vec![ObsKind::BookTop, ObsKind::Trade])
    );
}

#[test]
fn a_funding_feed_is_slow_by_its_kind() {
    let resolved = config()
        .feed(btc())
        .feed(feed("CRYPTO.BTC/USDT.FUNDING_8H").source(perp("binance", "BTCUSDT").mark()))
        .resolve()
        .expect("resolves");
    let price = resolved.feeds.first().expect("a feed");
    assert_eq!(price.heartbeat, PRICE_HEARTBEAT);
    let funding = resolved.feeds.get(1).expect("a second feed");
    assert_eq!(funding.heartbeat, SLOW_HEARTBEAT);
    assert_eq!(funding.max_age, Duration::from_secs(90));
    assert_eq!(funding.expo, -9);
}

#[test]
fn a_quiet_feed_sets_its_own_staleness_limit() {
    let resolved = config()
        .feed(btc().set("max_age_ms", 60_000))
        .feed(btc_mark())
        .resolve()
        .expect("resolves");
    let feed = resolved.feeds.first().expect("a feed");
    assert_eq!(feed.max_age, Duration::from_secs(60));
    let other = resolved.feeds.get(1).expect("a second feed");
    assert_eq!(
        other.max_age,
        Duration::from_secs(2),
        "the default elsewhere"
    );
    assert!(config().feed(btc().set("max_age_ms", 0)).resolve().is_err());
}

#[test]
fn a_feed_sets_its_own_sanity_band() {
    let resolved = config()
        .feed(btc().set("sanity_band", vec!["0.8", "1.25"]))
        .feed(btc_mark())
        .resolve()
        .expect("resolves");
    let feed = resolved.feeds.first().expect("a feed");
    assert_eq!(
        feed.sanity_band,
        (
            "0.8".parse().expect("fixed"),
            "1.25".parse().expect("fixed")
        )
    );
    let other = resolved.feeds.get(1).expect("a second feed");
    assert_eq!(
        other.sanity_band,
        ("0.5".parse().expect("fixed"), "2".parse().expect("fixed")),
        "the default elsewhere"
    );
    for bad in [["1.1", "2"], ["0.5", "0.9"], ["0", "2"]] {
        let band = config().feed(btc().set("sanity_band", bad.to_vec()));
        assert!(band.resolve().is_err(), "{bad:?}");
    }
}

#[test]
fn bad_symbols_venues_and_kinds_are_reported_at_startup() {
    for bad in [
        feed("not a symbol").source(spot("binance", "BTCUSDT")),
        feed(BTC).source(spot("ftx", "BTCUSDT")),
        feed(BTC).source(source("binance", "futures", "BTCUSDT")),
        feed(BTC_MARK).source(perp("binance", "BTCUSDT").kinds(&["nonsense"])),
    ] {
        let fixture = config().feed(bad);
        let failed = fixture
            .try_parse()
            .map_or(true, |config| config.resolve().is_err());
        assert!(failed, "should have been rejected:\n{}", fixture.toml());
    }
}

#[test]
fn a_feed_with_no_sources_is_refused() {
    assert!(config().feed(feed(BTC)).resolve().is_err());
}

/// The USDT-to-USD path, end to end through configuration.
#[test]
fn a_usd_feed_can_mix_native_and_converted_sources() {
    let peg = feed("CRYPTO.USDT/USD")
        .source(spot("coinbase", "USDT-USD"))
        .source(spot("kraken", "USDTUSD"));
    let btc = feed("CRYPTO.BTC/USD")
        .set("min_sources", 2)
        .set("peg", "CRYPTO.USDT/USD")
        .set("max_peg_conf_bps", "50")
        .source(spot("coinbase", "BTC-USD"))
        .source(spot("binance", "BTCUSDT").converted())
        .source(spot("bybit", "BTCUSDT").converted())
        .source(spot("okx", "BTC-USDT").converted());
    let resolved = config().feed(peg).feed(btc).resolve().expect("resolves");
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
    let resolved = config()
        .feed(feed(BTC).source(spot("kraken", "BTCUSDT")))
        .feed(btc_mark())
        .resolve()
        .expect("resolves");
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
    /// OKX drops a connection that is idle this long, and wants a plain-text ping.
    const OKX_IDLE_LIMIT: Duration = Duration::from_secs(30);
    let resolved = config()
        .feed(feed(BTC).source(spot("okx", "BTC-USDT")))
        .resolve()
        .expect("resolves");
    let spec = spec_for(&resolved, Venue::Okx);
    assert!(
        spec.subscribe
            .first()
            .is_some_and(|f| f.contains("bbo-tbt"))
    );
    let (period, payload) = spec.keepalive.clone().expect("okx needs a keepalive");
    assert_eq!(payload, "ping");
    assert!(period < OKX_IDLE_LIMIT);
}

#[test]
fn a_feed_sets_its_own_publication_policy() {
    let resolved = config()
        .feed(btc().set("deviation_bps", "0.5").set("min_interval_ms", 10))
        .feed(btc_mark())
        .resolve()
        .expect("resolves");
    let feed = resolved.feeds.first().expect("a feed");
    assert_eq!(feed.deviation_bps.to_string(), "0.5");
    assert_eq!(feed.min_interval, Duration::from_millis(10));
    let other = resolved.feeds.get(1).expect("a second feed");
    assert_eq!(other.deviation_bps.to_string(), "1", "the default");

    for (key, value, why) in [
        ("impact_notional", toml::Value::from("0"), "impact_notional"),
        ("impact_notional", "much".into(), "impact_notional"),
        ("min_interval_ms", 0.into(), "min_interval"),
        // Above the fixed one-second heartbeat, which could then never fire.
        ("min_interval_ms", 2_000.into(), "heartbeat"),
        ("deviation_bps", "-1".into(), "deviation_bps"),
        ("deviation_bps", "lots".into(), "deviation_bps"),
    ] {
        let Err(error) = config().feed(btc().set(key, value.clone())).resolve() else {
            panic!("{key} = {value} must be refused");
        };
        let error = error.to_string();
        assert!(error.contains(why), "{key} = {value}: {error}");
    }
}

/// A feed that prices from depth subscribes to it for every instrument it
/// reads, and only for those.
#[test]
fn impact_notional_turns_on_depth_for_its_instruments() {
    let resolved = config()
        .feed(btc().set("impact_notional", "20000"))
        .feed(btc_mark())
        .resolve()
        .expect("resolves");
    let feed = resolved.feeds.first().expect("a feed");
    assert_eq!(
        feed.impact_notional.map(|n| n.to_string()),
        Some("20000".to_owned())
    );
    assert!(resolved.binance.spot.iter().all(|spec| spec.depth));
    assert!(resolved.binance.perp.iter().all(|spec| !spec.depth));
}

/// An OKX swap counts in contracts, and a venue report counts in coins.
/// Without the contract size, the sizes and the depth would be wrong by the
/// contract's factor, so the config is refused, also for a mark-only source.
#[test]
fn an_okx_swap_needs_its_contract_size() {
    let swap = |size: Option<&str>| {
        let swap = perp("okx", "BTC-USDT-SWAP");
        match size {
            Some(size) => swap.contract_size(size),
            None => swap,
        }
    };
    let mark = |size| feed(BTC_MARK).source(swap(size).mark());
    let mid = |size| feed("CRYPTO.BTC/USDT.PERP_MID").source(swap(size));
    for alone in [mark(None), mid(None)] {
        let fixture = config().feed(alone);
        let Err(error) = fixture.resolve() else {
            panic!(
                "a swap without a contract size must be refused:\n{}",
                fixture.toml()
            );
        };
        assert!(error.to_string().contains("contract_size"), "{error}");
    }
    let size = Some("0.01");
    assert!(config().feed(mark(size)).feed(mid(size)).resolve().is_ok());
    // One subscription serves both feeds, so two sizes cannot both be right.
    let Err(error) = config().feed(mark(size)).feed(mid(Some("0.1"))).resolve() else {
        panic!("two contract sizes for one swap must be refused");
    };
    assert!(
        error.to_string().contains("another contract_size"),
        "{error}"
    );
}

#[test]
fn an_endpoint_replaces_the_built_in_url() {
    let local = "ws://127.0.0.1:9000/stream";
    let resolved = config()
        .feed(btc())
        .feed(btc_mark())
        .endpoint("binance", "spot", local)
        .resolve()
        .expect("resolves");
    assert_eq!(resolved.binance.spot_base_url, local);
    assert_eq!(
        resolved.binance.perp_base_url,
        BinanceConfig::default().perp_base_url
    );

    let regional = "wss://wsaws.okx.com:8443/ws/v5/public";
    let resolved = config()
        .feed(feed(BTC).source(spot("okx", "BTC-USDT")))
        .endpoint("okx", "spot", regional)
        .resolve()
        .expect("resolves");
    assert_eq!(spec_for(&resolved, Venue::Okx).url, regional);
}

#[test]
fn an_endpoint_nothing_reads_or_that_is_not_a_socket_is_refused() {
    for (endpoints, expected) in [
        (vec![("okx", "wss://x/ws")], "no feed reads"),
        (vec![("binance", "https://x/stream")], "not a ws://"),
        (
            vec![("binance", "ws://a/s"), ("binance", "ws://b/s")],
            "more than once",
        ),
    ] {
        let fixture = endpoints
            .iter()
            .fold(config().feed(btc()), |config, (venue, url)| {
                config.endpoint(venue, "spot", url)
            });
        let error = fixture.resolve().err().expect("refused").to_string();
        assert!(error.contains(expected), "{error}");
    }
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
    for (market, symbol) in [
        ("linear_perp", "BTC_USDC-PERPETUAL"),
        ("inverse_perp", "BTC-PERPETUAL"),
    ] {
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

/// MEXC spot takes 30 channels on one connection, and a perpetual needs its
/// contract size and names its contracts in the socket URL.
#[test]
fn mexc_splits_spot_by_its_channel_limit_and_a_perp_needs_its_contract_size() {
    let mexc = |contract: fn(Source) -> Source| {
        let spot = (0..12).map(|i| spot("mexc", &format!("C{i}USDT")));
        config()
            .feed(feed(BTC).sources(spot))
            .feed(feed(BTC_MARK).source(contract(perp("mexc", "BTC_USDT").mark())))
    };
    let Err(error) = mexc(|swap| swap).resolve() else {
        panic!("a MEXC perpetual without its contract size resolves");
    };
    assert!(error.to_string().contains("contractSize"), "{error}");
    let resolved = mexc(|swap| swap.contract_size("0.0001"))
        .resolve()
        .expect("resolves");
    let connections = connections_of(&resolved, Venue::Mexc);
    let mut spot: Vec<usize> = connections
        .iter()
        .filter(|c| c.spec.market == MarketKind::Spot)
        .map(|c| c.instruments.len())
        .collect();
    spot.sort_unstable();
    assert_eq!(spot, [2, 10]);
    assert!(
        connections
            .iter()
            .any(|c| c.spec.url == "wss://contract.mexc.com/edge?contracts=BTC_USDT")
    );
}

/// KuCoin connects through its token URL; a perpetual names its contracts
/// there and needs its contract size.
#[test]
fn kucoin_connects_through_its_token_url_and_a_perp_needs_its_contract_size() {
    let kucoin = |contract: fn(Source) -> Source| {
        config()
            .feed(feed(BTC).source(spot("kucoin", "BTC-USDT")))
            .feed(feed(BTC_MARK).source(contract(perp("kucoin", "XBTUSDTM").mark())))
    };
    let Err(error) = kucoin(|swap| swap).resolve() else {
        panic!("a KuCoin perpetual without its contract size resolves");
    };
    assert!(error.to_string().contains("contract_size"), "{error}");
    let resolved = kucoin(|swap| swap.contract_size("0.001"))
        .resolve()
        .expect("resolves");
    let connections = connections_of(&resolved, Venue::Kucoin);
    let urls: Vec<&str> = connections.iter().map(|c| c.spec.url.as_str()).collect();
    assert!(urls.contains(&kucoin::SPOT_TOKEN), "{urls:?}");
    assert!(
        urls.contains(&"https://api-futures.kucoin.com/api/v1/bullet-public?contracts=XBTUSDTM"),
        "{urls:?}"
    );
    for connection in connections {
        assert!(connection.spec.keepalive.is_some());
        assert!(!connection.spec.subscribe.is_empty());
    }
}

/// Bitfinex refuses more than about 30 channels on one connection, so its
/// markets go over several connections.
#[test]
fn bitfinex_markets_are_split_over_connections() {
    let markets = (0..14).map(|i| spot("bitfinex", &format!("tC{i}USD")));
    let resolved = config()
        .feed(feed("CRYPTO.BTC/USD").sources(markets))
        .resolve()
        .expect("resolves");
    let connections = connections_of(&resolved, Venue::Bitfinex);
    let sizes: Vec<usize> = connections.iter().map(|c| c.instruments.len()).collect();
    assert_eq!(sizes, [6, 6, 2]);
    for connection in connections {
        assert!(connection.spec.subscribe.len() <= 30);
        assert!(connection.spec.url.contains("api-pub.bitfinex.com"));
    }
}

#[test]
fn hyperliquid_perps_take_the_context_channel_and_spot_does_not() {
    let perp = one_source("hyperliquid", "linear_perp", "BTC").expect("resolves");
    let spec = spec_for(&perp, Venue::Hyperliquid);
    assert!(spec.url.contains("api.hyperliquid.xyz"), "{}", spec.url);
    assert!(spec.subscribe.iter().any(|f| f.contains("activeAssetCtx")));
    assert!(
        spec.keepalive
            .as_ref()
            .is_some_and(|(_, text)| text.contains("ping"))
    );

    let spot = one_source("hyperliquid", "spot", "@142").expect("resolves");
    let spot_spec = spec_for(&spot, Venue::Hyperliquid);
    assert!(
        !spot_spec
            .subscribe
            .iter()
            .any(|f| f.contains("activeAssetCtx"))
    );
    assert!(
        spot_spec
            .subscribe
            .iter()
            .any(|f| f.contains(r#""coin":"@142""#))
    );
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

#[test]
fn bitstamp_splits_its_markets_and_refuses_perps() {
    let markets = (0..25).map(|i| spot("bitstamp", &format!("c{i}usd")));
    let resolved = config()
        .feed(feed("CRYPTO.BTC/USD").sources(markets))
        .resolve()
        .expect("resolves");
    let connections = connections_of(&resolved, Venue::Bitstamp);
    let sizes: Vec<usize> = connections.iter().map(|c| c.instruments.len()).collect();
    assert_eq!(sizes, [20, 5]);
    for connection in connections {
        assert_eq!(connection.spec.url, bitstamp::URL);
        assert_eq!(
            connection.spec.subscribe.len(),
            connection.instruments.len() * 2
        );
        assert!(connection.spec.keepalive.is_some());
    }

    let error = one_source("bitstamp", "linear_perp", "btcusd-perp")
        .err()
        .expect("must refuse");
    assert!(
        matches!(&error, ConfigError::Invalid(m) if m.contains("spot only")),
        "got {error:?}"
    );
}

#[test]
fn bitget_splits_spot_and_perpetuals_and_takes_coin_margined_ones() {
    let spots = (0..30).map(|i| spot("bitget", &format!("C{i}USDT")));
    let perps = (0..13).map(|i| perp("bitget", &format!("C{i}USDT")).mark());
    let coin_margined = source("bitget", "inverse_perp", "BTCUSD_CM").mark();
    let resolved = config()
        .feed(feed(BTC).sources(spots))
        .feed(feed(BTC_MARK).sources(perps))
        .feed(feed("CRYPTO.BTC/USD.PERP_MARK").source(coin_margined))
        .resolve()
        .expect("resolves");
    let connections = connections_of(&resolved, Venue::Bitget);
    let mut sizes: Vec<(MarketKind, usize)> = connections
        .iter()
        .map(|c| (c.spec.market, c.instruments.len()))
        .collect();
    sizes.sort();
    assert_eq!(
        sizes,
        [
            (MarketKind::Spot, 6),
            (MarketKind::Spot, 24),
            (MarketKind::LinearPerp, 1),
            (MarketKind::LinearPerp, 12),
            (MarketKind::InversePerp, 1),
        ]
    );
    for connection in connections {
        assert_eq!(connection.spec.url, bitget::URL);
        assert_eq!(connection.spec.subscribe.len(), 1);
    }
}

#[test]
fn gate_splits_its_markets_and_a_perp_needs_its_contract_size() {
    let gate = |contract: fn(Source) -> Source| {
        // A feed takes at most 32 sources, so the 45 markets go in two feeds.
        let spots =
            |range: std::ops::Range<u32>| range.map(|i| spot("gate", &format!("C{i}_USDT")));
        config()
            .feed(feed(BTC).sources(spots(0..25)))
            .feed(feed("CRYPTO.ETH/USDT").sources(spots(25..45)))
            .feed(feed(BTC_MARK).source(contract(perp("gate", "BTC_USDT").mark())))
    };
    let Err(error) = gate(|swap| swap).resolve() else {
        panic!("a Gate perpetual without its contract size resolves");
    };
    assert!(error.to_string().contains("quanto_multiplier"), "{error}");
    let resolved = gate(|swap| swap.contract_size("0.0001"))
        .resolve()
        .expect("resolves");
    let mut sizes: Vec<(&str, usize)> = connections_of(&resolved, Venue::Gate)
        .iter()
        .map(|c| (c.spec.url.as_str(), c.instruments.len()))
        .collect();
    sizes.sort_unstable();
    assert_eq!(
        sizes,
        [
            (gate::SPOT_URL, 5),
            (gate::SPOT_URL, 40),
            (gate::FUTURES_URL, 1)
        ]
    );
    // An inverse perpetual is refused: this build reads the USDT-settled ones only.
    let error = one_source("gate", "inverse_perp", "BTC_USD")
        .err()
        .expect("must refuse");
    assert!(matches!(&error, ConfigError::Invalid(_)), "got {error:?}");
}

#[test]
fn lighter_splits_its_perpetuals_and_refuses_spot() {
    // A feed takes at most 32 sources, so the 61 markets go in two feeds.
    let perps =
        |range: std::ops::Range<u32>| range.map(|id| perp("lighter", &id.to_string()).mark());
    let resolved = config()
        .feed(feed(BTC_MARK).sources(perps(0..30)))
        .feed(feed("CRYPTO.ETH/USDT.PERP_MARK").sources(perps(30..61)))
        .resolve()
        .expect("resolves");
    let connections = connections_of(&resolved, Venue::Lighter);
    let mut sizes: Vec<usize> = connections.iter().map(|c| c.instruments.len()).collect();
    sizes.sort_unstable();
    assert_eq!(sizes, [1, 60]);
    for connection in connections {
        assert_eq!(connection.spec.url, lighter::URL);
        assert_eq!(
            connection.spec.subscribe.len(),
            connection.instruments.len() * 3
        );
    }
    let error = one_source("lighter", "spot", "2048")
        .err()
        .expect("must refuse");
    assert!(
        matches!(&error, ConfigError::Invalid(m) if m.contains("perpetuals only")),
        "got {error:?}"
    );
}

#[test]
fn dydx_splits_its_perpetuals_and_refuses_spot() {
    let perps = (0..12).map(|i| perp("dydx", &format!("C{i}-USD")).mark());
    let resolved = config()
        .feed(feed(BTC_MARK).sources(perps))
        .resolve()
        .expect("resolves");
    let connections = connections_of(&resolved, Venue::Dydx);
    let mut sizes: Vec<usize> = connections.iter().map(|c| c.instruments.len()).collect();
    sizes.sort_unstable();
    assert_eq!(sizes, [2, 10]);
    for connection in connections {
        assert_eq!(connection.spec.url, dydx::URL);
        // A book and the trades of each market, and the markets channel once.
        assert_eq!(
            connection.spec.subscribe.len(),
            connection.instruments.len() * 2 + 1
        );
    }
    let error = one_source("dydx", "spot", "BTC-USD")
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

/// Coinbase sends a ticker only on a trade, so each product's top comes from
/// a level2 book. Coinbase allows at most 30 of those on one connection.
#[test]
fn every_coinbase_product_gets_a_book_in_connections_of_at_most_25() {
    let bases: Vec<String> = ('A'..='C')
        .flat_map(|first| ('A'..='T').map(move |second| format!("{first}{second}")))
        .collect();
    let resolved = config()
        .feeds(bases.iter().map(|base| {
            feed(&format!("CRYPTO.{base}/USD")).source(spot("coinbase", &format!("{base}-USD")))
        }))
        .resolve()
        .expect("resolves");
    let (tickers, books): (Vec<_>, Vec<_>) = connections_of(&resolved, Venue::Coinbase)
        .iter()
        .partition(|connection| connection.spec.url == coinbase::URL);
    let [ticker] = tickers.as_slice() else {
        panic!("one ticker connection, got {}", tickers.len());
    };
    assert_eq!(ticker.instruments.len(), bases.len());
    let sizes: Vec<usize> = books.iter().map(|book| book.instruments.len()).collect();
    assert_eq!(sizes, [25, 25, 10]);
    let mut covered = Vec::new();
    for book in &books {
        assert_eq!(book.spec.url, coinbase::BOOK_URL);
        let level2 = book.spec.subscribe.first().expect("a level2 frame");
        assert!(level2.contains(r#""channel":"level2""#));
        for spec in &book.instruments {
            assert!(level2.contains(&format!("\"{}\"", spec.venue_symbol)));
            covered.push(spec.venue_symbol.clone());
        }
    }
    covered.sort();
    covered.dedup();
    assert_eq!(covered.len(), bases.len());
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
