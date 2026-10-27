//! The checks on a feed set's content before governance signs it, and its
//! canonical form. The canister runs them on `set_feed_set`, and the node's
//! `export-feeds` runs them before the call.
//!
//! These are the checks that need no venue connection. A node also resolves the
//! feeds against its own venues before it uses them, and refuses a set that fails.

use std::collections::HashSet;
use std::str::FromStr;

use super::{FeedSettings, MAX_FEEDS, MAX_SOURCE_KINDS, PushPolicy, SourceSettings};
use oracle_types::{Fixed, MAX_VENUE_ENTRIES, MarketKind, ObsKind, Symbol, Venue};
use serde::{Deserialize, Serialize};

/// What governance publishes: the feed set without its version, time and signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedContent {
    /// The oldest node version that can serve every feed; empty for any.
    #[serde(default)]
    pub min_node_version: String,
    /// The push pace; `None` leaves it to each node.
    #[serde(default)]
    pub push: Option<PushPolicy>,
    /// The feeds, in the order the nodes report them.
    pub feeds: Vec<FeedSettings>,
}

impl FeedContent {
    /// Checks the content and returns it with each name and decimal in one spelling, so that `0.10` signs as `0.1`.
    ///
    /// # Errors
    ///
    /// Returns the first problem, naming the feed and the source.
    pub fn canonical(&self) -> Result<Self, String> {
        check(&self.min_node_version, self.push, &self.feeds)
    }
}

fn decimal(feed: &str, field: &str, text: &str, positive: bool) -> Result<String, String> {
    let value =
        Fixed::from_str(text).map_err(|error| format!("{feed}: {field} `{text}`: {error}"))?;
    if value < Fixed::ZERO || (positive && value == Fixed::ZERO) {
        let bound = if positive {
            "above zero"
        } else {
            "zero or more"
        };
        return Err(format!("{feed}: {field} must be {bound}, not `{text}`"));
    }
    Ok(value.to_string())
}

fn optional(
    feed: &str,
    field: &str,
    text: Option<&String>,
    positive: bool,
) -> Result<Option<String>, String> {
    text.map(|text| decimal(feed, field, text, positive))
        .transpose()
}

fn source(feed: &str, has_peg: bool, source: &SourceSettings) -> Result<SourceSettings, String> {
    let at = format!(
        "{feed}: {}:{}:{}",
        source.venue, source.market, source.symbol
    );
    let venue = Venue::from_str(&source.venue).map_err(|error| format!("{at}: {error}"))?;
    let market = MarketKind::from_str(&source.market).map_err(|error| format!("{at}: {error}"))?;
    if source.symbol.is_empty() {
        return Err(format!("{at}: the venue symbol is empty"));
    }
    let kinds = match &source.kinds {
        None => None,
        Some(kinds) => {
            if kinds.is_empty() || kinds.len() > MAX_SOURCE_KINDS {
                return Err(format!(
                    "{at}: kinds must list 1 to {MAX_SOURCE_KINDS} kinds"
                ));
            }
            let mut seen = HashSet::new();
            let mut parsed = Vec::with_capacity(kinds.len());
            for kind in kinds {
                let kind = ObsKind::from_str(kind).map_err(|error| format!("{at}: {error}"))?;
                if !seen.insert(kind) {
                    return Err(format!("{at}: kind {kind} is listed twice"));
                }
                parsed.push(kind.as_str().to_owned());
            }
            Some(parsed)
        }
    };
    if source.converted && !has_peg {
        return Err(format!("{at}: a converted source needs the feed's peg"));
    }
    Ok(SourceSettings {
        venue: venue.as_str().to_owned(),
        market: market.as_str().to_owned(),
        symbol: source.symbol.clone(),
        kinds,
        weight: optional(&at, "weight", source.weight.as_ref(), true)?,
        converted: source.converted,
        contract_size: optional(&at, "contract_size", source.contract_size.as_ref(), true)?,
    })
}

fn feed(settings: &FeedSettings) -> Result<FeedSettings, String> {
    let symbol = Symbol::from_str(&settings.symbol)
        .map_err(|error| format!("symbol `{}`: {error}", settings.symbol))?
        .to_string();
    let peg = settings
        .peg
        .as_ref()
        .map(|peg| {
            Symbol::from_str(peg)
                .map(|peg| peg.to_string())
                .map_err(|error| format!("{symbol}: peg `{peg}`: {error}"))
        })
        .transpose()?;
    if peg.as_deref() == Some(symbol.as_str()) {
        return Err(format!("{symbol}: a feed cannot be its own peg"));
    }
    if settings.sources.is_empty() || settings.sources.len() > MAX_VENUE_ENTRIES {
        return Err(format!(
            "{symbol}: a feed needs 1 to {MAX_VENUE_ENTRIES} sources"
        ));
    }
    let mut seen = HashSet::new();
    let mut sources = Vec::with_capacity(settings.sources.len());
    for settings_source in &settings.sources {
        let checked = source(&symbol, peg.is_some(), settings_source)?;
        if !seen.insert((
            checked.venue.clone(),
            checked.market.clone(),
            checked.symbol.clone(),
        )) {
            return Err(format!(
                "{symbol}: {}:{}:{} is listed twice",
                checked.venue, checked.market, checked.symbol
            ));
        }
        sources.push(checked);
    }
    if let Some(min) = settings.min_sources
        && (min == 0 || usize::try_from(min).map_or(true, |min| min > sources.len()))
    {
        return Err(format!(
            "{symbol}: min_sources {min} must be 1 to the {} sources",
            sources.len()
        ));
    }
    for (field, value) in [
        ("min_interval_ms", settings.min_interval_ms),
        ("max_age_ms", settings.max_age_ms),
    ] {
        if value == Some(0) {
            return Err(format!("{symbol}: {field} must be above zero"));
        }
    }
    Ok(FeedSettings {
        max_peg_conf_bps: optional(
            &symbol,
            "max_peg_conf_bps",
            settings.max_peg_conf_bps.as_ref(),
            true,
        )?,
        min_sources: settings.min_sources,
        deviation_bps: optional(
            &symbol,
            "deviation_bps",
            settings.deviation_bps.as_ref(),
            false,
        )?,
        min_interval_ms: settings.min_interval_ms,
        max_age_ms: settings.max_age_ms,
        impact_notional: optional(
            &symbol,
            "impact_notional",
            settings.impact_notional.as_ref(),
            true,
        )?,
        sources,
        symbol,
        peg,
    })
}

/// The checks of [`FeedContent::canonical`], which [`super::FeedSet::verify`] runs too.
pub(super) fn check(
    min_node_version: &str,
    push: Option<PushPolicy>,
    feeds: &[FeedSettings],
) -> Result<FeedContent, String> {
    if feeds.is_empty() || feeds.len() > MAX_FEEDS {
        return Err(format!("a feed set lists 1 to {MAX_FEEDS} feeds"));
    }
    if !min_node_version.is_empty() {
        semver::Version::parse(min_node_version)
            .map_err(|error| format!("min_node_version `{min_node_version}`: {error}"))?;
    }
    let feeds = feeds.iter().map(feed).collect::<Result<Vec<_>, _>>()?;
    let mut symbols = HashSet::with_capacity(feeds.len());
    for checked in &feeds {
        if !symbols.insert(checked.symbol.as_str()) {
            return Err(format!("{} is listed twice", checked.symbol));
        }
    }
    let pegged: HashSet<&str> = feeds
        .iter()
        .filter(|checked| checked.peg.is_some())
        .map(|checked| checked.symbol.as_str())
        .collect();
    for checked in &feeds {
        if let Some(peg) = &checked.peg {
            if !symbols.contains(peg.as_str()) {
                return Err(format!(
                    "{}: its peg {peg} is not in the set",
                    checked.symbol
                ));
            }
            if pegged.contains(peg.as_str()) {
                return Err(format!(
                    "{}: its peg {peg} has a peg of its own",
                    checked.symbol
                ));
            }
        }
    }
    Ok(FeedContent {
        min_node_version: min_node_version.to_owned(),
        push: push
            .map(PushPolicy::check)
            .transpose()
            .map_err(|error| format!("push: {error}"))?,
        feeds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spot(venue: &str, symbol: &str) -> SourceSettings {
        SourceSettings {
            venue: venue.to_owned(),
            market: "spot".to_owned(),
            symbol: symbol.to_owned(),
            ..SourceSettings::default()
        }
    }

    fn feed_of(symbol: &str, sources: Vec<SourceSettings>) -> FeedSettings {
        FeedSettings {
            symbol: symbol.to_owned(),
            sources,
            ..FeedSettings::default()
        }
    }

    fn peg() -> FeedSettings {
        feed_of(
            "CRYPTO.USDT/USD",
            vec![spot("coinbase", "USDT-USD"), spot("kraken", "USDT/USD")],
        )
    }

    fn content(feeds: Vec<FeedSettings>) -> FeedContent {
        FeedContent {
            min_node_version: "0.1.0".to_owned(),
            push: None,
            feeds,
        }
    }

    fn refused(feeds: Vec<FeedSettings>) -> String {
        content(feeds).canonical().expect_err("refused")
    }

    #[test]
    fn a_set_comes_back_in_one_spelling() {
        let mut usdc = feed_of(
            "CRYPTO.USDC/USD",
            vec![
                spot("kraken", "USDC/USD"),
                SourceSettings {
                    converted: true,
                    weight: Some("1.50".to_owned()),
                    kinds: Some(vec!["book_top".to_owned(), "trade".to_owned()]),
                    ..spot("binance", "USDCUSDT")
                },
            ],
        );
        usdc.peg = Some("CRYPTO.USDT/USD".to_owned());
        usdc.deviation_bps = Some("0.10".to_owned());
        usdc.min_sources = Some(2);
        let checked = content(vec![peg(), usdc]).canonical().expect("passes");
        let usdc = checked.feeds.get(1).expect("a feed");
        assert_eq!(usdc.deviation_bps.as_deref(), Some("0.1"));
        assert_eq!(
            usdc.sources.get(1).and_then(|s| s.weight.as_deref()),
            Some("1.5")
        );
    }

    #[test]
    fn a_bad_name_or_number_is_refused_with_its_feed() {
        let error = refused(vec![feed_of(
            "CRYPTO.ETH/BTC",
            vec![spot("nasdaq", "ETHBTC")],
        )]);
        assert!(error.contains("CRYPTO.ETH/BTC"), "{error}");
        assert!(
            refused(vec![feed_of("not a symbol", vec![spot("binance", "X")])]).contains("symbol")
        );
        let mut bad_kind = spot("binance", "ETHBTC");
        bad_kind.kinds = Some(vec!["price".to_owned()]);
        refused(vec![feed_of("CRYPTO.ETH/BTC", vec![bad_kind])]);
        let mut negative = spot("binance", "ETHBTC");
        negative.weight = Some("-1".to_owned());
        refused(vec![feed_of("CRYPTO.ETH/BTC", vec![negative])]);
        let mut zero = feed_of("CRYPTO.ETH/BTC", vec![spot("binance", "ETHBTC")]);
        zero.max_age_ms = Some(0);
        refused(vec![zero]);
    }

    #[test]
    fn the_set_must_hold_each_peg_once_and_unpegged() {
        let mut usdc = feed_of("CRYPTO.USDC/USD", vec![spot("kraken", "USDC/USD")]);
        usdc.peg = Some("CRYPTO.USDT/USD".to_owned());
        assert!(refused(vec![usdc.clone()]).contains("not in the set"));
        let mut chained = peg();
        chained.peg = Some("CRYPTO.USDC/USD".to_owned());
        assert!(refused(vec![chained, usdc.clone()]).contains("peg of its own"));
        let mut own = peg();
        own.peg = Some("CRYPTO.USDT/USD".to_owned());
        assert!(refused(vec![own]).contains("own peg"));
        assert!(refused(vec![peg(), peg()]).contains("twice"));
        content(vec![peg(), usdc]).canonical().expect("passes");
    }

    #[test]
    fn a_converted_source_needs_a_peg_and_sources_are_bounded() {
        let converted = SourceSettings {
            converted: true,
            ..spot("binance", "ETHUSDT")
        };
        assert!(refused(vec![feed_of("CRYPTO.ETH/USD", vec![converted])]).contains("peg"));
        refused(vec![feed_of("CRYPTO.ETH/USD", vec![])]);
        refused(vec![feed_of(
            "CRYPTO.ETH/USD",
            vec![spot("binance", "ETHUSDT"), spot("binance", "ETHUSDT")],
        )]);
        let mut too_few = feed_of("CRYPTO.ETH/USD", vec![spot("binance", "ETHUSDT")]);
        too_few.min_sources = Some(2);
        refused(vec![too_few]);
        assert!(content(vec![]).canonical().is_err());
    }

    #[test]
    fn the_push_pace_and_the_node_version_are_checked() {
        let one = || vec![feed_of("CRYPTO.ETH/BTC", vec![spot("binance", "ETHBTC")])];
        let with = |push: PushPolicy| FeedContent {
            push: Some(push),
            ..content(one())
        };
        let pace = PushPolicy {
            heartbeat_secs: 7,
            deviation_bps: 10,
            min_interval_secs: 5,
        };
        with(pace).canonical().expect("passes");
        for bad in [
            PushPolicy {
                heartbeat_secs: 61,
                ..pace
            },
            PushPolicy {
                min_interval_secs: 8,
                ..pace
            },
            PushPolicy {
                deviation_bps: 0,
                ..pace
            },
        ] {
            assert!(with(bad).canonical().is_err(), "{bad:?}");
        }
        let unversioned = FeedContent {
            min_node_version: "soon".to_owned(),
            ..content(one())
        };
        assert!(unversioned.canonical().is_err());
    }
}
