//! The config tests' fixture: one minimal base, and a builder for what a test
//! adds to it. Each test then shows only the value that it is about.
//!
//! ```text
//! config().feed(feed(BTC).source(spot("okx", "BTC-USDT"))).endpoint(..).resolve()
//! ```

use super::{ConfigError, NodeConfig, ResolvedConfig};

/// A spot pair that most tests price.
pub(crate) const BTC: &str = "CRYPTO.BTC/USDT";
/// The mark of the same pair's perpetual.
pub(crate) const BTC_MARK: &str = "CRYPTO.BTC/USDT.PERP_MARK";
/// The governance address of the base. Parsing reads it; nothing verifies it.
pub(crate) const GOVERNANCE: &str = "0x0000000000000000000000000000000000000001";

/// The minimal base: a server, a key file, a registry file, and no feeds.
pub(crate) fn config() -> Config {
    Config {
        signing: r#"key_file = "signing.key""#.to_owned(),
        registry: r#"path = "registry.json""#.to_owned(),
        governance: GOVERNANCE.to_owned(),
        sections: Vec::new(),
        feeds: Vec::new(),
        endpoints: Vec::new(),
    }
}

pub(crate) struct Config {
    signing: String,
    registry: String,
    governance: String,
    sections: Vec<String>,
    feeds: Vec<Feed>,
    endpoints: Vec<[String; 3]>,
}

impl Config {
    pub(crate) fn signing(mut self, body: &str) -> Self {
        body.clone_into(&mut self.signing);
        self
    }

    /// The `[registry]` lines but `governance_address`.
    pub(crate) fn registry(mut self, source: &str) -> Self {
        source.clone_into(&mut self.registry);
        self
    }

    pub(crate) fn governance(mut self, address: impl ToString) -> Self {
        self.governance = address.to_string();
        self
    }

    /// A table as TOML text, such as `[clients]` or `[server.limits]`.
    pub(crate) fn section(mut self, text: &str) -> Self {
        self.sections.push(text.to_owned());
        self
    }

    pub(crate) fn feed(mut self, feed: Feed) -> Self {
        self.feeds.push(feed);
        self
    }

    pub(crate) fn feeds(mut self, feeds: impl IntoIterator<Item = Feed>) -> Self {
        self.feeds.extend(feeds);
        self
    }

    pub(crate) fn endpoint(mut self, venue: &str, market: &str, url: &str) -> Self {
        self.endpoints
            .push([venue.to_owned(), market.to_owned(), url.to_owned()]);
        self
    }

    pub(crate) fn toml(&self) -> String {
        // The schema has no default for `feeds`, and a top-level key must come
        // before the first table.
        let mut out = String::new();
        if self.feeds.is_empty() {
            out.push_str("feeds = []\n\n");
        }
        out.push_str(&format!(
            "[server]\nlisten = \"127.0.0.1:1\"\n\n[signing]\n{}\n\n[registry]\n{}\n\
             governance_address = {}\n",
            self.signing,
            self.registry,
            quoted(&self.governance),
        ));
        for section in &self.sections {
            out.push_str(&format!("\n{section}\n"));
        }
        for feed in &self.feeds {
            out.push_str(&feed.toml());
        }
        for [venue, market, url] in &self.endpoints {
            out.push_str(&format!(
                "\n[[endpoints]]\nvenue = {}\nmarket = {}\nurl = {}\n",
                quoted(venue),
                quoted(market),
                quoted(url),
            ));
        }
        out
    }

    pub(crate) fn try_parse(&self) -> Result<NodeConfig, toml::de::Error> {
        toml::from_str(&self.toml())
    }

    /// Panics with the text when the schema refuses it.
    pub(crate) fn parse(&self) -> NodeConfig {
        self.try_parse()
            .unwrap_or_else(|error| panic!("{error}\n{}", self.toml()))
    }

    pub(crate) fn resolve(&self) -> Result<ResolvedConfig, ConfigError> {
        self.parse().resolve()
    }
}

/// A `[[feeds]]` entry: `min_sources = 1` unless a test sets it.
pub(crate) fn feed(symbol: &str) -> Feed {
    Feed {
        symbol: symbol.to_owned(),
        settings: vec![("min_sources".to_owned(), toml::Value::from(1))],
        sources: Vec::new(),
    }
}

/// [`BTC`] from Binance spot.
pub(crate) fn btc() -> Feed {
    feed(BTC).source(spot("binance", "BTCUSDT"))
}

/// [`BTC_MARK`] from the Binance perpetual.
pub(crate) fn btc_mark() -> Feed {
    feed(BTC_MARK).source(perp("binance", "BTCUSDT").mark())
}

pub(crate) struct Feed {
    symbol: String,
    settings: Vec<(String, toml::Value)>,
    sources: Vec<Source>,
}

impl Feed {
    /// One key of the feed, in place of an earlier value.
    pub(crate) fn set(mut self, key: &str, value: impl Into<toml::Value>) -> Self {
        self.settings.retain(|(name, _)| name != key);
        self.settings.push((key.to_owned(), value.into()));
        self
    }

    pub(crate) fn source(mut self, source: Source) -> Self {
        self.sources.push(source);
        self
    }

    pub(crate) fn sources(mut self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.sources.extend(sources);
        self
    }

    fn toml(&self) -> String {
        let mut out = format!("\n[[feeds]]\nsymbol = {}\n", quoted(&self.symbol));
        for (key, value) in &self.settings {
            out.push_str(&format!("{key} = {value}\n"));
        }
        out.push_str("sources = [\n");
        for source in &self.sources {
            out.push_str(&format!("  {},\n", source.toml()));
        }
        out.push_str("]\n");
        out
    }
}

pub(crate) fn source(venue: &str, market: &str, symbol: &str) -> Source {
    Source {
        fields: vec![
            ("venue", toml::Value::from(venue)),
            ("market", toml::Value::from(market)),
            ("symbol", toml::Value::from(symbol)),
        ],
    }
}

pub(crate) fn spot(venue: &str, symbol: &str) -> Source {
    source(venue, "spot", symbol)
}

/// A USDT- or USDC-margined perpetual.
pub(crate) fn perp(venue: &str, symbol: &str) -> Source {
    source(venue, "linear_perp", symbol)
}

pub(crate) struct Source {
    fields: Vec<(&'static str, toml::Value)>,
}

impl Source {
    pub(crate) fn kinds(self, kinds: &[&str]) -> Self {
        self.with("kinds", kinds.to_vec())
    }

    pub(crate) fn mark(self) -> Self {
        self.kinds(&["mark_price"])
    }

    pub(crate) fn contract_size(self, size: &str) -> Self {
        self.with("contract_size", size)
    }

    /// Quoted in a stablecoin, and converted to USD through the feed's peg.
    pub(crate) fn converted(self) -> Self {
        self.with("converted", true)
    }

    fn with(mut self, key: &'static str, value: impl Into<toml::Value>) -> Self {
        self.fields.push((key, value.into()));
        self
    }

    fn toml(&self) -> String {
        let fields: Vec<String> = self
            .fields
            .iter()
            .map(|(key, value)| format!("{key} = {value}"))
            .collect();
        format!("{{ {} }}", fields.join(", "))
    }
}

fn quoted(text: &str) -> toml::Value {
    toml::Value::from(text)
}
