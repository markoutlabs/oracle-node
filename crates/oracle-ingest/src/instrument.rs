//! Mapping between a venue's own symbols and canonical feed symbols.

use std::collections::HashMap;

use oracle_types::{InstrumentId, MarketKind, Symbol, Venue};

use crate::IngestError;

/// Longest venue symbol handled without allocating during lookup.
const MAX_VENUE_SYMBOL: usize = 32;

/// One instrument an adapter is configured to stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstrumentSpec {
    /// The venue's own symbol, such as `BTCUSDT` or `BTC-USD`.
    pub venue_symbol: String,
    /// Spot or perpetual.
    pub market: MarketKind,
    /// The canonical feed symbol this instrument contributes to.
    pub canonical: Symbol,
    /// Subscribe to depth snapshots as well as the top of book.
    pub depth: bool,
}

impl InstrumentSpec {
    /// Builds a spec.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError::Config`] if the canonical symbol does not parse.
    pub fn new(
        venue_symbol: impl Into<String>,
        market: MarketKind,
        canonical: &str,
    ) -> Result<Self, IngestError> {
        let canonical = canonical
            .parse::<Symbol>()
            .map_err(|e| IngestError::Config(format!("bad canonical symbol: {e}")))?;
        Ok(Self {
            venue_symbol: venue_symbol.into(),
            market,
            canonical,
            depth: false,
        })
    }

    /// Also subscribes to depth snapshots, where the venue sends them.
    #[must_use]
    pub const fn with_depth(mut self) -> Self {
        self.depth = true;
        self
    }
}

/// What an instrument lookup yields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstrumentEntry {
    /// The identifier stamped onto observations.
    pub instrument: InstrumentId,
    /// The canonical feed this instrument feeds into.
    pub canonical: Symbol,
    /// Whether depth snapshots are subscribed.
    pub depth: bool,
}

/// Venue symbol to instrument lookup for one venue and market.
///
/// Keys are stored uppercase. Venues are inconsistent about case — Binance names
/// streams in lowercase but stamps payloads in uppercase — and the decode path
/// runs on every message, so the common case must not allocate.
#[derive(Clone, Debug)]
pub struct InstrumentMap {
    venue: Venue,
    market: MarketKind,
    by_symbol: HashMap<String, InstrumentEntry>,
}

impl InstrumentMap {
    /// Builds a map for one venue and market.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError::DuplicateInstrument`] if a venue symbol repeats, or
    /// [`IngestError::Config`] if a spec's market does not match `market`.
    pub fn new(
        venue: Venue,
        market: MarketKind,
        specs: &[InstrumentSpec],
    ) -> Result<Self, IngestError> {
        let mut by_symbol = HashMap::with_capacity(specs.len());
        for spec in specs {
            if spec.market != market {
                return Err(IngestError::Config(format!(
                    "instrument `{}` is {} but the map is {market}",
                    spec.venue_symbol, spec.market
                )));
            }
            if spec.venue_symbol.len() > MAX_VENUE_SYMBOL {
                return Err(IngestError::Config(format!(
                    "venue symbol `{}` exceeds {MAX_VENUE_SYMBOL} characters",
                    spec.venue_symbol
                )));
            }
            let key = spec.venue_symbol.to_ascii_uppercase();
            let entry = InstrumentEntry {
                instrument: InstrumentId::new(venue, market, spec.venue_symbol.as_str()),
                canonical: spec.canonical,
                depth: spec.depth,
            };
            if by_symbol.insert(key, entry).is_some() {
                return Err(IngestError::DuplicateInstrument {
                    venue,
                    symbol: spec.venue_symbol.clone(),
                });
            }
        }
        Ok(Self {
            venue,
            market,
            by_symbol,
        })
    }

    /// Returns the venue.
    #[must_use]
    pub const fn venue(&self) -> Venue {
        self.venue
    }

    /// Returns the market.
    #[must_use]
    pub const fn market(&self) -> MarketKind {
        self.market
    }

    /// Returns the number of instruments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_symbol.len()
    }

    /// Returns `true` if no instruments are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_symbol.is_empty()
    }

    /// Iterates the venue symbols, in unspecified order.
    pub fn venue_symbols(&self) -> impl Iterator<Item = &str> {
        self.by_symbol.keys().map(String::as_str)
    }

    /// Iterates the venue symbols that want depth snapshots, in unspecified order.
    pub fn depth_symbols(&self) -> impl Iterator<Item = &str> {
        self.by_symbol
            .iter()
            .filter(|(_, entry)| entry.depth)
            .map(|(symbol, _)| symbol.as_str())
    }

    /// Looks up an instrument by venue symbol, case-insensitively.
    ///
    /// The uppercase path is exact and allocation-free; anything else is
    /// normalized through a stack buffer. Only symbols longer than
    /// `MAX_VENUE_SYMBOL` miss, and those are rejected at construction.
    #[must_use]
    pub fn lookup(&self, venue_symbol: &str) -> Option<&InstrumentEntry> {
        if let Some(entry) = self.by_symbol.get(venue_symbol) {
            return Some(entry);
        }
        if venue_symbol.len() > MAX_VENUE_SYMBOL || !venue_symbol.is_ascii() {
            return None;
        }
        let mut buf = [0_u8; MAX_VENUE_SYMBOL];
        let target = buf.get_mut(..venue_symbol.len())?;
        target.copy_from_slice(venue_symbol.as_bytes());
        target.make_ascii_uppercase();
        let normalized = core::str::from_utf8(target).ok()?;
        self.by_symbol.get(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn specs() -> Vec<InstrumentSpec> {
        vec![
            InstrumentSpec::new("BTCUSDT", MarketKind::Spot, "CRYPTO.BTC/USDT").expect("valid"),
            InstrumentSpec::new("ETHUSDT", MarketKind::Spot, "CRYPTO.ETH/USDT").expect("valid"),
        ]
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let map = InstrumentMap::new(Venue::Binance, MarketKind::Spot, &specs()).expect("valid");
        let upper = map.lookup("BTCUSDT").expect("uppercase hits");
        let lower = map.lookup("btcusdt").expect("lowercase hits");
        let mixed = map.lookup("BtcUsdT").expect("mixed case hits");
        assert_eq!(upper, lower);
        assert_eq!(upper, mixed);
        assert_eq!(upper.instrument.venue, Venue::Binance);
        assert_eq!(upper.canonical.to_string(), "CRYPTO.BTC/USDT");
    }

    #[test]
    fn unknown_symbols_miss() {
        let map = InstrumentMap::new(Venue::Binance, MarketKind::Spot, &specs()).expect("valid");
        assert!(map.lookup("SOLUSDT").is_none());
        assert!(map.lookup("").is_none());
        assert!(map.lookup(&"X".repeat(64)).is_none());
        // Non-ASCII must not panic on the normalization path.
        assert!(map.lookup("BTC€USDT").is_none());
    }

    #[test]
    fn duplicates_are_rejected_regardless_of_case() {
        let mut specs = specs();
        specs.push(
            InstrumentSpec::new("btcusdt", MarketKind::Spot, "CRYPTO.BTC/USDT").expect("valid"),
        );
        assert!(matches!(
            InstrumentMap::new(Venue::Binance, MarketKind::Spot, &specs),
            Err(IngestError::DuplicateInstrument { .. })
        ));
    }

    #[test]
    fn market_mismatch_is_rejected() {
        let specs = specs();
        assert!(matches!(
            InstrumentMap::new(Venue::Binance, MarketKind::LinearPerp, &specs),
            Err(IngestError::Config(_))
        ));
    }

    #[test]
    fn same_symbol_on_spot_and_perp_are_distinct_instruments() {
        // BTCUSDT exists on both. Keeping one map per market is what stops a
        // perpetual mark price from being mistaken for a spot quote.
        let spot = InstrumentMap::new(Venue::Binance, MarketKind::Spot, &specs()).expect("valid");
        let perp_specs = vec![
            InstrumentSpec::new(
                "BTCUSDT",
                MarketKind::LinearPerp,
                "CRYPTO.BTC/USDT.PERP_MARK",
            )
            .expect("valid"),
        ];
        let perp =
            InstrumentMap::new(Venue::Binance, MarketKind::LinearPerp, &perp_specs).expect("valid");

        let a = spot.lookup("BTCUSDT").expect("hits");
        let b = perp.lookup("BTCUSDT").expect("hits");
        assert_ne!(a.instrument, b.instrument);
        assert_ne!(a.canonical, b.canonical);
    }

    #[test]
    fn over_long_symbols_are_rejected_at_construction() {
        let specs = vec![
            InstrumentSpec::new("X".repeat(33), MarketKind::Spot, "CRYPTO.BTC/USDT")
                .expect("valid"),
        ];
        assert!(matches!(
            InstrumentMap::new(Venue::Binance, MarketKind::Spot, &specs),
            Err(IngestError::Config(_))
        ));
    }
}
