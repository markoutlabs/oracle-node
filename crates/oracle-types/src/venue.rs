//! Exchange venues and the instruments they quote.

use core::fmt;
use core::str::FromStr;
use std::sync::Arc;

/// Errors from parsing a [`Venue`] or [`VenueSet`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VenueError {
    /// The venue name is not recognised.
    #[error("unknown venue `{0}`")]
    Unknown(String),

    /// A venue bitmap contained bits with no assigned venue.
    #[error("venue bitmap {0:#010x} has unassigned bits set")]
    UnassignedBits(u32),

    /// The text is not `venue:market:symbol`.
    #[error("`{0}` is not an instrument: give venue:market:symbol")]
    Instrument(String),
}

/// An exchange.
///
/// # Stability
///
/// The discriminants are **wire-stable**: they index the `source_bitmap` field
/// of a signed price update. Renumbering an existing venue silently reinterprets
/// every historical signature. Add new venues at the end; never reorder.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum Venue {
    /// Binance (spot and USD-margined futures).
    Binance = 0,
    /// Bybit v5 (spot and linear perpetuals).
    Bybit = 1,
    /// OKX v5 (spot and swaps).
    Okx = 2,
    /// Coinbase Advanced Trade (spot, natively USD-quoted).
    Coinbase = 3,
    /// Kraken (v2 spot, natively USD-quoted; Kraken Futures perpetuals).
    Kraken = 4,
    /// Deribit v2 (inverse and linear perpetuals; no spot in scope).
    Deribit = 5,
    /// Hyperliquid (USDC-quoted perpetuals and spot).
    Hyperliquid = 6,
    /// Bitfinex v2 (Tether spot and Tether-margined `F0` perpetuals).
    Bitfinex = 7,
    /// MEXC (spot over protobuf, and USDT-margined perpetuals in contracts).
    Mexc = 8,
    /// KuCoin (spot, and USDT-margined perpetuals in contracts; sockets open with a token).
    Kucoin = 9,
}

impl Venue {
    /// Every venue, in discriminant order.
    pub const ALL: [Self; 10] = [
        Self::Binance,
        Self::Bybit,
        Self::Okx,
        Self::Coinbase,
        Self::Kraken,
        Self::Deribit,
        Self::Hyperliquid,
        Self::Bitfinex,
        Self::Mexc,
        Self::Kucoin,
    ];

    /// Returns the wire-stable index.
    ///
    /// Written as an explicit match rather than a discriminant cast so that the
    /// numbering is stated once, in a form a reviewer can check against
    /// [`Venue::from_index`] at a glance.
    #[inline]
    #[must_use]
    pub const fn index(self) -> u8 {
        match self {
            Self::Binance => 0,
            Self::Bybit => 1,
            Self::Okx => 2,
            Self::Coinbase => 3,
            Self::Kraken => 4,
            Self::Deribit => 5,
            Self::Hyperliquid => 6,
            Self::Bitfinex => 7,
            Self::Mexc => 8,
            Self::Kucoin => 9,
        }
    }

    /// Returns this venue's bit within a [`VenueSet`].
    #[inline]
    #[must_use]
    pub const fn bit(self) -> u32 {
        1_u32 << self.index()
    }

    /// Returns the venue for a wire-stable index.
    #[must_use]
    pub const fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::Binance),
            1 => Some(Self::Bybit),
            2 => Some(Self::Okx),
            3 => Some(Self::Coinbase),
            4 => Some(Self::Kraken),
            5 => Some(Self::Deribit),
            6 => Some(Self::Hyperliquid),
            7 => Some(Self::Bitfinex),
            8 => Some(Self::Mexc),
            9 => Some(Self::Kucoin),
            _ => None,
        }
    }

    /// Returns the canonical name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Binance => "binance",
            Self::Bybit => "bybit",
            Self::Okx => "okx",
            Self::Coinbase => "coinbase",
            Self::Kraken => "kraken",
            Self::Deribit => "deribit",
            Self::Hyperliquid => "hyperliquid",
            Self::Bitfinex => "bitfinex",
            Self::Mexc => "mexc",
            Self::Kucoin => "kucoin",
        }
    }

    /// Returns `true` if this venue quotes natively in USD rather than a stablecoin.
    ///
    /// These venues are the anchor for [`crate::Symbol`]s whose quote asset is
    /// `USD`; without at least one of them live, every stablecoin-quoted price
    /// must be converted through a peg feed and carries that feed's uncertainty.
    /// Bitfinex has USD books, but a Bitfinex dollar is a balance at Bitfinex that
    /// trades about 15 bp apart from a dollar on Coinbase or Kraken.
    #[must_use]
    pub const fn quotes_native_usd(self) -> bool {
        matches!(self, Self::Coinbase | Self::Kraken)
    }
}

impl fmt::Display for Venue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Venue {
    type Err = VenueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|venue| venue.as_str() == s)
            .ok_or_else(|| VenueError::Unknown(s.to_owned()))
    }
}

/// A set of venues, encoded as the `source_bitmap` of a price update.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct VenueSet(u32);

impl VenueSet {
    /// The empty set.
    pub const EMPTY: Self = Self(0);

    /// Bits with an assigned venue.
    const ASSIGNED: u32 = {
        let mut mask = 0_u32;
        let mut i = 0;
        while i < Venue::ALL.len() {
            mask |= 1_u32 << i;
            i += 1;
        }
        mask
    };

    /// Builds a set from a raw bitmap, rejecting bits with no assigned venue.
    ///
    /// Rejecting unassigned bits is deliberate: a v1 verifier that silently
    /// ignored an unknown source bit would under-report how a price was formed.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError::UnassignedBits`] if any unknown bit is set.
    pub const fn from_bits(bits: u32) -> Result<Self, VenueError> {
        if bits & !Self::ASSIGNED != 0 {
            return Err(VenueError::UnassignedBits(bits));
        }
        Ok(Self(bits))
    }

    /// Returns the raw bitmap.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Adds a venue.
    #[inline]
    pub const fn insert(&mut self, venue: Venue) {
        self.0 |= venue.bit();
    }

    /// Returns a copy with `venue` added.
    #[inline]
    #[must_use]
    pub const fn with(mut self, venue: Venue) -> Self {
        self.insert(venue);
        self
    }

    /// Returns `true` if `venue` is in the set.
    #[inline]
    #[must_use]
    pub const fn contains(self, venue: Venue) -> bool {
        self.0 & venue.bit() != 0
    }

    /// Returns the number of venues in the set.
    #[inline]
    #[must_use]
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// Returns `true` if the set is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if any venue in the set quotes natively in USD.
    #[must_use]
    pub fn has_native_usd(self) -> bool {
        self.iter().any(Venue::quotes_native_usd)
    }

    /// Iterates the venues in the set, in discriminant order.
    pub fn iter(self) -> impl Iterator<Item = Venue> {
        Venue::ALL.into_iter().filter(move |v| self.contains(*v))
    }
}

impl FromIterator<Venue> for VenueSet {
    fn from_iter<I: IntoIterator<Item = Venue>>(iter: I) -> Self {
        iter.into_iter().fold(Self::EMPTY, Self::with)
    }
}

impl IntoIterator for VenueSet {
    type Item = Venue;
    type IntoIter = std::vec::IntoIter<Venue>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter().collect::<Vec<_>>().into_iter()
    }
}

impl fmt::Debug for VenueSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

/// Whether an instrument is spot, a linear perpetual, or an inverse perpetual.
///
/// Deliberately **not** `#[non_exhaustive]`, unlike [`Venue`]. A new venue is
/// additive — consumers that match on venue names carry on unaffected. A new
/// market kind is not: it changes which streams to subscribe to, which endpoint
/// to use, and how to price the instrument. Forcing a wildcard arm on every such
/// match would turn "we added inverse perpetuals" into a set of silent
/// mis-classifications instead of a compile error listing exactly what to fix.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum MarketKind {
    /// Spot market.
    Spot,
    /// Linear (stablecoin- or USD-margined) perpetual swap.
    ///
    /// Order sizes are in the **base** asset, like spot.
    LinearPerp,
    /// Inverse (coin-margined) perpetual swap, such as Deribit `BTC-PERPETUAL`.
    ///
    /// The price is still a quote-currency price per unit of base, so it
    /// aggregates alongside everything else. Order sizes are **not**: they are
    /// quoted in the *quote* currency, so a decoder must divide by price to
    /// report base units like every other market kind. Getting that wrong would
    /// not move any price today — `microprice` is scale-invariant within one
    /// observation and depth weighting is inert — which is exactly why it needs
    /// to be a distinct kind rather than a comment.
    InversePerp,
}

impl MarketKind {
    /// Returns the canonical name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spot => "spot",
            Self::LinearPerp => "linear_perp",
            Self::InversePerp => "inverse_perp",
        }
    }

    /// Returns `true` if this is a perpetual swap of either margining style.
    #[must_use]
    pub const fn is_perp(self) -> bool {
        matches!(self, Self::LinearPerp | Self::InversePerp)
    }

    /// Returns the wire-stable index. Never renumber: signed venue reports
    /// carry it.
    #[must_use]
    pub const fn index(self) -> u8 {
        match self {
            Self::Spot => 0,
            Self::LinearPerp => 1,
            Self::InversePerp => 2,
        }
    }

    /// Returns the market kind for a wire-stable index.
    #[must_use]
    pub const fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::Spot),
            1 => Some(Self::LinearPerp),
            2 => Some(Self::InversePerp),
            _ => None,
        }
    }
}

impl fmt::Display for MarketKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl MarketKind {
    /// Every market kind.
    pub const ALL: [Self; 3] = [Self::Spot, Self::LinearPerp, Self::InversePerp];
}

impl FromStr for MarketKind {
    type Err = VenueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|market| market.as_str() == s)
            .ok_or_else(|| VenueError::Unknown(s.to_owned()))
    }
}

/// A specific tradeable instrument on a specific venue.
///
/// The symbol is the venue's own spelling (`BTCUSDT`, `BTC-USD`, `XBT/USD`),
/// not a canonical [`crate::Symbol`]. Mapping between the two is ingest
/// configuration. Held behind an [`Arc`] so that cloning one per observation
/// costs a refcount bump rather than an allocation.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct InstrumentId {
    /// The venue quoting this instrument.
    pub venue: Venue,
    /// Spot or perpetual.
    pub market: MarketKind,
    /// The venue's own symbol for the instrument.
    pub symbol: Arc<str>,
}

impl InstrumentId {
    /// Builds an instrument identifier.
    #[must_use]
    pub fn new(venue: Venue, market: MarketKind, symbol: impl Into<Arc<str>>) -> Self {
        Self {
            venue,
            market,
            symbol: symbol.into(),
        }
    }
}

impl fmt::Display for InstrumentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.venue, self.market, self.symbol)
    }
}

/// Parses `venue:market:symbol`, the form that [`InstrumentId`] prints. The
/// symbol is the rest of the text, so it may hold a colon.
impl core::str::FromStr for InstrumentId {
    type Err = VenueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || VenueError::Instrument(s.to_owned());
        let mut parts = s.splitn(3, ':');
        let venue: Venue = parts.next().ok_or_else(invalid)?.parse()?;
        let market: MarketKind = parts.next().ok_or_else(invalid)?.parse()?;
        let symbol = parts
            .next()
            .filter(|symbol| !symbol.is_empty())
            .ok_or_else(invalid)?;
        Ok(Self::new(venue, market, symbol))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for InstrumentId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for InstrumentId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Venue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Venue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for MarketKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MarketKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for VenueSet {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for VenueSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = u32::deserialize(deserializer)?;
        Self::from_bits(bits).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks the wire-stable venue numbering. If this test needs editing, the
    /// change reinterprets the `source_bitmap` of every signature ever issued.
    #[test]
    fn venue_indices_are_wire_stable() {
        assert_eq!(Venue::Binance.index(), 0);
        assert_eq!(Venue::Bybit.index(), 1);
        assert_eq!(Venue::Okx.index(), 2);
        assert_eq!(Venue::Coinbase.index(), 3);
        assert_eq!(Venue::Kraken.index(), 4);
        assert_eq!(Venue::Deribit.index(), 5);
        assert_eq!(Venue::Hyperliquid.index(), 6);
        assert_eq!(Venue::Bitfinex.index(), 7);
        assert_eq!(Venue::Mexc.index(), 8);
        assert_eq!(Venue::Kucoin.index(), 9);
        for venue in Venue::ALL {
            assert_eq!(Venue::from_index(venue.index()), Some(venue));
        }
    }

    /// Adding a venue must only ever *widen* the set of accepted bitmaps. If a
    /// bit that used to be assigned stopped being assigned, every historical
    /// signature carrying it would become unverifiable.
    #[test]
    fn previously_assigned_bits_stay_assigned() {
        // The v1 five, as minted in the golden vectors.
        assert!(VenueSet::from_bits(0b1_1111).is_ok());
        assert_eq!(VenueSet::from_bits(0b1_1111).expect("assigned").len(), 5);
    }

    #[test]
    fn venue_set_round_trips() {
        let set: VenueSet = [Venue::Binance, Venue::Okx, Venue::Kraken]
            .into_iter()
            .collect();
        assert_eq!(set.len(), 3);
        assert!(set.contains(Venue::Okx));
        assert!(!set.contains(Venue::Bybit));
        assert_eq!(VenueSet::from_bits(set.bits()).expect("assigned bits"), set);
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            vec![Venue::Binance, Venue::Okx, Venue::Kraken]
        );
    }

    #[test]
    fn venue_set_rejects_unassigned_bits() {
        assert!(VenueSet::from_bits(1 << 31).is_err());
        // Every assigned bit, and the first one past them.
        assert!(VenueSet::from_bits(0b11_1111_1111).is_ok());
        assert!(VenueSet::from_bits(0b100_0000_0000).is_err());
    }

    #[test]
    fn native_usd_venues_are_identified() {
        assert!(Venue::Coinbase.quotes_native_usd());
        assert!(Venue::Kraken.quotes_native_usd());
        assert!(!Venue::Binance.quotes_native_usd());
        assert!(!Venue::Bitfinex.quotes_native_usd());

        let stablecoin_only: VenueSet = [Venue::Binance, Venue::Bybit, Venue::Okx]
            .into_iter()
            .collect();
        assert!(!stablecoin_only.has_native_usd());
        assert!(stablecoin_only.with(Venue::Kraken).has_native_usd());
    }

    #[test]
    fn market_name_round_trips() {
        for market in MarketKind::ALL {
            assert_eq!(
                market.as_str().parse::<MarketKind>().expect("known"),
                market
            );
        }
        assert!("futures".parse::<MarketKind>().is_err());
    }

    #[test]
    fn venue_name_round_trips() {
        for venue in Venue::ALL {
            assert_eq!(venue.as_str().parse::<Venue>().expect("known"), venue);
        }
        assert!("ftx".parse::<Venue>().is_err());
    }

    #[test]
    fn instrument_names_round_trip() {
        let instrument = InstrumentId::new(Venue::Okx, MarketKind::LinearPerp, "BTC-USDT-SWAP");
        assert_eq!(instrument.to_string().parse(), Ok(instrument));
        let colon = InstrumentId::new(Venue::Kraken, MarketKind::Spot, "BTC:USD");
        assert_eq!(
            colon.to_string().parse(),
            Ok(colon),
            "the symbol keeps its colon"
        );
        for bad in [
            "binance:spot:",
            "nowhere:spot:BTC",
            "binance:BTC",
            "",
            "binance",
        ] {
            assert!(bad.parse::<InstrumentId>().is_err(), "{bad}");
        }
    }
}
