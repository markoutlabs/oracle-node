//! Feed identity: canonical symbols and the 32-byte IDs derived from them.
//!
//! A [`Symbol`] is parsed, not validated — there is no way to hold one in a
//! non-canonical form. That property is what makes deriving a [`FeedId`] by
//! hashing safe: two independent implementations that agree on the grammar
//! necessarily agree on every feed ID, with no registry to coordinate.

use core::fmt::{self, Write as _};
use core::str::FromStr;

/// Maximum length of an asset code such as `BTC` or `1000PEPE`.
pub const MAX_ASSET_CODE_LEN: usize = 16;

/// Capacity of [`SymbolBuf`], comfortably above the longest legal symbol.
const SYMBOL_BUF_CAPACITY: usize = 64;

/// Errors from parsing a [`Symbol`], [`AssetCode`], or [`FeedId`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SymbolError {
    /// The symbol did not match `<CLASS>.<BASE>/<QUOTE>[.<KIND>]`.
    #[error("malformed symbol `{0}`, expected <CLASS>.<BASE>/<QUOTE>[.<KIND>]")]
    Malformed(String),

    /// The asset class is not recognised.
    #[error("unknown asset class `{0}`")]
    UnknownClass(String),

    /// The feed kind is not recognised.
    #[error("unknown feed kind `{0}`")]
    UnknownKind(String),

    /// An asset code was empty, too long, or contained illegal characters.
    #[error("invalid asset code `{0}`: must be 1-16 chars of A-Z and 0-9 with at least one letter")]
    InvalidAssetCode(String),

    /// A feed ID was not 32 bytes of hex.
    #[error("invalid feed id `{0}`: expected 32 bytes of hex")]
    InvalidFeedId(String),
}

/// A short uppercase asset code such as `BTC`, `USD`, or `1000PEPE`.
///
/// Fixed-size and `Copy`, so a [`Symbol`] never allocates.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetCode {
    bytes: [u8; MAX_ASSET_CODE_LEN],
    len: u8,
}

impl AssetCode {
    /// Parses an asset code.
    ///
    /// Legal codes are 1 to 16 characters of `A`-`Z` and `0`-`9`, containing at
    /// least one letter. The letter requirement rejects codes that would be
    /// ambiguous with a numeric field while still admitting the meme-token
    /// convention of a numeric multiplier prefix, as in `1000PEPE`.
    ///
    /// # Errors
    ///
    /// Returns [`SymbolError::InvalidAssetCode`] if the input violates the above.
    pub fn new(code: &str) -> Result<Self, SymbolError> {
        let raw = code.as_bytes();
        let invalid = || SymbolError::InvalidAssetCode(code.to_owned());
        if raw.is_empty() || raw.len() > MAX_ASSET_CODE_LEN {
            return Err(invalid());
        }
        let mut has_letter = false;
        for &byte in raw {
            match byte {
                b'A'..=b'Z' => has_letter = true,
                b'0'..=b'9' => {}
                _ => return Err(invalid()),
            }
        }
        if !has_letter {
            return Err(invalid());
        }
        let mut bytes = [0_u8; MAX_ASSET_CODE_LEN];
        bytes
            .get_mut(..raw.len())
            .ok_or_else(invalid)?
            .copy_from_slice(raw);
        let len = u8::try_from(raw.len()).map_err(|_| invalid())?;
        Ok(Self { bytes, len })
    }

    /// Returns the code as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        let len = usize::from(self.len);
        let slice = self.bytes.get(..len).unwrap_or(&[]);
        // Every byte was validated as ASCII alphanumeric at construction.
        core::str::from_utf8(slice).unwrap_or("")
    }
}

impl fmt::Display for AssetCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for AssetCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AssetCode({})", self.as_str())
    }
}

impl FromStr for AssetCode {
    type Err = SymbolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// The asset class of a feed.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum AssetClass {
    /// Digital assets.
    Crypto,
}

impl AssetClass {
    /// Returns the canonical wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Crypto => "CRYPTO",
        }
    }
}

impl fmt::Display for AssetClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AssetClass {
    type Err = SymbolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CRYPTO" => Ok(Self::Crypto),
            other => Err(SymbolError::UnknownClass(other.to_owned())),
        }
    }
}

/// What quantity a feed reports about its instrument.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[non_exhaustive]
pub enum FeedKind {
    /// Composite spot price. Omitted from the canonical symbol.
    #[default]
    Price,
    /// Composite perpetual mark price.
    PerpMark,
    /// Composite perpetual index price.
    PerpIndex,
    /// Composite perpetual mid, priced from the perps' own books. A mark is each
    /// venue's own formula; this is where the perps actually trade.
    PerpMid,
    /// Funding rate, normalised to an 8-hour interval, as a fraction.
    Funding8h,
    /// Aggregate open interest, in base-asset units.
    OpenInterest,
}

impl FeedKind {
    /// Returns the canonical suffix, or `None` for [`FeedKind::Price`], which is
    /// spelled by omission.
    #[must_use]
    pub const fn suffix(self) -> Option<&'static str> {
        match self {
            Self::Price => None,
            Self::PerpMark => Some("PERP_MARK"),
            Self::PerpIndex => Some("PERP_INDEX"),
            Self::PerpMid => Some("PERP_MID"),
            Self::Funding8h => Some("FUNDING_8H"),
            Self::OpenInterest => Some("OPEN_INTEREST"),
        }
    }

    /// Returns the decimal exponent this kind publishes at.
    ///
    /// Funding rates get three extra digits because they are small fractions:
    /// one basis point is `0.0001`, and at exponent `-8` that leaves only four
    /// significant digits.
    #[must_use]
    pub const fn default_expo(self) -> i32 {
        match self {
            Self::Price | Self::PerpMark | Self::PerpIndex | Self::PerpMid | Self::OpenInterest => {
                -8
            }
            Self::Funding8h => -9,
        }
    }
}

impl FromStr for FeedKind {
    type Err = SymbolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PERP_MARK" => Ok(Self::PerpMark),
            "PERP_INDEX" => Ok(Self::PerpIndex),
            "PERP_MID" => Ok(Self::PerpMid),
            "FUNDING_8H" => Ok(Self::Funding8h),
            "OPEN_INTEREST" => Ok(Self::OpenInterest),
            other => Err(SymbolError::UnknownKind(other.to_owned())),
        }
    }
}

/// A stack-allocated rendering of a canonical symbol.
///
/// Exists so that hashing a symbol into a [`FeedId`] costs no allocation.
#[derive(Clone, Copy)]
pub struct SymbolBuf {
    bytes: [u8; SYMBOL_BUF_CAPACITY],
    len: usize,
}

impl SymbolBuf {
    /// Returns the rendered symbol.
    #[must_use]
    pub fn as_str(&self) -> &str {
        let slice = self.bytes.get(..self.len).unwrap_or(&[]);
        core::str::from_utf8(slice).unwrap_or("")
    }

    /// Returns the rendered symbol as bytes, ready to hash.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

impl fmt::Write for SymbolBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len.checked_add(s.len()).ok_or(fmt::Error)?;
        let target = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        target.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

impl core::ops::Deref for SymbolBuf {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

/// A parsed, canonical feed symbol.
///
/// # Examples
///
/// ```
/// use oracle_types::{FeedKind, Symbol};
///
/// let spot: Symbol = "CRYPTO.BTC/USD".parse()?;
/// assert_eq!(spot.kind(), FeedKind::Price);
/// assert_eq!(spot.to_string(), "CRYPTO.BTC/USD");
///
/// let mark: Symbol = "CRYPTO.BTC/USD.PERP_MARK".parse()?;
/// assert_eq!(mark.kind(), FeedKind::PerpMark);
/// assert_ne!(spot, mark);
/// # Ok::<(), oracle_types::SymbolError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Symbol {
    class: AssetClass,
    base: AssetCode,
    quote: AssetCode,
    kind: FeedKind,
}

impl Symbol {
    /// Builds a symbol from already-parsed components.
    #[must_use]
    pub const fn new(class: AssetClass, base: AssetCode, quote: AssetCode, kind: FeedKind) -> Self {
        Self {
            class,
            base,
            quote,
            kind,
        }
    }

    /// Returns the asset class.
    #[must_use]
    pub const fn class(&self) -> AssetClass {
        self.class
    }

    /// Returns the base asset.
    #[must_use]
    pub const fn base(&self) -> AssetCode {
        self.base
    }

    /// Returns the quote asset.
    #[must_use]
    pub const fn quote(&self) -> AssetCode {
        self.quote
    }

    /// Returns the feed kind.
    #[must_use]
    pub const fn kind(&self) -> FeedKind {
        self.kind
    }

    /// Returns the exponent this feed publishes at.
    #[must_use]
    pub const fn expo(&self) -> i32 {
        self.kind.default_expo()
    }

    /// Renders the canonical symbol into a stack buffer.
    ///
    /// # Panics
    ///
    /// Cannot panic: the buffer is sized above the longest symbol the grammar
    /// admits (two 16-character asset codes plus the longest class and kind).
    #[must_use]
    pub fn canonical(&self) -> SymbolBuf {
        let mut buf = SymbolBuf {
            bytes: [0_u8; SYMBOL_BUF_CAPACITY],
            len: 0,
        };
        let _ = write!(buf, "{self}");
        buf
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}/{}", self.class.as_str(), self.base, self.quote)?;
        if let Some(suffix) = self.kind.suffix() {
            write!(f, ".{suffix}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Symbol({self})")
    }
}

impl FromStr for Symbol {
    type Err = SymbolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let malformed = || SymbolError::Malformed(s.to_owned());
        let (class_str, rest) = s.split_once('.').ok_or_else(malformed)?;
        let (base_str, tail) = rest.split_once('/').ok_or_else(malformed)?;
        let (quote_str, kind_str) = match tail.split_once('.') {
            Some((quote, kind)) => (quote, Some(kind)),
            None => (tail, None),
        };

        let class: AssetClass = class_str.parse()?;
        let base = AssetCode::new(base_str)?;
        let quote = AssetCode::new(quote_str)?;
        let kind = match kind_str {
            Some(k) => k.parse()?,
            None => FeedKind::Price,
        };
        Ok(Self {
            class,
            base,
            quote,
            kind,
        })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Symbol {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Symbol {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// A 32-byte feed identifier.
///
/// Derived as `keccak256(canonical_symbol)`. The derivation itself lives in
/// `oracle-wire` so that this crate stays free of cryptographic dependencies.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct FeedId([u8; 32]);

impl FeedId {
    /// Wraps 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for FeedId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for FeedId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FeedId({self})")
    }
}

impl fmt::LowerHex for FeedId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for FeedId {
    type Err = SymbolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let body = s.strip_prefix("0x").unwrap_or(s);
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(body, &mut bytes)
            .map_err(|_| SymbolError::InvalidFeedId(s.to_owned()))?;
        Ok(Self(bytes))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for FeedId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for FeedId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spot_and_kinded_symbols() {
        let spot: Symbol = "CRYPTO.BTC/USD".parse().expect("valid");
        assert_eq!(spot.class(), AssetClass::Crypto);
        assert_eq!(spot.base().as_str(), "BTC");
        assert_eq!(spot.quote().as_str(), "USD");
        assert_eq!(spot.kind(), FeedKind::Price);

        let funding: Symbol = "CRYPTO.BTC/USD.FUNDING_8H".parse().expect("valid");
        assert_eq!(funding.kind(), FeedKind::Funding8h);
        assert_eq!(funding.expo(), -9);
    }

    #[test]
    fn display_round_trips_through_parse() {
        for text in [
            "CRYPTO.BTC/USD",
            "CRYPTO.ETH/USD.PERP_MARK",
            "CRYPTO.1000PEPE/USDT.PERP_INDEX",
            "CRYPTO.BTC/USDT.PERP_MID",
            "CRYPTO.USDT/USD",
            "CRYPTO.SOL/USD.OPEN_INTEREST",
        ] {
            let symbol: Symbol = text.parse().expect("valid");
            assert_eq!(symbol.to_string(), text);
            assert_eq!(symbol.canonical().as_str(), text);
            assert_eq!(text.parse::<Symbol>().expect("valid"), symbol);
        }
    }

    #[test]
    fn rejects_non_canonical_and_malformed_symbols() {
        for text in [
            "crypto.btc/usd",     // lowercase
            "CRYPTO.BTC-USD",     // wrong separator
            "BTC/USD",            // missing class
            "CRYPTO.BTC/USD.FOO", // unknown kind
            "EQUITY.AAPL/USD",    // unknown class
            "CRYPTO./USD",        // empty base
            "CRYPTO.BTC/",        // empty quote
            "CRYPTO.123/USD",     // digits only
            "CRYPTO.VERYLONGASSETCODE1/USD",
        ] {
            assert!(text.parse::<Symbol>().is_err(), "should reject {text:?}");
        }
    }

    #[test]
    fn kind_changes_identity() {
        let spot: Symbol = "CRYPTO.BTC/USD".parse().expect("valid");
        let mark: Symbol = "CRYPTO.BTC/USD.PERP_MARK".parse().expect("valid");
        assert_ne!(spot, mark);
        assert_ne!(spot.canonical().as_str(), mark.canonical().as_str());
    }

    #[test]
    fn feed_id_hex_round_trips() {
        let id = FeedId::from_bytes([0xAB; 32]);
        let text = id.to_string();
        assert!(text.starts_with("0x"));
        assert_eq!(text.parse::<FeedId>().expect("valid"), id);
        // The 0x prefix is optional on input.
        assert_eq!(
            hex::encode([0xAB_u8; 32]).parse::<FeedId>().expect("valid"),
            id
        );
    }

    #[test]
    fn asset_code_boundaries() {
        assert!(AssetCode::new("B").is_ok());
        assert!(AssetCode::new("ABCDEFGHIJKLMNOP").is_ok()); // exactly 16
        assert!(AssetCode::new("ABCDEFGHIJKLMNOPQ").is_err()); // 17
        assert!(AssetCode::new("1000PEPE").is_ok());
        assert!(AssetCode::new("").is_err());
        assert!(AssetCode::new("BTC ").is_err());
        assert!(AssetCode::new("btc").is_err());
    }
}
