//! The venue report: what each source of a feed showed, and how it counted.
//!
//! A price update says what the node concluded. A venue report says what it saw:
//! each venue's book, its perp data, and whether that venue went into the price.
//! It is signed like a price update, under its own payload kind.

use core::fmt;

use crate::{FeedId, MarketKind, Venue};

/// The exponent of every size in a venue report: base units, eight decimals.
pub const QTY_EXPO: i32 = -8;

/// The exponent of every funding rate in a venue report.
pub const RATE_EXPO: i32 = -9;

/// The most entries one report carries.
pub const MAX_VENUE_ENTRIES: usize = 32;

/// How one source stood in its feed's last evaluation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SourceStatus {
    /// In the price, with a weight.
    Used,
    /// Dropped as an outlier.
    Outlier,
    /// Its newest data is older than the feed's `max_age`.
    Stale,
    /// Its book is crossed.
    Crossed,
    /// No data yet, or none since its connection dropped.
    NoData,
    /// Its data cannot be priced, such as a book price of zero.
    Invalid,
    /// It had a usable quote, but the feed halted.
    FeedHalted,
}

impl SourceStatus {
    /// Every status, in wire order.
    pub const ALL: [Self; 7] = [
        Self::Used,
        Self::Outlier,
        Self::Stale,
        Self::Crossed,
        Self::NoData,
        Self::Invalid,
        Self::FeedHalted,
    ];

    /// Returns the wire-stable index. Never renumber: signed reports carry it.
    #[must_use]
    pub const fn index(self) -> u8 {
        match self {
            Self::Used => 0,
            Self::Outlier => 1,
            Self::Stale => 2,
            Self::Crossed => 3,
            Self::NoData => 4,
            Self::Invalid => 5,
            Self::FeedHalted => 6,
        }
    }

    /// Returns the status for a wire-stable index.
    #[must_use]
    pub const fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::Used),
            1 => Some(Self::Outlier),
            2 => Some(Self::Stale),
            3 => Some(Self::Crossed),
            4 => Some(Self::NoData),
            5 => Some(Self::Invalid),
            6 => Some(Self::FeedHalted),
            _ => None,
        }
    }

    /// Returns the canonical name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Used => "used",
            Self::Outlier => "outlier",
            Self::Stale => "stale",
            Self::Crossed => "crossed",
            Self::NoData => "no_data",
            Self::Invalid => "invalid",
            Self::FeedHalted => "feed_halted",
        }
    }
}

impl fmt::Display for SourceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for SourceStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|status| status.as_str() == s)
            .ok_or_else(|| format!("unknown source status `{s}`"))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SourceStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SourceStatus {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// One source of a feed, as the node last saw it.
///
/// Prices are at the report's `expo`, sizes at [`QTY_EXPO`], and funding at
/// [`RATE_EXPO`]. A field the venue does not send for this instrument is `None`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct VenueEntry {
    /// The venue.
    pub venue: Venue,
    /// Spot or perpetual.
    pub market: MarketKind,
    /// How the source counted in the last evaluation.
    pub status: SourceStatus,
    /// The source's share of the price's total weight, in basis points. Zero
    /// unless used.
    pub weight_bps: u16,
    /// The best bid.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub bid: Option<i64>,
    /// The best ask.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub ask: Option<i64>,
    /// The size at the best bid.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub bid_qty: Option<u64>,
    /// The size at the best ask.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub ask_qty: Option<u64>,
    /// The average price to sell the feed's impact notional, from our book.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub impact_bid: Option<i64>,
    /// The average price to buy the feed's impact notional, from our book.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub impact_ask: Option<i64>,
    /// The venue's perpetual mark price.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub mark: Option<i64>,
    /// The venue's perpetual index price.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub index: Option<i64>,
    /// The venue's funding rate, over the venue's own interval.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub funding: Option<i64>,
    /// The venue's own timestamp on its newest observation.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub exchange_time_ns: Option<u64>,
    /// Our receipt time of its newest observation, or `0` with no data.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub local_recv_ns: u64,
}

/// What each source of one feed showed at one instant, signed by one node.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct VenueReport {
    /// The feed.
    pub feed_id: FeedId,
    /// When the node signed this report, in unix nanoseconds.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub publish_time_ns: u64,
    /// Monotonic per `(node, feed)`, separate from the price `seq`.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub seq: u64,
    /// The decimal exponent of every price in the entries: the feed's own.
    pub expo: i32,
    /// One entry per configured source, in configuration order.
    pub entries: Vec<VenueEntry>,
}

impl VenueReport {
    /// Returns `true` if no entry claims data received after the report was signed.
    #[must_use]
    pub fn timestamps_coherent(&self) -> bool {
        self.entries
            .iter()
            .all(|entry| entry.local_recv_ns <= self.publish_time_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_round_trip_through_their_index_and_name() {
        for status in SourceStatus::ALL {
            assert_eq!(SourceStatus::from_index(status.index()), Some(status));
            assert_eq!(status.as_str().parse::<SourceStatus>(), Ok(status));
        }
        assert_eq!(SourceStatus::from_index(7), None);
    }

    #[test]
    fn market_kinds_round_trip_through_their_index() {
        for market in MarketKind::ALL {
            assert_eq!(MarketKind::from_index(market.index()), Some(market));
        }
        assert_eq!(MarketKind::from_index(3), None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_report_serializes_with_strings_and_nulls() {
        let report = VenueReport {
            feed_id: FeedId::from_bytes([1; 32]),
            publish_time_ns: 1_754_582_400_123_456_789,
            seq: 7,
            expo: -8,
            entries: vec![VenueEntry {
                venue: Venue::Kraken,
                market: MarketKind::Spot,
                status: SourceStatus::Used,
                weight_bps: 5_000,
                bid: Some(6_431_250_000_000),
                ask: Some(6_431_260_000_000),
                bid_qty: Some(150_000_000),
                ask_qty: Some(200_000_000),
                impact_bid: None,
                impact_ask: None,
                mark: None,
                index: None,
                funding: None,
                exchange_time_ns: None,
                local_recv_ns: 1_754_582_400_100_000_000,
            }],
        };
        let json = serde_json::to_string(&report).expect("serializes");
        assert!(json.contains(r#""bid":"6431250000000""#), "{json}");
        assert!(json.contains(r#""mark":null"#), "{json}");
        assert!(json.contains(r#""status":"used""#), "{json}");
        assert!(json.contains(r#""market":"spot""#), "{json}");
        let back: VenueReport = serde_json::from_str(&json).expect("parses");
        assert_eq!(back, report);
    }
}
