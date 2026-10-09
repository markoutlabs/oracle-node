//! The funding of one perpetual, as its venue states it.
//!
//! Nothing is converted. The rate is a fraction over the venue's own basis, and
//! open interest is in the venue's own unit. A reader that compares two venues
//! uses the basis, the interval and the instrument's contract terms.

use core::time::Duration;

use crate::{Fixed, MarketKind, Venue};

/// The exponent of every rate in a funding update: the precision of [`Fixed`].
pub const FUNDING_EXPO: i32 = -12;

/// The exponent of the open interest in a funding update.
pub const OPEN_INTEREST_EXPO: i32 = -8;

/// The longest time between two funding frames of one perpetual. A node sends
/// a frame on each change, at most once a second, and this often without one.
pub const FUNDING_HEARTBEAT: Duration = Duration::from_secs(60);

/// What a funding rate is a fraction of the notional over.
///
/// # Stability
///
/// The discriminants are wire codes. Add new bases at the end; never reorder.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum FundingBasis {
    /// Paid at each funding time: Binance, Bybit, OKX, Kraken Futures. The
    /// update's interval says how long a period is, when the venue sends it.
    Interval,
    /// Over an 8-hour window, whatever the payment cadence: Deribit `funding_8h`.
    EightHours,
}

impl FundingBasis {
    /// Every basis, in wire-code order.
    pub const ALL: [Self; 2] = [Self::Interval, Self::EightHours];

    /// Returns the wire code.
    #[must_use]
    pub const fn index(self) -> u8 {
        match self {
            Self::Interval => 0,
            Self::EightHours => 1,
        }
    }

    /// Returns the basis with this wire code.
    #[must_use]
    pub const fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::Interval),
            1 => Some(Self::EightHours),
            _ => None,
        }
    }

    /// Returns the canonical name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interval => "interval",
            Self::EightHours => "eight_hours",
        }
    }
}

/// The unit of a venue's open interest.
///
/// # Stability
///
/// The discriminants are wire codes. Add new units at the end; never reorder.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum OpenInterestUnit {
    /// The base asset: Bybit linear.
    Base,
    /// Contracts of the instrument's contract value: Kraken Futures.
    Contracts,
    /// The quote currency: Deribit inverse, in USD.
    Quote,
}

impl OpenInterestUnit {
    /// Every unit, in wire-code order.
    pub const ALL: [Self; 3] = [Self::Base, Self::Contracts, Self::Quote];

    /// Returns the wire code.
    #[must_use]
    pub const fn index(self) -> u8 {
        match self {
            Self::Base => 0,
            Self::Contracts => 1,
            Self::Quote => 2,
        }
    }

    /// Returns the unit with this wire code.
    #[must_use]
    pub const fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::Base),
            1 => Some(Self::Contracts),
            2 => Some(Self::Quote),
            _ => None,
        }
    }

    /// Returns the canonical name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Contracts => "contracts",
            Self::Quote => "quote",
        }
    }
}

/// The funding fields that a venue sends with its rate. A field is `None` when
/// the venue does not send it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingInfo {
    /// What the rate is a fraction over.
    pub basis: FundingBasis,
    /// The venue's prediction of the next rate.
    pub predicted: Option<Fixed>,
    /// The length of one funding period, in nanoseconds.
    pub interval_ns: Option<u64>,
    /// When the current rate is next paid, in unix nanoseconds.
    pub next_funding_time_ns: Option<u64>,
    /// The last rate that the venue settled.
    pub settled: Option<(Fixed, u64)>,
    /// The open interest, in its unit.
    pub open_interest: Option<(Fixed, OpenInterestUnit)>,
}

impl FundingInfo {
    /// Info with only the basis.
    #[must_use]
    pub const fn new(basis: FundingBasis) -> Self {
        Self {
            basis,
            predicted: None,
            interval_ns: None,
            next_funding_time_ns: None,
            settled: None,
            open_interest: None,
        }
    }
}

/// A rate that the venue settled.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct SettledFunding {
    /// The rate mantissa, at [`FUNDING_EXPO`].
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub rate: i64,
    /// When it was paid, in unix nanoseconds.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub time_ns: u64,
}

/// A venue's open interest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct OpenInterest {
    /// The amount mantissa, at [`OPEN_INTEREST_EXPO`].
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub amount: u64,
    /// The unit of the amount.
    pub unit: OpenInterestUnit,
}

/// The funding of one perpetual, signed by one node.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct FundingUpdate {
    /// The venue.
    pub venue: Venue,
    /// The perpetual's market.
    pub market: MarketKind,
    /// The venue's own symbol for the instrument, such as `BTCUSDT`.
    pub symbol: String,
    /// When the node signed this update, in unix nanoseconds.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub publish_time_ns: u64,
    /// Monotonic per `(node, instrument)`.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub seq: u64,
    /// What the rates are a fraction over.
    pub basis: FundingBasis,
    /// The current rate mantissa, at [`FUNDING_EXPO`].
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub rate: i64,
    /// The venue's prediction of the next rate.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub predicted_rate: Option<i64>,
    /// The length of one funding period, in nanoseconds.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub interval_ns: Option<u64>,
    /// When the current rate is next paid, in unix nanoseconds.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub next_funding_time_ns: Option<u64>,
    /// The last rate that the venue settled.
    pub settled: Option<SettledFunding>,
    /// The venue's open interest.
    pub open_interest: Option<OpenInterest>,
    /// The venue's own timestamp on the newest funding data, if it sends one.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::opt_num_str"))]
    pub exchange_time_ns: Option<u64>,
    /// Our receipt time of the newest funding data.
    #[cfg_attr(feature = "serde", serde(with = "crate::update::num_str"))]
    pub local_recv_ns: u64,
}

impl FundingUpdate {
    /// Returns `true` if the funding data is not dated after the signature.
    #[must_use]
    pub const fn timestamps_coherent(&self) -> bool {
        self.local_recv_ns <= self.publish_time_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_codes_round_trip() {
        for basis in FundingBasis::ALL {
            assert_eq!(FundingBasis::from_index(basis.index()), Some(basis));
        }
        for unit in OpenInterestUnit::ALL {
            assert_eq!(OpenInterestUnit::from_index(unit.index()), Some(unit));
        }
        assert_eq!(FundingBasis::from_index(2), None);
        assert_eq!(OpenInterestUnit::from_index(3), None);
    }
}
