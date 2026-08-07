//! A single venue's view of a single instrument at a single instant.

use core::fmt;

use crate::{Fixed, InstrumentId, Venue};

/// What an [`Observation`] reports.
///
/// Exhaustive for the same reason as [`crate::MarketKind`]: aggregation must make
/// a deliberate decision for every kind, and a wildcard arm would quietly drop a
/// new one out of the price rather than failing to compile.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum ObsKind {
    /// Best bid and offer.
    BookTop,
    /// A trade print.
    Trade,
    /// A venue-computed perpetual mark price.
    MarkPrice,
    /// A venue-computed perpetual index price.
    IndexPrice,
    /// A funding rate, as a fraction over the venue's own interval.
    Funding,
    /// Open interest, in base-asset units.
    OpenInterest,
}

impl ObsKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::BookTop,
        Self::Trade,
        Self::MarkPrice,
        Self::IndexPrice,
        Self::Funding,
        Self::OpenInterest,
    ];

    /// Number of kinds. Sizes the per-venue latest-observation slots.
    pub const COUNT: usize = Self::ALL.len();

    /// Returns a dense index in `0..COUNT`, for array-backed lookups.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::BookTop => 0,
            Self::Trade => 1,
            Self::MarkPrice => 2,
            Self::IndexPrice => 3,
            Self::Funding => 4,
            Self::OpenInterest => 5,
        }
    }

    /// Returns `true` if this kind carries a two-sided book.
    #[must_use]
    pub const fn has_book(self) -> bool {
        matches!(self, Self::BookTop)
    }

    /// Returns the canonical name, suitable as a metrics label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BookTop => "book_top",
            Self::Trade => "trade",
            Self::MarkPrice => "mark_price",
            Self::IndexPrice => "index_price",
            Self::Funding => "funding",
            Self::OpenInterest => "open_interest",
        }
    }
}

impl fmt::Display for ObsKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One venue's observation of one instrument.
///
/// # Timestamps
///
/// There are two, and they are not interchangeable. [`Observation::local_recv_ns`]
/// is stamped by us on receipt and is the **only** timestamp that may drive a
/// staleness decision. [`Observation::exchange_time_ns`] is whatever the venue
/// claimed; venue clocks skew, jump, and during incidents lie outright, so it is
/// kept for measuring venue lag and for diagnostics, never for control flow.
///
/// It is optional because some feeds genuinely do not carry one — Binance's spot
/// `bookTicker` stream, for instance, sends only the update id and the quote.
/// Modelling that as `0` would have made a missing timestamp indistinguishable
/// from the unix epoch and turned every such observation into a fake 55-year
/// venue lag in the metrics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// The instrument observed.
    pub instrument: InstrumentId,
    /// What is being reported.
    pub kind: ObsKind,
    /// The primary value: trade price, mark, index, funding rate, or open interest.
    pub price: Fixed,
    /// Best bid, when the kind carries a book.
    pub bid: Option<Fixed>,
    /// Best offer, when the kind carries a book.
    pub ask: Option<Fixed>,
    /// Size resting at the best bid.
    pub bid_qty: Option<Fixed>,
    /// Size resting at the best offer.
    pub ask_qty: Option<Fixed>,
    /// Notional resting within one basis point of mid, the liquidity weight input.
    pub depth_notional_1bp: Option<Fixed>,
    /// The venue's own timestamp, when it supplies one. Diagnostics only — see
    /// the type documentation.
    pub exchange_time_ns: Option<u64>,
    /// Our receipt timestamp. Authoritative for staleness.
    pub local_recv_ns: u64,
    /// The venue's sequence number, where it provides one, for gap detection.
    pub seq: Option<u64>,
}

impl Observation {
    /// Returns the venue that produced this observation.
    #[must_use]
    pub const fn venue(&self) -> Venue {
        self.instrument.venue
    }

    /// Returns the arithmetic mid, if both sides are present.
    #[must_use]
    pub fn mid(&self) -> Option<Fixed> {
        let (bid, ask) = (self.bid?, self.ask?);
        bid.checked_add(ask)?.checked_div(Fixed::from_int(2).ok()?)
    }

    /// Returns the size-weighted microprice, if both sides and both sizes are present.
    ///
    /// `(bid · ask_qty + ask · bid_qty) / (bid_qty + ask_qty)`
    ///
    /// Weighting each side by the *opposite* size leans the price toward whichever
    /// side is thinner, which is where the next trade is more likely to print. On a
    /// balanced book it equals the mid; on a one-sided book it degrades far more
    /// gracefully than the mid, which quietly becomes fiction.
    #[must_use]
    pub fn microprice(&self) -> Option<Fixed> {
        let (bid, ask) = (self.bid?, self.ask?);
        let (bid_qty, ask_qty) = (self.bid_qty?, self.ask_qty?);
        let total = bid_qty.checked_add(ask_qty)?;
        if !total.is_positive() {
            return None;
        }
        let weighted = bid
            .checked_mul(ask_qty)?
            .checked_add(ask.checked_mul(bid_qty)?)?;
        weighted.checked_div(total)
    }

    /// Returns `ask - bid`, if both sides are present.
    #[must_use]
    pub fn spread(&self) -> Option<Fixed> {
        self.ask?.checked_sub(self.bid?)
    }

    /// Returns the spread in basis points of mid, if both sides are present.
    #[must_use]
    pub fn spread_bps(&self) -> Option<Fixed> {
        self.spread()?.to_bps_of(self.mid()?)
    }

    /// Returns `true` if the book is crossed or locked inside-out.
    ///
    /// A crossed top-of-book means the venue's feed is inconsistent — usually a
    /// dropped sequence or a partial update. Such an observation must be dropped,
    /// never repaired.
    #[must_use]
    pub fn is_crossed(&self) -> bool {
        match (self.bid, self.ask) {
            (Some(bid), Some(ask)) => bid > ask,
            _ => false,
        }
    }

    /// Returns how long ago this observation was received, in nanoseconds.
    ///
    /// Saturates at zero for timestamps in the future rather than wrapping.
    #[must_use]
    pub const fn age_ns(&self, now_ns: u64) -> u64 {
        now_ns.saturating_sub(self.local_recv_ns)
    }

    /// Returns `true` if this observation is older than `max_age_ns`.
    #[must_use]
    pub const fn is_stale(&self, now_ns: u64, max_age_ns: u64) -> bool {
        self.age_ns(now_ns) > max_age_ns
    }

    /// Returns the venue's reporting lag: how far its own clock trails ours.
    ///
    /// Diagnostics only, and `None` when the venue supplies no timestamp. A large
    /// or negative value indicates venue clock skew, not necessarily a stale
    /// feed. Saturates rather than wrapping.
    #[must_use]
    pub fn venue_lag_ns(&self) -> Option<i64> {
        let exchange_time_ns = self.exchange_time_ns?;
        Some(if self.local_recv_ns >= exchange_time_ns {
            i64::try_from(self.local_recv_ns - exchange_time_ns).unwrap_or(i64::MAX)
        } else {
            i64::try_from(exchange_time_ns - self.local_recv_ns).map_or(i64::MIN, i64::wrapping_neg)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MarketKind;

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("valid decimal")
    }

    fn book(bid: &str, ask: &str, bid_qty: &str, ask_qty: &str) -> Observation {
        Observation {
            instrument: InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT"),
            kind: ObsKind::BookTop,
            price: fixed(bid),
            bid: Some(fixed(bid)),
            ask: Some(fixed(ask)),
            bid_qty: Some(fixed(bid_qty)),
            ask_qty: Some(fixed(ask_qty)),
            depth_notional_1bp: None,
            exchange_time_ns: Some(1_000),
            local_recv_ns: 2_000,
            seq: None,
        }
    }

    #[test]
    fn kind_indices_are_dense_and_unique() {
        for (position, kind) in ObsKind::ALL.into_iter().enumerate() {
            assert_eq!(kind.index(), position);
        }
        assert_eq!(ObsKind::COUNT, 6);
    }

    #[test]
    fn mid_is_the_arithmetic_average() {
        let obs = book("100", "102", "1", "1");
        assert_eq!(obs.mid(), Some(fixed("101")));
    }

    #[test]
    fn microprice_equals_mid_on_a_balanced_book() {
        let obs = book("100", "102", "5", "5");
        assert_eq!(obs.microprice(), obs.mid());
    }

    #[test]
    fn microprice_leans_toward_the_thin_side() {
        // Heavy bid, thin ask: the next print is more likely to lift the offer,
        // so the microprice should sit above the mid.
        let obs = book("100", "102", "9", "1");
        let (micro, mid) = (obs.microprice().expect("book"), obs.mid().expect("book"));
        assert!(micro > mid, "{micro} should exceed {mid}");
        assert_eq!(micro, fixed("101.8"));
    }

    #[test]
    fn spread_and_bps() {
        let obs = book("99.99", "100.01", "1", "1");
        assert_eq!(obs.spread(), Some(fixed("0.02")));
        assert_eq!(obs.spread_bps().expect("book").to_string(), "2");
    }

    #[test]
    fn crossed_books_are_detected() {
        assert!(book("102", "100", "1", "1").is_crossed());
        assert!(!book("100", "102", "1", "1").is_crossed());
        // A locked book (bid == ask) is odd but not inconsistent.
        assert!(!book("100", "100", "1", "1").is_crossed());
    }

    #[test]
    fn staleness_uses_local_receipt_and_saturates() {
        let obs = book("100", "102", "1", "1");
        assert_eq!(obs.age_ns(5_000), 3_000);
        assert!(obs.is_stale(5_000, 1_000));
        assert!(!obs.is_stale(5_000, 10_000));
        // A receipt timestamp "in the future" reports zero age, never a huge one.
        assert_eq!(obs.age_ns(0), 0);
    }

    #[test]
    fn missing_book_sides_yield_no_derived_prices() {
        let mut obs = book("100", "102", "1", "1");
        obs.ask = None;
        assert_eq!(obs.mid(), None);
        assert_eq!(obs.microprice(), None);
        assert_eq!(obs.spread(), None);
        assert!(!obs.is_crossed());
    }

    #[test]
    fn venue_lag_is_absent_when_the_venue_supplies_no_timestamp() {
        let mut obs = book("100", "102", "1", "1");
        assert_eq!(obs.venue_lag_ns(), Some(1_000));
        // Binance spot bookTicker carries no event time.
        obs.exchange_time_ns = None;
        assert_eq!(obs.venue_lag_ns(), None);
        // Staleness is unaffected: it never consults the venue clock.
        assert_eq!(obs.age_ns(5_000), 3_000);
    }

    #[test]
    fn zero_total_size_yields_no_microprice() {
        let obs = book("100", "102", "0", "0");
        assert_eq!(obs.microprice(), None);
    }
}
