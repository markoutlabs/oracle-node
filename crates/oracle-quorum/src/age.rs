//! How old a signed frame may be (SPEC §7 step 4). The verifier, the quorum and
//! the client all read [`AgeLimits::max_age`], so the limits cannot drift apart.

use std::time::Duration;

use oracle_types::{FUNDING_HEARTBEAT, FeedKind, SLOW_HEARTBEAT};

/// Two slow heartbeats and a margin, so one lost heartbeat does not make a slow
/// feed stale.
pub const SLOW_MAX_AGE: Duration = Duration::from_secs(25);
const _: () = assert!(SLOW_MAX_AGE.as_secs() > 2 * SLOW_HEARTBEAT.as_secs());

/// How old a funding frame may be: a new subscriber gets a frame up to one heartbeat old.
pub const FUNDING_MAX_AGE: Duration = FUNDING_HEARTBEAT.saturating_mul(2);

/// A signed frame, with what its age limit depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
    /// A price update of a feed of this kind.
    Price(FeedKind),
    /// A venue report of a feed of this kind.
    VenueReport(FeedKind),
    /// A book snapshot or delta.
    Book,
    /// A funding update.
    Funding,
}

/// The two configured limits that [`AgeLimits::max_age`] picks from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgeLimits {
    /// The limit of a price feed and of a book: two of the nodes' 1 s heartbeats.
    pub max_age: Duration,
    /// The limit of a slow feed (funding, open interest), on a 10 s heartbeat.
    pub slow_max_age: Duration,
}

impl Default for AgeLimits {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(2),
            slow_max_age: SLOW_MAX_AGE,
        }
    }
}

impl AgeLimits {
    /// How old `frame` may be; a funding frame has the fixed [`FUNDING_MAX_AGE`].
    #[must_use]
    pub const fn max_age(self, frame: Frame) -> Duration {
        match frame {
            Frame::Price(kind) | Frame::VenueReport(kind) if kind.is_slow() => self.slow_max_age,
            Frame::Price(_) | Frame::VenueReport(_) | Frame::Book => self.max_age,
            Frame::Funding => FUNDING_MAX_AGE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_frame_kind_takes_its_limit() {
        let limits = AgeLimits {
            max_age: Duration::from_secs(2),
            slow_max_age: Duration::from_secs(25),
        };
        let cases = [
            (Frame::Price(FeedKind::Price), 2),
            (Frame::Price(FeedKind::PerpMark), 2),
            (Frame::Price(FeedKind::Funding8h), 25),
            (Frame::VenueReport(FeedKind::OpenInterest), 25),
            (Frame::VenueReport(FeedKind::PerpMid), 2),
            (Frame::Book, 2),
            (Frame::Funding, 120),
        ];
        for (frame, secs) in cases {
            assert_eq!(
                limits.max_age(frame),
                Duration::from_secs(secs),
                "{frame:?}"
            );
        }
    }
}
