//! A wall clock that only moves forward.
//!
//! Receipt timestamps drive staleness, and staleness decides whether a venue
//! still counts toward a price. That makes `SystemTime::now()` unsuitable on its
//! own: NTP can step it backwards, and a backwards step makes every in-flight
//! observation appear to arrive from the future, which then reads as age zero
//! forever. The failure is silent and looks like a perfectly healthy feed.
//!
//! [`MonotonicClock`] anchors a [`SystemTime`] reading to an [`Instant`] once, at
//! construction, and derives every later reading from the monotonic elapsed time.
//! Wall-clock corrections after that point are ignored: the clock keeps its own
//! pace and never goes back.
//!
//! The cost is that a long-running process slowly drifts from true wall time by
//! whatever the monotonic clock's error is. For staleness comparisons — all
//! measured against timestamps from this same clock — that is irrelevant. It
//! matters for `publish_time_ns`, which a consumer compares against *its* clock,
//! so the node re-anchors on a schedule and only ever forward.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use oracle_types::NANOS_PER_SEC;

/// A forward-only unix-nanosecond clock.
#[derive(Debug, Clone)]
pub struct MonotonicClock {
    anchor_instant: Instant,
    anchor_unix_ns: u64,
}

impl MonotonicClock {
    /// Anchors a new clock to the current wall time.
    #[must_use]
    pub fn new() -> Self {
        Self {
            anchor_instant: Instant::now(),
            anchor_unix_ns: wall_clock_unix_nanos(),
        }
    }

    /// Anchors a clock to an explicit unix time, for tests.
    #[must_use]
    pub fn anchored_at(anchor_unix_ns: u64) -> Self {
        Self {
            anchor_instant: Instant::now(),
            anchor_unix_ns,
        }
    }

    /// Returns the current time in unix nanoseconds.
    #[must_use]
    pub fn now_ns(&self) -> u64 {
        let elapsed = self.anchor_instant.elapsed();
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        self.anchor_unix_ns.saturating_add(elapsed_ns)
    }

    /// Re-anchors to wall time, but only forwards.
    ///
    /// Returns the correction applied, in nanoseconds, or `None` if wall time was
    /// behind this clock and was therefore ignored. Call periodically to bound
    /// drift; a returned `None` is worth a metric, because it means the host's
    /// wall clock stepped backwards.
    pub fn resync(&mut self) -> Option<u64> {
        let wall = wall_clock_unix_nanos();
        let current = self.now_ns();
        let correction = wall.checked_sub(current)?;
        if correction == 0 {
            return Some(0);
        }
        self.anchor_instant = Instant::now();
        self.anchor_unix_ns = wall;
        Some(correction)
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads the host wall clock in unix nanoseconds, saturating outside the representable range.
#[must_use]
pub fn wall_clock_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Converts venue milliseconds to unix nanoseconds.
///
/// Every venue in scope reports milliseconds. Saturates rather than wrapping on
/// absurd input, so a garbage timestamp cannot become a plausible one.
#[must_use]
pub const fn millis_to_nanos(millis: u64) -> u64 {
    millis.saturating_mul(NANOS_PER_SEC / 1_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readings_are_non_decreasing() {
        let clock = MonotonicClock::new();
        let mut previous = clock.now_ns();
        for _ in 0..1_000 {
            let now = clock.now_ns();
            assert!(now >= previous, "clock went backwards: {now} < {previous}");
            previous = now;
        }
    }

    #[test]
    fn anchoring_sets_the_epoch() {
        let clock = MonotonicClock::anchored_at(1_754_582_400_000_000_000);
        let now = clock.now_ns();
        assert!(now >= 1_754_582_400_000_000_000);
        // Elapsed time between construction and reading is tiny.
        assert!(
            now - 1_754_582_400_000_000_000 < NANOS_PER_SEC,
            "drifted by {now}"
        );
    }

    #[test]
    fn resync_refuses_to_move_backwards() {
        // Anchor far in the future: real wall time is behind, so a resync must be
        // declined rather than stepping the clock back.
        let mut clock = MonotonicClock::anchored_at(u64::MAX / 2);
        let before = clock.now_ns();
        assert_eq!(
            clock.resync(),
            None,
            "resync must not move the clock backwards"
        );
        assert!(clock.now_ns() >= before);
    }

    #[test]
    fn resync_applies_a_forward_correction() {
        // Anchor in the past: wall time is ahead, so a correction is applied.
        let mut clock = MonotonicClock::anchored_at(1_000);
        let correction = clock.resync().expect("wall clock is ahead of 1970");
        assert!(correction > 0);
        assert!(clock.now_ns() > 1_000_000_000_000_000);
    }

    #[test]
    fn millisecond_conversion() {
        assert_eq!(
            millis_to_nanos(1_754_582_400_000),
            1_754_582_400_000_000_000
        );
        assert_eq!(millis_to_nanos(0), 0);
        // Absurd input saturates instead of wrapping into a plausible timestamp.
        assert_eq!(millis_to_nanos(u64::MAX), u64::MAX);
    }
}
