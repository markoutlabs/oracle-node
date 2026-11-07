//! A wall clock that never goes back.
//!
//! Receipt timestamps drive staleness, and staleness decides whether a venue
//! still counts toward a price. That makes `SystemTime::now()` unsuitable on its
//! own: NTP can step it backwards, and a backwards step makes every in-flight
//! observation appear to arrive from the future, which then reads as age zero
//! forever. The failure is silent and looks like a perfectly healthy feed.
//!
//! [`MonotonicClock`] anchors a [`SystemTime`] reading to an [`Instant`], and
//! derives every later reading from the monotonic elapsed time. Clones share the
//! anchor, so every part of a node reads one clock.
//!
//! The monotonic clock drifts from wall time: about 1.4 ms a minute on one macOS
//! machine (measured 2026-10-07). A consumer compares `publish_time_ns` with
//! *its* wall clock, so the node calls [`MonotonicClock::resync`] every second.
//! A clock behind wall time steps forward. A clock ahead of it runs slow until
//! it matches, because a step back would date the next update before the last.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use oracle_types::NANOS_PER_SEC;

/// While the clock gives back a lead, it loses one nanosecond in this many: it
/// runs at 90% speed.
const SLEW_DIVISOR: u64 = 10;

/// A unix-nanosecond clock that never goes back.
#[derive(Debug, Clone)]
pub struct MonotonicClock {
    source: Source,
}

#[derive(Debug, Clone)]
enum Source {
    /// Real time, derived from the monotonic clock since the last anchor.
    Anchored(Arc<Anchored>),
    /// Whatever a replay driver last stored. Never advances on its own.
    Driven(Arc<AtomicU64>),
}

/// Readers load the anchor without a lock. A reader that loaded the anchor
/// just before a resync can run ahead of the new one, so `floor` keeps every
/// reading at or above the last.
#[derive(Debug)]
struct Anchored {
    anchor: ArcSwap<Anchor>,
    floor: AtomicU64,
}

impl Anchored {
    fn new(anchor: Anchor) -> Self {
        Self {
            floor: AtomicU64::new(anchor.unix_ns),
            anchor: ArcSwap::from_pointee(anchor),
        }
    }

    fn now_ns(&self) -> u64 {
        let reading = self.anchor.load().read(Instant::now());
        // Most readings are above the floor's last value by now: a plain load
        // first keeps the shared write rare.
        let floor = self.floor.load(Ordering::Acquire);
        if reading <= floor {
            return floor;
        }
        self.floor.fetch_max(reading, Ordering::AcqRel).max(reading)
    }
}

#[derive(Debug, Clone, Copy)]
struct Anchor {
    instant: Instant,
    unix_ns: u64,
    /// How far the clock was ahead of wall time at the anchor.
    lead_ns: u64,
}

impl Anchor {
    fn read(&self, at: Instant) -> u64 {
        let elapsed = at.saturating_duration_since(self.instant);
        slewed(
            self.unix_ns,
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
            self.lead_ns,
        )
    }
}

/// The reading `elapsed_ns` after an anchor at `unix_ns`, while the clock gives
/// back `lead_ns`.
const fn slewed(unix_ns: u64, elapsed_ns: u64, lead_ns: u64) -> u64 {
    let slow_by = elapsed_ns / SLEW_DIVISOR;
    let given_back = if lead_ns < slow_by { lead_ns } else { slow_by };
    unix_ns.saturating_add(elapsed_ns.saturating_sub(given_back))
}

/// What [`MonotonicClock::resync`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resync {
    /// Wall time was ahead by this many nanoseconds. The clock stepped forward.
    Stepped(u64),
    /// Wall time was behind by this many nanoseconds. The clock runs slow until
    /// it has given them back.
    Slewing(u64),
}

impl MonotonicClock {
    /// Anchors a new clock to the current wall time.
    #[must_use]
    pub fn new() -> Self {
        Self::anchored_at(wall_clock_unix_nanos())
    }

    /// Anchors a clock to an explicit unix time, for tests.
    #[must_use]
    pub fn anchored_at(anchor_unix_ns: u64) -> Self {
        Self {
            source: Source::Anchored(Arc::new(Anchored::new(Anchor {
                instant: Instant::now(),
                unix_ns: anchor_unix_ns,
                lead_ns: 0,
            }))),
        }
    }

    /// A clock that reads whatever `source` holds, for replay.
    ///
    /// A replaying transport stores each frame's recorded receipt time just
    /// before it hands the frame over, so the session stamps the observation
    /// with the time it was really received. Clones share the source. This only
    /// stays coherent on a single-threaded runtime, where nothing runs between
    /// the transport returning and the session reading the clock.
    #[must_use]
    pub fn driven(source: Arc<AtomicU64>) -> Self {
        Self {
            source: Source::Driven(source),
        }
    }

    /// Returns the current time in unix nanoseconds.
    #[must_use]
    pub fn now_ns(&self) -> u64 {
        match &self.source {
            Source::Anchored(anchored) => anchored.now_ns(),
            Source::Driven(source) => source.load(Ordering::Acquire),
        }
    }

    /// Re-anchors this clock and every clone to wall time, without going back.
    ///
    /// A large [`Resync::Slewing`] is worth a warning: the host wall clock
    /// stepped back.
    #[must_use = "a large correction means the host clock stepped"]
    pub fn resync(&self) -> Resync {
        let Source::Anchored(anchored) = &self.source else {
            // A driven clock belongs to a replay. Wall time means nothing to it.
            return Resync::Stepped(0);
        };
        let mut resync = Resync::Stepped(0);
        anchored.anchor.rcu(|anchor| {
            let at = Instant::now();
            let wall = wall_clock_unix_nanos();
            let current = anchor.read(at);
            let (unix_ns, lead_ns, outcome) = match wall.checked_sub(current) {
                Some(behind) => (wall, 0, Resync::Stepped(behind)),
                None => {
                    let lead = current.saturating_sub(wall);
                    (current, lead, Resync::Slewing(lead))
                }
            };
            resync = outcome;
            Anchor {
                instant: at,
                unix_ns,
                lead_ns,
            }
        });
        resync
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
        // 2025-08-07T16:00:00Z.
        const ANCHOR_NS: u64 = 1_754_582_400_000_000_000;
        let clock = MonotonicClock::anchored_at(ANCHOR_NS);
        let now = clock.now_ns();
        assert!(now >= ANCHOR_NS);
        // Elapsed time between construction and reading is tiny.
        assert!(now - ANCHOR_NS < NANOS_PER_SEC, "drifted by {now}");
    }

    #[test]
    fn a_driven_clock_reads_what_the_driver_stored() {
        let source = Arc::new(AtomicU64::new(5));
        let clock = MonotonicClock::driven(Arc::clone(&source));
        assert_eq!(clock.now_ns(), 5);
        source.store(9, Ordering::Release);
        assert_eq!(clock.clone().now_ns(), 9, "clones share the source");
    }

    #[test]
    fn a_slewing_clock_gives_back_its_lead_at_a_tenth_of_real_time() {
        assert_eq!(slewed(1_000, 0, 50), 1_000);
        assert_eq!(slewed(1_000, 100, 50), 1_090);
        assert_eq!(slewed(1_000, 500, 50), 1_450);
        assert_eq!(
            slewed(1_000, 1_000, 50),
            1_950,
            "the lead is all given back"
        );
        let mut previous = 0;
        for elapsed in 0..2_000 {
            let reading = slewed(1_000, elapsed, 50);
            assert!(reading >= previous, "went back at {elapsed}");
            previous = reading;
        }
    }

    #[test]
    fn a_clock_ahead_of_wall_time_slews_and_never_goes_back() {
        let clock = MonotonicClock::anchored_at(wall_clock_unix_nanos() + 10 * NANOS_PER_SEC);
        let before = clock.now_ns();
        let resync = clock.resync();
        assert!(
            matches!(resync, Resync::Slewing(lead) if lead > 9 * NANOS_PER_SEC),
            "{resync:?}"
        );
        assert!(clock.now_ns() >= before);
    }

    #[test]
    fn resync_steps_a_clock_behind_wall_time_forward() {
        let clock = MonotonicClock::anchored_at(1_000);
        assert!(matches!(clock.resync(), Resync::Stepped(step) if step > 0));
        assert!(clock.now_ns() > 1_000_000_000_000_000_000);
    }

    /// Readers on other threads never see the clock go back, while the
    /// anchor changes under them.
    #[test]
    fn readers_on_many_threads_never_go_back_across_resyncs() {
        const READERS: usize = 4;
        const READS: usize = 20_000;
        const RESYNCS: usize = 2_000;
        // Ahead of wall time, so each resync slews and moves the anchor back.
        let clock = MonotonicClock::anchored_at(wall_clock_unix_nanos() + 10 * NANOS_PER_SEC);
        std::thread::scope(|scope| {
            for _ in 0..READERS {
                let clock = clock.clone();
                scope.spawn(move || {
                    let mut previous = clock.now_ns();
                    for _ in 0..READS {
                        let now = clock.now_ns();
                        assert!(now >= previous, "went back: {now} < {previous}");
                        previous = now;
                    }
                });
            }
            for _ in 0..RESYNCS {
                let _ = clock.resync();
            }
        });
    }

    #[test]
    fn a_resync_moves_every_clone() {
        let clock = MonotonicClock::anchored_at(1_000);
        let clone = clock.clone();
        let _ = clock.resync();
        assert!(clone.now_ns() > 1_000_000_000_000_000_000);
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
