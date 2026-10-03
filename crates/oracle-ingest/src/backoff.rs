//! Reconnect backoff.
//!
//! The exponential ladder and the jitter come from `backon`. This module adds
//! the one rule `backon` does not have: the ladder resets after a connection
//! proved stable, so a flapping endpoint keeps backing off while a healthy one
//! that drops once starts again from the bottom.
//!
//! Jitter is not decoration. Five nodes and several venue connections all
//! reconnecting on the same exponential ladder will synchronise after a shared
//! outage and hammer the venue in lockstep at exactly the moment it is least able
//! to cope — and a venue that rate-limits in response turns a transient blip into
//! a long one. Jitter is seeded from OS entropy per [`Backoff`], so sibling
//! connections and sibling nodes never share a sequence. Tests pass a seed to
//! assert exact delays.

use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};

/// Backoff parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackoffConfig {
    /// Delay after the first failure.
    pub initial: Duration,
    /// Ceiling on the delay.
    pub max: Duration,
    /// Multiplier applied per consecutive failure.
    pub multiplier: u16,
    /// Add a random amount in `[0, delay)` to every delay.
    pub jitter: bool,
    /// Consecutive-failure count is reset after a connection stays up this long.
    ///
    /// Without this, a connection that flaps every few seconds would keep
    /// resetting its ladder and retry aggressively forever.
    pub reset_after_stable: Duration,
}

impl Default for BackoffConfig {
    /// 100ms to 30s, doubling, jittered, reset after 60s of stability.
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(30),
            multiplier: 2,
            jitter: true,
            reset_after_stable: Duration::from_secs(60),
        }
    }
}

/// An exponential backoff with jitter and a stability reset.
pub struct Backoff {
    config: BackoffConfig,
    seed: Option<u64>,
    failures: u32,
    ladder: backon::ExponentialBackoff,
}

impl Backoff {
    /// Builds a backoff whose jitter is seeded from OS entropy.
    #[must_use]
    pub fn new(config: BackoffConfig) -> Self {
        Self::build(config, None)
    }

    /// Builds a backoff with a fixed jitter seed, for tests that assert delays.
    #[must_use]
    pub fn with_seed(config: BackoffConfig, seed: u64) -> Self {
        Self::build(config, Some(seed))
    }

    fn build(config: BackoffConfig, seed: Option<u64>) -> Self {
        Self {
            ladder: ladder(config, seed),
            config,
            seed,
            failures: 0,
        }
    }

    /// Returns the delay to wait before the next attempt, and advances the ladder.
    ///
    /// Whole milliseconds. `backon` scales with `f32`, which leaves
    /// sub-millisecond noise on the ladder; nothing here needs finer than that.
    pub fn next_delay(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        // The ladder has no attempt limit, so `None` cannot happen. The ceiling
        // is the safe answer if it ever did.
        let delay = self.ladder.next().unwrap_or(self.config.max);
        let millis = delay.as_nanos().saturating_add(500_000) / 1_000_000;
        Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
    }

    /// Resets the ladder after a connection proved stable.
    ///
    /// `uptime` is how long the connection that just ended stayed up. Short-lived
    /// connections do not reset, so a flapping endpoint still backs off.
    pub fn record_disconnect(&mut self, uptime: Duration) {
        if uptime >= self.config.reset_after_stable {
            self.reset();
        }
    }

    /// Resets the ladder unconditionally.
    pub fn reset(&mut self) {
        self.failures = 0;
        // A fixed seed moves on, so a reset does not replay the same first
        // jitter. Two backoffs built from one seed still stay in step.
        self.seed = self.seed.map(|seed| seed.wrapping_add(1));
        self.ladder = ladder(self.config, self.seed);
    }

    /// Returns the number of consecutive failures recorded.
    #[must_use]
    pub const fn failures(&self) -> u32 {
        self.failures
    }
}

fn ladder(config: BackoffConfig, seed: Option<u64>) -> backon::ExponentialBackoff {
    let mut builder = ExponentialBuilder::default()
        .with_min_delay(config.initial)
        .with_max_delay(config.max)
        .with_factor(f32::from(config.multiplier.max(1)))
        .without_max_times();
    if config.jitter {
        builder = builder.with_jitter();
    }
    if let Some(seed) = seed {
        builder = builder.with_jitter_seed(seed);
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> BackoffConfig {
        BackoffConfig {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(30),
            multiplier: 2,
            jitter: false,
            reset_after_stable: Duration::from_secs(60),
        }
    }

    fn jittered() -> BackoffConfig {
        BackoffConfig {
            jitter: true,
            ..config()
        }
    }

    #[test]
    fn ladder_doubles_then_clamps() {
        let mut backoff = Backoff::new(config());
        let expected_ms = [
            100, 200, 400, 800, 1_600, 3_200, 6_400, 12_800, 25_600, 30_000, 30_000,
        ];
        for want in expected_ms {
            assert_eq!(backoff.next_delay(), Duration::from_millis(want));
        }
    }

    #[test]
    fn ladder_never_wraps_after_many_failures() {
        let mut backoff = Backoff::new(config());
        for _ in 0..1_000 {
            let delay = backoff.next_delay();
            assert!(
                delay <= Duration::from_secs(30),
                "delay escaped the ceiling: {delay:?}"
            );
        }
        // A saturating counter must not roll over into a short delay.
        assert_eq!(backoff.next_delay(), Duration::from_secs(30));
    }

    #[test]
    fn jitter_stays_within_bounds_and_varies() {
        let mut backoff = Backoff::with_seed(jittered(), 42);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            backoff.reset();
            let delay = backoff.next_delay();
            // Base 100ms plus [0, 100ms).
            assert!(
                delay >= Duration::from_millis(100) && delay <= Duration::from_millis(200),
                "jitter escaped its band: {delay:?}"
            );
            seen.insert(delay);
        }
        assert!(
            seen.len() > 10,
            "jitter is not actually varying: {} distinct values",
            seen.len()
        );
    }

    #[test]
    fn different_seeds_desynchronise() {
        // The whole point of jitter: two connections must not draw the same ladder.
        let mut a = Backoff::with_seed(jittered(), 1);
        let mut b = Backoff::with_seed(jittered(), 2);
        let series_a: Vec<_> = (0..8).map(|_| a.next_delay()).collect();
        let series_b: Vec<_> = (0..8).map(|_| b.next_delay()).collect();
        assert_ne!(series_a, series_b);
    }

    /// Two unseeded backoffs, as production builds them, must not share a
    /// sequence either. Identical config across a fleet used to mean identical
    /// jitter, which is the lockstep the module exists to prevent.
    #[test]
    fn unseeded_backoffs_draw_from_entropy() {
        let mut a = Backoff::new(jittered());
        let mut b = Backoff::new(jittered());
        let series_a: Vec<_> = (0..8).map(|_| a.next_delay()).collect();
        let series_b: Vec<_> = (0..8).map(|_| b.next_delay()).collect();
        assert_ne!(series_a, series_b);
    }

    #[test]
    fn same_seed_is_reproducible() {
        let mut a = Backoff::with_seed(jittered(), 7);
        let mut b = Backoff::with_seed(jittered(), 7);
        for _ in 0..16 {
            assert_eq!(a.next_delay(), b.next_delay());
        }
    }

    #[test]
    fn stable_connections_reset_the_ladder_and_flapping_ones_do_not() {
        let mut backoff = Backoff::new(config());
        for _ in 0..5 {
            let _ = backoff.next_delay();
        }
        assert_eq!(backoff.failures(), 5);

        // A connection that lasted two seconds was still flapping.
        backoff.record_disconnect(Duration::from_secs(2));
        assert_eq!(
            backoff.failures(),
            5,
            "a flapping connection must keep backing off"
        );
        assert_eq!(backoff.next_delay(), Duration::from_millis(3_200));

        // One that stayed up past the threshold earns a reset.
        backoff.record_disconnect(Duration::from_secs(120));
        assert_eq!(backoff.failures(), 0);
        assert_eq!(backoff.next_delay(), Duration::from_millis(100));
    }

    #[test]
    fn zero_jitter_is_exact() {
        let mut backoff = Backoff::with_seed(config(), 99);
        assert_eq!(backoff.next_delay(), Duration::from_millis(100));
    }
}
