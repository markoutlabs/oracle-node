//! Reconnect backoff.
//!
//! Pure and deterministic given a seed, so the schedule is asserted in tests
//! rather than observed in production.
//!
//! Jitter is not decoration. Five nodes and several venue connections all
//! reconnecting on the same exponential ladder will synchronise after a shared
//! outage and hammer the venue in lockstep at exactly the moment it is least able
//! to cope — and a venue that rate-limits in response turns a transient blip into
//! a long one.

use std::time::Duration;

/// Backoff parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackoffConfig {
    /// Delay after the first failure.
    pub initial: Duration,
    /// Ceiling on the delay.
    pub max: Duration,
    /// Multiplier applied per consecutive failure.
    pub multiplier: u32,
    /// Jitter as a percentage of the computed delay, applied symmetrically.
    pub jitter_percent: u32,
    /// Consecutive-failure count is reset after a connection stays up this long.
    ///
    /// Without this, a connection that flaps every few seconds would keep
    /// resetting its ladder and retry aggressively forever.
    pub reset_after_stable: Duration,
}

impl Default for BackoffConfig {
    /// 100ms to 30s, doubling, ±25% jitter, reset after 60s of stability.
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(30),
            multiplier: 2,
            jitter_percent: 25,
            reset_after_stable: Duration::from_secs(60),
        }
    }
}

/// An exponential backoff with jitter.
#[derive(Clone, Debug)]
pub struct Backoff {
    config: BackoffConfig,
    failures: u32,
    rng: Xorshift64,
}

impl Backoff {
    /// Builds a backoff with an explicit jitter seed.
    ///
    /// Seed each connection differently — from the venue and market, say — so
    /// that connections sharing a process do not draw the same jitter sequence
    /// and re-synchronise anyway.
    #[must_use]
    pub const fn with_seed(config: BackoffConfig, seed: u64) -> Self {
        Self {
            config,
            failures: 0,
            rng: Xorshift64::new(seed),
        }
    }

    /// Returns the delay to wait before the next attempt, and advances the ladder.
    pub fn next_delay(&mut self) -> Duration {
        let step = self.failures;
        self.failures = self.failures.saturating_add(1);

        let base_ms = u64::try_from(self.config.initial.as_millis()).unwrap_or(u64::MAX);
        let max_ms = u64::try_from(self.config.max.as_millis()).unwrap_or(u64::MAX);
        let multiplier = u64::from(self.config.multiplier.max(1));

        // Saturating exponentiation: the ladder clamps at `max` rather than
        // wrapping to a tiny delay after enough failures.
        let mut delay_ms = base_ms;
        for _ in 0..step {
            delay_ms = delay_ms.saturating_mul(multiplier);
            if delay_ms >= max_ms {
                delay_ms = max_ms;
                break;
            }
        }
        delay_ms = delay_ms.min(max_ms);

        Duration::from_millis(self.apply_jitter(delay_ms))
    }

    /// Applies symmetric jitter of ±`jitter_percent`.
    fn apply_jitter(&mut self, delay_ms: u64) -> u64 {
        let percent = u64::from(self.config.jitter_percent);
        if percent == 0 || delay_ms == 0 {
            return delay_ms;
        }
        let span = delay_ms.saturating_mul(percent) / 100;
        if span == 0 {
            return delay_ms;
        }
        // Uniform over [-span, +span].
        let offset = self
            .rng
            .next_below(span.saturating_mul(2).saturating_add(1));
        delay_ms.saturating_add(offset).saturating_sub(span)
    }

    /// Resets the ladder after a connection proved stable.
    ///
    /// `uptime` is how long the connection that just ended stayed up. Short-lived
    /// connections do not reset, so a flapping endpoint still backs off.
    pub fn record_disconnect(&mut self, uptime: Duration) {
        if uptime >= self.config.reset_after_stable {
            self.failures = 0;
        }
    }

    /// Resets the ladder unconditionally.
    pub const fn reset(&mut self) {
        self.failures = 0;
    }

    /// Returns the number of consecutive failures recorded.
    #[must_use]
    pub const fn failures(&self) -> u32 {
        self.failures
    }
}

/// A tiny xorshift PRNG.
///
/// Jitter needs to be spread out, not unpredictable, so a 5-line generator with
/// no dependency and a reproducible sequence is a better fit than a real CSPRNG.
#[derive(Clone, Debug)]
struct Xorshift64(u64);

impl Xorshift64 {
    const fn new(seed: u64) -> Self {
        // Zero is a fixed point for xorshift; substitute a non-zero constant.
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    const fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    const fn next_below(&mut self, bound: u64) -> u64 {
        if bound == 0 { 0 } else { self.next() % bound }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> BackoffConfig {
        BackoffConfig {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(30),
            multiplier: 2,
            jitter_percent: 0,
            reset_after_stable: Duration::from_secs(60),
        }
    }

    #[test]
    fn ladder_doubles_then_clamps() {
        let mut backoff = Backoff::with_seed(config(), 1);
        let expected_ms = [
            100, 200, 400, 800, 1_600, 3_200, 6_400, 12_800, 25_600, 30_000, 30_000,
        ];
        for want in expected_ms {
            assert_eq!(backoff.next_delay(), Duration::from_millis(want));
        }
    }

    #[test]
    fn ladder_never_wraps_after_many_failures() {
        let mut backoff = Backoff::with_seed(config(), 1);
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
        let mut config = config();
        config.jitter_percent = 25;
        let mut backoff = Backoff::with_seed(config, 42);

        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            backoff.reset();
            let delay = backoff.next_delay();
            // Base 100ms, ±25%.
            assert!(
                delay >= Duration::from_millis(75) && delay <= Duration::from_millis(125),
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
        let mut config = config();
        config.jitter_percent = 25;
        let mut a = Backoff::with_seed(config, 1);
        let mut b = Backoff::with_seed(config, 2);
        let series_a: Vec<_> = (0..8).map(|_| a.next_delay()).collect();
        let series_b: Vec<_> = (0..8).map(|_| b.next_delay()).collect();
        assert_ne!(series_a, series_b);
    }

    #[test]
    fn same_seed_is_reproducible() {
        let mut config = config();
        config.jitter_percent = 25;
        let mut a = Backoff::with_seed(config, 7);
        let mut b = Backoff::with_seed(config, 7);
        for _ in 0..16 {
            assert_eq!(a.next_delay(), b.next_delay());
        }
    }

    #[test]
    fn stable_connections_reset_the_ladder_and_flapping_ones_do_not() {
        let mut backoff = Backoff::with_seed(config(), 1);
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
