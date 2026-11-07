//! Tells systemd what the node is doing, for `Type=notify` in the unit.
//!
//! Each call does nothing outside systemd, where `NOTIFY_SOCKET` is unset.

use std::time::{Duration, Instant};

/// Shows `text` in `systemctl status`. It must be one line.
pub(crate) fn status(text: &str) {
    #[cfg(unix)]
    send(&[sd_notify::NotifyState::Status(text)]);
    #[cfg(not(unix))]
    let _ = text;
}

/// Gives the start `extra` more time before systemd times it out.
pub(crate) fn extend_start(extra: std::time::Duration) {
    #[cfg(unix)]
    send(&[sd_notify::NotifyState::ExtendTimeoutUsec(
        u32::try_from(extra.as_micros()).unwrap_or(u32::MAX),
    )]);
    #[cfg(not(unix))]
    let _ = extra;
}

/// The node serves: `systemctl start` returns.
pub(crate) fn ready(text: &str) {
    #[cfg(unix)]
    send(&[
        sd_notify::NotifyState::Ready,
        sd_notify::NotifyState::Status(text),
    ]);
    #[cfg(not(unix))]
    let _ = text;
}

/// The node shuts down.
pub(crate) fn stopping() {
    #[cfg(unix)]
    send(&[sd_notify::NotifyState::Stopping]);
}

/// Pings systemd for `WatchdogSec=` in the unit. A hung pipeline stops the
/// pings, and systemd then restarts the node instead of leaving it active.
pub(crate) struct Watchdog {
    every: Option<Duration>,
    last: Option<Instant>,
}

impl Watchdog {
    /// Half of systemd's `WATCHDOG_USEC`, as `sd_watchdog_enabled(3)` advises.
    pub(crate) fn from_env() -> Self {
        #[cfg(unix)]
        let every = sd_notify::watchdog_enabled().map(|interval| interval / 2);
        #[cfg(not(unix))]
        let every = None;
        Self { every, last: None }
    }

    /// Sends `WATCHDOG=1` at most once in each half interval, so a call after
    /// every batch costs one clock read.
    pub(crate) fn beat(&mut self, now: Instant) {
        if self.due(now) {
            self.last = Some(now);
            #[cfg(unix)]
            send(&[sd_notify::NotifyState::Watchdog]);
        }
    }

    fn due(&self, now: Instant) -> bool {
        self.every.is_some_and(|every| {
            self.last
                .is_none_or(|last| now.saturating_duration_since(last) >= every)
        })
    }
}

#[cfg(unix)]
fn send(states: &[sd_notify::NotifyState<'_>]) {
    if let Err(error) = sd_notify::notify(states) {
        tracing::debug!(%error, "cannot notify systemd");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_watchdog_pings_once_each_half_interval_and_never_without_systemd() {
        let half = Duration::from_secs(15);
        let start = Instant::now();
        let mut watchdog = Watchdog {
            every: Some(half),
            last: None,
        };
        assert!(watchdog.due(start), "the first beat pings");
        watchdog.beat(start);
        assert!(!watchdog.due(start + half / 2));
        assert!(watchdog.due(start + half));

        let off = Watchdog {
            every: None,
            last: None,
        };
        assert!(!off.due(start + half));
    }
}
