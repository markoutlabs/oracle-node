//! Tells systemd what the node is doing, for `Type=notify` in the unit.
//!
//! Each call does nothing outside systemd, where `NOTIFY_SOCKET` is unset.

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

#[cfg(unix)]
fn send(states: &[sd_notify::NotifyState<'_>]) {
    if let Err(error) = sd_notify::notify(states) {
        tracing::debug!(%error, "cannot notify systemd");
    }
}
