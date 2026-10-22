//! Limits on what one peer can cost the node before and after it authenticates.
//!
//! An IPv6 peer usually owns a whole /64, so a limit keys it by that prefix.
//! Otherwise one peer could take a fresh address for each socket.
//!
//! - `per_ip`: the key of an address, and a rate for each key.
//! - `admission`: open connections, in total and for each key.

mod admission;
mod per_ip;

use std::net::IpAddr;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::time::Duration;

use serde::Deserialize;

pub use admission::{Admission, Admitted, Refusal};
pub use per_ip::{PerIp, client_key};

/// The `[server.limits]` of a node. Each value is above 0.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Open TCP sockets, in total.
    pub max_sockets: NonZeroUsize,
    /// Open TCP sockets from one address.
    pub sockets_per_ip: NonZeroUsize,
    /// New TCP sockets from one address each minute.
    pub sockets_per_minute: NonZeroU32,
    /// Time to send a whole request head, and the most a keep-alive socket may idle, in ms.
    pub header_timeout_ms: NonZeroU64,
    /// Handshakes in progress, in total.
    pub max_handshakes: NonZeroUsize,
    /// Handshakes in progress from one address.
    pub handshakes_per_ip: NonZeroUsize,
    /// New handshakes from one address each minute.
    pub handshakes_per_minute: NonZeroU32,
    /// Time from the upgrade to `auth_ok`, in ms.
    pub handshake_timeout_ms: NonZeroU64,
    /// Sessions open at once for one client key, from any address.
    pub sessions_per_client: NonZeroUsize,
    /// Control messages from one session each second, pings and pongs too.
    pub messages_per_second: NonZeroU32,
    /// Requests to the REST routes from one address each minute.
    pub requests_per_minute: NonZeroU32,
    /// Applies the per-address limits to loopback peers too.
    pub limit_loopback: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sockets: NonZeroUsize::MIN.saturating_add(1_023),
            sockets_per_ip: NonZeroUsize::MIN.saturating_add(15),
            sockets_per_minute: NonZeroU32::MIN.saturating_add(59),
            header_timeout_ms: NonZeroU64::MIN.saturating_add(9_999),
            max_handshakes: NonZeroUsize::MIN.saturating_add(255),
            handshakes_per_ip: NonZeroUsize::MIN.saturating_add(3),
            handshakes_per_minute: NonZeroU32::MIN.saturating_add(29),
            handshake_timeout_ms: NonZeroU64::MIN.saturating_add(4_999),
            sessions_per_client: NonZeroUsize::MIN.saturating_add(7),
            messages_per_second: NonZeroU32::MIN.saturating_add(9),
            requests_per_minute: NonZeroU32::MIN.saturating_add(59),
            limit_loopback: false,
        }
    }
}

impl Limits {
    /// The key that the per-address limits count `peer` under, or `None` when
    /// they do not apply. A TLS proxy on the same host brings every client
    /// from loopback, so by default loopback counts only in the totals.
    #[must_use]
    pub fn key(&self, peer: IpAddr) -> Option<IpAddr> {
        let peer = peer.to_canonical();
        (self.limit_loopback || !peer.is_loopback()).then(|| client_key(peer))
    }

    /// [`Self::header_timeout_ms`] as a duration.
    #[must_use]
    pub const fn header_timeout(&self) -> Duration {
        Duration::from_millis(self.header_timeout_ms.get())
    }

    /// [`Self::handshake_timeout_ms`] as a duration.
    #[must_use]
    pub const fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn loopback_counts_only_in_the_totals_unless_asked() {
        let limits = Limits::default();
        assert_eq!(limits.key(ip("127.0.0.1")), None);
        assert_eq!(limits.key(ip("::1")), None);
        assert_eq!(limits.key(ip("::ffff:127.0.0.1")), None);
        assert_eq!(limits.key(ip("203.0.113.7")), Some(ip("203.0.113.7")));
        let strict = Limits {
            limit_loopback: true,
            ..Limits::default()
        };
        assert_eq!(strict.key(ip("127.0.0.1")), Some(ip("127.0.0.1")));
    }
}
