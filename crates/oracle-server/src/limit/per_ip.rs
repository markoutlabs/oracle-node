//! The key of an address, and a rate for each key.

use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};

/// An IPv4 address, or the /64 of an IPv6 address. An IPv4 address written in
/// IPv6 form counts as IPv4.
#[must_use]
pub fn client_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX))),
        v4 => v4,
    }
}

const PRUNE_EVERY: u64 = 4_096;

/// A rate for each address. Its memory follows the recent addresses, not every
/// address it ever saw.
pub struct PerIp {
    limiter: DefaultKeyedRateLimiter<IpAddr>,
    checks: AtomicU64,
}

impl PerIp {
    /// `count` a minute for each address, all at once at most.
    #[must_use]
    pub fn per_minute(count: NonZeroU32) -> Self {
        Self {
            limiter: RateLimiter::keyed(Quota::per_minute(count)),
            checks: AtomicU64::new(0),
        }
    }

    /// Takes one from the budget of `key`. Returns `false` when it is spent.
    pub fn check(&self, key: IpAddr) -> bool {
        if self.checks.fetch_add(1, Ordering::Relaxed) % PRUNE_EVERY == PRUNE_EVERY - 1 {
            self.limiter.retain_recent();
            self.limiter.shrink_to_fit();
        }
        self.limiter.check_key(&key).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limit::tests::ip;
    use std::time::Duration;

    #[test]
    fn an_ipv6_peer_counts_by_its_64_and_a_mapped_ipv4_as_ipv4() {
        assert_eq!(
            client_key(ip("2001:db8:1:2:aaaa::1")),
            client_key(ip("2001:db8:1:2:bbbb::9"))
        );
        assert_ne!(
            client_key(ip("2001:db8:1:2::1")),
            client_key(ip("2001:db8:1:3::1"))
        );
        assert_eq!(client_key(ip("::ffff:203.0.113.7")), ip("203.0.113.7"));
    }

    #[test]
    fn quiet_addresses_are_pruned() {
        let limit = PerIp::per_minute(NonZeroU32::new(60_000).expect("non-zero"));
        let before = PRUNE_EVERY - 1;
        for n in 0..u32::try_from(before).expect("fits") {
            limit.check(IpAddr::from(n.to_be_bytes()));
        }
        assert_eq!(limit.limiter.len(), usize::try_from(before).expect("fits"));
        std::thread::sleep(Duration::from_millis(20));
        limit.check(ip("127.0.0.1"));
        assert!(limit.limiter.len() <= 1, "pruned: {}", limit.limiter.len());
    }
}
