//! Open connections, in total and for each key, with a rate of new ones.

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::PerIp;

#[derive(Default)]
struct Open {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// Open connections, in total and for each address, and new ones for each
/// address. The map holds only the addresses with an open connection.
pub struct Admission {
    open: Mutex<Open>,
    new: PerIp,
    max_total: usize,
    per_ip: usize,
}

/// Why a connection was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The total is reached.
    Full,
    /// The address has its share of open connections.
    TooManyOpen,
    /// The address opened too many in the last minute.
    TooManyNew,
}

impl Admission {
    /// `max_total` open, `per_ip` of them from one address, and `per_minute`
    /// new ones from one address.
    #[must_use]
    pub fn new(max_total: NonZeroUsize, per_ip: NonZeroUsize, per_minute: NonZeroU32) -> Self {
        Self {
            open: Mutex::new(Open::default()),
            new: PerIp::per_minute(per_minute),
            max_total: max_total.get(),
            per_ip: per_ip.get(),
        }
    }

    /// Takes a place for a connection under `key`, from [`crate::Limits::key`]. With
    /// `None`, only the total counts.
    ///
    /// # Errors
    ///
    /// Returns the limit that is reached.
    pub fn admit(this: &Arc<Self>, key: Option<IpAddr>) -> Result<Admitted, Refusal> {
        let mut open = this.lock();
        // A connection refused for lack of a place spends none of the rate.
        if open.total >= this.max_total {
            return Err(Refusal::Full);
        }
        if let Some(key) = key {
            if open.per_ip.get(&key).copied().unwrap_or(0) >= this.per_ip {
                return Err(Refusal::TooManyOpen);
            }
            if !this.new.check(key) {
                return Err(Refusal::TooManyNew);
            }
            let count = open.per_ip.entry(key).or_default();
            *count = count.saturating_add(1);
        }
        open.total = open.total.saturating_add(1);
        Ok(Admitted {
            admission: Arc::clone(this),
            key,
        })
    }

    /// The open connections.
    #[must_use]
    pub fn open(&self) -> usize {
        self.lock().total
    }

    fn lock(&self) -> MutexGuard<'_, Open> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One admitted connection. Dropping it frees its place.
pub struct Admitted {
    admission: Arc<Admission>,
    key: Option<IpAddr>,
}

impl Drop for Admitted {
    fn drop(&mut self) {
        let mut open = self.admission.lock();
        open.total = open.total.saturating_sub(1);
        if let Some(key) = self.key
            && let Some(count) = open.per_ip.get_mut(&key)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.per_ip.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limit::client_key;
    use crate::limit::tests::ip;

    fn admission(max_total: usize, per_ip: usize, per_minute: u32) -> Arc<Admission> {
        Arc::new(Admission::new(
            NonZeroUsize::new(max_total).expect("non-zero"),
            NonZeroUsize::new(per_ip).expect("non-zero"),
            NonZeroU32::new(per_minute).expect("non-zero"),
        ))
    }

    #[test]
    fn admission_counts_each_address_and_frees_on_drop() {
        let admission = admission(16, 1, 30);
        let first =
            Admission::admit(&admission, Some(client_key(ip("2001:db8::1")))).expect("first");
        assert_eq!(
            Admission::admit(&admission, Some(client_key(ip("2001:db8::2")))).err(),
            Some(Refusal::TooManyOpen),
            "one for each /64"
        );
        drop(first);
        assert!(Admission::admit(&admission, Some(client_key(ip("2001:db8::1")))).is_ok());
        assert_eq!(admission.open(), 0);
        assert!(admission.lock().per_ip.is_empty(), "no address is kept");
    }

    #[test]
    fn a_full_admission_spends_no_rate() {
        let admission = admission(1, 8, 2);
        let held = Admission::admit(&admission, Some(ip("198.51.100.1"))).expect("a place");
        for _ in 0..5 {
            assert_eq!(
                Admission::admit(&admission, Some(ip("203.0.113.7"))).err(),
                Some(Refusal::Full)
            );
        }
        drop(held);
        assert!(Admission::admit(&admission, Some(ip("203.0.113.7"))).is_ok());
    }

    #[test]
    fn the_rate_counts_new_connections() {
        let admission = admission(16, 8, 2);
        let peer = Some(ip("203.0.113.7"));
        for _ in 0..2 {
            drop(Admission::admit(&admission, peer).expect("within the rate"));
        }
        assert_eq!(
            Admission::admit(&admission, peer).err(),
            Some(Refusal::TooManyNew)
        );
        assert!(Admission::admit(&admission, Some(ip("198.51.100.1"))).is_ok());
    }

    #[test]
    fn without_a_key_only_the_total_counts() {
        let admission = admission(2, 1, 1);
        let first = Admission::admit(&admission, None).expect("first");
        let second = Admission::admit(&admission, None).expect("second");
        assert_eq!(
            Admission::admit(&admission, None).err(),
            Some(Refusal::Full)
        );
        drop((first, second));
        assert_eq!(admission.open(), 0);
    }
}
