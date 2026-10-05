//! Broadcast keys: what each one is bound to, when it is used, and who gets it.

use std::fmt;
use std::sync::Arc;

use aes_gcm_siv::Aes256GcmSiv;
use aes_gcm_siv::aead::KeyInit as _;
use hkdf::Hkdf;
use hpke::rand_core::CryptoRng;
use oracle_wire::Address;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Seconds before an epoch boundary at which the next key is handed out.
pub const KEY_LEAD_SECS: u64 = 10;

/// Seconds a client keeps a key after its epoch ends, for frames in flight.
pub const KEY_GRACE_SECS: u64 = 5;

/// Identifies a broadcast key on the wire. Derived, never chosen.
pub type KeyId = [u8; 16];

const CONTEXT_LABEL: &[u8] = b"price-oracle/2 epoch";
const FRAME_KEY_INFO: &[u8] = b"price-oracle/2 frame-key";
const KEY_ID_INFO: &[u8] = b"price-oracle/2 key-id";

/// Everything a broadcast key is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyContext {
    /// The node that seals with it.
    pub node: Address,
    /// The grid epoch, `not_before / epoch_secs` for a grid key.
    pub epoch_index: u64,
    /// Strictly increasing within one node process, across every key it makes.
    pub generation: u64,
    /// First second of use, unix seconds.
    pub not_before: u64,
    /// End of use, unix seconds, exclusive.
    pub not_after: u64,
}

impl KeyContext {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80);
        put_prefixed(&mut out, CONTEXT_LABEL);
        out.extend_from_slice(self.node.as_bytes());
        for value in [
            self.epoch_index,
            self.generation,
            self.not_before,
            self.not_after,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out
    }
}

pub(crate) fn put_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A broadcast key with its context, id and frame cipher.
///
/// The cipher key and the id both come from the secret and the full context,
/// so a key cannot be used under another node, epoch or generation.
pub struct EpochKey {
    context: KeyContext,
    secret: Zeroizing<[u8; 32]>,
    key_id: KeyId,
    cipher: Aes256GcmSiv,
}

impl EpochKey {
    /// Makes a new key from fresh randomness.
    pub fn generate(context: KeyContext, rng: &mut impl CryptoRng) -> Self {
        let mut secret = Zeroizing::new([0_u8; 32]);
        rng.fill_bytes(secret.as_mut());
        Self::from_secret(context, secret)
    }

    /// Rebuilds a key from a delivered secret and the context the receiver
    /// knows. A wrong context gives a different key, not an error.
    ///
    /// # Panics
    ///
    /// Cannot panic: 32 and 16 bytes are valid HKDF-SHA256 outputs and 32 is the
    /// AES-256 key size.
    #[must_use]
    pub fn from_secret(context: KeyContext, secret: Zeroizing<[u8; 32]>) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, secret.as_ref());
        let encoded = context.encode();
        let mut frame_key = Zeroizing::new([0_u8; 32]);
        hkdf.expand_multi_info(&[FRAME_KEY_INFO, &encoded], frame_key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output");
        let mut key_id = [0_u8; 16];
        hkdf.expand_multi_info(&[KEY_ID_INFO, &encoded], &mut key_id)
            .expect("16 bytes is a valid HKDF-SHA256 output");
        let cipher =
            Aes256GcmSiv::new_from_slice(frame_key.as_ref()).expect("AES-256 takes 32 bytes");
        Self {
            context,
            secret,
            key_id,
            cipher,
        }
    }

    /// Returns what the key is bound to.
    #[must_use]
    pub const fn context(&self) -> &KeyContext {
        &self.context
    }

    /// Returns the key id carried in each frame.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    pub(crate) const fn cipher(&self) -> &Aes256GcmSiv {
        &self.cipher
    }
}

impl fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EpochKey")
            .field("context", &self.context)
            .field("key_id", &hex::encode(self.key_id))
            .finish_non_exhaustive()
    }
}

/// The last second a client may hold a session: `expires_at` rounded down to
/// the epoch grid, so no client ever holds a key for an epoch it outlives.
#[must_use]
pub const fn session_deadline(expires_at: u64, epoch_secs: u64) -> u64 {
    if epoch_secs == 0 {
        return expires_at;
    }
    expires_at - expires_at % epoch_secs
}

/// `true` if a session with this deadline may receive the key.
#[must_use]
pub const fn eligible(key: &KeyContext, deadline: u64) -> bool {
    key.not_after <= deadline
}

/// What one call to [`NodeKeySchedule::tick`] changed.
#[derive(Debug)]
pub enum Tick {
    /// Nothing to do.
    Unchanged,
    /// The next key exists. Deliver it now; switch to it at its `not_before`.
    NextReady(Arc<EpochKey>),
    /// Sealing must switch to this key. `announced` is `false` when it was
    /// never handed out as the next key, so it must be delivered first.
    Switched {
        /// The new current key.
        key: Arc<EpochKey>,
        /// It was already delivered through [`Tick::NextReady`].
        announced: bool,
    },
}

/// A node's broadcast keys: the current one and, near a boundary, the next.
#[derive(Debug)]
pub struct NodeKeySchedule {
    node: Address,
    epoch_secs: u64,
    generation: u64,
    current: Arc<EpochKey>,
    next: Option<Arc<EpochKey>>,
}

impl NodeKeySchedule {
    /// Starts with a key for the epoch that contains `now`.
    pub fn new(node: Address, epoch_secs: u64, now: u64, rng: &mut impl CryptoRng) -> Self {
        let epoch_secs = epoch_secs.max(1);
        let current = Arc::new(grid_key(node, epoch_secs, now / epoch_secs, 1, rng));
        Self {
            node,
            epoch_secs,
            generation: 1,
            current,
            next: None,
        }
    }

    /// Returns the key sealing now.
    #[must_use]
    pub const fn current(&self) -> &Arc<EpochKey> {
        &self.current
    }

    /// Returns the next key, once it exists.
    #[must_use]
    pub const fn next(&self) -> Option<&Arc<EpochKey>> {
        self.next.as_ref()
    }

    /// Returns the epoch length.
    #[must_use]
    pub const fn epoch_secs(&self) -> u64 {
        self.epoch_secs
    }

    /// The keys a session with this deadline may hold now.
    #[must_use]
    pub fn keys_for(&self, deadline: u64) -> Vec<Arc<EpochKey>> {
        std::iter::once(&self.current)
            .chain(self.next.as_ref())
            .filter(|key| eligible(key.context(), deadline))
            .cloned()
            .collect()
    }

    /// Advances the schedule to `now`. Call at least once a second.
    ///
    /// The epoch never moves backwards: if the wall clock steps back, the
    /// current key stays until its own end.
    pub fn tick(&mut self, now: u64, rng: &mut impl CryptoRng) -> Tick {
        let current = self.current.context();
        if now >= current.not_after {
            let target = (now / self.epoch_secs).max(current.epoch_index.saturating_add(1));
            let (key, announced) = match self.next.take() {
                Some(next) if next.context().epoch_index == target => (next, true),
                _ => (self.make_grid_key(target, rng), false),
            };
            self.current = Arc::clone(&key);
            return Tick::Switched { key, announced };
        }
        if self.next.is_none() && now >= current.not_after.saturating_sub(KEY_LEAD_SECS) {
            let key = self.make_grid_key(current.epoch_index.saturating_add(1), rng);
            self.next = Some(Arc::clone(&key));
            return Tick::NextReady(key);
        }
        Tick::Unchanged
    }

    /// Replaces the current key, and the next one if it was already handed out,
    /// after a revocation. Returns the new keys: deliver them to the sessions
    /// that remain, then seal with the first.
    pub fn force_rotate(&mut self, now: u64, rng: &mut impl CryptoRng) -> Vec<Arc<EpochKey>> {
        let previous = self.current.context().clone();
        self.generation = self.generation.saturating_add(1);
        let current = Arc::new(EpochKey::generate(
            KeyContext {
                node: self.node,
                epoch_index: previous.epoch_index,
                generation: self.generation,
                not_before: now.min(previous.not_after.saturating_sub(1)),
                not_after: previous.not_after,
            },
            rng,
        ));
        self.current = Arc::clone(&current);
        let mut fresh = vec![current];
        if let Some(next) = self.next.take() {
            let replacement = self.make_grid_key(next.context().epoch_index, rng);
            self.next = Some(Arc::clone(&replacement));
            fresh.push(replacement);
        }
        fresh
    }

    fn make_grid_key(&mut self, epoch_index: u64, rng: &mut impl CryptoRng) -> Arc<EpochKey> {
        self.generation = self.generation.saturating_add(1);
        Arc::new(grid_key(
            self.node,
            self.epoch_secs,
            epoch_index,
            self.generation,
            rng,
        ))
    }
}

fn grid_key(
    node: Address,
    epoch_secs: u64,
    epoch_index: u64,
    generation: u64,
    rng: &mut impl CryptoRng,
) -> EpochKey {
    EpochKey::generate(
        KeyContext {
            node,
            epoch_index,
            generation,
            not_before: epoch_index.saturating_mul(epoch_secs),
            not_after: epoch_index.saturating_add(1).saturating_mul(epoch_secs),
        },
        rng,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os_rng;

    const T: u64 = 60;
    const BOUNDARY: u64 = 1_754_582_400; // a multiple of 60

    const NODE_A: Address = Address::from_bytes([0xA1; 20]);

    fn schedule(now: u64) -> NodeKeySchedule {
        NodeKeySchedule::new(NODE_A, T, now, &mut os_rng())
    }

    #[test]
    fn the_deadline_snaps_down_to_the_grid() {
        assert_eq!(session_deadline(BOUNDARY, T), BOUNDARY, "on a boundary");
        assert_eq!(
            session_deadline(BOUNDARY - 1, T),
            BOUNDARY - T,
            "one second before"
        );
        assert_eq!(
            session_deadline(BOUNDARY + 1, T),
            BOUNDARY,
            "one second after"
        );
        assert!(session_deadline(BOUNDARY + 59, T) <= BOUNDARY + 59);
    }

    #[test]
    fn a_key_goes_only_to_sessions_that_outlive_its_epoch() {
        let key = KeyContext {
            node: NODE_A,
            epoch_index: BOUNDARY / T - 1,
            generation: 1,
            not_before: BOUNDARY - T,
            not_after: BOUNDARY,
        };
        assert!(
            eligible(&key, BOUNDARY),
            "deadline exactly at the epoch end"
        );
        assert!(!eligible(&key, BOUNDARY - T), "deadline at the epoch start");
        let next = KeyContext {
            epoch_index: BOUNDARY / T,
            not_before: BOUNDARY,
            not_after: BOUNDARY + T,
            ..key
        };
        assert!(!eligible(&next, BOUNDARY), "never a key past the deadline");
        // expires_at one second before the boundary: no key for the epoch it ends in.
        let deadline = session_deadline(BOUNDARY - 1, T);
        assert!(!eligible(
            &KeyContext {
                not_before: BOUNDARY - T,
                not_after: BOUNDARY,
                ..next
            },
            deadline
        ));
    }

    #[test]
    fn the_next_key_is_ready_early_and_takes_over_at_the_boundary() {
        let mut s = schedule(BOUNDARY - 30);
        let first = Arc::clone(s.current());
        assert_eq!(first.context().not_after, BOUNDARY);
        assert!(matches!(
            s.tick(BOUNDARY - KEY_LEAD_SECS - 1, &mut os_rng()),
            Tick::Unchanged
        ));
        let Tick::NextReady(next) = s.tick(BOUNDARY - KEY_LEAD_SECS, &mut os_rng()) else {
            panic!("the next key must be ready {KEY_LEAD_SECS} s early");
        };
        assert_eq!(next.context().not_before, BOUNDARY);
        assert!(matches!(
            s.tick(BOUNDARY - 1, &mut os_rng()),
            Tick::Unchanged
        ));
        let Tick::Switched { key, announced } = s.tick(BOUNDARY, &mut os_rng()) else {
            panic!("must switch at the boundary");
        };
        assert!(announced);
        assert_eq!(key.key_id(), next.key_id());
        assert_ne!(key.key_id(), first.key_id());
    }

    #[test]
    fn the_epoch_never_runs_backwards() {
        let mut s = schedule(BOUNDARY + 5);
        let id = *s.current().key_id();
        assert!(matches!(
            s.tick(BOUNDARY - 3_600, &mut os_rng()),
            Tick::Unchanged
        ));
        assert_eq!(
            s.current().key_id(),
            &id,
            "a clock step back changes nothing"
        );
    }

    #[test]
    fn a_clock_jump_forward_switches_to_a_fresh_key_that_must_be_delivered() {
        let mut s = schedule(BOUNDARY + 5);
        let _ = s.tick(BOUNDARY + T - KEY_LEAD_SECS, &mut os_rng());
        let Tick::Switched { key, announced } = s.tick(BOUNDARY + 10 * T + 7, &mut os_rng()) else {
            panic!("must switch");
        };
        assert!(!announced, "the announced next key is for a skipped epoch");
        assert_eq!(key.context().epoch_index, BOUNDARY / T + 10);
    }

    #[test]
    fn a_forced_rotation_replaces_current_and_next_with_new_generations() {
        let mut s = schedule(BOUNDARY - 30);
        let Tick::NextReady(old_next) = s.tick(BOUNDARY - 5, &mut os_rng()) else {
            panic!("next ready");
        };
        let old_current = Arc::clone(s.current());
        let fresh = s.force_rotate(BOUNDARY - 4, &mut os_rng());
        let [current, next] = fresh.as_slice() else {
            panic!("current and next are both replaced");
        };
        assert_ne!(current.key_id(), old_current.key_id());
        assert_ne!(next.key_id(), old_next.key_id());
        assert_eq!(
            current.context().not_after,
            BOUNDARY,
            "still ends on the grid"
        );
        assert_eq!(current.context().not_before, BOUNDARY - 4);
        assert!(current.context().generation > old_next.context().generation);
        assert_eq!(s.current().key_id(), current.key_id());
    }

    #[test]
    fn the_same_secret_under_another_context_is_another_key() {
        let secret = [7_u8; 32];
        let context = KeyContext {
            node: NODE_A,
            epoch_index: 1,
            generation: 1,
            not_before: 60,
            not_after: 120,
        };
        let base = EpochKey::from_secret(context.clone(), Zeroizing::new(secret));
        for other in [
            KeyContext {
                node: Address::from_bytes([0xB2; 20]),
                ..context.clone()
            },
            KeyContext {
                epoch_index: 2,
                ..context.clone()
            },
            KeyContext {
                generation: 2,
                ..context.clone()
            },
            KeyContext {
                not_before: 61,
                ..context.clone()
            },
            KeyContext {
                not_after: 121,
                ..context.clone()
            },
        ] {
            let derived = EpochKey::from_secret(other, Zeroizing::new(secret));
            assert_ne!(derived.key_id(), base.key_id());
        }
    }
}
