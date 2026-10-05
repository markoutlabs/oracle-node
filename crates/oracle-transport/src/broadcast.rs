//! Price frames under the node's broadcast key: sealed once, opened by every
//! authorised client.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use aes_gcm_siv::Nonce;
use aes_gcm_siv::aead::{Aead as _, Payload};
use hpke::rand_core::CryptoRng;
use oracle_wire::Address;

use crate::schedule::{EpochKey, KEY_GRACE_SECS, KeyId, put_prefixed};
use crate::session::KeyGrant;
use crate::{TransportError, WIRE_VERSION};

/// The type byte of a sealed price frame.
pub const TYPE_FRAME: u8 = 0x10;
/// Nonce length. AES-GCM-SIV tolerates a repeat, so a random nonce is safe even
/// after a VM snapshot restore or clone.
pub const NONCE_LEN: usize = 12;
const KEY_ID_LEN: usize = 16;
const HEADER_LEN: usize = 2 + KEY_ID_LEN + NONCE_LEN;
/// Length of a sealed 182-byte price frame.
pub const SEALED_FRAME_LEN: usize = HEADER_LEN + oracle_wire::FRAME_SIZE + 16;

const FRAME_LABEL: &[u8] = b"price-oracle/2 frame";
const MAX_RING_KEYS: usize = 8;

fn aad(node: Address, key_id: &KeyId) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    put_prefixed(&mut out, FRAME_LABEL);
    out.extend_from_slice(node.as_bytes());
    out.push(WIRE_VERSION);
    out.push(TYPE_FRAME);
    out.extend_from_slice(key_id);
    out
}

pub(crate) fn seal_with_nonce(key: &EpochKey, frame: &[u8], nonce: [u8; NONCE_LEN]) -> Vec<u8> {
    let ciphertext = key
        .cipher()
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: frame,
                aad: &aad(key.context().node, key.key_id()),
            },
        )
        .expect("a price frame is far below the AES-GCM-SIV limit");
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.push(WIRE_VERSION);
    out.push(TYPE_FRAME);
    out.extend_from_slice(key.key_id());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Seals frames under the node's current broadcast key. One per node, shared
/// by the publish path; it never sees a subscriber.
#[derive(Debug)]
pub struct BroadcastSealer {
    current: RwLock<Arc<EpochKey>>,
    seals: AtomicU64,
}

impl BroadcastSealer {
    /// Starts sealing under `key`.
    #[must_use]
    pub fn new(key: Arc<EpochKey>) -> Self {
        Self {
            current: RwLock::new(key),
            seals: AtomicU64::new(0),
        }
    }

    /// Switches to `key`. Deliver it to every eligible session first.
    pub fn install(&self, key: Arc<EpochKey>) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = key;
    }

    /// Returns the key sealing now.
    #[must_use]
    pub fn current(&self) -> Arc<EpochKey> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Seals one signed frame.
    pub fn seal(&self, frame: &[u8], rng: &mut impl CryptoRng) -> Vec<u8> {
        let key = self.current();
        let mut nonce = [0_u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        self.seals.fetch_add(1, Ordering::Relaxed);
        seal_with_nonce(&key, frame, nonce)
    }

    /// Returns how many frames were sealed. The fan-out test reads it.
    #[must_use]
    pub fn seals(&self) -> u64 {
        self.seals.load(Ordering::Relaxed)
    }
}

/// A client's broadcast keys for one node.
#[derive(Debug)]
pub struct KeyRing {
    node: Address,
    keys: Vec<EpochKey>,
}

impl KeyRing {
    /// An empty ring for the node the client dialled.
    #[must_use]
    pub const fn new(node: Address) -> Self {
        Self {
            node,
            keys: Vec::new(),
        }
    }

    /// Adds a delivered key, bound to this ring's node.
    pub fn insert(&mut self, grant: KeyGrant) {
        let key = grant.into_key(self.node);
        if self.keys.iter().any(|held| held.key_id() == key.key_id()) {
            return;
        }
        self.keys.push(key);
        if self.keys.len() > MAX_RING_KEYS {
            self.keys.sort_by_key(|held| held.context().not_after);
            self.keys.remove(0);
        }
    }

    /// Drops keys whose epoch ended more than the grace period ago.
    pub fn prune(&mut self, now: u64) {
        self.keys
            .retain(|key| key.context().not_after.saturating_add(KEY_GRACE_SECS) > now);
    }

    /// Returns how many keys are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns `true` if no key is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Opens a sealed frame. The plaintext is unverified: pass it to the SDK
    /// verifier like any other frame.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Malformed`] for a bad header,
    /// [`TransportError::UnknownKey`] for a key this ring lacks, and
    /// [`TransportError::Decrypt`] for anything else.
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, TransportError> {
        let (header, ciphertext) = sealed
            .split_at_checked(HEADER_LEN)
            .ok_or_else(|| TransportError::Malformed("short frame".to_owned()))?;
        let (kind, rest) = header.split_at(2);
        if kind != [WIRE_VERSION, TYPE_FRAME] {
            return Err(TransportError::Malformed("not a v2 frame".to_owned()));
        }
        let (key_id, nonce) = rest.split_at(KEY_ID_LEN);
        let key = self
            .keys
            .iter()
            .find(|key| key.key_id().as_slice() == key_id)
            .ok_or(TransportError::UnknownKey)?;
        let nonce: [u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| TransportError::Malformed("bad nonce".to_owned()))?;
        key.cipher()
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad(self.node, key.key_id()),
                },
            )
            .map_err(|_| TransportError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os_rng;
    use crate::schedule::{KeyContext, NodeKeySchedule};

    const NOW: u64 = 1_754_582_400;
    const NODE_A: Address = Address::from_bytes([0xA1; 20]);

    fn frame(byte: u8) -> Vec<u8> {
        vec![byte; oracle_wire::FRAME_SIZE]
    }

    fn ring_for(key: &EpochKey) -> KeyRing {
        let mut ring = KeyRing::new(key.context().node);
        ring.insert(KeyGrant::from_key(key));
        ring
    }

    #[test]
    fn a_sealed_frame_opens_with_the_delivered_key() {
        let schedule = NodeKeySchedule::new(NODE_A, 60, NOW, &mut os_rng());
        let sealer = BroadcastSealer::new(Arc::clone(schedule.current()));
        let sealed = sealer.seal(&frame(1), &mut os_rng());
        assert_eq!(sealed.len(), SEALED_FRAME_LEN);
        let ring = ring_for(schedule.current());
        assert_eq!(ring.open(&sealed).expect("opens"), frame(1));
    }

    /// A ring for another node rebuilds another key from the same grant.
    #[test]
    fn a_key_never_opens_another_nodes_frames() {
        let a = NodeKeySchedule::new(NODE_A, 60, NOW, &mut os_rng());
        let sealed = BroadcastSealer::new(Arc::clone(a.current())).seal(&frame(1), &mut os_rng());
        let mut wrong = KeyRing::new(Address::from_bytes([0xB2; 20]));
        wrong.insert(KeyGrant::from_key(a.current()));
        assert_eq!(wrong.open(&sealed), Err(TransportError::UnknownKey));
    }

    #[test]
    fn a_tampered_header_or_body_does_not_open() {
        let s = NodeKeySchedule::new(NODE_A, 60, NOW, &mut os_rng());
        let ring = ring_for(s.current());
        let sealed = BroadcastSealer::new(Arc::clone(s.current())).seal(&frame(1), &mut os_rng());
        for index in [2, HEADER_LEN - 1, HEADER_LEN, sealed.len() - 1] {
            let mut bad = sealed.clone();
            if let Some(byte) = bad.get_mut(index) {
                *byte ^= 1;
            }
            assert!(ring.open(&bad).is_err(), "byte {index}");
        }
    }

    /// The property random nonces alone cannot give: a repeat, as after a VM
    /// snapshot restore, reveals only whether two frames were equal.
    #[test]
    fn a_repeated_nonce_reveals_only_equality() {
        let s = NodeKeySchedule::new(NODE_A, 60, NOW, &mut os_rng());
        let key = s.current();
        let nonce = [9_u8; NONCE_LEN];
        let first = seal_with_nonce(key, &frame(1), nonce);
        let same = seal_with_nonce(key, &frame(1), nonce);
        let other = seal_with_nonce(key, &frame(2), nonce);
        assert_eq!(first, same, "equal frames give equal bytes");
        let body = |sealed: &[u8]| sealed.get(HEADER_LEN..).map(<[u8]>::to_vec);
        let xor: Vec<u8> = body(&first)
            .expect("body")
            .iter()
            .zip(body(&other).expect("body"))
            .map(|(a, b)| a ^ b)
            .collect();
        let plain_xor: Vec<u8> = frame(1).iter().zip(frame(2)).map(|(a, b)| a ^ b).collect();
        assert_ne!(
            xor.get(..plain_xor.len()),
            Some(plain_xor.as_slice()),
            "no keystream reuse"
        );
        let ring = ring_for(key);
        assert_eq!(ring.open(&other).expect("opens"), frame(2));
    }

    #[test]
    fn the_ring_keeps_a_key_only_for_the_grace_period() {
        let key = EpochKey::generate(
            KeyContext {
                node: NODE_A,
                epoch_index: NOW / 60,
                generation: 1,
                not_before: NOW,
                not_after: NOW + 60,
            },
            &mut os_rng(),
        );
        let mut ring = ring_for(&key);
        ring.prune(NOW + 60 + KEY_GRACE_SECS - 1);
        assert_eq!(ring.len(), 1);
        ring.prune(NOW + 60 + KEY_GRACE_SECS);
        assert!(ring.is_empty());
    }
}
