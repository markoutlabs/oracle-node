//! The per-session control channel: sealed, ordered, one key per direction.
//!
//! Carries the application's control messages and the transport's own: key
//! delivery, deadline changes and close. Never price frames.

use aes_gcm_siv::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use zeroize::Zeroizing;

use crate::schedule::{EpochKey, KeyContext, put_prefixed};
use crate::{TransportError, WIRE_VERSION};

/// The type byte of a sealed control message.
pub const TYPE_CONTROL: u8 = 0x11;

pub(crate) const N2C_LABEL: &str = "price-oracle/2 ctl-n2c";
pub(crate) const C2N_LABEL: &str = "price-oracle/2 ctl-c2n";

const HEADER_LEN: usize = 2 + 8;

const TAG_APP: u8 = 0x01;
const TAG_KEY_UPDATE: u8 = 0x02;
const TAG_SESSION_UPDATE: u8 = 0x03;
const TAG_CLOSE: u8 = 0x04;

/// Why a node ends a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The client's authorisation reached its deadline.
    Expired,
    /// Governance removed the client or moved its expiry earlier.
    Revoked,
    /// The node's client list is too old to trust.
    Stale,
    /// The subscriber fell too far behind.
    Lagged,
    /// The peer broke the protocol.
    Protocol,
}

impl CloseReason {
    const fn code(self) -> u8 {
        match self {
            Self::Expired => 1,
            Self::Revoked => 2,
            Self::Stale => 3,
            Self::Lagged => 4,
            Self::Protocol => 5,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Expired,
            2 => Self::Revoked,
            3 => Self::Stale,
            4 => Self::Lagged,
            5 => Self::Protocol,
            _ => return None,
        })
    }
}

/// A broadcast key as delivered. The receiver adds the `node_id` it dialled.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyGrant {
    /// The key's epoch.
    pub epoch_index: u64,
    /// The key's generation.
    pub generation: u64,
    /// First second of use.
    pub not_before: u64,
    /// End of use, exclusive.
    pub not_after: u64,
    /// The epoch secret.
    pub secret: Zeroizing<[u8; 32]>,
}

impl KeyGrant {
    /// The grant for a node's key.
    #[must_use]
    pub fn from_key(key: &EpochKey) -> Self {
        let context = key.context();
        Self {
            epoch_index: context.epoch_index,
            generation: context.generation,
            not_before: context.not_before,
            not_after: context.not_after,
            secret: Zeroizing::new(*key.secret()),
        }
    }

    /// Rebuilds the key, bound to the node this session was opened with.
    #[must_use]
    pub fn into_key(self, node_id: &str) -> EpochKey {
        EpochKey::from_secret(
            KeyContext {
                node_id: node_id.to_owned(),
                epoch_index: self.epoch_index,
                generation: self.generation,
                not_before: self.not_before,
                not_after: self.not_after,
            },
            self.secret,
        )
    }
}

impl std::fmt::Debug for KeyGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyGrant")
            .field("epoch_index", &self.epoch_index)
            .field("generation", &self.generation)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

/// One control message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Control {
    /// An application control message, opaque here (JSON in practice).
    App(Vec<u8>),
    /// A broadcast key.
    KeyUpdate(KeyGrant),
    /// The session deadline moved, unix seconds.
    SessionUpdate {
        /// The new deadline.
        deadline: u64,
    },
    /// The node is ending the session.
    Close(CloseReason),
}

impl Control {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(64));
        match self {
            Self::App(body) => {
                out.push(TAG_APP);
                out.extend_from_slice(body);
            }
            Self::KeyUpdate(grant) => {
                out.push(TAG_KEY_UPDATE);
                for value in [
                    grant.epoch_index,
                    grant.generation,
                    grant.not_before,
                    grant.not_after,
                ] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
                out.extend_from_slice(grant.secret.as_ref());
            }
            Self::SessionUpdate { deadline } => {
                out.push(TAG_SESSION_UPDATE);
                out.extend_from_slice(&deadline.to_be_bytes());
            }
            Self::Close(reason) => {
                out.push(TAG_CLOSE);
                out.push(reason.code());
            }
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        let malformed = |what: &str| TransportError::Malformed(what.to_owned());
        let (&tag, body) = bytes
            .split_first()
            .ok_or_else(|| malformed("empty control"))?;
        match tag {
            TAG_APP => Ok(Self::App(body.to_vec())),
            TAG_KEY_UPDATE => {
                let (numbers, secret) = body
                    .split_at_checked(32)
                    .ok_or_else(|| malformed("short key_update"))?;
                let secret: [u8; 32] = secret
                    .try_into()
                    .map_err(|_| malformed("key_update secret is not 32 bytes"))?;
                let mut fields = numbers.chunks_exact(8).map(read_u64);
                let mut next = || fields.next().ok_or_else(|| malformed("short key_update"));
                Ok(Self::KeyUpdate(KeyGrant {
                    epoch_index: next()?,
                    generation: next()?,
                    not_before: next()?,
                    not_after: next()?,
                    secret: Zeroizing::new(secret),
                }))
            }
            TAG_SESSION_UPDATE => {
                let deadline: [u8; 8] = body
                    .try_into()
                    .map_err(|_| malformed("session_update is not 8 bytes"))?;
                Ok(Self::SessionUpdate {
                    deadline: u64::from_be_bytes(deadline),
                })
            }
            TAG_CLOSE => match body {
                [code] => CloseReason::from_code(*code)
                    .map(Self::Close)
                    .ok_or_else(|| malformed("unknown close reason")),
                _ => Err(malformed("close is not 1 byte")),
            },
            _ => Err(malformed("unknown control tag")),
        }
    }
}

fn read_u64(chunk: &[u8]) -> u64 {
    let mut word = [0_u8; 8];
    word.copy_from_slice(chunk);
    u64::from_be_bytes(word)
}

fn nonce(counter: u64) -> Nonce {
    let mut bytes = [0_u8; 12];
    bytes[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(bytes)
}

fn aad(label: &str, counter: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    put_prefixed(&mut out, label.as_bytes());
    out.push(WIRE_VERSION);
    out.push(TYPE_CONTROL);
    out.extend_from_slice(&counter.to_be_bytes());
    out
}

fn cipher(key: &[u8; 32]) -> Aes256GcmSiv {
    Aes256GcmSiv::new_from_slice(key).expect("AES-256 takes 32 bytes")
}

/// Seals one direction. Owned by the single task that writes it, so its
/// counter can never be reused.
pub struct Sealer {
    cipher: Aes256GcmSiv,
    label: &'static str,
    next: u64,
}

impl Sealer {
    pub(crate) fn new(key: &[u8; 32], label: &'static str) -> Self {
        Self {
            cipher: cipher(key),
            label,
            next: 0,
        }
    }

    /// Seals the next message.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::CounterExhausted`] after 2^64 − 1 messages.
    ///
    /// # Panics
    ///
    /// Cannot panic: AES-GCM-SIV encryption fails only for inputs over 2^36 bytes.
    pub fn seal(&mut self, message: &Control) -> Result<Vec<u8>, TransportError> {
        let counter = self.next;
        self.next = counter
            .checked_add(1)
            .ok_or(TransportError::CounterExhausted)?;
        let plaintext = message.encode();
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce(counter),
                Payload {
                    msg: &plaintext,
                    aad: &aad(self.label, counter),
                },
            )
            .expect("control messages are far below the AES-GCM-SIV limit");
        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.push(WIRE_VERSION);
        out.push(TYPE_CONTROL);
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
}

/// Opens one direction, in order. Any gap, repeat or forgery is an error, and
/// the caller ends the connection.
pub struct Opener {
    cipher: Aes256GcmSiv,
    label: &'static str,
    next: u64,
}

impl Opener {
    pub(crate) fn new(key: &[u8; 32], label: &'static str) -> Self {
        Self {
            cipher: cipher(key),
            label,
            next: 0,
        }
    }

    /// Opens the next message.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Malformed`] for a bad header,
    /// [`TransportError::OutOfSequence`] for a wrong counter, and
    /// [`TransportError::Decrypt`] for a forgery.
    pub fn open(&mut self, bytes: &[u8]) -> Result<Control, TransportError> {
        let (header, ciphertext) = bytes
            .split_at_checked(HEADER_LEN)
            .ok_or_else(|| TransportError::Malformed("short control message".to_owned()))?;
        let (kind, counter) = header.split_at(2);
        if kind != [WIRE_VERSION, TYPE_CONTROL] {
            return Err(TransportError::Malformed(
                "not a v2 control message".to_owned(),
            ));
        }
        let counter = read_u64(counter);
        if counter != self.next {
            return Err(TransportError::OutOfSequence {
                expected: self.next,
                got: counter,
            });
        }
        let plaintext = Zeroizing::new(
            self.cipher
                .decrypt(
                    &nonce(counter),
                    Payload {
                        msg: ciphertext,
                        aad: &aad(self.label, counter),
                    },
                )
                .map_err(|_| TransportError::Decrypt)?,
        );
        self.next = counter
            .checked_add(1)
            .ok_or(TransportError::CounterExhausted)?;
        Control::decode(&plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Sealer, Opener) {
        let key = [3_u8; 32];
        (Sealer::new(&key, N2C_LABEL), Opener::new(&key, N2C_LABEL))
    }

    fn grant() -> KeyGrant {
        KeyGrant {
            epoch_index: 7,
            generation: 9,
            not_before: 420,
            not_after: 480,
            secret: Zeroizing::new([5; 32]),
        }
    }

    #[test]
    fn every_control_message_round_trips() {
        let (mut sealer, mut opener) = pair();
        for message in [
            Control::App(br#"{"op":"subscribe"}"#.to_vec()),
            Control::KeyUpdate(grant()),
            Control::SessionUpdate { deadline: 1_234 },
            Control::Close(CloseReason::Revoked),
        ] {
            let sealed = sealer.seal(&message).expect("seals");
            assert_eq!(opener.open(&sealed).expect("opens"), message);
        }
    }

    #[test]
    fn a_replayed_reordered_or_tampered_message_is_refused() {
        let (mut sealer, mut opener) = pair();
        let first = sealer.seal(&Control::App(b"a".to_vec())).expect("seals");
        let second = sealer.seal(&Control::App(b"b".to_vec())).expect("seals");
        assert!(matches!(
            opener.open(&second),
            Err(TransportError::OutOfSequence {
                expected: 0,
                got: 1
            })
        ));
        opener.open(&first).expect("in order");
        assert!(matches!(
            opener.open(&first),
            Err(TransportError::OutOfSequence { .. })
        ));
        let mut tampered = second.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 1;
        }
        assert_eq!(opener.open(&tampered), Err(TransportError::Decrypt));
    }

    #[test]
    fn one_direction_cannot_be_reflected_into_the_other() {
        let key = [3_u8; 32];
        let mut n2c = Sealer::new(&key, N2C_LABEL);
        let mut c2n = Opener::new(&key, C2N_LABEL);
        let sealed = n2c.seal(&Control::App(b"x".to_vec())).expect("seals");
        assert_eq!(c2n.open(&sealed), Err(TransportError::Decrypt));
    }

    #[test]
    fn a_granted_key_rebuilds_only_under_the_dialled_node() {
        let a = grant().into_key("oracle-a");
        let again = grant().into_key("oracle-a");
        let b = grant().into_key("oracle-b");
        assert_eq!(a.key_id(), again.key_id());
        assert_ne!(a.key_id(), b.key_id());
        assert_eq!(KeyGrant::from_key(&a), grant());
    }
}
