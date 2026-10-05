//! The transport (SPEC §6.1): who may connect, and how the stream is encrypted.
//!
//! Pure: no sockets, no clocks, no tasks. Callers pass `now` and an RNG, so every
//! rule here is a unit test.
//!
//! Two layers, kept apart:
//! - **Per session**: the handshake, the control channel and key delivery. HPKE
//!   sets up the session keys; AES-256-GCM-SIV seals the control messages.
//! - **Per update**: one broadcast key per node and epoch. Each price frame is
//!   sealed once, and every subscriber gets the same bytes.
//!
//! Opening a frame proves nothing about the price inside. Every authorised
//! client holds the broadcast key, so every opened frame must still pass the
//! SDK verifier.

mod broadcast;
mod handshake;
mod schedule;
mod session;

pub use broadcast::{BroadcastSealer, KeyRing, NONCE_LEN, SEALED_FRAME_LEN, TYPE_FRAME};
pub use handshake::{
    Admitted, AwaitingAuthOk, ClientHandshake, ClientSession, HandshakeMessage, NodeHandshake,
    NodeSession,
};
pub use schedule::{
    EpochKey, KEY_GRACE_SECS, KEY_LEAD_SECS, KeyContext, KeyId, NodeKeySchedule, Tick, eligible,
    session_deadline,
};
pub use session::{CloseReason, Control, KeyGrant, Opener, Sealer, TYPE_CONTROL};

/// The version byte of every v2 binary message.
pub const WIRE_VERSION: u8 = 2;

/// The operating system's CSPRNG, in the form `hpke` and this crate take.
#[must_use]
pub fn os_rng() -> hpke::rand_core::UnwrapErr<getrandom::SysRng> {
    hpke::rand_core::UnwrapErr(getrandom::SysRng)
}

/// A transport rule was broken. Every variant ends the connection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// A message did not have the expected shape.
    #[error("malformed message: {0}")]
    Malformed(String),
    /// The peer speaks another protocol version.
    #[error("unsupported protocol `{0}`")]
    Protocol(String),
    /// The challenge names another node than the one dialled. After a
    /// rotation, the endpoint serves the node's new address.
    #[error("challenge is from node {got}, expected {expected}")]
    WrongNode {
        /// The node the client dialled.
        expected: oracle_wire::Address,
        /// The node named in the challenge.
        got: oracle_wire::Address,
    },
    /// The client's address is not in the client list.
    #[error("unknown client {0}")]
    UnknownClient(oracle_wire::Address),
    /// The client's authorisation has ended.
    #[error("client authorisation ended at {deadline} (now {now})")]
    Expired {
        /// The session deadline, unix seconds.
        deadline: u64,
        /// The time of the check, unix seconds.
        now: u64,
    },
    /// The client's signature does not match its key and this transcript.
    #[error("client signature does not verify")]
    BadSignature,
    /// The node's signature does not come from the dialled address.
    #[error("auth_ok is signed by {found}, expected the node {expected}")]
    UntrustedNode {
        /// Address recovered from the signature.
        found: oracle_wire::Address,
        /// The node the client dialled.
        expected: oracle_wire::Address,
    },
    /// HPKE setup or export failed.
    #[error("key agreement failed")]
    KeyAgreement,
    /// A ciphertext did not open: wrong key, wrong context, or tampered.
    #[error("message does not decrypt")]
    Decrypt,
    /// A frame names a key this side does not hold.
    #[error("unknown broadcast key")]
    UnknownKey,
    /// A control message arrived out of sequence.
    #[error("control message {got} out of sequence, expected {expected}")]
    OutOfSequence {
        /// The next counter this side accepts.
        expected: u64,
        /// The counter the message carried.
        got: u64,
    },
    /// A counter ran out. Unreachable in practice; reconnect.
    #[error("message counter exhausted")]
    CounterExhausted,
    /// The wire crate refused an encoding.
    #[error(transparent)]
    Wire(#[from] oracle_wire::WireError),
}
