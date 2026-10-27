//! Error types for encoding, signing, and verification.
//!
//! The split between [`WireError`] and [`VerifyError`] is deliberate and maps
//! onto a distinction that matters: [`WireError`] means "these bytes are not a
//! well-formed update", while [`VerifyError`] means "these bytes are well-formed
//! and correctly signed, but not by anyone we trust". Collapsing the two invites
//! the mistake of treating a successful signature recovery as a successful
//! verification.

use crate::Address;

/// A structural or cryptographic failure while decoding or signing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WireError {
    /// The input was shorter than the format requires.
    #[error("truncated input: need {expected} bytes, got {actual}")]
    Truncated {
        /// Bytes required.
        expected: usize,
        /// Bytes supplied.
        actual: usize,
    },

    /// Trailing bytes remained after decoding a fixed-size structure.
    #[error("trailing bytes: {0} unexpected byte(s) after the payload")]
    TrailingBytes(usize),

    /// The payload declared a protocol version this build does not implement.
    #[error("unsupported payload version {0}")]
    UnsupportedVersion(u8),

    /// The payload declared a different kind than the decoder expected.
    #[error("unexpected payload kind {actual:#04x}, expected {expected:#04x}")]
    UnexpectedKind {
        /// Kind the decoder was called for.
        expected: u8,
        /// Kind found in the payload.
        actual: u8,
    },

    /// The frame declared an unknown frame type.
    #[error("unknown frame type {0:#04x}")]
    UnknownFrameType(u8),

    /// Reserved flag bits were set. See `oracle_types::Flags` for why this is a
    /// rejection rather than a mask.
    #[error("reserved flag bits set: {0:#06x}")]
    ReservedFlags(u16),

    /// The source bitmap referenced venues this build does not know.
    #[error("source bitmap {0:#010x} references unassigned venues")]
    UnassignedVenueBits(u32),

    /// The recovery byte was not 27 or 28.
    #[error("invalid recovery byte {0}, expected 27 or 28")]
    InvalidRecoveryByte(u8),

    /// The signature's `s` value was above the curve half-order.
    ///
    /// High-`s` signatures are malleable: for every valid signature there is a
    /// second, equally valid byte string. Accepting both would break signature-keyed
    /// deduplication and caching, so only the canonical low-`s` form is allowed.
    #[error("non-canonical signature: s value is above the curve half-order")]
    HighS,

    /// The signature's `r` or `s` value was zero.
    #[error("invalid signature: r or s is zero")]
    ZeroScalar,

    /// Public key recovery failed.
    #[error("public key recovery failed")]
    RecoveryFailed,

    /// A secret key was not a valid scalar for the curve.
    #[error("invalid secret key")]
    InvalidSecretKey,

    /// The operating system's entropy source could not be read.
    ///
    /// Fatal by design. Falling back to a weaker source would produce a key that
    /// looks exactly like a good one and is guessable, and nothing downstream
    /// could ever detect the difference.
    #[error("cannot read entropy from the operating system: {0}")]
    EntropyUnavailable(String),

    /// A compressed public key did not decode to a curve point.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// A mixed-case address failed its EIP-55 checksum.
    ///
    /// Lowercase carries no checksum and is accepted as is. Mixed case is a
    /// claim, and a claim that does not check out is a typo in a pinned address.
    #[error("address {0} is mixed-case but fails its EIP-55 checksum")]
    AddressChecksum(String),

    /// A hex-encoded field was malformed or the wrong length.
    #[error("invalid hex for {field}: expected {expected} bytes")]
    InvalidHex {
        /// Which field failed.
        field: &'static str,
        /// Expected decoded length in bytes.
        expected: usize,
    },

    /// A venue report listed more entries than the format allows.
    #[error("too many venue entries: {actual} exceeds the limit of {limit}")]
    TooManyEntries {
        /// Entries listed.
        actual: usize,
        /// Maximum permitted.
        limit: usize,
    },

    /// A one-byte code was not one this build knows.
    #[error("unknown {field} code {value}")]
    UnknownCode {
        /// Which field.
        field: &'static str,
        /// The code.
        value: u8,
    },

    /// A value has more than one byte form, and this was not the canonical one.
    ///
    /// A signature commits to bytes. Two encodings of one report would give two
    /// valid signatures for it.
    #[error("non-canonical encoding: {0}")]
    NonCanonical(&'static str),

    /// A length-delimited field exceeded its cap.
    ///
    /// The caps exist so that parsing an untrusted registry cannot be turned
    /// into unbounded work or memory.
    #[error("field `{field}` too long: {actual} exceeds the limit of {limit}")]
    FieldTooLong {
        /// Which field failed.
        field: &'static str,
        /// Observed length.
        actual: usize,
        /// Maximum permitted.
        limit: usize,
    },

    /// A string field was not valid UTF-8.
    #[error("field `{0}` is not valid UTF-8")]
    InvalidUtf8(&'static str),
}

/// A trust failure: the bytes are well-formed, but not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The update was malformed or its signature was structurally invalid.
    #[error(transparent)]
    Wire(#[from] WireError),

    /// The signature recovered to a key that is not in the registry.
    ///
    /// This is the expected outcome for a forged update: recovery itself always
    /// succeeds for a well-formed signature and yields *some* address. Only the
    /// registry lookup distinguishes a node from an impostor.
    #[error("signer {signer} is not in the registry")]
    UnknownSigner {
        /// The recovered address.
        signer: Address,
    },

    /// A stored update was signed while its signer was not listed.
    ///
    /// Judged against the update's publish time, not the current time, so a
    /// rotation does not invalidate what the old key signed while listed.
    #[error("{signer} was not listed at {published} (listed from {added_at} until {removed_at:?})")]
    NotListedAt {
        /// The recovered address.
        signer: Address,
        /// Update publish time, unix seconds.
        published: u64,
        /// When the address was listed, unix seconds.
        added_at: u64,
        /// When it stopped being listed, unix seconds.
        removed_at: Option<u64>,
    },

    /// A governance document's signature did not match the pinned key.
    #[error("governance signature is from {found}, expected {expected}")]
    UntrustedGovernance {
        /// Address recovered from the registry signature.
        found: Address,
        /// Address the caller pinned.
        expected: Address,
    },

    /// The registry version was not newer than the version already trusted.
    ///
    /// Rejecting equal or lower versions is what stops an attacker from replaying
    /// an old registry to reinstate a revoked key.
    #[error("registry version {found} is not newer than the trusted version {minimum}")]
    StaleRegistry {
        /// Version in the supplied registry.
        found: u64,
        /// Minimum the caller will accept.
        minimum: u64,
    },

    /// The registry was structurally invalid.
    #[error("malformed registry: {0}")]
    MalformedRegistry(String),

    /// The client list version was not newer than the version already trusted.
    #[error("client list version {found} is not newer than the trusted version {minimum}")]
    StaleClientList {
        /// Version in the supplied list.
        found: u64,
        /// Minimum the caller will accept.
        minimum: u64,
    },

    /// The client list was structurally invalid.
    #[error("malformed client list: {0}")]
    MalformedClientList(String),

    /// The feed set version was not newer than the version already trusted.
    #[error("feed set version {found} is not newer than the trusted version {minimum}")]
    StaleFeedSet {
        /// Version in the supplied set.
        found: u64,
        /// Minimum the caller will accept.
        minimum: u64,
    },

    /// The feed set was structurally invalid.
    #[error("malformed feed set: {0}")]
    MalformedFeedSet(String),
}
