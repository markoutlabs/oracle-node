//! The 182-byte wire frame, and the typestate that makes verification unskippable.
//!
//! ```text
//! [0]        u8       frame type = 1
//! [1..21]    [u8;20]  signer address  — UNAUTHENTICATED routing hint
//! [21..117]  [u8;96]  payload         — the signed bytes
//! [117..182] [u8;65]  signature       — r ‖ s ‖ v
//! ```
//!
//! # Why the types are shaped this way
//!
//! Parsing a frame yields an [`UnverifiedFrame`], which deliberately does not
//! hand out a [`PriceUpdate`] you can act on. The only method that produces a
//! [`VerifiedUpdate`] requires a [`VerifiedRegistry`], so the single most
//! dangerous mistake a consumer can make — recovering a signer and treating that
//! as verification — is not expressible by accident.
//!
//! Recovery on its own always succeeds and always yields *some* address. An
//! attacker signing with a key generated a moment ago produces a frame that
//! recovers flawlessly. Only the registry lookup distinguishes a node from an
//! impostor.

use oracle_types::PriceUpdate;

use crate::Recovered;
use crate::payload::{PRICE_UPDATE_SIZE, decode_price_update, encode_price_update};
use crate::registry::VerifiedRegistry;
use crate::signature::SIGNATURE_LEN;
use crate::{Address, Signature, Signer, VerifyError, WireError, domain, signer};

/// Frame type for a price update.
pub const FRAME_TYPE_PRICE_UPDATE: u8 = 1;

/// Total size of a price-update frame.
pub const FRAME_SIZE: usize = 1 + Address::LEN + PRICE_UPDATE_SIZE + SIGNATURE_LEN;

const PAYLOAD_START: usize = 1 + Address::LEN;
const SIGNATURE_START: usize = PAYLOAD_START + PRICE_UPDATE_SIZE;

/// A price update this node has just signed.
///
/// Holds the encoded payload so that emitting a frame to many subscribers costs
/// no re-encoding and no re-signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedUpdate {
    update: PriceUpdate,
    payload: [u8; PRICE_UPDATE_SIZE],
    signature: Signature,
    signer: Address,
}

impl SignedUpdate {
    /// Returns the update.
    #[must_use]
    pub const fn update(&self) -> &PriceUpdate {
        &self.update
    }

    /// Returns the canonical signed bytes.
    #[must_use]
    pub const fn payload(&self) -> &[u8; PRICE_UPDATE_SIZE] {
        &self.payload
    }

    /// Returns the signature.
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }

    /// Returns the signing address.
    #[must_use]
    pub const fn signer(&self) -> Address {
        self.signer
    }

    /// Encodes the wire frame.
    #[must_use]
    pub fn encode_frame(&self) -> [u8; FRAME_SIZE] {
        let mut frame = [0_u8; FRAME_SIZE];
        if let Some(slot) = frame.first_mut() {
            *slot = FRAME_TYPE_PRICE_UPDATE;
        }
        if let Some(slice) = frame.get_mut(1..PAYLOAD_START) {
            slice.copy_from_slice(self.signer.as_bytes());
        }
        if let Some(slice) = frame.get_mut(PAYLOAD_START..SIGNATURE_START) {
            slice.copy_from_slice(&self.payload);
        }
        if let Some(slice) = frame.get_mut(SIGNATURE_START..) {
            slice.copy_from_slice(self.signature.as_bytes());
        }
        frame
    }
}

impl Signer {
    /// Signs a price update.
    ///
    /// # Panics
    ///
    /// See [`Signer::sign_digest`].
    #[must_use]
    pub fn sign_update(&self, update: &PriceUpdate) -> SignedUpdate {
        let payload = encode_price_update(update);
        let signature = self.sign_payload(&payload);
        SignedUpdate {
            update: *update,
            payload,
            signature,
            signer: self.address(),
        }
    }
}

/// A structurally valid frame that has **not** been checked against a registry.
///
/// See the module documentation for why this type exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedFrame {
    payload: [u8; PRICE_UPDATE_SIZE],
    signature: Signature,
    signer_hint: Address,
}

impl UnverifiedFrame {
    /// Parses a frame, checking only its structure.
    ///
    /// # Errors
    ///
    /// - [`WireError::Truncated`] or [`WireError::TrailingBytes`] if the input is
    ///   not exactly [`FRAME_SIZE`] bytes.
    /// - [`WireError::UnknownFrameType`] for an unrecognised leading byte.
    /// - Signature errors from [`Signature::from_bytes`], including the
    ///   non-canonical high-`s` form.
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < FRAME_SIZE {
            return Err(WireError::Truncated {
                expected: FRAME_SIZE,
                actual: bytes.len(),
            });
        }
        if bytes.len() > FRAME_SIZE {
            return Err(WireError::TrailingBytes(bytes.len() - FRAME_SIZE));
        }

        let frame_type = bytes.first().copied().unwrap_or_default();
        if frame_type != FRAME_TYPE_PRICE_UPDATE {
            return Err(WireError::UnknownFrameType(frame_type));
        }

        let mut signer_hint = [0_u8; Address::LEN];
        signer_hint.copy_from_slice(bytes.get(1..PAYLOAD_START).ok_or(WireError::Truncated {
            expected: FRAME_SIZE,
            actual: bytes.len(),
        })?);

        let mut payload = [0_u8; PRICE_UPDATE_SIZE];
        payload.copy_from_slice(bytes.get(PAYLOAD_START..SIGNATURE_START).ok_or(
            WireError::Truncated {
                expected: FRAME_SIZE,
                actual: bytes.len(),
            },
        )?);

        let mut signature = [0_u8; SIGNATURE_LEN];
        signature.copy_from_slice(bytes.get(SIGNATURE_START..).ok_or(WireError::Truncated {
            expected: FRAME_SIZE,
            actual: bytes.len(),
        })?);

        Ok(Self {
            payload,
            signature: Signature::from_bytes(signature)?,
            signer_hint: Address::from_bytes(signer_hint),
        })
    }

    /// Returns the frame's signed bytes.
    #[must_use]
    pub const fn payload(&self) -> &[u8; PRICE_UPDATE_SIZE] {
        &self.payload
    }

    /// Returns the signature.
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }

    /// Returns the address the frame *claims* to be from.
    ///
    /// This field is outside the signature. It is a routing hint for dispatching
    /// work before the expensive recovery, and nothing else. Never compare it
    /// against a registry.
    #[must_use]
    pub const fn signer_hint(&self) -> Address {
        self.signer_hint
    }

    /// Recovers the address that actually signed the payload.
    ///
    /// # Security
    ///
    /// This establishes authorship, not trust. See the module documentation.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::RecoveryFailed`] if recovery fails.
    pub fn recover_signer(&self) -> Result<Address, WireError> {
        signer::recover_address(&domain::digest(&self.payload), &self.signature)
    }

    /// Returns `true` if the unauthenticated hint matches the recovered signer.
    ///
    /// A mismatch means a buggy or mischievous relay rewrote the hint. It is not
    /// a security failure — the hint carries no authority — but it is worth a
    /// metric.
    #[must_use]
    pub fn hint_matches(&self) -> bool {
        self.recover_signer()
            .is_ok_and(|recovered| recovered == self.signer_hint)
    }

    /// Decodes the payload **without** any trust check.
    ///
    /// For tooling, replay, and diagnostics. Never for pricing decisions: these
    /// bytes may have been signed by anyone at all.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if the payload is not a well-formed v1 price update.
    pub fn decode_unverified(&self) -> Result<PriceUpdate, WireError> {
        decode_price_update(&self.payload)
    }

    /// Verifies the frame against a trusted registry.
    ///
    /// # What this checks, and what it does not
    ///
    /// Checked here: payload well-formedness, signature canonicality, and that
    /// the recovered signer is a registered node.
    ///
    /// **Not** checked here, and mandatory before acting on the price:
    /// sequence-number monotonicity per `(node, feed)`, staleness against the
    /// local clock, and cross-node quorum. Those are consumer policy and live in
    /// the client SDK. A verified update is one that a known node really did
    /// sign — it is not necessarily fresh, and a signed update is a bearer token
    /// that stays valid forever.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError`] for malformed payloads and unknown signers.
    pub fn verify(&self, registry: &VerifiedRegistry) -> Result<VerifiedUpdate, VerifyError> {
        self.recover()?.authorize(registry)
    }

    /// Decodes the payload and recovers the signer: the costly half of [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError`] for a malformed payload or a failed recovery.
    pub fn recover(&self) -> Result<Recovered<PriceUpdate>, VerifyError> {
        let update = decode_price_update(&self.payload)?;
        Ok(Recovered::new(update, self.recover_signer()?))
    }
}

impl Recovered<PriceUpdate> {
    /// Finds the signer in a trusted registry: the second half of
    /// [`UnverifiedFrame::verify`].
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::UnknownSigner`] if no node has the signer's address.
    pub fn authorize(self, registry: &VerifiedRegistry) -> Result<VerifiedUpdate, VerifyError> {
        let node_index = registry.authorize(self.signer)?;
        Ok(VerifiedUpdate {
            update: self.value,
            signer: self.signer,
            node_index,
        })
    }
}

/// An update that a registered node provably signed.
///
/// Freshness and quorum are still the consumer's job — see
/// [`UnverifiedFrame::verify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedUpdate {
    update: PriceUpdate,
    signer: Address,
    node_index: usize,
}

impl VerifiedUpdate {
    /// Returns the update.
    #[must_use]
    pub const fn update(&self) -> &PriceUpdate {
        &self.update
    }

    /// Consumes this wrapper and returns the update.
    #[must_use]
    pub const fn into_update(self) -> PriceUpdate {
        self.update
    }

    /// Returns the signing address.
    #[must_use]
    pub const fn signer(&self) -> Address {
        self.signer
    }

    /// Returns the index of the signing node in the registry it was verified against.
    #[must_use]
    pub const fn node_index(&self) -> usize {
        self.node_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{NodeEntry, Quorum, Registry};
    use oracle_types::{FeedId, Flags, NANOS_PER_SEC, Venue};

    const NOW_SECS: u64 = 1_754_582_400;

    fn governance() -> Signer {
        Signer::from_secret_bytes([0x91; 32]).expect("valid key")
    }

    fn hot() -> Signer {
        Signer::from_secret_bytes([0x21; 32]).expect("valid key")
    }

    fn verified_registry() -> VerifiedRegistry {
        let node = NodeEntry {
            address: hot().address(),
            endpoints: vec!["wss://eu1.example/v2/ws".to_owned()],
            weight: 1,
        };
        Registry::sign(
            &governance(),
            1,
            NOW_SECS,
            vec![node],
            Quorum {
                min_nodes: 1,
                recommended: 3,
            },
        )
        .expect("signs")
        .verify(governance().address(), 0)
        .expect("verifies")
    }

    fn update() -> PriceUpdate {
        PriceUpdate {
            feed_id: FeedId::from_bytes([0x11; 32]),
            flags: Flags::NONE,
            price: 6_431_250_000_000,
            conf: 3_200_000,
            expo: -8,
            publish_time_ns: NOW_SECS * NANOS_PER_SEC,
            observation_time_ns: NOW_SECS * NANOS_PER_SEC - 2_000_000,
            prev_publish_time_ns: (NOW_SECS - 1) * NANOS_PER_SEC,
            seq: 42,
            num_sources: 2,
            sources: [Venue::Binance, Venue::Coinbase].into_iter().collect(),
        }
    }

    #[test]
    fn frame_size_matches_the_specification() {
        assert_eq!(FRAME_SIZE, 182);
    }

    #[test]
    fn sign_encode_parse_verify_round_trip() {
        let signed = hot().sign_update(&update());
        let frame = signed.encode_frame();
        assert_eq!(frame.len(), FRAME_SIZE);
        assert_eq!(frame[0], FRAME_TYPE_PRICE_UPDATE);

        let parsed = UnverifiedFrame::parse(&frame).expect("parses");
        assert_eq!(parsed.signer_hint(), hot().address());
        assert!(parsed.hint_matches());

        let verified = parsed.verify(&verified_registry()).expect("verifies");
        assert_eq!(verified.update(), &update());
        assert_eq!(verified.signer(), hot().address());
        assert_eq!(verified.node_index(), 0);
    }

    #[test]
    fn recover_then_authorize_is_verify() {
        let frame = hot().sign_update(&update()).encode_frame();
        let parsed = UnverifiedFrame::parse(&frame).expect("parses");
        let recovered = parsed.recover().expect("recovers");
        assert_eq!(recovered.signer(), hot().address());
        assert_eq!(recovered.unverified(), &update());
        assert_eq!(
            recovered.authorize(&verified_registry()),
            parsed.verify(&verified_registry())
        );
    }

    #[test]
    fn a_forged_update_recovers_but_is_not_authorized() {
        let impostor = Signer::from_secret_bytes([0xDD; 32]).expect("valid key");
        let frame = impostor.sign_update(&update()).encode_frame();
        let recovered = UnverifiedFrame::parse(&frame)
            .expect("parses")
            .recover()
            .expect("recovers");
        assert_eq!(recovered.signer(), impostor.address());
        assert!(matches!(
            recovered.authorize(&verified_registry()),
            Err(VerifyError::UnknownSigner { .. })
        ));
    }

    #[test]
    fn a_forged_update_recovers_cleanly_but_fails_verification() {
        // The whole point: recovery is not verification.
        let impostor = Signer::from_secret_bytes([0xDD; 32]).expect("valid key");
        let mut forged = update();
        forged.price = 1;
        let frame = impostor.sign_update(&forged).encode_frame();

        let parsed = UnverifiedFrame::parse(&frame).expect("parses");
        assert_eq!(
            parsed.recover_signer().expect("recovers"),
            impostor.address()
        );
        assert!(matches!(
            parsed.verify(&verified_registry()),
            Err(VerifyError::UnknownSigner { .. })
        ));
    }

    #[test]
    fn tampering_with_the_payload_breaks_verification() {
        let signed = hot().sign_update(&update());
        let mut frame = signed.encode_frame();
        // Bump the price mantissa inside the signed region.
        frame[PAYLOAD_START + 36] ^= 0x01;

        let parsed = UnverifiedFrame::parse(&frame).expect("parses");
        assert_ne!(parsed.recover_signer().expect("recovers"), hot().address());
        assert!(parsed.verify(&verified_registry()).is_err());
    }

    #[test]
    fn rewriting_the_hint_does_not_grant_trust() {
        let impostor = Signer::from_secret_bytes([0xDD; 32]).expect("valid key");
        let mut frame = impostor.sign_update(&update()).encode_frame();
        // Claim to be the legitimate node.
        frame[1..PAYLOAD_START].copy_from_slice(hot().address().as_bytes());

        let parsed = UnverifiedFrame::parse(&frame).expect("parses");
        assert_eq!(parsed.signer_hint(), hot().address());
        assert!(
            !parsed.hint_matches(),
            "the hint is a lie and must be detectable"
        );
        assert!(matches!(
            parsed.verify(&verified_registry()),
            Err(VerifyError::UnknownSigner { .. })
        ));
    }

    #[test]
    fn rejects_malformed_frames() {
        let frame = hot().sign_update(&update()).encode_frame();

        assert!(matches!(
            UnverifiedFrame::parse(&frame[..FRAME_SIZE - 1]),
            Err(WireError::Truncated {
                expected: FRAME_SIZE,
                ..
            })
        ));

        let mut long = frame.to_vec();
        long.push(0);
        assert_eq!(
            UnverifiedFrame::parse(&long),
            Err(WireError::TrailingBytes(1))
        );

        let mut wrong_type = frame;
        wrong_type[0] = 9;
        assert_eq!(
            UnverifiedFrame::parse(&wrong_type),
            Err(WireError::UnknownFrameType(9))
        );

        let mut high_s = frame;
        high_s[SIGNATURE_START + 32] |= 0x80;
        assert_eq!(UnverifiedFrame::parse(&high_s), Err(WireError::HighS));
    }

    #[test]
    fn signed_update_exposes_the_exact_signed_bytes() {
        let signed = hot().sign_update(&update());
        let frame = signed.encode_frame();
        assert_eq!(
            &frame[PAYLOAD_START..SIGNATURE_START],
            signed.payload().as_slice()
        );
        assert_eq!(
            &frame[SIGNATURE_START..],
            signed.signature().as_bytes().as_slice()
        );
    }
}
