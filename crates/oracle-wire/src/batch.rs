//! The price batch: several price updates under one signature (SPEC §3.4).
//!
//! A node pushes a batch to the registry canister, which then checks one
//! signature for the whole push instead of one for each update.
//!
//! ```text
//! payload:
//! [0]       u8       version = 1
//! [1]       u8       kind = 0x02
//! [2..4]    u16      update count N, 1..=32
//! then      N × 96   price update payloads (SPEC §3.3), each feed at most once
//!
//! frame: [0] type = 5 ‖ [1..21] signer hint ‖ payload ‖ 65-byte signature
//! ```

use std::collections::HashSet;

use oracle_types::PriceUpdate;

use crate::Recovered;
use crate::codec::{Reader, Sink as _};
use crate::payload::{
    KIND_PRICE_BATCH, PAYLOAD_VERSION, PRICE_UPDATE_SIZE, decode_price_update, encode_price_update,
};
use crate::registry::VerifiedRegistry;
use crate::varframe::{self, RawFrame};
use crate::{Address, Signature, Signer, VerifyError, WireError};

/// Frame type for a price batch.
pub const FRAME_TYPE_PRICE_BATCH: u8 = 5;

/// The most updates that one batch carries.
pub const MAX_BATCH_UPDATES: usize = 32;

const HEADER_SIZE: usize = 4;

/// Encodes price updates into one canonical batch payload.
///
/// # Errors
///
/// Returns [`WireError::NonCanonical`] for no updates or a feed twice, and
/// [`WireError::TooManyEntries`] for more than [`MAX_BATCH_UPDATES`].
pub fn encode_price_batch(updates: &[PriceUpdate]) -> Result<Vec<u8>, WireError> {
    check_updates(updates)?;
    let mut buf = Vec::with_capacity(HEADER_SIZE + updates.len() * PRICE_UPDATE_SIZE);
    buf.put_u8(PAYLOAD_VERSION);
    buf.put_u8(KIND_PRICE_BATCH);
    buf.put_u16(u16::try_from(updates.len()).unwrap_or(u16::MAX));
    for update in updates {
        buf.put_bytes(&encode_price_update(update));
    }
    Ok(buf)
}

/// Decodes a canonical batch payload.
///
/// # Errors
///
/// Returns [`WireError`] if the bytes are not exactly one canonical v1 batch:
/// a count that does not match the length, an update that does not decode,
/// or a feed twice.
pub fn decode_price_batch(bytes: &[u8]) -> Result<Vec<PriceUpdate>, WireError> {
    let mut reader = Reader::new(bytes);
    let version = reader.u8()?;
    if version != PAYLOAD_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }
    let kind = reader.u8()?;
    if kind != KIND_PRICE_BATCH {
        return Err(WireError::UnexpectedKind {
            expected: KIND_PRICE_BATCH,
            actual: kind,
        });
    }
    let count = usize::from(reader.u16()?);
    if count > MAX_BATCH_UPDATES {
        return Err(WireError::TooManyEntries {
            actual: count,
            limit: MAX_BATCH_UPDATES,
        });
    }
    let mut updates = Vec::with_capacity(count);
    for _ in 0..count {
        updates.push(decode_price_update(reader.take(PRICE_UPDATE_SIZE)?)?);
    }
    reader.finish()?;
    check_updates(&updates)?;
    Ok(updates)
}

fn check_updates(updates: &[PriceUpdate]) -> Result<(), WireError> {
    if updates.is_empty() {
        return Err(WireError::NonCanonical("a batch with no updates"));
    }
    if updates.len() > MAX_BATCH_UPDATES {
        return Err(WireError::TooManyEntries {
            actual: updates.len(),
            limit: MAX_BATCH_UPDATES,
        });
    }
    let mut feeds = HashSet::with_capacity(updates.len());
    if updates.iter().all(|update| feeds.insert(update.feed_id)) {
        Ok(())
    } else {
        Err(WireError::NonCanonical("a feed twice in one batch"))
    }
}

/// A price batch this node has just signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPriceBatch {
    updates: Vec<PriceUpdate>,
    payload: Vec<u8>,
    signature: Signature,
    signer: Address,
}

impl SignedPriceBatch {
    /// Returns the updates.
    #[must_use]
    pub fn updates(&self) -> &[PriceUpdate] {
        &self.updates
    }

    /// Returns the signing address.
    #[must_use]
    pub const fn signer(&self) -> Address {
        self.signer
    }

    /// Returns the canonical signed bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the signature.
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }

    /// Encodes the wire frame.
    #[must_use]
    pub fn encode_frame(&self) -> Vec<u8> {
        varframe::encode(
            FRAME_TYPE_PRICE_BATCH,
            self.signer,
            &self.payload,
            self.signature,
        )
    }
}

impl Signer {
    /// Signs price updates as one batch.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if the updates cannot form a batch; see
    /// [`encode_price_batch`].
    ///
    /// # Panics
    ///
    /// See [`Signer::sign_digest`].
    pub fn sign_price_batch(&self, updates: &[PriceUpdate]) -> Result<SignedPriceBatch, WireError> {
        let payload = encode_price_batch(updates)?;
        let signature = self.sign_payload(&payload);
        Ok(SignedPriceBatch {
            updates: updates.to_vec(),
            payload,
            signature,
            signer: self.address(),
        })
    }
}

/// A structurally valid batch frame that has **not** been checked against a
/// registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedPriceBatch {
    raw: RawFrame,
}

impl UnverifiedPriceBatch {
    /// Parses a frame, checking only its structure.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::UnknownFrameType`] for another frame type, a length
    /// error outside the payload bounds, and signature errors from
    /// [`Signature::from_bytes`].
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        RawFrame::parse(
            bytes,
            FRAME_TYPE_PRICE_BATCH,
            HEADER_SIZE + PRICE_UPDATE_SIZE,
            HEADER_SIZE + MAX_BATCH_UPDATES * PRICE_UPDATE_SIZE,
        )
        .map(|raw| Self { raw })
    }

    /// Returns the address the frame *claims* to be from. Outside the signature.
    #[must_use]
    pub const fn signer_hint(&self) -> Address {
        self.raw.signer_hint
    }

    /// Decodes the payload **without** any trust check, for checks that cost
    /// less than a signature recovery.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if the payload is not a canonical batch.
    pub fn decode_unverified(&self) -> Result<Vec<PriceUpdate>, WireError> {
        decode_price_batch(&self.raw.payload)
    }

    /// Verifies the frame against a trusted registry: one signature for every
    /// update. Freshness and the sequence are the consumer's job, as for a
    /// price frame.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError`] for malformed payloads and unknown signers.
    pub fn verify(&self, registry: &VerifiedRegistry) -> Result<VerifiedPriceBatch, VerifyError> {
        self.recover()?.authorize(registry)
    }

    /// Decodes the payload and recovers the signer: the costly half of [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError`] for a malformed payload or a failed recovery.
    pub fn recover(&self) -> Result<Recovered<Vec<PriceUpdate>>, VerifyError> {
        let updates = decode_price_batch(&self.raw.payload)?;
        Ok(Recovered::new(updates, self.raw.recover_signer()?))
    }
}

impl Recovered<Vec<PriceUpdate>> {
    /// Finds the signer in a trusted registry: the second half of
    /// [`UnverifiedPriceBatch::verify`].
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::UnknownSigner`] if no node has the signer's address.
    pub fn authorize(self, registry: &VerifiedRegistry) -> Result<VerifiedPriceBatch, VerifyError> {
        let node_index = registry.authorize(self.signer)?;
        Ok(VerifiedPriceBatch {
            updates: self.value,
            signer: self.signer,
            node_index,
        })
    }
}

/// A price batch that a registered node provably signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPriceBatch {
    updates: Vec<PriceUpdate>,
    signer: Address,
    node_index: usize,
}

impl VerifiedPriceBatch {
    /// Returns the updates.
    #[must_use]
    pub fn updates(&self) -> &[PriceUpdate] {
        &self.updates
    }

    /// Consumes this wrapper and returns the updates.
    #[must_use]
    pub fn into_updates(self) -> Vec<PriceUpdate> {
        self.updates
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
    use oracle_types::{FeedId, Flags, Venue, VenueSet};

    use super::*;
    use crate::registry::{NodeEntry, Quorum, Registry};

    fn node() -> Signer {
        Signer::from_secret_bytes([0x21; 32]).expect("valid key")
    }

    fn registry() -> VerifiedRegistry {
        let governance = Signer::from_secret_bytes([0x91; 32]).expect("valid key");
        let entry = NodeEntry {
            address: node().address(),
            endpoints: vec!["wss://eu1.example/v2/ws".to_owned()],
            weight: 1,
        };
        let quorum = Quorum {
            min_nodes: 1,
            recommended: 3,
        };
        Registry::sign(&governance, 1, 1_754_582_400, vec![entry], quorum)
            .expect("signs")
            .verify(governance.address(), 0)
            .expect("verifies")
    }

    fn update(feed: u8, seq: u64) -> PriceUpdate {
        PriceUpdate {
            feed_id: FeedId::from_bytes([feed; 32]),
            flags: Flags::NONE,
            price: 6_400_000_000_000,
            conf: 50_000_000,
            expo: -8,
            publish_time_ns: 1_754_582_400_000_000_000,
            observation_time_ns: 1_754_582_399_999_000_000,
            prev_publish_time_ns: 1_754_582_399_000_000_000,
            seq,
            num_sources: 5,
            sources: Venue::ALL.into_iter().collect::<VenueSet>(),
        }
    }

    #[test]
    fn a_batch_round_trips_and_verifies_with_one_signature() {
        let updates = [update(1, 7), update(2, 8)];
        let signed = node().sign_price_batch(&updates).expect("signs");
        let frame = signed.encode_frame();
        assert_eq!(frame.len(), 1 + 20 + 4 + 2 * 96 + 65);
        let parsed = UnverifiedPriceBatch::parse(&frame).expect("parses");
        assert_eq!(parsed.decode_unverified().expect("decodes"), updates);
        let verified = parsed.verify(&registry()).expect("verifies");
        assert_eq!(verified.updates(), updates);
        assert_eq!(verified.signer(), node().address());
    }

    #[test]
    fn an_empty_batch_a_feed_twice_and_too_many_updates_are_refused() {
        assert!(encode_price_batch(&[]).is_err());
        assert!(encode_price_batch(&[update(1, 1), update(1, 2)]).is_err());
        let many: Vec<PriceUpdate> = (0..=32).map(|feed| update(feed, 1)).collect();
        assert!(matches!(
            encode_price_batch(&many),
            Err(WireError::TooManyEntries { actual: 33, .. })
        ));
    }

    #[test]
    fn a_count_that_does_not_match_the_length_is_refused() {
        let mut payload = encode_price_batch(&[update(1, 1), update(2, 1)]).expect("encodes");
        if let Some(count) = payload.get_mut(3) {
            *count = 1;
        }
        assert!(decode_price_batch(&payload).is_err());
    }

    /// The kind byte is inside the signed bytes, so the signature of a batch
    /// of one update recovers to another address on that update's own frame.
    #[test]
    fn a_batch_signature_never_passes_as_a_price_frame() {
        let single = update(1, 1);
        let signed = node().sign_price_batch(&[single]).expect("signs");
        let mut frame = vec![crate::FRAME_TYPE_PRICE_UPDATE];
        frame.extend_from_slice(node().address().as_bytes());
        frame.extend_from_slice(&encode_price_update(&single));
        frame.extend_from_slice(signed.signature().as_bytes());
        let parsed = crate::UnverifiedFrame::parse(&frame).expect("a well-formed frame");
        assert!(matches!(
            parsed.verify(&registry()),
            Err(VerifyError::UnknownSigner { .. })
        ));
    }
}
