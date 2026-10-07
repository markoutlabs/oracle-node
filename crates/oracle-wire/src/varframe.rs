//! The frame shape shared by the variable-length payloads: venue reports and
//! book updates.
//!
//! ```text
//! [0] frame type ‖ [1..21] signer hint ‖ payload ‖ 65-byte signature
//! ```

use crate::signature::SIGNATURE_LEN;
use crate::{Address, Signature, WireError, domain, signer};

/// The parts of a parsed frame. Nothing here is trusted yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawFrame {
    pub(crate) payload: Vec<u8>,
    pub(crate) signature: Signature,
    pub(crate) signer_hint: Address,
}

impl RawFrame {
    /// Splits a frame of `frame_type` whose payload is `min..=max` bytes long.
    pub(crate) fn parse(
        bytes: &[u8],
        frame_type: u8,
        min: usize,
        max: usize,
    ) -> Result<Self, WireError> {
        let found = bytes.first().copied().unwrap_or_default();
        if found != frame_type {
            return Err(WireError::UnknownFrameType(found));
        }
        let overhead = 1 + Address::LEN + SIGNATURE_LEN;
        let truncated = WireError::Truncated {
            expected: overhead + min,
            actual: bytes.len(),
        };
        if bytes.len() < overhead + min {
            return Err(truncated);
        }
        if bytes.len() > overhead + max {
            return Err(WireError::TrailingBytes(bytes.len() - overhead - max));
        }
        let signature_start = bytes.len() - SIGNATURE_LEN;
        let hint: [u8; Address::LEN] = bytes
            .get(1..=Address::LEN)
            .and_then(|hint| hint.try_into().ok())
            .ok_or(truncated.clone())?;
        let payload = bytes
            .get(1 + Address::LEN..signature_start)
            .ok_or(truncated.clone())?;
        let signature: [u8; SIGNATURE_LEN] = bytes
            .get(signature_start..)
            .and_then(|tail| tail.try_into().ok())
            .ok_or(truncated)?;
        Ok(Self {
            payload: payload.to_vec(),
            signature: Signature::from_bytes(signature)?,
            signer_hint: Address::from_bytes(hint),
        })
    }

    /// Recovers the address that signed the payload. Authorship, not trust.
    pub(crate) fn recover_signer(&self) -> Result<Address, WireError> {
        signer::recover_address(&domain::digest(&self.payload), &self.signature)
    }
}

/// Builds a frame from its parts.
pub(crate) fn encode(
    frame_type: u8,
    signer: Address,
    payload: &[u8],
    signature: Signature,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + Address::LEN + payload.len() + SIGNATURE_LEN);
    frame.push(frame_type);
    frame.extend_from_slice(signer.as_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(signature.as_bytes());
    frame
}
