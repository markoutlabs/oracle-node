//! The signed transcripts of the transport handshake (SPEC §6.1).
//!
//! Both are 34-byte payloads, `version ‖ kind ‖ keccak(transcript)`, signed
//! through [`domain::digest`](crate::domain::digest) like every other payload.
//! Their kinds keep them apart from price updates and from each other.

use crate::cert::MAX_NODE_ID_LEN;
use crate::codec::Sink as _;
use crate::keccak::keccak256;
use crate::payload::{KIND_CLIENT_AUTH, KIND_NODE_AUTH_OK, PAYLOAD_VERSION};
use crate::{CompressedPublicKey, WireError};

/// The protocol name a node announces in its challenge.
pub const TRANSPORT_PROTOCOL: &str = "price-oracle/2";

/// Size of an auth payload.
pub const AUTH_PAYLOAD_SIZE: usize = 34;

const CLIENT_AUTH_LABEL: &str = "price-oracle/2 client-auth";
const AUTH_OK_LABEL: &str = "price-oracle/2 auth-ok";
const LABEL_LIMIT: usize = 64;

/// Hashes what a client signs to authenticate: the node, the node's challenge,
/// the client's own nonce, its API key, and its per-connection X25519 key.
///
/// # Errors
///
/// Returns [`WireError::FieldTooLong`] if `node_id` exceeds its cap.
pub fn client_auth_transcript(
    node_id: &str,
    challenge: &[u8; 32],
    client_nonce: &[u8; 32],
    client_pubkey: &CompressedPublicKey,
    eph_public: &[u8; 32],
) -> Result<[u8; 32], WireError> {
    let mut out = Vec::with_capacity(256);
    out.try_put_str("label", CLIENT_AUTH_LABEL, LABEL_LIMIT)?;
    out.try_put_str("node_id", node_id, MAX_NODE_ID_LEN)?;
    out.put_bytes(challenge);
    out.put_bytes(client_nonce);
    out.put_bytes(client_pubkey.as_bytes());
    out.put_bytes(eph_public);
    Ok(keccak256(&out))
}

/// The payload a client's API key signs.
#[must_use]
pub fn client_auth_payload(transcript: &[u8; 32]) -> [u8; AUTH_PAYLOAD_SIZE] {
    payload(KIND_CLIENT_AUTH, transcript)
}

/// Hashes what a node signs to accept a session: the client's transcript, the
/// HPKE encapsulation, the session deadline, and the sealed initial keys.
///
/// # Errors
///
/// Cannot fail today; fallible like the other builders so the label can grow.
pub fn auth_ok_transcript(
    client_auth: &[u8; 32],
    enc: &[u8; 32],
    session_deadline: u64,
    initial_digest: &[u8; 32],
) -> Result<[u8; 32], WireError> {
    let mut out = Vec::with_capacity(160);
    out.try_put_str("label", AUTH_OK_LABEL, LABEL_LIMIT)?;
    out.put_bytes(client_auth);
    out.put_bytes(enc);
    out.put_u64(session_deadline);
    out.put_bytes(initial_digest);
    Ok(keccak256(&out))
}

/// The payload a node's live signing key signs.
#[must_use]
pub fn auth_ok_payload(transcript: &[u8; 32]) -> [u8; AUTH_PAYLOAD_SIZE] {
    payload(KIND_NODE_AUTH_OK, transcript)
}

fn payload(kind: u8, transcript: &[u8; 32]) -> [u8; AUTH_PAYLOAD_SIZE] {
    let mut out = [0_u8; AUTH_PAYLOAD_SIZE];
    out[0] = PAYLOAD_VERSION;
    out[1] = kind;
    out[2..].copy_from_slice(transcript);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Signer, decode_price_update, recover_payload_signer};

    fn key(seed: u8) -> Signer {
        Signer::from_secret_bytes([seed; 32]).expect("valid key")
    }

    fn transcript(node_id: &str, challenge: u8, nonce: u8, client: u8, eph: u8) -> [u8; 32] {
        client_auth_transcript(
            node_id,
            &[challenge; 32],
            &[nonce; 32],
            &key(client).public_key(),
            &[eph; 32],
        )
        .expect("encodes")
    }

    #[test]
    fn every_bound_field_changes_the_client_transcript() {
        let base = transcript("n1", 1, 2, 3, 4);
        for other in [
            transcript("n2", 1, 2, 3, 4),
            transcript("n1", 9, 2, 3, 4),
            transcript("n1", 1, 9, 3, 4),
            transcript("n1", 1, 2, 9, 4),
            transcript("n1", 1, 2, 3, 9),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn every_bound_field_changes_the_auth_ok_transcript() {
        let ok = |a: u8, e: u8, d: u64, i: u8| {
            auth_ok_transcript(&[a; 32], &[e; 32], d, &[i; 32]).expect("encodes")
        };
        let base = ok(1, 2, 3, 4);
        for other in [
            ok(9, 2, 3, 4),
            ok(1, 9, 3, 4),
            ok(1, 2, 9, 4),
            ok(1, 2, 3, 9),
        ] {
            assert_ne!(base, other);
        }
    }

    /// The two auth kinds and a price update can never stand in for each other.
    #[test]
    fn auth_signatures_do_not_cross_contexts() {
        let t = transcript("n1", 1, 2, 3, 4);
        let client_payload = client_auth_payload(&t);
        let node_payload = auth_ok_payload(&t);
        assert_eq!(client_payload[1], KIND_CLIENT_AUTH);
        assert_eq!(node_payload[1], KIND_NODE_AUTH_OK);

        let signer = key(3);
        let sig = signer.sign_payload(&client_payload);
        assert_eq!(
            recover_payload_signer(&client_payload, &sig).expect("recovers"),
            signer.address()
        );
        assert_ne!(
            recover_payload_signer(&node_payload, &sig).ok(),
            Some(signer.address())
        );
        assert!(decode_price_update(&client_payload).is_err());
        assert!(decode_price_update(&node_payload).is_err());
    }
}
