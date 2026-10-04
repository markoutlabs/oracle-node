//! Threshold ECDSA: the governance key, and signatures over document bytes.

use ic_cdk_management_canister::{
    EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs, SignWithEcdsaArgs, ecdsa_public_key,
    sign_with_ecdsa,
};
use oracle_wire::{CompressedPublicKey, Signature};

use crate::runtime::{read_state, with_state};

fn key_id() -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: read_state(|s| s.config.key_name.clone()),
    }
}

/// Signs canonical document bytes with the threshold key.
pub(crate) async fn sign(signing_bytes: &[u8]) -> Result<Signature, String> {
    let governance = ensure_governance_key().await?;
    let expected = governance.address().map_err(|error| error.to_string())?;
    let digest = oracle_wire::domain::digest(signing_bytes);
    let signed = sign_with_ecdsa(&SignWithEcdsaArgs {
        message_hash: digest.to_vec(),
        derivation_path: Vec::new(),
        key_id: key_id(),
    })
    .await
    .map_err(|error| format!("sign_with_ecdsa failed: {error}"))?;
    let compact: [u8; 64] = signed.signature.as_slice().try_into().map_err(|_| {
        format!(
            "sign_with_ecdsa returned {} bytes, expected 64",
            signed.signature.len()
        )
    })?;
    Signature::from_compact_for(&digest, &compact, expected)
        .map_err(|error| format!("cannot adapt the threshold signature: {error}"))
}

pub(crate) async fn ensure_governance_key() -> Result<CompressedPublicKey, String> {
    if let Some(key) = read_state(|s| s.governance_key) {
        return Ok(key);
    }
    let result = ecdsa_public_key(&EcdsaPublicKeyArgs {
        canister_id: None,
        derivation_path: Vec::new(),
        key_id: key_id(),
    })
    .await
    .map_err(|error| format!("ecdsa_public_key failed: {error}"))?;
    let bytes: [u8; 33] = result.public_key.as_slice().try_into().map_err(|_| {
        format!(
            "ecdsa_public_key returned {} bytes, expected 33",
            result.public_key.len()
        )
    })?;
    let key = CompressedPublicKey::from_bytes(bytes);
    key.address()
        .map_err(|error| format!("the threshold key is not a curve point: {error}"))?;
    with_state(|s| s.set_governance_key(key));
    Ok(key)
}
