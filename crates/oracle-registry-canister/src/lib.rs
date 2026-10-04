//! The node registry as an Internet Computer canister (SPEC §3.6).
//!
//! The canister is the trust root for membership. It holds every node, its
//! live signing key and its retired ones, and the authorised clients. It
//! publishes two documents signed with a threshold ECDSA key: the registry and
//! the client list. The governance address consumers pin is the address of
//! that key, so no consumer needs an Internet Computer agent.
//!
//! # Roles
//!
//! **Governance** is the set of canister controllers, and the only caller of
//! update methods. Node operators and clients send their keys to governance
//! off-chain. `inspect_message` drops all other ingress before the canister
//! pays for it.
//!
//! # Interchange
//!
//! Entries, certificates, the registry document and key histories cross the
//! Candid boundary as JSON strings in the protocol's own JSON format. The
//! document a consumer fetches over HTTPS is the same JSON, so there is one
//! schema, not a Candid mirror of it.
//!
//! # Signing rounds
//!
//! Publication is on demand: each change signs the next version of the
//! document it changed, and nothing re-signs on a timer. Consumers judge
//! freshness by the IC certificate on the HTTP response, not by
//! `effective_from`. A round that fails changes nothing.

mod certify;
mod publish;
mod runtime;
mod signing;
pub mod state;

use candid::CandidType;
use ic_http_certification::utils::add_v2_certificate_header;
use ic_http_certification::{HttpCertificationPath, Method};
pub use ic_http_certification::{HttpRequest, HttpResponse};
use oracle_wire::{CompressedPublicKey, NodeEntry, Quorum, SigningKeyCert};
use serde::Deserialize;

use crate::certify::{CERTIFIED, certify_documents};
use crate::publish::{Document, mutate_and_publish};
use crate::runtime::{STATE, governance_only, is_governance, now_secs, read_state};
use crate::signing::ensure_governance_key;
use crate::state::{Config, DEFAULT_EPOCH_SECS, State};

/// Install arguments.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArgs {
    /// Threshold ECDSA key name: `dfx_test_key` locally, `key_1` on mainnet.
    pub key_name: String,
    /// Minimum seconds between two rotations fleet-wide.
    pub rotation_window_secs: u64,
    /// Fewest nodes a consumer should require.
    pub min_nodes: u16,
    /// Recommended quorum.
    pub recommended: u16,
    /// Broadcast-key epoch for the client list. Default 60.
    pub epoch_secs: Option<u64>,
}

#[ic_cdk::init]
fn init(args: InitArgs) {
    let state = State::new(
        Config {
            key_name: args.key_name,
            rotation_window_secs: args.rotation_window_secs,
            epoch_secs: args.epoch_secs.unwrap_or(DEFAULT_EPOCH_SECS).max(1),
        },
        Quorum {
            min_nodes: args.min_nodes,
            recommended: args.recommended,
        },
    )
    .unwrap_or_else(|error| ic_cdk::trap(error.to_string()));
    STATE.with(|cell| *cell.borrow_mut() = Some(state));
    certify_documents();
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    let bytes = read_state(serde_json::to_vec).expect("state serialises");
    ic_cdk::storage::stable_save((bytes,)).expect("stable memory is writable");
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let (bytes,): (Vec<u8>,) =
        ic_cdk::storage::stable_restore().expect("stable memory holds the state");
    let state: State = serde_json::from_slice(&bytes).expect("state deserialises");
    STATE.with(|cell| *cell.borrow_mut() = Some(state));
    certify_documents();
}

/// Only controllers get past this, so spam costs the canister nothing.
///
/// One replica runs this check, so every update method has the
/// `governance_only` guard too.
#[ic_cdk::inspect_message]
fn inspect_message() {
    if is_governance() {
        ic_cdk::api::accept_message();
    }
}

/// Governance lists a node. `entry_json` is the operator's `NodeEntry`, with
/// exactly one certificate. Returns the new version.
#[ic_cdk::update(guard = "governance_only")]
async fn add_node(entry_json: String) -> Result<u64, String> {
    let entry: NodeEntry = serde_json::from_str(&entry_json)
        .map_err(|error| format!("entry is not valid JSON: {error}"))?;
    mutate_and_publish(Document::Registry, |s| s.add_node(entry, now_secs())).await
}

/// Governance swaps a node's signing key. `cert_json` is a `SigningKeyCert`
/// the node's identity key issued. Returns the new version.
#[ic_cdk::update(guard = "governance_only")]
async fn rotate_key(node_id: String, cert_json: String) -> Result<u64, String> {
    let cert: SigningKeyCert = serde_json::from_str(&cert_json)
        .map_err(|error| format!("certificate is not valid JSON: {error}"))?;
    mutate_and_publish(Document::Registry, |s| {
        s.rotate_key(&node_id, cert, now_secs())
    })
    .await
}

/// Governance de-lists a node. Returns the new version.
#[ic_cdk::update(guard = "governance_only")]
async fn remove_node(node_id: String) -> Result<u64, String> {
    mutate_and_publish(Document::Registry, |s| s.remove_node(&node_id, now_secs())).await
}

/// Governance changes the quorum guidance. Returns the new version.
#[ic_cdk::update(guard = "governance_only")]
async fn set_quorum(min_nodes: u16, recommended: u16) -> Result<u64, String> {
    let quorum = Quorum {
        min_nodes,
        recommended,
    };
    mutate_and_publish(Document::Registry, |s| s.set_quorum(quorum)).await
}

/// Governance re-signs the registry with no change. Returns the new version.
#[ic_cdk::update(guard = "governance_only")]
async fn republish() -> Result<u64, String> {
    mutate_and_publish(Document::Registry, |_| Ok(())).await
}

/// Governance re-signs the client list with no change, for example to publish
/// an empty list before the first client. Returns the new client-list version.
#[ic_cdk::update(guard = "governance_only")]
async fn republish_clients() -> Result<u64, String> {
    mutate_and_publish(Document::Clients, |_| Ok(())).await
}

/// Governance authorises a client. `pubkey` is its 33-byte compressed
/// secp256k1 API key in hex. Returns the new client-list version.
#[ic_cdk::update(guard = "governance_only")]
async fn add_client(client_id: String, pubkey: String, expires_at: u64) -> Result<u64, String> {
    let pubkey: CompressedPublicKey = pubkey.parse().map_err(|error| format!("pubkey: {error}"))?;
    mutate_and_publish(Document::Clients, |s| {
        s.add_client(client_id, pubkey, expires_at, now_secs())
    })
    .await
}

/// Governance moves a client's expiry. Returns the new client-list version.
#[ic_cdk::update(guard = "governance_only")]
async fn set_client_expiry(client_id: String, expires_at: u64) -> Result<u64, String> {
    mutate_and_publish(Document::Clients, |s| {
        s.set_client_expiry(&client_id, expires_at)
    })
    .await
}

/// Governance removes a client. Returns the new client-list version.
#[ic_cdk::update(guard = "governance_only")]
async fn remove_client(client_id: String) -> Result<u64, String> {
    mutate_and_publish(Document::Clients, |s| s.remove_client(&client_id)).await
}

/// Fetches the threshold public key if it is not cached. Returns the
/// governance address consumers pin.
#[ic_cdk::update(guard = "governance_only")]
async fn refresh_governance_key() -> Result<String, String> {
    let key = ensure_governance_key().await?;
    key.address()
        .map(|address| address.to_checksummed())
        .map_err(|error| error.to_string())
}

/// The last published registry document as JSON, if any.
#[ic_cdk::query]
fn get_registry() -> Option<String> {
    read_state(|s| {
        s.published
            .as_ref()
            .map(|registry| serde_json::to_string(registry).expect("registry serialises"))
    })
}

/// The last published client list as JSON, if any.
#[ic_cdk::query]
fn get_clients() -> Option<String> {
    read_state(|s| {
        s.clients_published
            .as_ref()
            .map(|list| serde_json::to_string(list).expect("client list serialises"))
    })
}

/// The version of the last published document. Zero before the first.
#[ic_cdk::query]
fn get_version() -> u64 {
    read_state(|s| s.version)
}

/// The governance address, once the threshold key has been fetched.
#[ic_cdk::query]
fn get_governance() -> Option<String> {
    read_state(|s| {
        s.governance_key
            .and_then(|key| key.address().ok())
            .map(|address| address.to_checksummed())
    })
}

/// Every generation of a node's keys as JSON, for stored-frame verification.
#[ic_cdk::query]
fn get_key_history(node_id: String) -> Option<String> {
    read_state(|s| {
        s.key_history(&node_id)
            .map(|history| serde_json::to_string(&history).expect("history serialises"))
    })
}

/// Serves `/registry.json` and `/clients.json` as certified query responses.
#[ic_cdk::query]
fn http_request(request: HttpRequest<'static>) -> HttpResponse<'static> {
    let path = request.get_path().ok();
    CERTIFIED.with(|cell| {
        let cell = cell.borrow();
        let certified = cell
            .as_ref()
            .expect("certified in init, post_upgrade, and every publish");
        let document = certified
            .documents
            .iter()
            .find(|doc| request.method() == Method::GET && path.as_deref() == Some(doc.path));
        let Some(document) = document else {
            return HttpResponse::not_found(
                b"not found".to_vec(),
                vec![("content-type".to_owned(), "text/plain".to_owned())],
            )
            .build();
        };
        let mut response = document.response.clone();
        // `None` in a replicated call, where consensus certifies the reply.
        if let Some(certificate) = ic_cdk::api::data_certificate() {
            let witness = certified
                .tree
                .witness(&document.entry, document.path)
                .expect("the entry is in the tree");
            add_v2_certificate_header(
                &certificate,
                &mut response,
                &witness,
                &HttpCertificationPath::exact(document.path).to_expr_path(),
            );
        }
        response
    })
}

// Generates `__get_candid_interface_tmp_hack`, which `candid-extractor` reads
// to produce `oracle-registry-canister.did`.
#[allow(missing_docs)]
mod candid_export {
    use super::*;
    ic_cdk::export_candid!();
}

#[cfg(test)]
mod tests {
    /// SPEC §3.6: governance is the only caller of update methods. The guard
    /// is an attribute, so a new method could ship without it.
    #[test]
    fn every_update_method_is_governance_only() {
        let source = include_str!("lib.rs");
        let updates: Vec<&str> = source
            .lines()
            .filter(|line| line.starts_with("#[ic_cdk::update"))
            .collect();
        assert_eq!(updates.len(), 10);
        for line in updates {
            assert_eq!(line, "#[ic_cdk::update(guard = \"governance_only\")]");
        }
    }
}
