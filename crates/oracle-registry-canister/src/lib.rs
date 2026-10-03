//! The node registry as an Internet Computer canister (SPEC §3.6).
//!
//! The canister is the trust root for membership. It holds every node, its
//! operator principal, its live signing key and its retired ones, and it
//! publishes the registry document signed with a threshold ECDSA key. The
//! governance address consumers pin is the address of that key, so
//! `Registry::verify` in `oracle-wire` is unchanged and no consumer needs an
//! Internet Computer agent.
//!
//! # Roles
//!
//! - **Governance** is the set of canister controllers. It approves and
//!   removes nodes and sets the quorum guidance.
//! - **An operator** is the principal that submitted a node. Only it may
//!   rotate that node's key.
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
//! A mutation applies to the state, then one signing round produces the next
//! version. Mutations are refused while a round is in flight, so a document
//! never describes a state that no longer exists. If the round fails, the
//! mutation stands and the heartbeat timer retries the publish.

pub mod state;

use std::cell::{Cell, RefCell};
use std::time::Duration;

use candid::CandidType;
use ic_cdk_management_canister::{
    EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs, SignWithEcdsaArgs, ecdsa_public_key,
    sign_with_ecdsa,
};
use oracle_wire::{CompressedPublicKey, NodeEntry, Quorum, Signature, SigningKeyCert};
use serde::Deserialize;

use crate::state::{Config, State, StateError};

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    /// A signing round is in flight.
    static BUSY: Cell<bool> = const { Cell::new(false) };
}

/// Install arguments.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArgs {
    /// Threshold ECDSA key name: `dfx_test_key` locally, `key_1` on mainnet.
    pub key_name: String,
    /// Minimum seconds between two rotations fleet-wide.
    pub rotation_window_secs: u64,
    /// Seconds between heartbeat re-signs.
    pub heartbeat_secs: u64,
    /// Fewest nodes a consumer should require.
    pub min_nodes: u16,
    /// Recommended quorum.
    pub recommended: u16,
}

/// An HTTP request as the gateway delivers it.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct HttpRequest {
    /// HTTP method.
    pub method: String,
    /// Path and query.
    pub url: String,
    /// Request headers.
    pub headers: Vec<(String, String)>,
    /// Request body.
    pub body: Vec<u8>,
}

/// An HTTP response for the gateway.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct HttpResponse {
    /// HTTP status.
    pub status_code: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
}

fn now_secs() -> u64 {
    ic_cdk::api::time() / 1_000_000_000
}

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|cell| {
        f(cell
            .borrow_mut()
            .as_mut()
            .expect("the canister is initialised"))
    })
}

fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|cell| f(cell.borrow().as_ref().expect("the canister is initialised")))
}

fn is_governance() -> bool {
    ic_cdk::api::is_controller(&ic_cdk::api::msg_caller())
}

fn key_id() -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: read_state(|s| s.config.key_name.clone()),
    }
}

fn schedule_heartbeat() {
    let interval = read_state(|s| Duration::from_secs(s.config.heartbeat_secs));
    ic_cdk_timers::set_timer_interval(interval, || async {
        if let Err(error) = publish().await {
            ic_cdk::api::debug_print(format!("heartbeat publish failed: {error}"));
        }
    });
}

#[ic_cdk::init]
fn init(args: InitArgs) {
    let state = State::new(
        Config {
            key_name: args.key_name,
            rotation_window_secs: args.rotation_window_secs,
            heartbeat_secs: args.heartbeat_secs,
        },
        Quorum {
            min_nodes: args.min_nodes,
            recommended: args.recommended,
        },
    )
    .unwrap_or_else(|error| ic_cdk::trap(error.to_string()));
    STATE.with(|cell| *cell.borrow_mut() = Some(state));
    schedule_heartbeat();
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
    schedule_heartbeat();
}

/// Runs a mutation, then one signing round. Returns the new version.
async fn mutate_and_publish(
    mutation: impl FnOnce(&mut State) -> Result<(), StateError>,
) -> Result<u64, String> {
    if BUSY.get() {
        return Err("a signing round is in flight; retry shortly".to_owned());
    }
    with_state(mutation).map_err(|error| error.to_string())?;
    publish().await
}

/// One signing round over the current state.
async fn publish() -> Result<u64, String> {
    if BUSY.get() {
        return Err("a signing round is in flight; retry shortly".to_owned());
    }
    BUSY.set(true);
    let result = publish_inner().await;
    BUSY.set(false);
    result
}

async fn publish_inner() -> Result<u64, String> {
    let governance = ensure_governance_key().await?;
    let expected = governance.address().map_err(|error| error.to_string())?;
    let document =
        with_state(|s| s.unsigned_document(now_secs())).map_err(|error| error.to_string())?;
    let digest = oracle_wire::domain::digest(&document.signing_bytes);

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
    let signature = Signature::from_compact_for(&digest, &compact, expected)
        .map_err(|error| format!("cannot adapt the threshold signature: {error}"))?;

    with_state(|s| s.publish(document, signature)).map_err(|error| error.to_string())
}

async fn ensure_governance_key() -> Result<CompressedPublicKey, String> {
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

/// An operator proposes a node. `entry_json` is a `NodeEntry` with exactly
/// one certificate. Nothing is published until governance approves it.
#[ic_cdk::update]
fn submit_entry(entry_json: String) -> Result<(), String> {
    let entry: NodeEntry = serde_json::from_str(&entry_json)
        .map_err(|error| format!("entry is not valid JSON: {error}"))?;
    with_state(|s| s.submit_entry(ic_cdk::api::msg_caller(), entry, now_secs()))
        .map_err(|error| error.to_string())
}

/// Governance drops a pending entry.
#[ic_cdk::update]
fn reject_entry(node_id: String) -> Result<(), String> {
    with_state(|s| s.reject_entry(is_governance(), &node_id)).map_err(|error| error.to_string())
}

/// Governance lists a pending node. Returns the new version.
#[ic_cdk::update]
async fn approve_entry(node_id: String) -> Result<u64, String> {
    let governance = is_governance();
    mutate_and_publish(move |s| s.approve_entry(governance, &node_id, now_secs())).await
}

/// The node's operator swaps its signing key. `cert_json` is a
/// `SigningKeyCert` issued by the node's identity key. Returns the new version.
#[ic_cdk::update]
async fn rotate_key(node_id: String, cert_json: String) -> Result<u64, String> {
    let cert: SigningKeyCert = serde_json::from_str(&cert_json)
        .map_err(|error| format!("certificate is not valid JSON: {error}"))?;
    let caller = ic_cdk::api::msg_caller();
    mutate_and_publish(move |s| s.rotate_key(caller, &node_id, cert, now_secs())).await
}

/// Governance de-lists a node. Returns the new version.
#[ic_cdk::update]
async fn remove_node(node_id: String) -> Result<u64, String> {
    let governance = is_governance();
    mutate_and_publish(move |s| s.remove_node(governance, &node_id, now_secs())).await
}

/// Governance changes the quorum guidance. Returns the new version.
#[ic_cdk::update]
async fn set_quorum(min_nodes: u16, recommended: u16) -> Result<u64, String> {
    let governance = is_governance();
    mutate_and_publish(move |s| {
        s.set_quorum(
            governance,
            Quorum {
                min_nodes,
                recommended,
            },
        )
    })
    .await
}

/// Governance forces a signing round. Returns the new version.
#[ic_cdk::update]
async fn republish() -> Result<u64, String> {
    if !is_governance() {
        return Err(StateError::NotGovernance.to_string());
    }
    publish().await
}

/// Fetches the threshold public key if it is not cached. Returns the
/// governance address consumers pin.
#[ic_cdk::update]
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

/// Pending entries as JSON.
#[ic_cdk::query]
fn get_pending() -> String {
    read_state(|s| {
        let pending: Vec<&state::PendingEntry> = s.pending.values().collect();
        serde_json::to_string(&pending).expect("pending serialises")
    })
}

/// Serves the registry document at `/registry.json`.
///
/// The response is not certified by the subnet. It does not need to be: the
/// document carries its own governance signature, which is the check every
/// consumer runs. Fetch it through a raw gateway domain or an agent.
#[ic_cdk::query]
fn http_request(request: HttpRequest) -> HttpResponse {
    let path = request.url.split('?').next().unwrap_or_default();
    if request.method != "GET" || path != "/registry.json" {
        return HttpResponse {
            status_code: 404,
            headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
            body: b"not found".to_vec(),
        };
    }
    match get_registry() {
        Some(json) => HttpResponse {
            status_code: 200,
            headers: vec![
                ("content-type".to_owned(), "application/json".to_owned()),
                ("cache-control".to_owned(), "no-cache".to_owned()),
            ],
            body: json.into_bytes(),
        },
        None => HttpResponse {
            status_code: 503,
            headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
            body: b"no registry version has been published yet".to_vec(),
        },
    }
}

// Generates `__get_candid_interface_tmp_hack`, which `candid-extractor` reads
// to produce `oracle-registry-canister.did`.
#[allow(missing_docs)]
mod candid_export {
    use super::*;
    ic_cdk::export_candid!();
}
