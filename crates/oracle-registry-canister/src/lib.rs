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
//! A mutation applies to the state, then one signing round produces the next
//! version of the document it changed. Mutations are refused while a round is in flight, so a document
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
use ic_http_certification::utils::add_v2_certificate_header;
use ic_http_certification::{
    CERTIFICATE_EXPRESSION_HEADER_NAME, DefaultCelBuilder, DefaultResponseCertification,
    HttpCertification, HttpCertificationPath, HttpCertificationTree, HttpCertificationTreeEntry,
    Method, StatusCode,
};
pub use ic_http_certification::{HttpRequest, HttpResponse};
use oracle_wire::{CompressedPublicKey, NodeEntry, Quorum, Signature, SigningKeyCert};
use serde::Deserialize;

use crate::state::{Config, DEFAULT_CLIENTS_HEARTBEAT_SECS, DEFAULT_EPOCH_SECS, State, StateError};

const REGISTRY_PATH: &str = "/registry.json";
const CLIENTS_PATH: &str = "/clients.json";

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    /// A signing round is in flight.
    static BUSY: Cell<bool> = const { Cell::new(false) };
    // Not in stable memory: rebuilt from `STATE` in `post_upgrade`.
    static CERTIFIED: RefCell<Option<Certified>> = const { RefCell::new(None) };
}

struct Certified {
    tree: HttpCertificationTree,
    documents: Vec<CertifiedDocument>,
}

struct CertifiedDocument {
    path: &'static str,
    entry: HttpCertificationTreeEntry<'static>,
    response: HttpResponse<'static>,
}

/// The two signed documents the canister publishes.
#[derive(Clone, Copy, Debug)]
enum Document {
    Registry,
    Clients,
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
    /// Broadcast-key epoch for the client list. Default 60.
    pub epoch_secs: Option<u64>,
    /// Seconds between client-list re-signs. Default 3600.
    pub clients_heartbeat_secs: Option<u64>,
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
    let interval = read_state(|s| {
        Duration::from_secs(
            s.config
                .heartbeat_secs
                .min(s.config.clients_heartbeat_secs)
                .max(1),
        )
    });
    ic_cdk_timers::set_timer_interval(interval, || async {
        // The timer can fire again while a round awaits its signature.
        if BUSY.get() {
            return;
        }
        let now = now_secs();
        let (registry, clients) = read_state(|s| (s.registry_due(now), s.clients_due(now)));
        for (due, document) in [(registry, Document::Registry), (clients, Document::Clients)] {
            if due && let Err(error) = publish(document).await {
                ic_cdk::api::debug_print(format!("heartbeat publish failed: {error}"));
            }
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
            epoch_secs: args.epoch_secs.unwrap_or(DEFAULT_EPOCH_SECS).max(1),
            clients_heartbeat_secs: args
                .clients_heartbeat_secs
                .unwrap_or(DEFAULT_CLIENTS_HEARTBEAT_SECS)
                .max(1),
        },
        Quorum {
            min_nodes: args.min_nodes,
            recommended: args.recommended,
        },
    )
    .unwrap_or_else(|error| ic_cdk::trap(error.to_string()));
    STATE.with(|cell| *cell.borrow_mut() = Some(state));
    certify_documents();
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
    certify_documents();
    schedule_heartbeat();
}

/// Runs a mutation, then one signing round for `document`. Returns its new version.
async fn mutate_and_publish(
    document: Document,
    mutation: impl FnOnce(&mut State) -> Result<(), StateError>,
) -> Result<u64, String> {
    if BUSY.get() {
        return Err("a signing round is in flight; retry shortly".to_owned());
    }
    with_state(mutation).map_err(|error| error.to_string())?;
    publish(document).await
}

/// One signing round for one document.
async fn publish(document: Document) -> Result<u64, String> {
    if BUSY.get() {
        return Err("a signing round is in flight; retry shortly".to_owned());
    }
    BUSY.set(true);
    let result = publish_inner(document).await;
    BUSY.set(false);
    result
}

async fn publish_inner(document: Document) -> Result<u64, String> {
    let now = now_secs();
    let version = match document {
        Document::Registry => {
            let unsigned =
                with_state(|s| s.unsigned_document(now)).map_err(|error| error.to_string())?;
            let signature = sign(&unsigned.signing_bytes).await?;
            with_state(|s| s.publish(unsigned, signature)).map_err(|error| error.to_string())?
        }
        Document::Clients => {
            let unsigned =
                with_state(|s| s.unsigned_client_list(now)).map_err(|error| error.to_string())?;
            let signature = sign(&unsigned.signing_bytes).await?;
            with_state(|s| s.publish_clients(unsigned, signature))
                .map_err(|error| error.to_string())?
        }
    };
    certify_documents();
    Ok(version)
}

/// Signs canonical document bytes with the threshold key.
async fn sign(signing_bytes: &[u8]) -> Result<Signature, String> {
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

/// Certifies the current `/registry.json` and `/clients.json` responses in one
/// tree, so the query path can serve either.
fn certify_documents() {
    let cel = DefaultCelBuilder::response_only_certification()
        .with_response_certification(DefaultResponseCertification::response_header_exclusions(
            vec![],
        ))
        .build();
    let headers = |content_type: &str| {
        vec![
            ("content-type".to_owned(), content_type.to_owned()),
            ("cache-control".to_owned(), "no-cache".to_owned()),
            (
                CERTIFICATE_EXPRESSION_HEADER_NAME.to_owned(),
                cel.to_string(),
            ),
        ]
    };
    let response = |json: Option<String>, missing: &'static [u8]| match json {
        Some(json) => HttpResponse::ok(json.into_bytes(), headers("application/json")).build(),
        None => HttpResponse::builder()
            .with_status_code(StatusCode::SERVICE_UNAVAILABLE)
            .with_headers(headers("text/plain"))
            .with_body(missing.to_vec())
            .build(),
    };
    let mut tree = HttpCertificationTree::default();
    let documents: Vec<CertifiedDocument> = [
        (
            REGISTRY_PATH,
            response(
                get_registry(),
                b"no registry version has been published yet",
            ),
        ),
        (
            CLIENTS_PATH,
            response(
                get_clients(),
                b"no client list version has been published yet",
            ),
        ),
    ]
    .into_iter()
    .map(|(path, response)| {
        let certification = HttpCertification::response_only(&cel, &response, None)
            .expect("the response carries its own CEL expression");
        let entry =
            HttpCertificationTreeEntry::new(HttpCertificationPath::exact(path), certification);
        tree.insert(&entry);
        CertifiedDocument {
            path,
            entry,
            response,
        }
    })
    .collect();
    ic_cdk::api::certified_data_set(tree.root_hash());
    CERTIFIED.with(|cell| *cell.borrow_mut() = Some(Certified { tree, documents }));
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

/// Only controllers get past this, so spam costs the canister nothing.
///
/// One replica runs this check, so every update method checks again.
#[ic_cdk::inspect_message]
fn inspect_message() {
    if is_governance() {
        ic_cdk::api::accept_message();
    }
}

/// Governance lists a node. `entry_json` is the operator's `NodeEntry`, with
/// exactly one certificate. Returns the new version.
#[ic_cdk::update]
async fn add_node(entry_json: String) -> Result<u64, String> {
    let entry: NodeEntry = serde_json::from_str(&entry_json)
        .map_err(|error| format!("entry is not valid JSON: {error}"))?;
    let governance = is_governance();
    mutate_and_publish(Document::Registry, move |s| {
        s.add_node(governance, entry, now_secs())
    })
    .await
}

/// Governance swaps a node's signing key. `cert_json` is a `SigningKeyCert`
/// the node's identity key issued. Returns the new version.
#[ic_cdk::update]
async fn rotate_key(node_id: String, cert_json: String) -> Result<u64, String> {
    let cert: SigningKeyCert = serde_json::from_str(&cert_json)
        .map_err(|error| format!("certificate is not valid JSON: {error}"))?;
    let governance = is_governance();
    mutate_and_publish(Document::Registry, move |s| {
        s.rotate_key(governance, &node_id, cert, now_secs())
    })
    .await
}

/// Governance de-lists a node. Returns the new version.
#[ic_cdk::update]
async fn remove_node(node_id: String) -> Result<u64, String> {
    let governance = is_governance();
    mutate_and_publish(Document::Registry, move |s| {
        s.remove_node(governance, &node_id, now_secs())
    })
    .await
}

/// Governance changes the quorum guidance. Returns the new version.
#[ic_cdk::update]
async fn set_quorum(min_nodes: u16, recommended: u16) -> Result<u64, String> {
    let governance = is_governance();
    mutate_and_publish(Document::Registry, move |s| {
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
    publish(Document::Registry).await
}

/// Governance authorises a client. `pubkey` is its 33-byte compressed
/// secp256k1 API key in hex. Returns the new client-list version.
#[ic_cdk::update]
async fn add_client(client_id: String, pubkey: String, expires_at: u64) -> Result<u64, String> {
    let pubkey: CompressedPublicKey = pubkey.parse().map_err(|error| format!("pubkey: {error}"))?;
    let governance = is_governance();
    mutate_and_publish(Document::Clients, move |s| {
        s.add_client(governance, client_id, pubkey, expires_at, now_secs())
    })
    .await
}

/// Governance moves a client's expiry. Returns the new client-list version.
#[ic_cdk::update]
async fn set_client_expiry(client_id: String, expires_at: u64) -> Result<u64, String> {
    let governance = is_governance();
    mutate_and_publish(Document::Clients, move |s| {
        s.set_client_expiry(governance, &client_id, expires_at)
    })
    .await
}

/// Governance removes a client. Returns the new client-list version.
#[ic_cdk::update]
async fn remove_client(client_id: String) -> Result<u64, String> {
    let governance = is_governance();
    mutate_and_publish(Document::Clients, move |s| {
        s.remove_client(governance, &client_id)
    })
    .await
}

/// Fetches the threshold public key if it is not cached. Returns the
/// governance address consumers pin.
#[ic_cdk::update]
async fn refresh_governance_key() -> Result<String, String> {
    if !is_governance() {
        return Err(StateError::NotGovernance.to_string());
    }
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
