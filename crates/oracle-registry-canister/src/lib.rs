//! The node registry as an Internet Computer canister (SPEC §3.6).
//!
//! The canister is the trust root for membership. It holds every node and
//! every client by address, and the addresses it retired. It publishes two
//! documents signed with a threshold ECDSA key: the registry and the client
//! list. The governance address consumers pin is the address of that key, so
//! no consumer needs an Internet Computer agent.
//!
//! It also takes the nodes' signed price frames and resolves each listed feed
//! to the median of the nodes, with the SDK's own checks. Clients fetch the
//! certified `/prices.json`; other canisters call `get_price`.
//!
//! # Roles
//!
//! **Governance** is the set of canister controllers, and the only caller of
//! every update method but `push`. Node operators and clients send their keys
//! to governance off-chain.
//!
//! **Nodes** call `push` with their latest frames, as the anonymous identity.
//! `inspect_message` lets a push in only when one of its frames is new and
//! valid, and drops all other ingress, before the canister pays for it.
//!
//! # Interchange
//!
//! Entries, the registry document and node listings cross the Candid boundary
//! as JSON strings in the protocol's own JSON format. Addresses are `0x` hex. The
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
pub mod prices;
mod publish;
mod runtime;
mod signing;
pub mod state;
#[cfg(not(target_arch = "wasm32"))]
pub mod testing;

use candid::CandidType;
use ic_http_certification::utils::add_v2_certificate_header;
pub use ic_http_certification::{HttpRequest, HttpResponse};
use oracle_types::{FeedId, Symbol};
use oracle_wire::{NodeEntry, Quorum};
use serde::Deserialize;
use serde_bytes::ByteBuf;

use crate::certify::{CERTIFIED, certify_documents};
use crate::prices::{MAX_FRAMES_PER_PUSH, PriceRecord, Prices, StoredPrices, Verdict};
use crate::publish::{Document, mutate_and_publish};
use crate::runtime::{
    PRICES, STATE, address, anonymous_only, governance_only, is_governance, now_ns, now_secs,
    read_prices, read_state, with_prices,
};
use crate::signing::ensure_governance_key;
use crate::state::{Config, DEFAULT_EPOCH_SECS, State};

/// Install arguments.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArgs {
    /// Threshold ECDSA key name: `dfx_test_key` locally, `key_1` on mainnet.
    pub key_name: String,
    /// Fewest nodes a consumer should require.
    pub min_nodes: u16,
    /// Recommended quorum.
    pub recommended: u16,
    /// Broadcast-key epoch for the client list. Default 60.
    pub epoch_secs: Option<u64>,
    /// The feeds the canister prices, as canonical symbols. Default none.
    pub feeds: Option<Vec<String>>,
}

/// One listed feed.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FeedInfo {
    /// The 32-byte feed id: keccak256 of the symbol.
    pub feed_id: ByteBuf,
    /// The canonical symbol, such as `CRYPTO.BTC/USD`.
    pub symbol: String,
}

fn symbols(texts: &[String]) -> Result<Vec<Symbol>, String> {
    texts
        .iter()
        .map(|text| {
            text.parse()
                .map_err(|error| format!("symbol `{text}`: {error}"))
        })
        .collect()
}

#[ic_cdk::init]
fn init(args: InitArgs) {
    let feeds =
        symbols(&args.feeds.unwrap_or_default()).unwrap_or_else(|error| ic_cdk::trap(error));
    let state = State::new(
        Config {
            key_name: args.key_name,
            epoch_secs: args.epoch_secs.unwrap_or(DEFAULT_EPOCH_SECS).max(1),
        },
        Quorum {
            min_nodes: args.min_nodes,
            recommended: args.recommended,
        },
    )
    .unwrap_or_else(|error| ic_cdk::trap(error.to_string()));
    STATE.with(|cell| *cell.borrow_mut() = Some(state));
    with_prices(|prices| prices.set_feeds(&feeds));
    certify_documents();
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    let bytes = read_state(serde_json::to_vec).expect("state serialises");
    let prices = read_prices(Prices::to_stored);
    ic_cdk::storage::stable_save((bytes, Some(prices))).expect("stable memory is writable");
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    // A canister from before the prices saved one value, so the second is `None`.
    let (bytes, prices): (Vec<u8>, Option<StoredPrices>) =
        ic_cdk::storage::stable_restore().expect("stable memory holds the state");
    let state: State = serde_json::from_slice(&bytes).expect("state deserialises");
    let registry = state.verified_registry();
    STATE.with(|cell| *cell.borrow_mut() = Some(state));
    let prices = Prices::restore(&prices.unwrap_or_default(), registry);
    PRICES.with(|cell| *cell.borrow_mut() = prices);
    certify_documents();
}

/// Only controllers and pushes with a new, valid frame get past this, so
/// spam costs the canister nothing.
///
/// One replica runs this check, so every update method has a guard too, and
/// `push` checks every frame again.
#[ic_cdk::inspect_message]
fn inspect_message() {
    if is_governance() || accepts_push() {
        ic_cdk::api::accept_message();
    }
}

/// The IC drops the changes that `inspect_message` makes, so the frame that
/// `accepts_any` stores here is stored again only under consensus.
fn accepts_push() -> bool {
    if ic_cdk::api::msg_method_name() != "push" || anonymous_only().is_err() {
        return false;
    }
    let Ok((frames,)) = candid::decode_args::<(Vec<ByteBuf>,)>(&ic_cdk::api::msg_arg_data()) else {
        return false;
    };
    frames.len() <= MAX_FRAMES_PER_PUSH
        && with_prices(|prices| prices.accepts_any(&frames, now_ns()))
}

/// A node pushes its latest updates as one batch, or as single frames.
/// Returns one verdict for each update, in order.
#[ic_cdk::update(guard = "anonymous_only")]
fn push(frames: Vec<ByteBuf>) -> Result<Vec<Verdict>, String> {
    if frames.len() > MAX_FRAMES_PER_PUSH {
        return Err(format!(
            "a push carries at most {MAX_FRAMES_PER_PUSH} frames"
        ));
    }
    let verdicts = with_prices(|prices| prices.push(&frames, now_ns()));
    if verdicts.contains(&Verdict::Accepted) {
        certify_documents();
    }
    Ok(verdicts)
}

/// Governance sets the feeds that the canister prices, as canonical symbols.
/// A feed that stays keeps its frames.
#[ic_cdk::update(guard = "governance_only")]
fn set_feeds(feeds: Vec<String>) -> Result<(), String> {
    let feeds = symbols(&feeds)?;
    with_prices(|prices| prices.set_feeds(&feeds));
    certify_documents();
    Ok(())
}

/// Governance lists a node. `entry_json` is the operator's `NodeEntry`.
/// Returns the new version.
#[ic_cdk::update(guard = "governance_only")]
async fn add_node(entry_json: String) -> Result<u64, String> {
    let entry: NodeEntry = serde_json::from_str(&entry_json)
        .map_err(|error| format!("entry is not valid JSON: {error}"))?;
    mutate_and_publish(Document::Registry, |s| s.add_node(entry, now_secs())).await
}

/// Governance rotates a node's key: the `new` address takes the place of
/// `old`, with the same endpoints and weight. Returns the new version.
#[ic_cdk::update(guard = "governance_only")]
async fn replace_node(old: String, new: String) -> Result<u64, String> {
    let (old, new) = (address(&old)?, address(&new)?);
    mutate_and_publish(Document::Registry, |s| s.replace_node(old, new, now_secs())).await
}

/// Governance de-lists a node. Returns the new version.
#[ic_cdk::update(guard = "governance_only")]
async fn remove_node(node: String) -> Result<u64, String> {
    let node = address(&node)?;
    mutate_and_publish(Document::Registry, |s| s.remove_node(node, now_secs())).await
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

/// Governance authorises a client: the address of its secp256k1 API key.
/// Returns the new client-list version.
#[ic_cdk::update(guard = "governance_only")]
async fn add_client(client: String, expires_at: u64) -> Result<u64, String> {
    let client = address(&client)?;
    mutate_and_publish(Document::Clients, |s| {
        s.add_client(client, expires_at, now_secs())
    })
    .await
}

/// Governance moves a client's expiry. Returns the new client-list version.
#[ic_cdk::update(guard = "governance_only")]
async fn set_client_expiry(client: String, expires_at: u64) -> Result<u64, String> {
    let client = address(&client)?;
    mutate_and_publish(Document::Clients, |s| {
        s.set_client_expiry(client, expires_at)
    })
    .await
}

/// Governance revokes a client. Returns the new client-list version.
#[ic_cdk::update(guard = "governance_only")]
async fn remove_client(client: String) -> Result<u64, String> {
    let client = address(&client)?;
    mutate_and_publish(Document::Clients, |s| s.remove_client(client)).await
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

/// The listed feeds: the 32-byte id and the symbol of each.
#[ic_cdk::query]
fn get_feeds() -> Vec<FeedInfo> {
    read_prices(|prices| {
        prices
            .feeds()
            .map(|(id, symbol)| FeedInfo {
                feed_id: ByteBuf::from(id.as_bytes().to_vec()),
                symbol: symbol.to_string(),
            })
            .collect()
    })
}

/// One feed's price, resolved now, by its 32-byte feed id.
#[ic_cdk::query]
fn get_price(feed_id: ByteBuf) -> Option<PriceRecord> {
    let id = FeedId::from_bytes(<[u8; 32]>::try_from(feed_id.as_slice()).ok()?);
    read_prices(|prices| prices.price(&id, now_ns()))
}

/// Every listed feed's price, resolved now.
#[ic_cdk::query]
fn get_prices() -> Vec<PriceRecord> {
    read_prices(|prices| prices.prices(now_ns()))
}

/// `/prices.json`: each feed resolved when the last frame was accepted.
pub(crate) fn prices_document() -> String {
    let now = now_ns();
    let prices = read_prices(|prices| prices.resolve_all(now));
    serde_json::json!({ "resolved_at_ns": now.to_string(), "prices": prices }).to_string()
}

/// `/frames.json`: each frame or batch that holds a node's latest update of a
/// feed, for clients that verify the nodes themselves.
pub(crate) fn frames_document() -> String {
    let frames: Vec<serde_json::Value> = read_prices(|prices| {
        prices
            .sources()
            .into_iter()
            .map(|source| {
                let kind = if source.bytes.first() == Some(&oracle_wire::FRAME_TYPE_PRICE_BATCH) {
                    "batch"
                } else {
                    "price"
                };
                let symbols: Vec<String> = source.symbols.iter().map(ToString::to_string).collect();
                serde_json::json!({
                    "node": source.node.to_checksummed(),
                    "kind": kind,
                    "symbols": symbols,
                    "bytes": format!("0x{}", hex::encode(source.bytes)),
                })
            })
            .collect()
    });
    serde_json::json!({ "frames": frames }).to_string()
}

/// When a node address was listed, as JSON, for stored-frame verification.
#[ic_cdk::query]
fn get_node_listing(node: String) -> Option<String> {
    let node = address(&node).ok()?;
    read_state(|s| {
        s.node_listing(node)
            .map(|listing| serde_json::to_string(&listing).expect("listing serialises"))
    })
}

/// Serves `/registry.json`, `/clients.json`, `/prices.json`, `/frames.json`,
/// and a 404 for every other path, as certified query responses.
#[ic_cdk::query]
fn http_request(request: HttpRequest<'static>) -> HttpResponse<'static> {
    let path = request.get_path().unwrap_or_else(|_| "/".to_owned());
    CERTIFIED.with(|cell| {
        let cell = cell.borrow();
        let certified = cell
            .as_ref()
            .expect("certified in init, post_upgrade, and every publish");
        let served = certified.lookup(&path);
        let mut response = served.response.clone();
        // `None` in a replicated call, where consensus certifies the reply.
        if let Some(certificate) = ic_cdk::api::data_certificate() {
            let witness = certified
                .tree
                .witness(&served.entry, &path)
                .expect("the entry covers the path");
            add_v2_certificate_header(
                &certificate,
                &mut response,
                &witness,
                &served.path.to_expr_path(),
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
    /// SPEC §3.6: governance is the only caller of update methods but
    /// `push`. The guard is an attribute, so a new method could ship without it.
    #[test]
    fn every_update_method_but_push_is_governance_only() {
        let source = include_str!("lib.rs");
        let updates: Vec<(&str, &str)> = source
            .lines()
            .zip(source.lines().skip(1))
            .filter(|(attribute, _)| attribute.starts_with("#[ic_cdk::update"))
            .collect();
        assert_eq!(updates.len(), 12);
        for (attribute, signature) in updates {
            let guard = if signature.starts_with("fn push(") {
                "anonymous_only"
            } else {
                "governance_only"
            };
            assert_eq!(
                attribute,
                format!("#[ic_cdk::update(guard = \"{guard}\")]"),
                "{signature}"
            );
        }
    }
}
