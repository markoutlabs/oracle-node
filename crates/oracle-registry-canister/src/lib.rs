//! The node registry as an Internet Computer canister (SPEC §3.6).
//!
//! The canister is the trust root for membership. It holds every node and
//! every client by address, and the addresses it retired. It publishes three
//! documents signed with a threshold ECDSA key: the registry, the client list
//! and the feed set. The governance address consumers pin is the address of
//! that key, so no consumer needs an Internet Computer agent.
//!
//! It also takes the nodes' signed price batches and resolves each listed feed
//! to the median of the nodes, with the SDK's own checks. Clients fetch the
//! certified `/prices.json`; other canisters call `get_price` and pay for it
//! with attached cycles.
//!
//! # Roles
//!
//! **Governance** is the set of canister controllers, and the only caller of
//! every update method but `push`. Node operators and clients send their keys
//! to governance off-chain.
//!
//! **Nodes** call `push` with their latest batch, as the anonymous identity.
//! `inspect_message` lets a push in only when it passes every admission rule
//! of [`admission`], and drops all other ingress, before the canister pays.
//!
//! **Other canisters** call `get_price` and `get_prices` with attached cycles.
//! Every other method refuses their calls, which would cost the canister an
//! execution fee each.
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

pub mod admission;
mod certify;
pub mod prices;
mod publish;
mod runtime;
mod signing;
pub mod stable;
pub mod state;
#[cfg(not(target_arch = "wasm32"))]
pub mod testing;

use ic_http_certification::utils::add_v2_certificate_header;
pub use ic_http_certification::{HttpRequest, HttpResponse};
pub use oracle_registry_api::{FeedInfo, InitArgs};
use oracle_types::{FeedId, Symbol};
use oracle_wire::{FeedContent, NodeEntry, PushPolicy, Quorum};
use serde_bytes::ByteBuf;

use crate::admission::{Admission, Ingress, Refusal};
use crate::certify::{CERTIFIED, certify_documents, certify_prices};
use crate::prices::{PriceRecord, Prices, Verdict};
use crate::publish::{Document, idle, mutate_and_publish};
use crate::runtime::{
    PRICES, STATE, address, anonymous_only, governance_only, is_governance, no_replicated_callers,
    now_ns, now_secs, read_prices, read_state, replicated_callers_pay, with_prices,
};
use crate::signing::ensure_governance_key;
use crate::stable::Stable;
use crate::state::{Config, DEFAULT_EPOCH_SECS, State, StateError};

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
    // SPEC §3.7 P11: an install has no feed set, so it prices no feed.
    Admission::check_pace(None, feeds.len()).unwrap_or_else(|error| ic_cdk::trap(error));
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
    let prices = read_prices(Prices::to_stored);
    let stable = read_state(|state| Stable::save(state, prices)).expect("the state serialises");
    ic_cdk::storage::stable_save(stable.into_arguments()).expect("stable memory is writable");
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let stable =
        Stable::decode(&ic_cdk::stable::stable_bytes()).expect("stable memory holds the state");
    let state = stable.state().expect("the state loads");
    for document in state.documents_that_do_not_verify() {
        // SPEC §3.7: a rollback across a signed field drops it, and governance signs again.
        ic_cdk::println!(
            "post_upgrade: the published {document} does not verify; governance must sign it again"
        );
    }
    let (registry, pace) = (state.verified_registry(), state.push_pace());
    STATE.with(|cell| *cell.borrow_mut() = Some(state));
    let prices = Prices::restore(&stable.prices.unwrap_or_default(), registry, pace);
    PRICES.with(|cell| *cell.borrow_mut() = prices);
    certify_documents();
}

/// Only controllers and pushes that pass the admission rules get past this,
/// so spam costs the canister nothing (SPEC §3.7).
///
/// One replica runs this check, so every update method has a guard too, and
/// `push` runs the rules again.
#[ic_cdk::inspect_message]
fn inspect_message() {
    if is_governance() {
        ic_cdk::api::accept_message();
        return;
    }
    // The trap message reaches the sender, so a node's log names the rule.
    match accepts_push() {
        Ok(()) => ic_cdk::api::accept_message(),
        Err(refusal) => ic_cdk::trap(refusal.to_string()),
    }
}

/// The IC drops the changes that `inspect` makes, so the batches that it
/// stores here are stored again only under consensus.
fn accepts_push() -> Result<(), Refusal> {
    let arg = ic_cdk::api::msg_arg_data();
    Admission::check_ingress(Ingress {
        method: &ic_cdk::api::msg_method_name(),
        anonymous: anonymous_only().is_ok(),
        arg_bytes: arg.len(),
    })?;
    Admission::check_balance(ic_cdk::api::canister_cycle_balance())?;
    let (frames,) =
        candid::decode_args::<(Vec<ByteBuf>,)>(&arg).map_err(|_| Refusal::Undecodable)?;
    with_prices(|prices| prices.inspect(&frames, now_ns()))
}

/// A node pushes its latest updates as one price batch. Returns one verdict
/// for each update, in order.
#[ic_cdk::update(guard = "anonymous_only")]
fn push(frames: Vec<ByteBuf>) -> Result<Vec<Verdict>, String> {
    Admission::check_balance(ic_cdk::api::canister_cycle_balance())
        .map_err(|refusal| refusal.to_string())?;
    let verdicts = with_prices(|prices| prices.push(&frames, now_ns()))
        .map_err(|refusal| refusal.to_string())?;
    if verdicts.contains(&Verdict::Accepted) {
        certify_prices();
    }
    Ok(verdicts)
}

/// Governance sets how long a node's latest update counts toward the quorum,
/// in seconds. About three push intervals: 180 for pushes every 60 s.
#[ic_cdk::update(guard = "governance_only")]
fn set_price_window(secs: u64) -> Result<(), String> {
    idle()?;
    let heartbeat = read_state(|s| s.feed_content.as_ref().and_then(|c| c.push))
        .map(|push| push.heartbeat_secs);
    if let Some(heartbeat) = heartbeat
        && PushPolicy::min_window_secs(heartbeat) > secs
    {
        return Err(format!(
            "the feed set pushes every {heartbeat} s at the latest; a window below {} s drops quiet feeds",
            PushPolicy::min_window_secs(heartbeat)
        ));
    }
    with_prices(|prices| prices.set_window(std::time::Duration::from_secs(secs)))?;
    certify_prices();
    Ok(())
}

/// Governance sets the feeds that the canister prices, as canonical symbols.
/// A feed that stays keeps its frames.
#[ic_cdk::update(guard = "governance_only")]
fn set_feeds(feeds: Vec<String>) -> Result<(), String> {
    idle()?;
    let feeds = symbols(&feeds)?;
    if let Some(missing) = read_state(|s| s.first_unlisted(&feeds)) {
        return Err(format!("{missing} is not in the feed set"));
    }
    // Without a feed set, no pace exists either.
    let pace = read_state(|s| s.feed_content.as_ref().and_then(|content| content.push));
    Admission::check_pace(pace, feeds.len())?;
    with_prices(|prices| prices.set_feeds(&feeds));
    certify_prices();
    Ok(())
}

/// Governance publishes the network's feed set, `{ "min_node_version", "push", "feeds" }` as JSON.
/// Returns the new feed set version.
#[ic_cdk::update(guard = "governance_only")]
async fn set_feed_set(content_json: String) -> Result<u64, String> {
    let content: FeedContent = serde_json::from_str(&content_json)
        .map_err(|error| format!("the feed set is not valid JSON: {error}"))?;
    Admission::check_pace(content.push, read_prices(Prices::feed_count))?;
    let window = read_prices(|prices| prices.window().as_secs());
    if let Some(push) = content.push
        && PushPolicy::min_window_secs(push.heartbeat_secs) > window
    {
        return Err(format!(
            "push.heartbeat_secs {} is more than half the price window of {window} s",
            push.heartbeat_secs
        ));
    }
    let priced: Vec<Symbol> =
        read_prices(|prices| prices.feeds().map(|(_, symbol)| symbol).collect());
    mutate_and_publish(Document::Feeds, |s| {
        s.set_feed_content(&content)?;
        match s.first_unlisted(&priced) {
            Some(missing) => Err(StateError::InvalidFeedSet(format!(
                "{missing} is priced on-chain; remove it with set_feeds first"
            ))),
            None => Ok(()),
        }
    })
    .await
}

/// Governance re-signs the feed set with no change. Returns the new feed set version.
#[ic_cdk::update(guard = "governance_only")]
async fn republish_feeds() -> Result<u64, String> {
    mutate_and_publish(Document::Feeds, |_| Ok(())).await
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
#[ic_cdk::query(guard = "no_replicated_callers")]
fn get_registry() -> Option<String> {
    read_state(|s| {
        s.registry
            .published
            .as_ref()
            .map(|registry| serde_json::to_string(registry).expect("registry serialises"))
    })
}

/// The last published client list as JSON, if any.
#[ic_cdk::query(guard = "no_replicated_callers")]
fn get_clients() -> Option<String> {
    read_state(|s| {
        s.client_list
            .published
            .as_ref()
            .map(|list| serde_json::to_string(list).expect("client list serialises"))
    })
}

/// The last published feed set as JSON, if any.
#[ic_cdk::query(guard = "no_replicated_callers")]
fn get_feed_set() -> Option<String> {
    read_state(|s| {
        s.feed_set
            .published
            .as_ref()
            .map(|set| serde_json::to_string(set).expect("feed set serialises"))
    })
}

/// The version of the last published document. Zero before the first.
#[ic_cdk::query(guard = "no_replicated_callers")]
fn get_version() -> u64 {
    read_state(|s| s.registry.version)
}

/// The governance address, once the threshold key has been fetched.
#[ic_cdk::query(guard = "no_replicated_callers")]
fn get_governance() -> Option<String> {
    read_state(|s| {
        s.governance_key
            .and_then(|key| key.address().ok())
            .map(|address| address.to_checksummed())
    })
}

/// The listed feeds: the 32-byte id and the symbol of each.
#[ic_cdk::query(guard = "no_replicated_callers")]
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

/// How long a node's latest update counts toward the quorum, in seconds.
#[ic_cdk::query(guard = "no_replicated_callers")]
fn get_price_window() -> u64 {
    read_prices(|prices| prices.window().as_secs())
}

/// One feed's price, resolved now, by its 32-byte feed id. Another canister
/// attaches 10M cycles (`PRICE_CALL_CYCLES`).
#[ic_cdk::query(guard = "replicated_callers_pay")]
fn get_price(feed_id: ByteBuf) -> Option<PriceRecord> {
    let id = FeedId::from_bytes(<[u8; 32]>::try_from(feed_id.as_slice()).ok()?);
    read_prices(|prices| prices.price(&id, now_ns()))
}

/// Every listed feed's price, resolved now. Another canister attaches 10M
/// cycles (`PRICE_CALL_CYCLES`).
#[ic_cdk::query(guard = "replicated_callers_pay")]
fn get_prices() -> Vec<PriceRecord> {
    read_prices(|prices| prices.prices(now_ns()))
}

/// When a node address was listed, as JSON, for stored-frame verification.
#[ic_cdk::query(guard = "no_replicated_callers")]
fn get_node_listing(node: String) -> Option<String> {
    let node = address(&node).ok()?;
    read_state(|s| {
        s.node_listing(node)
            .map(|listing| serde_json::to_string(&listing).expect("listing serialises"))
    })
}

/// Serves `/registry.json`, `/clients.json`, `/feeds.json`, `/prices.json`,
/// `/frames.json`, and a 404 for every other path, as certified query responses.
#[ic_cdk::query(guard = "no_replicated_callers")]
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

    #[cfg(test)]
    mod tests {
        /// `tests/callers.rs` checks each method of the `.did`, so the `.did` must be this interface.
        #[test]
        fn the_did_is_the_exported_service() {
            assert_eq!(
                super::__export_service().trim_end(),
                include_str!("../oracle-registry-canister.did").trim_end(),
                "the .did is stale: `make canister` writes it from the wasm"
            );
        }
    }
}
