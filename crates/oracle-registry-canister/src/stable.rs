//! Stable memory across an upgrade (SPEC §3.7, "State" and "Upgrades and
//! rollbacks").
//!
//! The layout is one [`Stable`] record: a layout version, the registry state as
//! JSON, and the prices. It goes to stable memory as three Candid arguments,
//! `(state_json, prices, version)`, because the wasm before this layout reads
//! the first two and skips the rest.
//!
//! The state JSON keeps the field names of the first mainnet layout. The
//! canister writes it with the wire types and reads it with this module's own
//! types, which ignore unknown fields: a field that a newer wasm stores cannot
//! stop this wasm or a later one in `post_upgrade`.
//!
//! The mainnet wasm 6127923 is older than this module. It reads `FeedSettings`
//! with `deny_unknown_fields` and does not know `sanity_band`, which
//! `node/all-feeds.toml` sets. So a rollback to 6127923 works only until the
//! first `set_feed_set` on this wasm; after it, roll back only to this wasm or
//! a later one.
//!
//! A rollback across a signed field that the older wasm does not know drops
//! the field, and the document's signature then fails. `post_upgrade` logs
//! each such document, and the prices halt until governance signs again with
//! `republish`, `republish_clients` and `republish_feeds`.

use std::collections::{BTreeMap, BTreeSet};

use candid::utils::ArgumentDecoder;
use oracle_wire::{
    Address, ClientEntry, ClientList, CompressedPublicKey, FeedContent, FeedSet, FeedSettings,
    NodeEntry, PushPolicy, Quorum, Registry, Signature, SourceSettings,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::prices::StoredPrices;
use crate::state::{ClientRecord, Config, NodeRecord, RetiredNode, SignedSlot, State};

/// The layout that this wasm writes. Layout 1, `(state_json, prices)`, has no version.
pub const LAYOUT_VERSION: u32 = 2;

/// What the canister keeps across an upgrade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stable {
    /// The layout version: 1 for a blob from before the version.
    pub version: u32,
    /// The registry state, as JSON in the first mainnet layout.
    pub state_json: Vec<u8>,
    /// The prices. `None` from a canister from before the prices.
    pub prices: Option<StoredPrices>,
}

/// The arguments as they are in stable memory.
type Arguments = (ByteBuf, Option<StoredPrices>, Option<u32>);

impl Stable {
    /// The layout of this wasm, for `pre_upgrade`.
    ///
    /// # Errors
    ///
    /// Returns the error of a state that does not serialise.
    pub fn save(state: &State, prices: StoredPrices) -> Result<Self, serde_json::Error> {
        Ok(Self {
            version: LAYOUT_VERSION,
            state_json: serde_json::to_vec(&SavedState::of(state))?,
            prices: Some(prices),
        })
    }

    /// The Candid arguments that go to stable memory.
    #[must_use]
    pub fn into_arguments(self) -> Arguments {
        (
            ByteBuf::from(self.state_json),
            self.prices,
            Some(self.version),
        )
    }

    /// Reads any layout from the bytes of stable memory, which can end in zeros.
    ///
    /// # Errors
    ///
    /// Returns the Candid error of bytes that hold no layout.
    pub fn decode(bytes: &[u8]) -> Result<Self, candid::Error> {
        let mut decoder = candid::de::IDLDeserialize::new(bytes)?;
        let (state_json, prices, version): Arguments = ArgumentDecoder::decode(&mut decoder)?;
        Ok(Self {
            version: version.unwrap_or(1),
            state_json: state_json.into_vec(),
            prices,
        })
    }

    /// The registry state.
    ///
    /// # Errors
    ///
    /// Returns the error of JSON that holds no state.
    pub fn state(&self) -> Result<State, serde_json::Error> {
        serde_json::from_slice::<LoadedState>(&self.state_json).map(State::from)
    }
}

/// The state as the first mainnet layout writes it, with the wire types.
#[derive(Serialize)]
struct SavedState<'a> {
    config: &'a Config,
    quorum: Quorum,
    nodes: &'a BTreeMap<Address, NodeRecord>,
    retired: &'a BTreeMap<Address, RetiredNode>,
    version: u64,
    published: Option<&'a Registry>,
    governance_key: Option<CompressedPublicKey>,
    clients: &'a BTreeMap<Address, ClientRecord>,
    removed_clients: &'a BTreeSet<Address>,
    clients_version: u64,
    clients_published: Option<&'a ClientList>,
    feed_content: Option<&'a FeedContent>,
    feeds_version: u64,
    feeds_published: Option<&'a FeedSet>,
}

impl<'a> SavedState<'a> {
    fn of(state: &'a State) -> Self {
        Self {
            config: &state.config,
            quorum: state.quorum,
            nodes: &state.nodes,
            retired: &state.retired,
            version: state.registry.version,
            published: state.registry.published.as_ref(),
            governance_key: state.governance_key,
            clients: &state.clients,
            removed_clients: &state.removed_clients,
            clients_version: state.client_list.version,
            clients_published: state.client_list.published.as_ref(),
            feed_content: state.feed_content.as_ref(),
            feeds_version: state.feed_set.version,
            feeds_published: state.feed_set.published.as_ref(),
        }
    }
}

// The types below read what `SavedState` wrote, and ignore what they do not
// know. Each conversion names every field of the wire type, so a new wire
// field fails the build here until it has a place.

#[derive(Deserialize)]
struct LoadedState {
    config: Config,
    quorum: LoadedQuorum,
    nodes: BTreeMap<Address, NodeRecord>,
    retired: BTreeMap<Address, RetiredNode>,
    version: u64,
    published: Option<LoadedRegistry>,
    governance_key: Option<CompressedPublicKey>,
    clients: BTreeMap<Address, ClientRecord>,
    removed_clients: BTreeSet<Address>,
    clients_version: u64,
    clients_published: Option<LoadedClientList>,
    // The feed set came after the first mainnet install.
    #[serde(default)]
    feed_content: Option<LoadedFeedContent>,
    #[serde(default)]
    feeds_version: u64,
    #[serde(default)]
    feeds_published: Option<LoadedFeedSet>,
}

impl From<LoadedState> for State {
    fn from(loaded: LoadedState) -> Self {
        Self {
            config: loaded.config,
            quorum: loaded.quorum.into(),
            nodes: loaded.nodes,
            retired: loaded.retired,
            registry: SignedSlot {
                version: loaded.version,
                published: loaded.published.map(Into::into),
            },
            governance_key: loaded.governance_key,
            clients: loaded.clients,
            removed_clients: loaded.removed_clients,
            client_list: SignedSlot {
                version: loaded.clients_version,
                published: loaded.clients_published.map(Into::into),
            },
            feed_content: loaded.feed_content.map(Into::into),
            feed_set: SignedSlot {
                version: loaded.feeds_version,
                published: loaded.feeds_published.map(Into::into),
            },
        }
    }
}

#[derive(Deserialize)]
struct LoadedQuorum {
    min_nodes: u16,
    recommended: u16,
}

impl From<LoadedQuorum> for Quorum {
    fn from(loaded: LoadedQuorum) -> Self {
        Self {
            min_nodes: loaded.min_nodes,
            recommended: loaded.recommended,
        }
    }
}

#[derive(Deserialize)]
struct LoadedNodeEntry {
    address: Address,
    endpoints: Vec<String>,
    weight: u16,
}

impl From<LoadedNodeEntry> for NodeEntry {
    fn from(loaded: LoadedNodeEntry) -> Self {
        Self {
            address: loaded.address,
            endpoints: loaded.endpoints,
            weight: loaded.weight,
        }
    }
}

#[derive(Deserialize)]
struct LoadedRegistry {
    version: u64,
    effective_from: u64,
    nodes: Vec<LoadedNodeEntry>,
    quorum: LoadedQuorum,
    governance_signature: Signature,
}

impl From<LoadedRegistry> for Registry {
    fn from(loaded: LoadedRegistry) -> Self {
        Self {
            version: loaded.version,
            effective_from: loaded.effective_from,
            nodes: loaded.nodes.into_iter().map(Into::into).collect(),
            quorum: loaded.quorum.into(),
            governance_signature: loaded.governance_signature,
        }
    }
}

#[derive(Deserialize)]
struct LoadedClientEntry {
    address: Address,
    expires_at: u64,
}

impl From<LoadedClientEntry> for ClientEntry {
    fn from(loaded: LoadedClientEntry) -> Self {
        Self {
            address: loaded.address,
            expires_at: loaded.expires_at,
        }
    }
}

#[derive(Deserialize)]
struct LoadedClientList {
    version: u64,
    effective_from: u64,
    epoch_secs: u64,
    clients: Vec<LoadedClientEntry>,
    governance_signature: Signature,
}

impl From<LoadedClientList> for ClientList {
    fn from(loaded: LoadedClientList) -> Self {
        Self {
            version: loaded.version,
            effective_from: loaded.effective_from,
            epoch_secs: loaded.epoch_secs,
            clients: loaded.clients.into_iter().map(Into::into).collect(),
            governance_signature: loaded.governance_signature,
        }
    }
}

#[derive(Deserialize)]
struct LoadedPushPolicy {
    heartbeat_secs: u64,
    deviation_bps: u32,
    min_interval_secs: u64,
}

impl From<LoadedPushPolicy> for PushPolicy {
    fn from(loaded: LoadedPushPolicy) -> Self {
        Self {
            heartbeat_secs: loaded.heartbeat_secs,
            deviation_bps: loaded.deviation_bps,
            min_interval_secs: loaded.min_interval_secs,
        }
    }
}

#[derive(Deserialize)]
struct LoadedSourceSettings {
    venue: String,
    market: String,
    symbol: String,
    #[serde(default)]
    kinds: Option<Vec<String>>,
    #[serde(default)]
    weight: Option<String>,
    #[serde(default)]
    converted: bool,
    #[serde(default)]
    contract_size: Option<String>,
}

impl From<LoadedSourceSettings> for SourceSettings {
    fn from(loaded: LoadedSourceSettings) -> Self {
        Self {
            venue: loaded.venue,
            market: loaded.market,
            symbol: loaded.symbol,
            kinds: loaded.kinds,
            weight: loaded.weight,
            converted: loaded.converted,
            contract_size: loaded.contract_size,
        }
    }
}

#[derive(Deserialize)]
struct LoadedFeedSettings {
    symbol: String,
    #[serde(default)]
    peg: Option<String>,
    #[serde(default)]
    max_peg_conf_bps: Option<String>,
    #[serde(default)]
    min_sources: Option<u32>,
    #[serde(default)]
    deviation_bps: Option<String>,
    #[serde(default)]
    min_interval_ms: Option<u64>,
    #[serde(default)]
    max_age_ms: Option<u64>,
    #[serde(default)]
    impact_notional: Option<String>,
    #[serde(default)]
    sanity_band: Option<[String; 2]>,
    sources: Vec<LoadedSourceSettings>,
}

impl From<LoadedFeedSettings> for FeedSettings {
    fn from(loaded: LoadedFeedSettings) -> Self {
        Self {
            symbol: loaded.symbol,
            peg: loaded.peg,
            max_peg_conf_bps: loaded.max_peg_conf_bps,
            min_sources: loaded.min_sources,
            deviation_bps: loaded.deviation_bps,
            min_interval_ms: loaded.min_interval_ms,
            max_age_ms: loaded.max_age_ms,
            impact_notional: loaded.impact_notional,
            sanity_band: loaded.sanity_band,
            sources: loaded.sources.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Deserialize)]
struct LoadedFeedContent {
    #[serde(default)]
    min_node_version: String,
    #[serde(default)]
    push: Option<LoadedPushPolicy>,
    feeds: Vec<LoadedFeedSettings>,
}

impl From<LoadedFeedContent> for FeedContent {
    fn from(loaded: LoadedFeedContent) -> Self {
        Self {
            min_node_version: loaded.min_node_version,
            push: loaded.push.map(Into::into),
            feeds: loaded.feeds.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Deserialize)]
struct LoadedFeedSet {
    version: u64,
    effective_from: u64,
    min_node_version: String,
    push: Option<LoadedPushPolicy>,
    feeds: Vec<LoadedFeedSettings>,
    governance_signature: Signature,
}

impl From<LoadedFeedSet> for FeedSet {
    fn from(loaded: LoadedFeedSet) -> Self {
        Self {
            version: loaded.version,
            effective_from: loaded.effective_from,
            min_node_version: loaded.min_node_version,
            push: loaded.push.map(Into::into),
            feeds: loaded.feeds.into_iter().map(Into::into).collect(),
            governance_signature: loaded.governance_signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use oracle_quorum::testing::REGISTRY_ISSUED_AT;
    use oracle_types::{NANOS_PER_SEC, Symbol};
    use oracle_wire::feed_id;

    use super::*;
    use crate::prices::{PriceStatus, Prices};
    use crate::state::tests::{address, governance_signer, listed, one_feed, publish};

    /// The layout of the canister before this module, as `pre_upgrade` wrote it.
    const LAYOUT_1: &[u8] = include_bytes!("../tests/fixtures/stable-v1.bin");
    /// When the fixture's frames were signed.
    const FIXTURE_FRAMES_NS: u64 = (REGISTRY_ISSUED_AT + 600) * NANOS_PER_SEC;

    /// A state with every optional field set, so a dropped field shows.
    fn full_state() -> State {
        let mut state = listed(&[1, 2]);
        state.set_governance_key(governance_signer().public_key());
        state
            .replace_node(address(1), address(3), REGISTRY_ISSUED_AT + 1)
            .expect("replaces");
        publish(&mut state, REGISTRY_ISSUED_AT + 1);
        state
            .add_client(address(8), REGISTRY_ISSUED_AT + 60, REGISTRY_ISSUED_AT)
            .expect("adds");
        state
            .add_client(address(9), REGISTRY_ISSUED_AT + 60, REGISTRY_ISSUED_AT)
            .expect("adds");
        state.remove_client(address(9)).expect("removes");
        let list = state.next_client_list(REGISTRY_ISSUED_AT).expect("encodes");
        let signature = governance_signer().sign_payload(&list.signing_bytes);
        state
            .client_list
            .publish(list, signature)
            .expect("publishes");

        let mut content = one_feed();
        content.min_node_version = "0.2.0".to_owned();
        content.push = Some(PushPolicy {
            heartbeat_secs: 60,
            deviation_bps: 2,
            min_interval_secs: 60,
        });
        let peg = FeedSettings {
            symbol: "CRYPTO.BTC/USD".to_owned(),
            ..content.feeds.first().cloned().expect("one feed")
        };
        if let Some(feed) = content.feeds.first_mut() {
            *feed = FeedSettings {
                peg: Some("CRYPTO.BTC/USD".to_owned()),
                max_peg_conf_bps: Some("50".to_owned()),
                min_sources: Some(1),
                min_interval_ms: Some(250),
                max_age_ms: Some(9_000),
                impact_notional: Some("100000".to_owned()),
                sanity_band: Some(["0.5".to_owned(), "2".to_owned()]),
                sources: vec![SourceSettings {
                    kinds: Some(vec!["book_top".to_owned()]),
                    weight: Some("2".to_owned()),
                    converted: true,
                    contract_size: Some("0.1".to_owned()),
                    ..feed.sources.first().cloned().expect("one source")
                }],
                ..feed.clone()
            };
        }
        content.feeds.push(peg);
        state.set_feed_content(&content).expect("passes");
        let set = state.next_feed_set(REGISTRY_ISSUED_AT).expect("encodes");
        let signature = governance_signer().sign_payload(&set.signing_bytes);
        state.feed_set.publish(set, signature).expect("publishes");
        state
    }

    fn round_trip(state: &State) -> State {
        let saved = Stable::save(state, StoredPrices::default()).expect("saves");
        let bytes = candid::encode_args(saved.into_arguments()).expect("encodes");
        Stable::decode(&bytes)
            .expect("decodes")
            .state()
            .expect("loads")
    }

    #[test]
    fn the_state_round_trips_through_stable_memory() {
        let state = full_state();
        assert!(
            state
                .feed_content
                .as_ref()
                .is_some_and(|content| content.feeds.iter().any(|f| f.sanity_band.is_some())),
            "the fixture sets the newest field"
        );
        assert_eq!(round_trip(&state), state);
    }

    fn add_unknown_fields(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(fields) => {
                for nested in fields.values_mut() {
                    add_unknown_fields(nested);
                }
                // A map keyed by address is not a struct, so a new key there is not a field.
                let map = fields.is_empty() || fields.keys().any(|key| key.starts_with("0x"));
                if !map {
                    fields.insert("field_of_a_newer_wasm".to_owned(), serde_json::json!(1));
                }
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(add_unknown_fields),
            _ => {}
        }
    }

    /// SPEC §3.7: a rollback to this wasm must not trap on a field that a
    /// newer wasm stored.
    #[test]
    fn a_field_that_a_newer_wasm_stored_does_not_stop_the_load() {
        let state = full_state();
        let saved = Stable::save(&state, StoredPrices::default()).expect("saves");
        let mut json: serde_json::Value = serde_json::from_slice(&saved.state_json).expect("JSON");
        add_unknown_fields(&mut json);
        let newer = Stable {
            state_json: serde_json::to_vec(&json).expect("serialises"),
            ..saved
        };
        assert_eq!(newer.state().expect("loads"), state);
    }

    #[test]
    fn a_document_that_lost_a_signed_field_is_reported() {
        let mut state = full_state();
        assert!(state.documents_that_do_not_verify().is_empty());
        for feed in state
            .feed_set
            .published
            .iter_mut()
            .flat_map(|set| set.feeds.iter_mut())
        {
            feed.sanity_band = None;
        }
        assert_eq!(
            state.documents_that_do_not_verify(),
            ["feed set (republish_feeds)"]
        );
    }

    /// The canister before this layout reads with the wire types, which refuse
    /// unknown fields, and stops after two arguments. This copy uses today's
    /// wire types, so it cannot see a field that the old wasm does not know,
    /// such as `sanity_band` for 6127923; the rollback test with the release
    /// wasm covers that.
    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct StateOfLayout1 {
        config: Config,
        quorum: Quorum,
        nodes: BTreeMap<Address, NodeRecord>,
        retired: BTreeMap<Address, RetiredNode>,
        version: u64,
        published: Option<Registry>,
        governance_key: Option<CompressedPublicKey>,
        clients: BTreeMap<Address, ClientRecord>,
        removed_clients: BTreeSet<Address>,
        clients_version: u64,
        clients_published: Option<ClientList>,
        #[serde(default)]
        feed_content: Option<FeedContent>,
        #[serde(default)]
        feeds_version: u64,
        #[serde(default)]
        feeds_published: Option<FeedSet>,
    }

    #[test]
    fn the_wasm_before_this_layout_reads_it_for_a_rollback() {
        let mut state = full_state();
        // The mainnet wasm does not know the sanity band; a set without one stays readable.
        for feed in state
            .feed_content
            .iter_mut()
            .flat_map(|content| content.feeds.iter_mut())
        {
            feed.sanity_band = None;
        }
        let saved = Stable::save(&state, StoredPrices::default()).expect("saves");
        let bytes = candid::encode_args(saved.into_arguments()).expect("encodes");
        let mut decoder = candid::de::IDLDeserialize::new(&bytes).expect("decodes");
        let (json, prices): (Vec<u8>, Option<StoredPrices>) =
            ArgumentDecoder::decode(&mut decoder).expect("two arguments of three");
        assert_eq!(prices, Some(StoredPrices::default()));
        serde_json::from_slice::<StateOfLayout1>(&json).expect("the wire types read it");
    }

    /// The blob that the canister wrote before the versioned layout, made by
    /// that code (`tests/fixtures`), decodes into this layout.
    #[test]
    fn the_layout_before_the_version_decodes() {
        let stable = Stable::decode(LAYOUT_1).expect("decodes");
        assert_eq!(stable.version, 1);
        let state = stable.state().expect("loads");
        assert_eq!(
            (
                state.registry.version,
                state.client_list.version,
                state.feed_set.version
            ),
            (2, 1, 1)
        );
        assert_eq!(state.nodes.len(), 2);
        assert_eq!(state.retired.len(), 1);
        assert_eq!(
            state.push_pace().map(|pace| pace.min_interval_secs),
            Some(60)
        );
        let registry = state.verified_registry().expect("the registry verifies");

        let stored = stable.prices.expect("the prices");
        assert_eq!(stored.frames.len(), 2, "a batch and a single frame");
        let prices = Prices::restore(&stored, Some(registry), state.push_pace());
        assert_eq!(
            prices.to_stored().frames.len(),
            1,
            "the single frame is dropped"
        );
        let btc: Symbol = "CRYPTO.BTC/USD".parse().expect("a symbol");
        let record = prices
            .price(&feed_id(&btc), FIXTURE_FRAMES_NS)
            .expect("listed");
        assert_eq!((record.nodes, record.status), (1, PriceStatus::Halted));
        assert_eq!(prices.window().as_secs(), 180);

        // The state that it loads saves to the same JSON, so a rollback finds what it wrote.
        let again = Stable::save(&state, stored).expect("saves");
        let before: serde_json::Value = serde_json::from_slice(&stable.state_json).expect("JSON");
        let after: serde_json::Value = serde_json::from_slice(&again.state_json).expect("JSON");
        assert_eq!(after, before);
    }

    /// A canister from before the prices saved one value, which reads back as no prices.
    #[test]
    fn the_layout_before_the_prices_decodes() {
        let state = listed(&[1]);
        let json = serde_json::to_vec(&SavedState::of(&state)).expect("serialises");
        let old = candid::encode_args((json,)).expect("encodes");
        let stable = Stable::decode(&old).expect("decodes");
        assert_eq!((stable.version, stable.prices.as_ref()), (1, None));
        assert_eq!(stable.state().expect("loads"), state);
    }

    /// The stable memory of a canister holds zeros after the arguments.
    #[test]
    fn zeros_after_the_layout_are_ignored() {
        let mut bytes = candid::encode_args(
            Stable::save(&listed(&[1]), StoredPrices::default())
                .expect("saves")
                .into_arguments(),
        )
        .expect("encodes");
        bytes.resize(bytes.len() + 4096, 0);
        assert_eq!(
            Stable::decode(&bytes).expect("decodes").version,
            LAYOUT_VERSION
        );
    }

    /// The mainnet state was saved before the feed set, so it lacks the fields.
    #[test]
    fn a_state_from_before_the_feed_set_loads() {
        let mut state = listed(&[1]);
        state.set_feed_content(&one_feed()).expect("passes");
        let mut old = serde_json::to_value(SavedState::of(&state)).expect("serialises");
        let fields = old.as_object_mut().expect("an object");
        for field in ["feed_content", "feeds_version", "feeds_published"] {
            fields.remove(field).expect("the field");
        }
        let loaded = Stable {
            version: 1,
            state_json: serde_json::to_vec(&old).expect("serialises"),
            prices: None,
        }
        .state()
        .expect("loads");
        assert_eq!(loaded.feed_content, None);
        assert_eq!(loaded.feed_set.version, 0);
        assert_eq!(loaded.registry, state.registry);
    }

    /// Nothing was deployed with node ids, so there is no migration. An old
    /// state fails to load, `post_upgrade` traps, and the old wasm stays.
    #[test]
    fn a_state_keyed_by_node_id_does_not_load() {
        let state = listed(&[1]);
        let mut old = serde_json::to_value(SavedState::of(&state)).expect("serialises");
        let nodes = old.get_mut("nodes").expect("the nodes");
        let node = nodes
            .get(address(1).to_string())
            .cloned()
            .expect("the node");
        *nodes = serde_json::json!({ "oracle-a": node });
        let stable = Stable {
            version: 1,
            state_json: serde_json::to_vec(&old).expect("serialises"),
            prices: None,
        };
        assert!(stable.state().is_err());
    }
}
