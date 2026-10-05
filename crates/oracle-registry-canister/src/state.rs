//! The registry state machine.
//!
//! No Internet Computer dependency here. Every rule in SPEC §3.6 is a unit
//! test in this file rather than a PocketIC run, and the canister glue in
//! `lib.rs` only adds the caller, the clock, and the threshold signature.

use std::collections::{BTreeMap, BTreeSet};

use oracle_wire::{
    Address, ClientEntry, ClientList, CompressedPublicKey, MAX_CLIENTS, MAX_NODES, NodeEntry,
    NodeListing, Quorum, Registry, Signature, WireError,
};
use serde::{Deserialize, Serialize};

/// A rule of the registry was broken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StateError {
    /// No listed node has this address.
    #[error("unknown node {0}")]
    UnknownNode(Address),
    /// The entry failed a structural check.
    #[error("invalid entry: {0}")]
    InvalidEntry(String),
    /// An address is listed once, ever, as a node or as a client.
    #[error("address {0} is or was already in the registry; use a new key")]
    AddressUsed(Address),
    /// Removing the node would leave consumers unable to reach the quorum.
    #[error("removing the node would leave {remaining} nodes, below min_nodes {min_nodes}")]
    BelowQuorum {
        /// Nodes that would remain.
        remaining: usize,
        /// The registry's `min_nodes`.
        min_nodes: u16,
    },
    /// The wire format caps the node count.
    #[error("the registry already holds {MAX_NODES} nodes")]
    TooManyNodes,
    /// No listed client has this address.
    #[error("unknown client {0}")]
    UnknownClient(Address),
    /// The client failed a check.
    #[error("invalid client: {0}")]
    InvalidClient(String),
    /// The wire format caps the client count.
    #[error("the client list already holds {MAX_CLIENTS} clients")]
    TooManyClients,
    /// The quorum values are inconsistent.
    #[error("invalid quorum: {0}")]
    InvalidQuorum(String),
    /// A signing round was started against a different version.
    #[error("version mismatch: expected {expected}, got {got}")]
    VersionMismatch {
        /// `version + 1` at publish time.
        expected: u64,
        /// The version the signature was made for.
        got: u64,
    },
    /// The wire crate rejected an encoding.
    #[error(transparent)]
    Wire(#[from] WireError),
}

/// Canister configuration, fixed at install.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Threshold ECDSA key name: `dfx_test_key` locally, `key_1` on mainnet.
    pub key_name: String,
    /// Broadcast-key epoch, published in the client list.
    pub epoch_secs: u64,
}

/// Default broadcast-key epoch (SPEC §6.1).
pub const DEFAULT_EPOCH_SECS: u64 = 60;

/// A listed node. Its address is the map key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    /// Who runs it.
    pub operator: String,
    /// WebSocket endpoints.
    pub endpoints: Vec<String>,
    /// Relative weight hint.
    pub weight: u16,
    /// When governance listed it, unix seconds.
    pub added_at: u64,
}

impl NodeRecord {
    fn entry(&self, address: Address) -> NodeEntry {
        NodeEntry {
            address,
            operator: self.operator.clone(),
            endpoints: self.endpoints.clone(),
            weight: self.weight,
        }
    }
}

/// A node governance replaced or removed. Kept so the address is never
/// listed again, and for stored-frame verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredNode {
    /// Who ran it.
    pub operator: String,
    /// When governance listed it, unix seconds.
    pub added_at: u64,
    /// When governance replaced or removed it, unix seconds.
    pub removed_at: u64,
}

/// One authorised client. Its address is the map key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRecord {
    /// End of authorisation, unix seconds.
    pub expires_at: u64,
    /// When governance added it, unix seconds.
    pub added_at: u64,
}

/// A registry document ready to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedDocument {
    /// `State::version + 1`.
    pub version: u64,
    /// The issue time, unix seconds.
    pub effective_from: u64,
    /// The listed nodes.
    pub nodes: Vec<NodeEntry>,
    /// The quorum guidance.
    pub quorum: Quorum,
    /// `Registry::signing_bytes` over the above.
    pub signing_bytes: Vec<u8>,
}

/// A client list ready to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedClientList {
    /// `State::clients_version + 1`.
    pub version: u64,
    /// The issue time, unix seconds.
    pub effective_from: u64,
    /// The broadcast-key epoch.
    pub epoch_secs: u64,
    /// The clients.
    pub clients: Vec<ClientEntry>,
    /// `ClientList::signing_bytes` over the above.
    pub signing_bytes: Vec<u8>,
}

/// The whole canister state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Install-time configuration.
    pub config: Config,
    /// Quorum guidance published in the document.
    pub quorum: Quorum,
    /// Listed nodes by address.
    pub nodes: BTreeMap<Address, NodeRecord>,
    /// Nodes governance replaced or removed, by address.
    pub retired: BTreeMap<Address, RetiredNode>,
    /// Version of the last published document. Zero before the first.
    pub version: u64,
    /// The last signed document.
    pub published: Option<Registry>,
    /// The threshold public key, once fetched.
    pub governance_key: Option<CompressedPublicKey>,
    /// Authorised clients by address.
    pub clients: BTreeMap<Address, ClientRecord>,
    /// Clients governance removed. Their addresses are never listed again.
    pub removed_clients: BTreeSet<Address>,
    /// Version of the last published client list. Zero before the first.
    pub clients_version: u64,
    /// The last signed client list.
    pub clients_published: Option<ClientList>,
}

impl State {
    /// A fresh registry with no nodes.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidQuorum`] for an inconsistent quorum.
    pub fn new(config: Config, quorum: Quorum) -> Result<Self, StateError> {
        check_quorum(quorum)?;
        Ok(Self {
            config,
            quorum,
            nodes: BTreeMap::new(),
            retired: BTreeMap::new(),
            version: 0,
            published: None,
            governance_key: None,
            clients: BTreeMap::new(),
            removed_clients: BTreeSet::new(),
            clients_version: 0,
            clients_published: None,
        })
    }

    /// Governance lists a node from the entry its operator sent. Bumps the document.
    ///
    /// # Errors
    ///
    /// Returns an error if the address was ever used, the entry is invalid,
    /// or the registry is full.
    pub fn add_node(&mut self, entry: NodeEntry, now: u64) -> Result<(), StateError> {
        self.check_unused(entry.address)?;
        if self.nodes.len() >= MAX_NODES {
            return Err(StateError::TooManyNodes);
        }
        entry
            .validate()
            .map_err(|error| StateError::InvalidEntry(error.to_string()))?;
        let NodeEntry {
            address,
            operator,
            endpoints,
            weight,
        } = entry;
        self.nodes.insert(
            address,
            NodeRecord {
                operator,
                endpoints,
                weight,
                added_at: now,
            },
        );
        Ok(())
    }

    /// Governance rotates a node's key: `new` takes the place of `old`, with
    /// the same operator, endpoints and weight. Bumps the document.
    ///
    /// One version for both changes, so consumers never see the node twice
    /// or not at all, and the node count does not change.
    ///
    /// # Errors
    ///
    /// Returns an error if `old` is not listed or `new` was ever used.
    pub fn replace_node(&mut self, old: Address, new: Address, now: u64) -> Result<(), StateError> {
        if !self.nodes.contains_key(&old) {
            return Err(StateError::UnknownNode(old));
        }
        self.check_unused(new)?;
        let record = self.retire(old, now)?;
        self.nodes.insert(
            new,
            NodeRecord {
                added_at: now,
                ..record
            },
        );
        Ok(())
    }

    /// Governance de-lists a node. Its address is never listed again. Bumps
    /// the document.
    ///
    /// # Errors
    ///
    /// Returns an error if the node is unknown, or the remaining count would
    /// fall below `quorum.min_nodes`.
    pub fn remove_node(&mut self, address: Address, now: u64) -> Result<(), StateError> {
        if !self.nodes.contains_key(&address) {
            return Err(StateError::UnknownNode(address));
        }
        let remaining = self.nodes.len().saturating_sub(1);
        if remaining < usize::from(self.quorum.min_nodes) {
            return Err(StateError::BelowQuorum {
                remaining,
                min_nodes: self.quorum.min_nodes,
            });
        }
        self.retire(address, now)?;
        Ok(())
    }

    fn retire(&mut self, address: Address, now: u64) -> Result<NodeRecord, StateError> {
        let record = self
            .nodes
            .remove(&address)
            .ok_or(StateError::UnknownNode(address))?;
        self.retired.insert(
            address,
            RetiredNode {
                operator: record.operator.clone(),
                added_at: record.added_at,
                removed_at: now,
            },
        );
        Ok(record)
    }

    /// Governance changes the quorum guidance. Bumps the document.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidQuorum`] if the values are inconsistent.
    pub fn set_quorum(&mut self, quorum: Quorum) -> Result<(), StateError> {
        check_quorum(quorum)?;
        self.quorum = quorum;
        Ok(())
    }

    /// Records the threshold public key.
    pub fn set_governance_key(&mut self, key: CompressedPublicKey) {
        self.governance_key = Some(key);
    }

    /// Builds the next document and its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns a wire error if the document does not encode, which means a
    /// listed entry broke a limit that `NodeEntry::validate` should have caught.
    pub fn unsigned_document(&self, now: u64) -> Result<UnsignedDocument, StateError> {
        let version = self.version.saturating_add(1);
        let nodes: Vec<NodeEntry> = self
            .nodes
            .iter()
            .map(|(address, node)| node.entry(*address))
            .collect();
        let signing_bytes = Registry::signing_bytes(version, now, &nodes, self.quorum)?;
        Ok(UnsignedDocument {
            version,
            effective_from: now,
            nodes,
            quorum: self.quorum,
            signing_bytes,
        })
    }

    /// Stores a signed document as the published registry.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::VersionMismatch`] if the document was built for
    /// a version other than the next one.
    pub fn publish(
        &mut self,
        document: UnsignedDocument,
        governance_signature: Signature,
    ) -> Result<u64, StateError> {
        let expected = self.version.saturating_add(1);
        if document.version != expected {
            return Err(StateError::VersionMismatch {
                expected,
                got: document.version,
            });
        }
        self.published = Some(Registry {
            version: document.version,
            effective_from: document.effective_from,
            nodes: document.nodes,
            quorum: document.quorum,
            governance_signature,
        });
        self.version = document.version;
        Ok(self.version)
    }

    /// Governance authorises a client until `expires_at`. Bumps the client list.
    ///
    /// # Errors
    ///
    /// Returns an error if the address was ever used, the list is full, or
    /// `expires_at` is not in the future.
    pub fn add_client(
        &mut self,
        address: Address,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StateError> {
        self.check_unused(address)?;
        if self.clients.len() >= MAX_CLIENTS {
            return Err(StateError::TooManyClients);
        }
        if expires_at <= now {
            return Err(StateError::InvalidClient(
                "expires_at must be in the future".to_owned(),
            ));
        }
        self.clients.insert(
            address,
            ClientRecord {
                expires_at,
                added_at: now,
            },
        );
        Ok(())
    }

    /// Governance moves a client's expiry, earlier or later. Bumps the client list.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::UnknownClient`] if the client is unknown.
    pub fn set_client_expiry(
        &mut self,
        address: Address,
        expires_at: u64,
    ) -> Result<(), StateError> {
        let record = self
            .clients
            .get_mut(&address)
            .ok_or(StateError::UnknownClient(address))?;
        record.expires_at = expires_at;
        Ok(())
    }

    /// Governance revokes a client. Its address is never listed again. Bumps
    /// the client list.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::UnknownClient`] if the client is unknown.
    pub fn remove_client(&mut self, address: Address) -> Result<(), StateError> {
        self.clients
            .remove(&address)
            .ok_or(StateError::UnknownClient(address))?;
        self.removed_clients.insert(address);
        Ok(())
    }

    /// Builds the next client list and its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns a wire error if the list does not encode.
    pub fn unsigned_client_list(&self, now: u64) -> Result<UnsignedClientList, StateError> {
        let version = self.clients_version.saturating_add(1);
        let clients: Vec<ClientEntry> = self
            .clients
            .iter()
            .map(|(address, record)| ClientEntry {
                address: *address,
                expires_at: record.expires_at,
            })
            .collect();
        let signing_bytes =
            ClientList::signing_bytes(version, now, self.config.epoch_secs, &clients)?;
        Ok(UnsignedClientList {
            version,
            effective_from: now,
            epoch_secs: self.config.epoch_secs,
            clients,
            signing_bytes,
        })
    }

    /// Stores a signed client list as the published one.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::VersionMismatch`] if the list was built for a
    /// version other than the next one.
    pub fn publish_clients(
        &mut self,
        list: UnsignedClientList,
        governance_signature: Signature,
    ) -> Result<u64, StateError> {
        let expected = self.clients_version.saturating_add(1);
        if list.version != expected {
            return Err(StateError::VersionMismatch {
                expected,
                got: list.version,
            });
        }
        self.clients_published = Some(ClientList {
            version: list.version,
            effective_from: list.effective_from,
            epoch_secs: list.epoch_secs,
            clients: list.clients,
            governance_signature,
        });
        self.clients_version = list.version;
        Ok(self.clients_version)
    }

    /// When a node address was listed, whether it still is or not.
    #[must_use]
    pub fn node_listing(&self, address: Address) -> Option<NodeListing> {
        if let Some(node) = self.nodes.get(&address) {
            return Some(NodeListing {
                address,
                operator: node.operator.clone(),
                added_at: node.added_at,
                removed_at: None,
            });
        }
        self.retired.get(&address).map(|node| NodeListing {
            address,
            operator: node.operator.clone(),
            added_at: node.added_at,
            removed_at: Some(node.removed_at),
        })
    }

    /// `true` if the address is or was a node or a client.
    #[must_use]
    pub fn address_used(&self, address: Address) -> bool {
        self.nodes.contains_key(&address)
            || self.retired.contains_key(&address)
            || self.clients.contains_key(&address)
            || self.removed_clients.contains(&address)
    }

    fn check_unused(&self, address: Address) -> Result<(), StateError> {
        if self.address_used(address) {
            return Err(StateError::AddressUsed(address));
        }
        Ok(())
    }
}

fn check_quorum(quorum: Quorum) -> Result<(), StateError> {
    if quorum.min_nodes == 0 {
        return Err(StateError::InvalidQuorum(
            "min_nodes must be at least 1".to_owned(),
        ));
    }
    if quorum.recommended < quorum.min_nodes {
        return Err(StateError::InvalidQuorum(
            "recommended must be at least min_nodes".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use oracle_wire::Signer;

    use super::*;

    const NOW: u64 = 1_754_582_400;

    fn config() -> Config {
        Config {
            key_name: "dfx_test_key".to_owned(),
            epoch_secs: 60,
        }
    }

    fn quorum(min_nodes: u16) -> Quorum {
        Quorum {
            min_nodes,
            recommended: min_nodes.max(3),
        }
    }

    fn governance_signer() -> Signer {
        Signer::from_secret_bytes([0x33; 32]).expect("valid key")
    }

    fn address(seed: u8) -> Address {
        Signer::from_secret_bytes([seed; 32])
            .expect("valid key")
            .address()
    }

    fn entry(seed: u8) -> NodeEntry {
        NodeEntry {
            address: address(seed),
            operator: format!("op-{seed}"),
            endpoints: vec![format!("wss://node{seed}.example/v2/ws")],
            weight: 1,
        }
    }

    /// Signs and publishes the way the canister does, with an in-process key
    /// standing in for the threshold key.
    fn publish(state: &mut State, now: u64) -> Registry {
        let doc = state.unsigned_document(now).expect("encodes");
        let signature = governance_signer().sign_payload(&doc.signing_bytes);
        state.publish(doc, signature).expect("publishes");
        state.published.clone().expect("published")
    }

    fn listed(seeds: &[u8], min_nodes: u16) -> State {
        let mut state = State::new(config(), quorum(min_nodes)).expect("valid");
        for &seed in seeds {
            state.add_node(entry(seed), NOW).expect("adds");
        }
        publish(&mut state, NOW);
        state
    }

    #[test]
    fn added_nodes_publish_and_verify() {
        let mut state = State::new(config(), quorum(3)).expect("valid");
        for seed in 1..=3 {
            state.add_node(entry(seed), NOW).expect("adds");
        }
        assert_eq!(
            state.add_node(entry(1), NOW),
            Err(StateError::AddressUsed(address(1)))
        );

        let registry = publish(&mut state, NOW);
        assert_eq!(registry.version, 1);
        assert_eq!(registry.nodes.len(), 3);

        // The in-process stand-in verifies exactly like the threshold key will.
        let verified = registry
            .verify(governance_signer().address(), 0)
            .expect("verifies");
        assert_eq!(verified.nodes().len(), 3);
    }

    #[test]
    fn invalid_entries_are_refused() {
        let mut state = State::new(config(), quorum(1)).expect("valid");
        let mutations: [fn(&mut NodeEntry); 4] = [
            |e| e.operator = " ".to_owned(),
            |e| e.endpoints.clear(),
            |e| e.endpoints = vec!["https://node.example".to_owned()],
            |e| e.weight = 0,
        ];
        for mutate in mutations {
            let mut bad = entry(1);
            mutate(&mut bad);
            assert!(matches!(
                state.add_node(bad, NOW),
                Err(StateError::InvalidEntry(_))
            ));
        }
        assert!(state.nodes.is_empty());
    }

    #[test]
    fn a_replacement_swaps_the_address_in_one_version() {
        let mut state = listed(&[1, 2], 2);
        let later = NOW + 10;
        state
            .replace_node(address(1), address(50), later)
            .expect("replaces");

        let registry = publish(&mut state, later);
        assert_eq!(registry.version, 2);
        assert_eq!(registry.nodes.len(), 2, "the count never changes");
        let replaced = registry
            .nodes
            .iter()
            .find(|n| n.address == address(50))
            .expect("the new address is listed");
        assert_eq!(replaced.operator, "op-1");
        assert_eq!(replaced.endpoints, entry(1).endpoints);
        assert!(registry.nodes.iter().all(|n| n.address != address(1)));

        assert_eq!(
            state.node_listing(address(1)),
            Some(NodeListing {
                address: address(1),
                operator: "op-1".to_owned(),
                added_at: NOW,
                removed_at: Some(later),
            })
        );
        assert_eq!(
            state
                .node_listing(address(50))
                .map(|l| (l.added_at, l.removed_at)),
            Some((later, None))
        );
        assert_eq!(state.node_listing(address(99)), None);

        assert_eq!(
            state.replace_node(address(1), address(51), later),
            Err(StateError::UnknownNode(address(1)))
        );
        for used in [address(1), address(2), address(50)] {
            assert_eq!(
                state.replace_node(address(2), used, later),
                Err(StateError::AddressUsed(used))
            );
        }
    }

    #[test]
    fn removal_never_goes_below_min_nodes_and_never_comes_back() {
        let mut state = listed(&[1, 2, 3], 3);
        assert_eq!(
            state.remove_node(address(3), NOW + 1),
            Err(StateError::BelowQuorum {
                remaining: 2,
                min_nodes: 3
            })
        );
        state.set_quorum(quorum(2)).expect("valid");
        state.remove_node(address(3), NOW + 1).expect("removes");
        assert_eq!(
            state
                .node_listing(address(3))
                .and_then(|listing| listing.removed_at),
            Some(NOW + 1)
        );
        assert_eq!(
            state.add_node(entry(3), NOW + 2),
            Err(StateError::AddressUsed(address(3)))
        );
        assert_eq!(
            state.remove_node(address(3), NOW + 2),
            Err(StateError::UnknownNode(address(3)))
        );
    }

    /// A client key lives on a consumer's machine. It must never become a
    /// price-signing key, and a revoked one must never come back.
    #[test]
    fn an_address_has_one_role_once() {
        let mut state = listed(&[1], 1);
        assert_eq!(
            state.add_client(address(1), NOW + 60, NOW),
            Err(StateError::AddressUsed(address(1)))
        );
        state.add_client(address(9), NOW + 60, NOW).expect("adds");
        assert_eq!(
            state.add_node(entry(9), NOW),
            Err(StateError::AddressUsed(address(9)))
        );
        assert_eq!(
            state.replace_node(address(1), address(9), NOW),
            Err(StateError::AddressUsed(address(9)))
        );
        state.remove_client(address(9)).expect("removes");
        assert_eq!(
            state.add_client(address(9), NOW + 60, NOW),
            Err(StateError::AddressUsed(address(9)))
        );
        assert_eq!(
            state.add_node(entry(9), NOW),
            Err(StateError::AddressUsed(address(9)))
        );
    }

    #[test]
    fn client_changes_follow_the_rules() {
        let mut state = State::new(config(), quorum(1)).expect("valid");
        state.add_client(address(1), NOW + 60, NOW).expect("adds");
        assert_eq!(
            state.add_client(address(1), NOW + 60, NOW),
            Err(StateError::AddressUsed(address(1)))
        );
        assert!(matches!(
            state.add_client(address(2), NOW, NOW),
            Err(StateError::InvalidClient(_))
        ));

        state
            .set_client_expiry(address(1), NOW + 120)
            .expect("extends");
        assert_eq!(
            state.clients.get(&address(1)).map(|c| c.expires_at),
            Some(NOW + 120)
        );
        assert_eq!(
            state.remove_client(address(9)),
            Err(StateError::UnknownClient(address(9)))
        );
        state.remove_client(address(1)).expect("removes");
        assert!(state.clients.is_empty());
    }

    #[test]
    fn the_client_list_publishes_with_its_own_version() {
        let mut state = listed(&[1], 1);
        let registry_version = state.version;
        state.add_client(address(7), NOW + 600, NOW).expect("adds");

        let list = state.unsigned_client_list(NOW).expect("encodes");
        let signature = governance_signer().sign_payload(&list.signing_bytes);
        assert_eq!(state.publish_clients(list.clone(), signature), Ok(1));
        assert_eq!(state.version, registry_version);
        let published = state.clients_published.clone().expect("published");
        let verified = published
            .verify(governance_signer().address(), 0)
            .expect("verifies with oracle-wire");
        assert_eq!(verified.epoch_secs(), 60);
        assert_eq!(
            verified.get(address(7)).map(|c| c.expires_at),
            Some(NOW + 600)
        );

        let signature = governance_signer().sign_payload(&list.signing_bytes);
        assert!(matches!(
            state.publish_clients(list, signature),
            Err(StateError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn a_stale_signing_round_cannot_publish() {
        let mut state = listed(&[1], 1);
        let doc = state.unsigned_document(NOW + 5).expect("encodes");
        publish(&mut state, NOW + 6);
        let signature = governance_signer().sign_payload(&doc.signing_bytes);
        assert_eq!(
            state.publish(doc, signature),
            Err(StateError::VersionMismatch {
                expected: 3,
                got: 2,
            })
        );
    }

    #[test]
    fn the_state_round_trips_through_stable_memory() {
        let mut state = listed(&[1, 2], 1);
        state
            .replace_node(address(1), address(3), NOW + 1)
            .expect("replaces");
        state.add_client(address(8), NOW + 60, NOW).expect("adds");
        state.add_client(address(9), NOW + 60, NOW).expect("adds");
        state.remove_client(address(9)).expect("removes");
        publish(&mut state, NOW + 1);

        let bytes = serde_json::to_vec(&state).expect("serialises");
        let loaded: State = serde_json::from_slice(&bytes).expect("loads");
        assert_eq!(loaded, state);
    }

    /// Nothing was deployed with node ids, so there is no migration. An old
    /// state fails to load, `post_upgrade` traps, and the old wasm stays.
    #[test]
    fn a_state_keyed_by_node_id_does_not_load() {
        let state = listed(&[1], 1);
        let mut old = serde_json::to_value(&state).expect("serialises");
        let nodes = old.get_mut("nodes").expect("the nodes");
        let node = nodes
            .get(address(1).to_string())
            .cloned()
            .expect("the node");
        *nodes = serde_json::json!({ "oracle-a": node });
        assert!(serde_json::from_value::<State>(old).is_err());
    }
}
