//! The registry state machine.
//!
//! No Internet Computer dependency here. Every rule in SPEC §3.6 is a unit
//! test in this file rather than a PocketIC run, and the canister glue in
//! `lib.rs` only adds the caller, the clock, and the threshold signature.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use oracle_types::Symbol;
use oracle_wire::{
    Address, ClientEntry, ClientList, CompressedPublicKey, FeedContent, FeedSet, MAX_CLIENTS,
    MAX_NODES, NodeEntry, NodeListing, PushPolicy, Quorum, Registry, Signature, VerifiedRegistry,
    WireError,
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
    /// Removing the node would leave fewer nodes than the canister prices with.
    #[error(
        "removing the node would leave {remaining} nodes, below the quorum of {recommended} \
         that the canister prices with, so every priced feed would halt; lower `recommended` \
         with set_quorum first"
    )]
    BelowQuorum {
        /// Nodes that would remain.
        remaining: usize,
        /// The registry's `recommended`.
        recommended: u16,
    },
    /// Raising the quorum above the listed nodes halts every priced feed.
    #[error(
        "a quorum of {recommended} with {nodes} listed nodes halts every priced feed; \
         list the nodes first"
    )]
    QuorumAboveNodes {
        /// The `recommended` that governance asked for.
        recommended: u16,
        /// The listed nodes.
        nodes: usize,
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
    /// The feed set failed a check.
    #[error("invalid feed set: {0}")]
    InvalidFeedSet(String),
    /// No feed set has been set, so there is nothing to sign.
    #[error("no feed set has been set yet; call set_feed_set first")]
    NoFeedSet,
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
            endpoints: self.endpoints.clone(),
            weight: self.weight,
        }
    }
}

/// A node governance replaced or removed. Kept so the address is never
/// listed again, and for stored-frame verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredNode {
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

/// A document that the governance key signs: the registry, the client list or the feed set.
pub trait SignedDocument: Sized {
    /// What a version holds besides its version, its issue time and its signature.
    type Content: Clone + fmt::Debug + PartialEq + Eq;

    /// The canonical bytes that the governance key signs.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::FieldTooLong`] if a field exceeds its cap.
    fn signing_bytes(
        version: u64,
        effective_from: u64,
        content: &Self::Content,
    ) -> Result<Vec<u8>, WireError>;

    /// The signed document.
    fn seal(
        version: u64,
        effective_from: u64,
        content: Self::Content,
        governance_signature: Signature,
    ) -> Self;
}

/// What a registry version lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryContent {
    /// The listed nodes.
    pub nodes: Vec<NodeEntry>,
    /// The quorum guidance.
    pub quorum: Quorum,
}

/// What a client list version lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientsContent {
    /// The broadcast-key epoch.
    pub epoch_secs: u64,
    /// The clients.
    pub clients: Vec<ClientEntry>,
}

impl SignedDocument for Registry {
    type Content = RegistryContent;

    fn signing_bytes(
        version: u64,
        at: u64,
        content: &RegistryContent,
    ) -> Result<Vec<u8>, WireError> {
        Self::signing_bytes(version, at, &content.nodes, content.quorum)
    }

    fn seal(version: u64, at: u64, content: RegistryContent, signature: Signature) -> Self {
        Self {
            version,
            effective_from: at,
            nodes: content.nodes,
            quorum: content.quorum,
            governance_signature: signature,
        }
    }
}

impl SignedDocument for ClientList {
    type Content = ClientsContent;

    fn signing_bytes(
        version: u64,
        at: u64,
        content: &ClientsContent,
    ) -> Result<Vec<u8>, WireError> {
        Self::signing_bytes(version, at, content.epoch_secs, &content.clients)
    }

    fn seal(version: u64, at: u64, content: ClientsContent, signature: Signature) -> Self {
        Self {
            version,
            effective_from: at,
            epoch_secs: content.epoch_secs,
            clients: content.clients,
            governance_signature: signature,
        }
    }
}

impl SignedDocument for FeedSet {
    type Content = FeedContent;

    fn signing_bytes(version: u64, at: u64, content: &FeedContent) -> Result<Vec<u8>, WireError> {
        Self::signing_bytes(
            version,
            at,
            &content.min_node_version,
            content.push,
            &content.feeds,
        )
    }

    fn seal(version: u64, at: u64, content: FeedContent, signature: Signature) -> Self {
        Self {
            version,
            effective_from: at,
            min_node_version: content.min_node_version,
            push: content.push,
            feeds: content.feeds,
            governance_signature: signature,
        }
    }
}

/// A document ready to sign: the next version, and its canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unsigned<T: SignedDocument> {
    /// The slot's version + 1.
    pub version: u64,
    /// The issue time, unix seconds.
    pub effective_from: u64,
    /// What the version holds.
    pub content: T::Content,
    /// [`SignedDocument::signing_bytes`] over the above.
    pub signing_bytes: Vec<u8>,
}

/// One signed document and its version: each publish signs the next version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSlot<T> {
    /// Version of the last published document. Zero before the first.
    pub version: u64,
    /// The last signed document.
    pub published: Option<T>,
}

impl<T> Default for SignedSlot<T> {
    fn default() -> Self {
        Self {
            version: 0,
            published: None,
        }
    }
}

impl<T: SignedDocument> SignedSlot<T> {
    /// Builds the next version of the document from its content.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::Wire`] if a field exceeds its cap.
    pub fn next(&self, now: u64, content: T::Content) -> Result<Unsigned<T>, StateError> {
        let version = self.version.saturating_add(1);
        let signing_bytes = T::signing_bytes(version, now, &content)?;
        Ok(Unsigned {
            version,
            effective_from: now,
            content,
            signing_bytes,
        })
    }

    /// Stores a signed document as the published one. Returns its version.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::VersionMismatch`] if the document was built for
    /// a version other than the next one.
    pub fn publish(
        &mut self,
        unsigned: Unsigned<T>,
        governance_signature: Signature,
    ) -> Result<u64, StateError> {
        let expected = self.version.saturating_add(1);
        if unsigned.version != expected {
            return Err(StateError::VersionMismatch {
                expected,
                got: unsigned.version,
            });
        }
        self.published = Some(T::seal(
            unsigned.version,
            unsigned.effective_from,
            unsigned.content,
            governance_signature,
        ));
        self.version = unsigned.version;
        Ok(self.version)
    }
}

/// The whole canister state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    /// Install-time configuration.
    pub config: Config,
    /// Quorum guidance published in the document.
    pub quorum: Quorum,
    /// Listed nodes by address.
    pub nodes: BTreeMap<Address, NodeRecord>,
    /// Nodes governance replaced or removed, by address.
    pub retired: BTreeMap<Address, RetiredNode>,
    /// The registry document.
    pub registry: SignedSlot<Registry>,
    /// The threshold public key, once fetched.
    pub governance_key: Option<CompressedPublicKey>,
    /// Authorised clients by address.
    pub clients: BTreeMap<Address, ClientRecord>,
    /// Clients governance removed. Their addresses are never listed again.
    pub removed_clients: BTreeSet<Address>,
    /// The client list.
    pub client_list: SignedSlot<ClientList>,
    /// The feed set governance last set, in canonical form. `None` before the first.
    pub feed_content: Option<FeedContent>,
    /// The feed set.
    pub feed_set: SignedSlot<FeedSet>,
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
            registry: SignedSlot::default(),
            governance_key: None,
            clients: BTreeMap::new(),
            removed_clients: BTreeSet::new(),
            client_list: SignedSlot::default(),
            feed_content: None,
            feed_set: SignedSlot::default(),
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
            endpoints,
            weight,
        } = entry;
        self.nodes.insert(
            address,
            NodeRecord {
                endpoints,
                weight,
                added_at: now,
            },
        );
        Ok(())
    }

    /// Governance rotates a node's key: `new` takes the place of `old`, with
    /// the same endpoints and weight. Bumps the document.
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
    /// fall below `quorum.recommended`, the quorum that the canister prices
    /// with. That bound also keeps `quorum.min_nodes`.
    pub fn remove_node(&mut self, address: Address, now: u64) -> Result<(), StateError> {
        if !self.nodes.contains_key(&address) {
            return Err(StateError::UnknownNode(address));
        }
        let remaining = self.nodes.len().saturating_sub(1);
        if remaining < usize::from(self.quorum.recommended) {
            return Err(StateError::BelowQuorum {
                remaining,
                recommended: self.quorum.recommended,
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
    /// Returns [`StateError::InvalidQuorum`] if the values are inconsistent,
    /// and [`StateError::QuorumAboveNodes`] for a raise of `recommended` above
    /// the listed nodes. Lowering it, or keeping it, always passes.
    pub fn set_quorum(&mut self, quorum: Quorum) -> Result<(), StateError> {
        check_quorum(quorum)?;
        if usize::from(quorum.recommended) > self.nodes.len()
            && quorum.recommended > self.quorum.recommended
        {
            return Err(StateError::QuorumAboveNodes {
                recommended: quorum.recommended,
                nodes: self.nodes.len(),
            });
        }
        self.quorum = quorum;
        Ok(())
    }

    /// Records the threshold public key.
    pub fn set_governance_key(&mut self, key: CompressedPublicKey) {
        self.governance_key = Some(key);
    }

    /// Builds the next registry document and its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns a wire error if the document does not encode, which means a
    /// listed entry broke a limit that `NodeEntry::validate` should have caught.
    pub fn next_registry(&self, now: u64) -> Result<Unsigned<Registry>, StateError> {
        let nodes = self
            .nodes
            .iter()
            .map(|(address, node)| node.entry(*address))
            .collect();
        self.registry.next(
            now,
            RegistryContent {
                nodes,
                quorum: self.quorum,
            },
        )
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
    pub fn next_client_list(&self, now: u64) -> Result<Unsigned<ClientList>, StateError> {
        let clients = self
            .clients
            .iter()
            .map(|(address, record)| ClientEntry {
                address: *address,
                expires_at: record.expires_at,
            })
            .collect();
        self.client_list.next(
            now,
            ClientsContent {
                epoch_secs: self.config.epoch_secs,
                clients,
            },
        )
    }

    /// Checks a feed set and keeps its canonical form for the next signing round.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidFeedSet`] with the first problem.
    pub fn set_feed_content(&mut self, content: &FeedContent) -> Result<(), StateError> {
        self.feed_content = Some(content.canonical().map_err(StateError::InvalidFeedSet)?);
        Ok(())
    }

    /// Builds the next feed set to sign, from the content governance last set.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::NoFeedSet`] before the first `set_feed_set`, and
    /// [`StateError::Wire`] if a field exceeds its cap.
    pub fn next_feed_set(&self, now: u64) -> Result<Unsigned<FeedSet>, StateError> {
        let content = self.feed_content.clone().ok_or(StateError::NoFeedSet)?;
        self.feed_set.next(now, content)
    }

    /// The push pace of the published feed set, which the nodes follow.
    #[must_use]
    pub fn push_pace(&self) -> Option<PushPolicy> {
        self.feed_set.published.as_ref().and_then(|set| set.push)
    }

    /// The first of `feeds` that the feed set does not list; `None` when it lists all, or when there is no set.
    #[must_use]
    pub fn first_unlisted(&self, feeds: &[Symbol]) -> Option<Symbol> {
        let content = self.feed_content.as_ref()?;
        let listed: BTreeSet<Symbol> = content
            .feeds
            .iter()
            .filter_map(|feed| feed.symbol.parse().ok())
            .collect();
        feeds.iter().find(|feed| !listed.contains(feed)).copied()
    }

    /// The published documents whose signature fails against the governance
    /// key, such as after a rollback that dropped a signed field.
    #[must_use]
    pub fn documents_that_do_not_verify(&self) -> Vec<&'static str> {
        let Some(governance) = self.governance_key.and_then(|key| key.address().ok()) else {
            return Vec::new();
        };
        let mut failed = Vec::new();
        if let Some(registry) = &self.registry.published
            && registry.verify(governance, 0).is_err()
        {
            failed.push("registry (republish)");
        }
        if let Some(list) = &self.client_list.published
            && list.verify(governance, 0).is_err()
        {
            failed.push("client list (republish_clients)");
        }
        if let Some(set) = &self.feed_set.published
            && set.verify(governance, 0).is_err()
        {
            failed.push("feed set (republish_feeds)");
        }
        failed
    }

    /// The published document, verified against the governance key. The
    /// price checks use it.
    #[must_use]
    pub fn verified_registry(&self) -> Option<VerifiedRegistry> {
        let governance = self.governance_key?.address().ok()?;
        self.registry.published.as_ref()?.verify(governance, 0).ok()
    }

    /// When a node address was listed, whether it still is or not.
    #[must_use]
    pub fn node_listing(&self, address: Address) -> Option<NodeListing> {
        if let Some(node) = self.nodes.get(&address) {
            return Some(NodeListing {
                address,
                added_at: node.added_at,
                removed_at: None,
            });
        }
        self.retired.get(&address).map(|node| NodeListing {
            address,
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
pub(crate) mod tests {
    use oracle_wire::Signer;
    use zeroize::Zeroizing;

    use super::*;

    const NOW: u64 = 1_754_582_400;

    pub(crate) fn config() -> Config {
        Config {
            key_name: "dfx_test_key".to_owned(),
            epoch_secs: 60,
        }
    }

    fn quorum(min_nodes: u16, recommended: u16) -> Quorum {
        Quorum {
            min_nodes,
            recommended,
        }
    }

    pub(crate) fn governance_signer() -> Signer {
        Signer::from_secret(&Zeroizing::new([0x33; 32])).expect("valid key")
    }

    pub(crate) fn address(seed: u8) -> Address {
        Signer::from_secret(&Zeroizing::new([seed; 32]))
            .expect("valid key")
            .address()
    }

    pub(crate) fn entry(seed: u8) -> NodeEntry {
        NodeEntry {
            address: address(seed),
            endpoints: vec![format!("wss://node{seed}.example/v2/ws")],
            weight: 1,
        }
    }

    /// Signs and publishes the way the canister does, with an in-process key
    /// standing in for the threshold key.
    pub(crate) fn publish(state: &mut State, now: u64) -> Registry {
        let doc = state.next_registry(now).expect("encodes");
        let signature = governance_signer().sign_payload(&doc.signing_bytes);
        state.registry.publish(doc, signature).expect("publishes");
        state.registry.published.clone().expect("published")
    }

    /// Nodes from these seeds, a quorum of all of them, and one published registry.
    pub(crate) fn listed(seeds: &[u8]) -> State {
        let count = u16::try_from(seeds.len()).expect("a few nodes");
        let mut state = State::new(config(), quorum(1, count.max(1))).expect("valid");
        for &seed in seeds {
            state.add_node(entry(seed), NOW).expect("adds");
        }
        publish(&mut state, NOW);
        state
    }

    #[test]
    fn added_nodes_publish_and_verify() {
        let mut state = State::new(config(), quorum(3, 3)).expect("valid");
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
        let mut state = State::new(config(), quorum(1, 1)).expect("valid");
        let mutations: [fn(&mut NodeEntry); 3] = [
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
        let mut state = listed(&[1, 2]);
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
        assert_eq!(replaced.endpoints, entry(1).endpoints);
        assert!(registry.nodes.iter().all(|n| n.address != address(1)));

        assert_eq!(
            state.node_listing(address(1)),
            Some(NodeListing {
                address: address(1),
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

    /// SPEC §3.6: the canister prices with `recommended`, so a removal below it
    /// would halt every priced feed. Governance lowers the quorum first.
    #[test]
    fn removal_never_goes_below_the_price_quorum_and_never_comes_back() {
        let mut state = listed(&[1, 2, 3]);
        assert_eq!(
            state.remove_node(address(3), NOW + 1),
            Err(StateError::BelowQuorum {
                remaining: 2,
                recommended: 3
            })
        );
        state.set_quorum(quorum(1, 3)).expect("valid");
        assert!(
            state.remove_node(address(3), NOW + 1).is_err(),
            "min_nodes alone does not decide"
        );
        state.set_quorum(quorum(1, 2)).expect("a lower quorum");
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

    /// A quorum above the listed nodes halts every priced feed, so a raise to
    /// it is refused; a quorum that already was above them can stay.
    #[test]
    fn a_quorum_raise_above_the_listed_nodes_is_refused() {
        let mut state = listed(&[1, 2]);
        assert_eq!(
            state.set_quorum(quorum(1, 3)),
            Err(StateError::QuorumAboveNodes {
                recommended: 3,
                nodes: 2
            })
        );
        state.set_quorum(quorum(1, 1)).expect("lower");
        state
            .set_quorum(quorum(2, 2))
            .expect("up to the listed nodes");

        let mut empty = State::new(config(), quorum(1, 3)).expect("valid");
        empty
            .set_quorum(quorum(2, 3))
            .expect("the install quorum stays while nodes are listed");
    }

    /// A client key lives on a consumer's machine. It must never become a
    /// price-signing key, and a revoked one must never come back.
    #[test]
    fn an_address_has_one_role_once() {
        let mut state = listed(&[1]);
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
        let mut state = State::new(config(), quorum(1, 1)).expect("valid");
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
        let mut state = listed(&[1]);
        let registry_version = state.registry.version;
        state.add_client(address(7), NOW + 600, NOW).expect("adds");

        let list = state.next_client_list(NOW).expect("encodes");
        let signature = governance_signer().sign_payload(&list.signing_bytes);
        assert_eq!(state.client_list.publish(list.clone(), signature), Ok(1));
        assert_eq!(state.registry.version, registry_version);
        let published = state.client_list.published.clone().expect("published");
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
            state.client_list.publish(list, signature),
            Err(StateError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn a_stale_signing_round_cannot_publish() {
        let mut state = listed(&[1]);
        let doc = state.next_registry(NOW + 5).expect("encodes");
        publish(&mut state, NOW + 6);
        let signature = governance_signer().sign_payload(&doc.signing_bytes);
        assert_eq!(
            state.registry.publish(doc, signature),
            Err(StateError::VersionMismatch {
                expected: 3,
                got: 2,
            })
        );
    }

    pub(crate) fn one_feed() -> FeedContent {
        FeedContent {
            min_node_version: String::new(),
            push: None,
            feeds: vec![oracle_wire::FeedSettings {
                symbol: "CRYPTO.ETH/BTC".to_owned(),
                deviation_bps: Some("0.50".to_owned()),
                sources: vec![oracle_wire::SourceSettings {
                    venue: "binance".to_owned(),
                    market: "spot".to_owned(),
                    symbol: "ETHBTC".to_owned(),
                    ..oracle_wire::SourceSettings::default()
                }],
                ..oracle_wire::FeedSettings::default()
            }],
        }
    }

    #[test]
    fn a_feed_set_publishes_in_canonical_form_and_verifies() {
        let mut state = listed(&[1]);
        assert_eq!(state.next_feed_set(NOW), Err(StateError::NoFeedSet));
        state.set_feed_content(&one_feed()).expect("passes");
        let unsigned = state.next_feed_set(NOW).expect("encodes");
        let signature = governance_signer().sign_payload(&unsigned.signing_bytes);
        assert_eq!(state.feed_set.publish(unsigned.clone(), signature), Ok(1));
        let published = state.feed_set.published.clone().expect("published");
        let verified = published
            .verify(governance_signer().address(), 0)
            .expect("verifies");
        assert_eq!(
            verified
                .feeds()
                .first()
                .and_then(|feed| feed.deviation_bps.as_deref()),
            Some("0.5")
        );
        assert_eq!(
            state.feed_set.publish(unsigned, signature),
            Err(StateError::VersionMismatch {
                expected: 2,
                got: 1,
            })
        );
        let eth: Symbol = "CRYPTO.ETH/BTC".parse().expect("a symbol");
        let sol: Symbol = "CRYPTO.SOL/BTC".parse().expect("a symbol");
        assert_eq!(state.first_unlisted(&[eth]), None);
        assert_eq!(state.first_unlisted(&[eth, sol]), Some(sol));
        let mut bad = one_feed();
        bad.feeds.clear();
        assert!(matches!(
            state.set_feed_content(&bad),
            Err(StateError::InvalidFeedSet(_))
        ));
    }
}
