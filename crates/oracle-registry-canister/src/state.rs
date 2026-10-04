//! The registry state machine.
//!
//! No Internet Computer dependency here. Every rule in SPEC §3.6 is a unit
//! test in this file rather than a PocketIC run, and the canister glue in
//! `lib.rs` only adds the caller, the clock, and the threshold signature.

use std::collections::BTreeMap;

use oracle_wire::{
    Address, ClientEntry, ClientList, CompressedPublicKey, KeyHistoryEntry, MAX_CLIENT_ID_LEN,
    MAX_CLIENTS, MAX_ENDPOINT_LEN, MAX_ENDPOINTS, MAX_NODE_ID_LEN, MAX_NODES, MAX_OPERATOR_LEN,
    NodeEntry, Quorum, Registry, Signature, SigningKeyCert, WireError,
};
use serde::{Deserialize, Serialize};

/// A rule of the registry was broken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StateError {
    /// Only a canister controller may do this.
    #[error("only governance (a canister controller) may do this")]
    NotGovernance,
    /// No listed node has this id.
    #[error("unknown node `{0}`")]
    UnknownNode(String),
    /// The node is already in the registry.
    #[error("node `{0}` is already listed")]
    AlreadyListed(String),
    /// The entry failed a structural check.
    #[error("invalid entry: {0}")]
    InvalidEntry(String),
    /// The certificate failed a check.
    #[error("invalid certificate: {0}")]
    InvalidCert(String),
    /// A signing address may belong to one key of one node, ever.
    #[error("signing address {0} is already known to the registry")]
    AddressInUse(Address),
    /// An identity key may back one node.
    #[error("identity key is already used by node `{0}`")]
    IdentityInUse(String),
    /// Rotations are serialised fleet-wide (SPEC §3.6).
    #[error("a rotation happened at {last}; the next is allowed at {next_allowed}")]
    RotationTooSoon {
        /// When the last rotation happened, unix seconds.
        last: u64,
        /// When the next one is allowed, unix seconds.
        next_allowed: u64,
    },
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
    /// No client has this id.
    #[error("unknown client `{0}`")]
    UnknownClient(String),
    /// A client with this id is already listed.
    #[error("client `{0}` is already listed")]
    ClientExists(String),
    /// Another client already uses this key.
    #[error("the key is already used by client `{0}`")]
    ClientKeyInUse(String),
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
    /// Minimum seconds between two rotations fleet-wide.
    pub rotation_window_secs: u64,
    /// Seconds between heartbeat re-signs.
    pub heartbeat_secs: u64,
    /// Broadcast-key epoch, published in the client list.
    #[serde(default = "default_epoch_secs")]
    pub epoch_secs: u64,
    /// Seconds between client-list heartbeat re-signs.
    #[serde(default = "default_clients_heartbeat_secs")]
    pub clients_heartbeat_secs: u64,
}

/// Default broadcast-key epoch (SPEC §6.1).
pub const DEFAULT_EPOCH_SECS: u64 = 60;
/// Default client-list heartbeat. Nodes stop admitting clients after three
/// missed beats, so it bounds how long a withheld revocation can go unseen.
pub const DEFAULT_CLIENTS_HEARTBEAT_SECS: u64 = 3_600;

const fn default_epoch_secs() -> u64 {
    DEFAULT_EPOCH_SECS
}

const fn default_clients_heartbeat_secs() -> u64 {
    DEFAULT_CLIENTS_HEARTBEAT_SECS
}

/// One authorised client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRecord {
    /// The client's secp256k1 API key.
    pub pubkey: CompressedPublicKey,
    /// End of authorisation, unix seconds.
    pub expires_at: u64,
    /// When governance added it, unix seconds.
    pub added_at: u64,
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

/// One signing key of one node, live or retired.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// The certificate the operator issued with the node's identity key.
    pub cert: SigningKeyCert,
    /// When the key became live, unix seconds.
    pub added_at: u64,
    /// When the key stopped being live, unix seconds. `None` while live.
    pub retired_at: Option<u64>,
}

/// A listed node and its whole key history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    /// Who runs it.
    pub operator: String,
    /// The long-lived identity key that issues the node's certificates.
    pub identity_pubkey: CompressedPublicKey,
    /// WebSocket endpoints.
    pub endpoints: Vec<String>,
    /// Relative weight hint.
    pub weight: u16,
    /// The generation whose key verifies live frames.
    pub live: u32,
    /// Every generation, including retired ones.
    pub keys: BTreeMap<u32, KeyRecord>,
}

impl NodeRecord {
    fn live_cert(&self) -> &SigningKeyCert {
        &self
            .keys
            .get(&self.live)
            .expect("the live generation is always present")
            .cert
    }

    fn entry(&self, node_id: &str) -> NodeEntry {
        NodeEntry {
            node_id: node_id.to_owned(),
            operator: self.operator.clone(),
            identity_pubkey: self.identity_pubkey,
            endpoints: self.endpoints.clone(),
            signing_keys: vec![self.live_cert().clone()],
            weight: self.weight,
        }
    }

    fn retire_live(&mut self, now: u64) {
        if let Some(record) = self.keys.get_mut(&self.live) {
            record.retired_at = Some(now);
        }
    }
}

/// A registry document ready to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedDocument {
    /// `State::version + 1`.
    pub version: u64,
    /// The issue time, unix seconds.
    pub effective_from: u64,
    /// Listed nodes, each with its live certificate only.
    pub nodes: Vec<NodeEntry>,
    /// The quorum guidance.
    pub quorum: Quorum,
    /// `Registry::signing_bytes` over the above.
    pub signing_bytes: Vec<u8>,
}

/// The whole canister state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Install-time configuration.
    pub config: Config,
    /// Quorum guidance published in the document.
    pub quorum: Quorum,
    /// Listed nodes by id.
    pub nodes: BTreeMap<String, NodeRecord>,
    /// Nodes governance removed, kept for their key history.
    pub removed: BTreeMap<String, NodeRecord>,
    /// Version of the last published document. Zero before the first.
    pub version: u64,
    /// When the last rotation happened, unix seconds.
    pub last_rotation_at: Option<u64>,
    /// The last signed document.
    pub published: Option<Registry>,
    /// The threshold public key, once fetched.
    pub governance_key: Option<CompressedPublicKey>,
    /// A mutation happened since the last publish.
    pub dirty: bool,
    /// Authorised clients by id. Absent in states saved before clients existed.
    #[serde(default)]
    pub clients: BTreeMap<String, ClientRecord>,
    /// Version of the last published client list. Zero before the first.
    #[serde(default)]
    pub clients_version: u64,
    /// The last signed client list.
    #[serde(default)]
    pub clients_published: Option<ClientList>,
    /// A client change happened since the last client-list publish.
    #[serde(default)]
    pub clients_dirty: bool,
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
            removed: BTreeMap::new(),
            version: 0,
            last_rotation_at: None,
            published: None,
            governance_key: None,
            dirty: true,
            clients: BTreeMap::new(),
            clients_version: 0,
            clients_published: None,
            clients_dirty: true,
        })
    }

    /// Governance lists a node from the entry its operator sent. Bumps the document.
    ///
    /// A node that was removed earlier continues its generation numbers, so
    /// its key history never has two generation ones.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller is not governance, the id is listed, the
    /// registry is full, or the entry or its certificate fails a check.
    pub fn add_node(
        &mut self,
        is_governance: bool,
        entry: NodeEntry,
        now: u64,
    ) -> Result<(), StateError> {
        if !is_governance {
            return Err(StateError::NotGovernance);
        }
        if self.nodes.contains_key(&entry.node_id) {
            return Err(StateError::AlreadyListed(entry.node_id));
        }
        if self.nodes.len() >= MAX_NODES {
            return Err(StateError::TooManyNodes);
        }
        self.validate_entry(&entry, now)?;
        let NodeEntry {
            node_id,
            operator,
            identity_pubkey,
            endpoints,
            signing_keys,
            weight,
        } = entry;
        let cert = signing_keys
            .into_iter()
            .next()
            .ok_or_else(|| StateError::InvalidEntry("entry has no certificate".to_owned()))?;

        let mut keys = self
            .removed
            .remove(&node_id)
            .map(|old| old.keys)
            .unwrap_or_default();
        let generation = keys
            .keys()
            .next_back()
            .map_or(1, |last| last.saturating_add(1));
        keys.insert(
            generation,
            KeyRecord {
                cert,
                added_at: now,
                retired_at: None,
            },
        );
        self.nodes.insert(
            node_id,
            NodeRecord {
                operator,
                identity_pubkey,
                endpoints,
                weight,
                live: generation,
                keys,
            },
        );
        self.dirty = true;
        Ok(())
    }

    /// Governance swaps a node's signing key with the certificate its operator
    /// sent. Atomic: the new generation is live and the old one retired in the
    /// same call. Bumps the document.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller is not governance, the node is unknown,
    /// the certificate fails a check, or another rotation happened inside the
    /// rotation window.
    pub fn rotate_key(
        &mut self,
        is_governance: bool,
        node_id: &str,
        cert: SigningKeyCert,
        now: u64,
    ) -> Result<(), StateError> {
        if !is_governance {
            return Err(StateError::NotGovernance);
        }
        let node = self
            .nodes
            .get(node_id)
            .ok_or_else(|| StateError::UnknownNode(node_id.to_owned()))?;
        let identity = node.identity_pubkey;
        self.validate_cert(node_id, &identity, &cert, now)?;
        if let Some(last) = self.last_rotation_at {
            let next_allowed = last.saturating_add(self.config.rotation_window_secs);
            if now < next_allowed {
                return Err(StateError::RotationTooSoon { last, next_allowed });
            }
        }

        let Some(node) = self.nodes.get_mut(node_id) else {
            return Err(StateError::UnknownNode(node_id.to_owned()));
        };
        node.retire_live(now);
        let generation = node.live.saturating_add(1);
        node.keys.insert(
            generation,
            KeyRecord {
                cert,
                added_at: now,
                retired_at: None,
            },
        );
        node.live = generation;
        self.last_rotation_at = Some(now);
        self.dirty = true;
        Ok(())
    }

    /// Governance de-lists a node. Its keys stay in history. Bumps the document.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller is not governance, the node is unknown,
    /// or the remaining count would fall below `quorum.min_nodes`.
    pub fn remove_node(
        &mut self,
        is_governance: bool,
        node_id: &str,
        now: u64,
    ) -> Result<(), StateError> {
        if !is_governance {
            return Err(StateError::NotGovernance);
        }
        if !self.nodes.contains_key(node_id) {
            return Err(StateError::UnknownNode(node_id.to_owned()));
        }
        let remaining = self.nodes.len().saturating_sub(1);
        if remaining < usize::from(self.quorum.min_nodes) {
            return Err(StateError::BelowQuorum {
                remaining,
                min_nodes: self.quorum.min_nodes,
            });
        }
        let Some(mut node) = self.nodes.remove(node_id) else {
            return Err(StateError::UnknownNode(node_id.to_owned()));
        };
        node.retire_live(now);
        self.removed.insert(node_id.to_owned(), node);
        self.dirty = true;
        Ok(())
    }

    /// Governance changes the quorum guidance. Bumps the document.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller is not governance or the values are
    /// inconsistent.
    pub fn set_quorum(&mut self, is_governance: bool, quorum: Quorum) -> Result<(), StateError> {
        if !is_governance {
            return Err(StateError::NotGovernance);
        }
        check_quorum(quorum)?;
        self.quorum = quorum;
        self.dirty = true;
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
    /// listed entry broke a limit that `validate_entry` should have caught.
    pub fn unsigned_document(&self, now: u64) -> Result<UnsignedDocument, StateError> {
        let version = self.version.saturating_add(1);
        let nodes: Vec<NodeEntry> = self.nodes.iter().map(|(id, node)| node.entry(id)).collect();
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
        self.dirty = false;
        Ok(self.version)
    }

    /// `true` if the published document is missing or behind the state.
    #[must_use]
    pub const fn needs_publish(&self) -> bool {
        self.dirty || self.published.is_none()
    }

    /// `true` if the registry needs a signing round now: a change, or a
    /// heartbeat that is due.
    #[must_use]
    pub fn registry_due(&self, now: u64) -> bool {
        self.needs_publish()
            || self.published.as_ref().is_some_and(|registry| {
                now >= registry
                    .effective_from
                    .saturating_add(self.config.heartbeat_secs)
            })
    }

    /// `true` if the client list needs a signing round now.
    #[must_use]
    pub fn clients_due(&self, now: u64) -> bool {
        self.clients_dirty
            || self.clients_published.as_ref().is_none_or(|list| {
                now >= list
                    .effective_from
                    .saturating_add(self.config.clients_heartbeat_secs)
            })
    }

    /// Governance authorises a client until `expires_at`. Bumps the client list.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller is not governance, the id is taken or
    /// invalid, the key is not a curve point or belongs to another client, the
    /// list is full, or `expires_at` is not in the future.
    pub fn add_client(
        &mut self,
        is_governance: bool,
        client_id: String,
        pubkey: CompressedPublicKey,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StateError> {
        if !is_governance {
            return Err(StateError::NotGovernance);
        }
        let trimmed = client_id.trim();
        if trimmed.is_empty() || trimmed != client_id || client_id.len() > MAX_CLIENT_ID_LEN {
            return Err(StateError::InvalidClient(format!(
                "client_id must be 1..={MAX_CLIENT_ID_LEN} bytes with no surrounding whitespace"
            )));
        }
        if self.clients.contains_key(&client_id) {
            return Err(StateError::ClientExists(client_id));
        }
        if self.clients.len() >= MAX_CLIENTS {
            return Err(StateError::TooManyClients);
        }
        if pubkey.decompress().is_err() {
            return Err(StateError::InvalidClient(
                "the key is not a curve point".to_owned(),
            ));
        }
        if let Some((other, _)) = self
            .clients
            .iter()
            .find(|(_, record)| record.pubkey == pubkey)
        {
            return Err(StateError::ClientKeyInUse(other.clone()));
        }
        if expires_at <= now {
            return Err(StateError::InvalidClient(
                "expires_at must be in the future".to_owned(),
            ));
        }
        self.clients.insert(
            client_id,
            ClientRecord {
                pubkey,
                expires_at,
                added_at: now,
            },
        );
        self.clients_dirty = true;
        Ok(())
    }

    /// Governance moves a client's expiry, earlier or later. Bumps the client list.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller is not governance or the client is unknown.
    pub fn set_client_expiry(
        &mut self,
        is_governance: bool,
        client_id: &str,
        expires_at: u64,
    ) -> Result<(), StateError> {
        if !is_governance {
            return Err(StateError::NotGovernance);
        }
        let record = self
            .clients
            .get_mut(client_id)
            .ok_or_else(|| StateError::UnknownClient(client_id.to_owned()))?;
        record.expires_at = expires_at;
        self.clients_dirty = true;
        Ok(())
    }

    /// Governance removes a client. Bumps the client list.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller is not governance or the client is unknown.
    pub fn remove_client(
        &mut self,
        is_governance: bool,
        client_id: &str,
    ) -> Result<(), StateError> {
        if !is_governance {
            return Err(StateError::NotGovernance);
        }
        self.clients
            .remove(client_id)
            .ok_or_else(|| StateError::UnknownClient(client_id.to_owned()))?;
        self.clients_dirty = true;
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
            .map(|(client_id, record)| ClientEntry {
                client_id: client_id.clone(),
                pubkey: record.pubkey,
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
        self.clients_dirty = false;
        Ok(self.clients_version)
    }

    /// Every generation of a node's keys, listed or removed.
    #[must_use]
    pub fn key_history(&self, node_id: &str) -> Option<Vec<KeyHistoryEntry>> {
        let node = self
            .nodes
            .get(node_id)
            .or_else(|| self.removed.get(node_id))?;
        Some(
            node.keys
                .iter()
                .map(|(&generation, record)| KeyHistoryEntry {
                    generation,
                    cert: record.cert.clone(),
                    added_at: record.added_at,
                    retired_at: record.retired_at,
                })
                .collect(),
        )
    }

    /// `true` if any key of any node, listed or removed, has this address.
    #[must_use]
    pub fn address_known(&self, address: Address) -> bool {
        self.nodes
            .values()
            .chain(self.removed.values())
            .flat_map(|node| node.keys.values())
            .any(|record| record.cert.address == address)
    }

    fn validate_entry(&self, entry: &NodeEntry, now: u64) -> Result<(), StateError> {
        let id = entry.node_id.trim();
        if id.is_empty() || id != entry.node_id {
            return Err(StateError::InvalidEntry(
                "node_id must be non-empty with no surrounding whitespace".to_owned(),
            ));
        }
        if entry.node_id.len() > MAX_NODE_ID_LEN {
            return Err(StateError::InvalidEntry(format!(
                "node_id is {} bytes; the limit is {MAX_NODE_ID_LEN}",
                entry.node_id.len()
            )));
        }
        if entry.operator.trim().is_empty() || entry.operator.len() > MAX_OPERATOR_LEN {
            return Err(StateError::InvalidEntry(format!(
                "operator must be 1..={MAX_OPERATOR_LEN} bytes"
            )));
        }
        if entry.endpoints.is_empty() || entry.endpoints.len() > MAX_ENDPOINTS {
            return Err(StateError::InvalidEntry(format!(
                "endpoints must number 1..={MAX_ENDPOINTS}"
            )));
        }
        for endpoint in &entry.endpoints {
            if endpoint.len() > MAX_ENDPOINT_LEN {
                return Err(StateError::InvalidEntry(format!(
                    "endpoint `{endpoint}` exceeds {MAX_ENDPOINT_LEN} bytes"
                )));
            }
            if !(endpoint.starts_with("wss://") || endpoint.starts_with("ws://")) {
                return Err(StateError::InvalidEntry(format!(
                    "endpoint `{endpoint}` is not a WebSocket URL"
                )));
            }
        }
        if entry.weight == 0 {
            return Err(StateError::InvalidEntry(
                "weight must be at least 1".to_owned(),
            ));
        }
        if entry.signing_keys.len() != 1 {
            return Err(StateError::InvalidEntry(format!(
                "exactly one signing certificate is required, got {}",
                entry.signing_keys.len()
            )));
        }
        if let Some((other_id, _)) = self
            .nodes
            .iter()
            .find(|(_, node)| node.identity_pubkey == entry.identity_pubkey)
        {
            return Err(StateError::IdentityInUse(other_id.clone()));
        }
        let cert = entry
            .signing_keys
            .first()
            .expect("checked to be exactly one");
        self.validate_cert(&entry.node_id, &entry.identity_pubkey, cert, now)
    }

    fn validate_cert(
        &self,
        node_id: &str,
        identity: &CompressedPublicKey,
        cert: &SigningKeyCert,
        now: u64,
    ) -> Result<(), StateError> {
        if cert.node_id != node_id {
            return Err(StateError::InvalidCert(format!(
                "certificate names node `{}`, expected `{node_id}`",
                cert.node_id
            )));
        }
        if !cert.has_valid_window() {
            return Err(StateError::InvalidCert(
                "not_before must be earlier than not_after".to_owned(),
            ));
        }
        if now < cert.not_before || now >= cert.not_after {
            return Err(StateError::InvalidCert(format!(
                "window [{}, {}) does not cover now ({now})",
                cert.not_before, cert.not_after
            )));
        }
        let expected = identity.address().map_err(|_| {
            StateError::InvalidEntry("identity key is not a curve point".to_owned())
        })?;
        let issuer = cert
            .recover_issuer()
            .map_err(|e| StateError::InvalidCert(format!("issuer does not recover: {e}")))?;
        if issuer != expected {
            return Err(StateError::InvalidCert(format!(
                "issued by {issuer}, expected the node's identity key {expected}"
            )));
        }
        if self.address_known(cert.address) {
            return Err(StateError::AddressInUse(cert.address));
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
    const WINDOW: u64 = 600;

    fn config() -> Config {
        Config {
            key_name: "dfx_test_key".to_owned(),
            rotation_window_secs: WINDOW,
            heartbeat_secs: 86_400,
            epoch_secs: 60,
            clients_heartbeat_secs: 3_600,
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

    /// A node operator with an identity key and a signing key.
    struct Operator {
        identity: Signer,
        signing: Signer,
        node_id: String,
    }

    impl Operator {
        fn new(seed: u8, node_id: &str) -> Self {
            Self {
                identity: Signer::from_secret_bytes([seed; 32]).expect("valid key"),
                signing: Signer::from_secret_bytes([seed.wrapping_add(100); 32])
                    .expect("valid key"),
                node_id: node_id.to_owned(),
            }
        }

        fn cert_for(&self, signing: &Signer, now: u64) -> SigningKeyCert {
            SigningKeyCert::issue(
                &self.identity,
                &self.node_id,
                signing.address(),
                now.saturating_sub(60),
                now + 30 * 86_400,
            )
            .expect("issues")
        }

        fn entry(&self, now: u64) -> NodeEntry {
            NodeEntry {
                node_id: self.node_id.clone(),
                operator: format!("op-{}", self.node_id),
                identity_pubkey: self.identity.public_key(),
                endpoints: vec![format!("wss://{}.example/v1/ws", self.node_id)],
                signing_keys: vec![self.cert_for(&self.signing, now)],
                weight: 1,
            }
        }

        fn rotate(&mut self, seed: u8, now: u64) -> SigningKeyCert {
            self.signing = Signer::from_secret_bytes([seed; 32]).expect("valid key");
            self.cert_for(&self.signing, now)
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

    fn listed(ops: &[Operator], min_nodes: u16) -> State {
        let mut state = State::new(config(), quorum(min_nodes)).expect("valid");
        for op in ops {
            state.add_node(true, op.entry(NOW), NOW).expect("adds");
        }
        publish(&mut state, NOW);
        state
    }

    #[test]
    fn added_nodes_publish_with_one_live_key_each() {
        let ops = [
            Operator::new(1, "a"),
            Operator::new(2, "b"),
            Operator::new(3, "c"),
        ];
        let mut state = State::new(config(), quorum(3)).expect("valid");
        assert!(state.needs_publish());
        let first = ops.first().expect("three operators");
        assert_eq!(
            state.add_node(false, first.entry(NOW), NOW),
            Err(StateError::NotGovernance)
        );
        for op in &ops {
            state.add_node(true, op.entry(NOW), NOW).expect("adds");
        }
        assert_eq!(
            state.add_node(true, first.entry(NOW), NOW),
            Err(StateError::AlreadyListed("a".to_owned()))
        );

        let registry = publish(&mut state, NOW);
        assert_eq!(registry.version, 1);
        assert_eq!(registry.nodes.len(), 3);
        assert!(registry.nodes.iter().all(|n| n.signing_keys.len() == 1));
        assert!(!state.needs_publish());

        // The in-process stand-in verifies exactly like the threshold key will.
        let verified = registry
            .verify(governance_signer().address(), 0)
            .expect("verifies");
        assert_eq!(verified.nodes().len(), 3);
    }

    #[test]
    fn a_signing_address_belongs_to_one_node_ever() {
        let a = Operator::new(1, "a");
        let mut state = listed(&[a], 1);

        // A second node whose certificate names node a's live signing key.
        let b = Operator::new(2, "b");
        let mut entry = b.entry(NOW);
        let a_signing = Signer::from_secret_bytes([101; 32]).expect("valid key");
        entry.signing_keys = vec![b.cert_for(&a_signing, NOW)];
        assert_eq!(
            state.add_node(true, entry, NOW),
            Err(StateError::AddressInUse(a_signing.address()))
        );
    }

    #[test]
    fn rotation_is_atomic_and_keeps_history() {
        let mut a = Operator::new(1, "a");
        let b = Operator::new(2, "b");
        let mut state = listed(&[Operator::new(1, "a"), b], 2);
        let old_address = a.signing.address();

        let cert = a.rotate(50, NOW + 10);
        assert_eq!(
            state.rotate_key(false, "a", cert.clone(), NOW + 10),
            Err(StateError::NotGovernance)
        );
        state
            .rotate_key(true, "a", cert.clone(), NOW + 10)
            .expect("rotates");

        let registry = publish(&mut state, NOW + 10);
        assert_eq!(registry.version, 2);
        let listed_a = registry.nodes.iter().find(|n| n.node_id == "a").expect("a");
        assert_eq!(listed_a.signing_keys.len(), 1, "one live key per node");
        assert_eq!(
            listed_a.signing_keys.first().map(|c| c.address),
            Some(cert.address)
        );

        let history = state.key_history("a").expect("known");
        assert_eq!(history.len(), 2);
        let gen1 = history.first().expect("generation 1");
        let gen2 = history.get(1).expect("generation 2");
        assert_eq!(gen1.cert.address, old_address);
        assert_eq!(gen1.retired_at, Some(NOW + 10));
        assert_eq!(gen2.generation, 2);
        assert_eq!(gen2.retired_at, None);

        // The retired address can never come back, even for the same node.
        let revived = a.cert_for(
            &Signer::from_secret_bytes([101; 32]).expect("valid key"),
            NOW + 20,
        );
        assert_eq!(
            state.rotate_key(true, "a", revived, NOW + WINDOW + 20),
            Err(StateError::AddressInUse(old_address))
        );
    }

    #[test]
    fn rotations_are_serialised_fleet_wide() {
        let mut a = Operator::new(1, "a");
        let mut b = Operator::new(2, "b");
        let mut state = listed(&[Operator::new(1, "a"), Operator::new(2, "b")], 2);

        state
            .rotate_key(true, "a", a.rotate(50, NOW), NOW)
            .expect("rotates");
        let cert_b = b.rotate(51, NOW + 1);
        assert_eq!(
            state.rotate_key(true, "b", cert_b.clone(), NOW + 1),
            Err(StateError::RotationTooSoon {
                last: NOW,
                next_allowed: NOW + WINDOW,
            })
        );
        state
            .rotate_key(true, "b", cert_b, NOW + WINDOW)
            .expect("rotates once the window has passed");
    }

    #[test]
    fn removal_never_goes_below_min_nodes_and_keeps_history() {
        let ops = [
            Operator::new(1, "a"),
            Operator::new(2, "b"),
            Operator::new(3, "c"),
        ];
        let mut state = listed(&ops, 3);

        assert_eq!(
            state.remove_node(true, "c", NOW + 1),
            Err(StateError::BelowQuorum {
                remaining: 2,
                min_nodes: 3,
            })
        );
        state.set_quorum(true, quorum(2)).expect("sets");
        state.remove_node(true, "c", NOW + 1).expect("removes");
        let registry = publish(&mut state, NOW + 1);
        assert_eq!(registry.nodes.len(), 2);
        assert_eq!(registry.quorum.min_nodes, 2);

        let history = state.key_history("c").expect("history survives removal");
        assert_eq!(history.first().map(|k| k.retired_at), Some(Some(NOW + 1)));

        // Re-listing continues the generation count.
        let mut c = Operator::new(3, "c");
        let mut entry = c.entry(NOW + 2);
        entry.signing_keys = vec![c.rotate(60, NOW + 2)];
        state.add_node(true, entry, NOW + 2).expect("re-adds");
        let history = state.key_history("c").expect("known");
        assert_eq!(history.len(), 2);
        assert_eq!(history.get(1).map(|k| k.generation), Some(2));
    }

    #[test]
    fn certificates_are_checked_against_the_identity_key_and_the_clock() {
        let a = Operator::new(1, "a");
        let mut state = State::new(config(), quorum(1)).expect("valid");

        let mut stale = a.entry(NOW);
        stale.signing_keys = vec![a.cert_for(&a.signing, NOW - 365 * 86_400)];
        assert!(matches!(
            state.add_node(true, stale, NOW),
            Err(StateError::InvalidCert(_))
        ));

        let impostor = Operator::new(7, "a");
        let mut forged = a.entry(NOW);
        forged.signing_keys = vec![impostor.cert_for(&a.signing, NOW)];
        assert!(matches!(
            state.add_node(true, forged, NOW),
            Err(StateError::InvalidCert(_))
        ));

        let mut two_keys = a.entry(NOW);
        two_keys
            .signing_keys
            .push(a.cert_for(&impostor.signing, NOW));
        assert!(matches!(
            state.add_node(true, two_keys, NOW),
            Err(StateError::InvalidEntry(_))
        ));

        state
            .add_node(true, a.entry(NOW), NOW)
            .expect("a well-formed entry is accepted");
    }

    /// States saved by earlier canister versions still load: dropped fields are
    /// ignored and new ones take their defaults.
    #[test]
    fn a_state_saved_by_an_earlier_version_still_loads() {
        let state = listed(&[Operator::new(1, "a")], 1);
        let mut saved = serde_json::to_value(&state).expect("serialises");
        for (path, field, value) in [
            ("", "pending", Some(serde_json::json!({}))),
            (
                "/nodes/a",
                "operator_principal",
                Some(serde_json::json!("aaaaa-aa")),
            ),
            ("", "clients", None),
            ("", "clients_version", None),
            ("", "clients_published", None),
            ("", "clients_dirty", None),
            ("/config", "epoch_secs", None),
            ("/config", "clients_heartbeat_secs", None),
        ] {
            let object = saved
                .pointer_mut(path)
                .and_then(serde_json::Value::as_object_mut)
                .expect("an object");
            match value {
                Some(value) => {
                    object.insert(field.to_owned(), value);
                }
                None => {
                    object.remove(field);
                }
            }
        }
        let loaded: State = serde_json::from_value(saved).expect("loads");
        assert_eq!(loaded.nodes, state.nodes);
        assert!(loaded.clients.is_empty());
        assert_eq!(loaded.config.epoch_secs, DEFAULT_EPOCH_SECS);
        assert_eq!(
            loaded.config.clients_heartbeat_secs,
            DEFAULT_CLIENTS_HEARTBEAT_SECS
        );
        assert!(
            loaded.clients_due(NOW),
            "a list that was never published is due"
        );
    }

    fn client_key(seed: u8) -> CompressedPublicKey {
        Signer::from_secret_bytes([seed; 32])
            .expect("valid key")
            .public_key()
    }

    #[test]
    fn client_changes_follow_the_rules() {
        let mut state = State::new(config(), quorum(1)).expect("valid");
        let add = |state: &mut State, governance: bool, id: &str, seed: u8, expires_at: u64| {
            state.add_client(governance, id.to_owned(), client_key(seed), expires_at, NOW)
        };
        assert_eq!(
            add(&mut state, false, "c-1", 1, NOW + 60),
            Err(StateError::NotGovernance)
        );
        add(&mut state, true, "c-1", 1, NOW + 60).expect("adds");
        assert_eq!(
            add(&mut state, true, "c-1", 2, NOW + 60),
            Err(StateError::ClientExists("c-1".to_owned()))
        );
        assert_eq!(
            add(&mut state, true, "c-2", 1, NOW + 60),
            Err(StateError::ClientKeyInUse("c-1".to_owned()))
        );
        for (id, expires_at) in [(" c-3", NOW + 60), ("", NOW + 60), ("c-3", NOW)] {
            assert!(matches!(
                add(&mut state, true, id, 3, expires_at),
                Err(StateError::InvalidClient(_))
            ));
        }
        let mut bad_key = *client_key(4).as_bytes();
        bad_key[0] = 0x05;
        assert!(matches!(
            state.add_client(
                true,
                "c-4".to_owned(),
                CompressedPublicKey::from_bytes(bad_key),
                NOW + 60,
                NOW
            ),
            Err(StateError::InvalidClient(_))
        ));

        assert_eq!(
            state.set_client_expiry(false, "c-1", NOW),
            Err(StateError::NotGovernance)
        );
        state
            .set_client_expiry(true, "c-1", NOW + 120)
            .expect("extends");
        assert_eq!(
            state.clients.get("c-1").map(|c| c.expires_at),
            Some(NOW + 120)
        );
        assert_eq!(
            state.remove_client(true, "c-9"),
            Err(StateError::UnknownClient("c-9".to_owned()))
        );
        state.remove_client(true, "c-1").expect("removes");
        assert!(state.clients.is_empty());
    }

    #[test]
    fn the_client_list_publishes_with_its_own_version() {
        let mut state = listed(&[Operator::new(1, "a")], 1);
        let registry_version = state.version;
        state
            .add_client(true, "c-1".to_owned(), client_key(1), NOW + 600, NOW)
            .expect("adds");
        assert!(state.clients_due(NOW));
        assert!(
            !state.registry_due(NOW),
            "a client change leaves the registry alone"
        );

        let list = state.unsigned_client_list(NOW).expect("encodes");
        let signature = governance_signer().sign_payload(&list.signing_bytes);
        assert_eq!(state.publish_clients(list.clone(), signature), Ok(1));
        assert_eq!(state.version, registry_version);
        let published = state.clients_published.clone().expect("published");
        let verified = published
            .verify(governance_signer().address(), 0)
            .expect("verifies with oracle-wire");
        assert_eq!(verified.epoch_secs(), 60);
        assert_eq!(verified.get("c-1").map(|c| c.expires_at), Some(NOW + 600));

        assert!(!state.clients_due(NOW + 3_599));
        assert!(state.clients_due(NOW + 3_600), "the hourly heartbeat");
        assert!(!state.registry_due(NOW + 3_600));
        assert!(state.registry_due(NOW + 86_400), "the daily heartbeat");

        let signature = governance_signer().sign_payload(&list.signing_bytes);
        assert!(matches!(
            state.publish_clients(list, signature),
            Err(StateError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn a_stale_signing_round_cannot_publish() {
        let a = Operator::new(1, "a");
        let mut state = listed(&[a], 1);
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
}
