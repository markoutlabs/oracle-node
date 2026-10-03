//! The registry state machine.
//!
//! No Internet Computer dependency here. Every rule in SPEC §3.6 is a unit
//! test in this file rather than a PocketIC run, and the canister glue in
//! `lib.rs` only adds the caller, the clock, and the threshold signature.

use std::collections::BTreeMap;

use candid::Principal;
use oracle_wire::{
    Address, CompressedPublicKey, MAX_ENDPOINT_LEN, MAX_ENDPOINTS, MAX_NODE_ID_LEN, MAX_NODES,
    MAX_OPERATOR_LEN, NodeEntry, Quorum, Registry, Signature, SigningKeyCert, WireError,
};
use serde::{Deserialize, Serialize};

/// A rule of the registry was broken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StateError {
    /// Only a canister controller may do this.
    #[error("only governance (a canister controller) may do this")]
    NotGovernance,
    /// The caller is not the principal that submitted this node.
    #[error("caller is not the operator of node `{0}`")]
    NotOperator(String),
    /// No listed node has this id.
    #[error("unknown node `{0}`")]
    UnknownNode(String),
    /// The node is already in the registry.
    #[error("node `{0}` is already listed")]
    AlreadyListed(String),
    /// Another principal already has a pending entry under this id.
    #[error("node `{0}` already has a pending entry from another operator")]
    PendingByOther(String),
    /// Nothing is pending under this id.
    #[error("no pending entry for `{0}`")]
    NoPending(String),
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
    /// The principal allowed to rotate this node's key.
    pub operator_principal: Principal,
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

/// An entry an operator submitted that governance has not approved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingEntry {
    /// The entry as submitted, with exactly one certificate.
    pub entry: NodeEntry,
    /// Who submitted it, and who will be allowed to rotate its key.
    pub operator_principal: Principal,
    /// When, unix seconds.
    pub submitted_at: u64,
}

/// One generation in a node's key history, as served to auditors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyHistoryEntry {
    /// Generation number, from 1.
    pub generation: u32,
    /// The certificate.
    pub cert: SigningKeyCert,
    /// When the key became live.
    pub added_at: u64,
    /// When it stopped being live. `None` while live.
    pub retired_at: Option<u64>,
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
    /// Submitted, not yet approved.
    pub pending: BTreeMap<String, PendingEntry>,
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
            pending: BTreeMap::new(),
            version: 0,
            last_rotation_at: None,
            published: None,
            governance_key: None,
            dirty: true,
        })
    }

    /// An operator proposes a node. Nothing is published until governance
    /// approves it.
    ///
    /// A resubmission by the same principal replaces the pending entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the id is listed or pending under another
    /// principal, or if the entry or its certificate fails a check.
    pub fn submit_entry(
        &mut self,
        caller: Principal,
        entry: NodeEntry,
        now: u64,
    ) -> Result<(), StateError> {
        let node_id = entry.node_id.clone();
        if self.nodes.contains_key(&node_id) {
            return Err(StateError::AlreadyListed(node_id));
        }
        if let Some(existing) = self.pending.get(&node_id)
            && existing.operator_principal != caller
        {
            return Err(StateError::PendingByOther(node_id));
        }
        if !self.pending.contains_key(&node_id) && self.pending.len() >= MAX_NODES {
            return Err(StateError::TooManyNodes);
        }

        // Validate against everything except the entry this one replaces.
        let previous = self.pending.remove(&node_id);
        let checked = self.validate_entry(&entry, now);
        match checked {
            Ok(()) => {
                self.pending.insert(
                    node_id,
                    PendingEntry {
                        entry,
                        operator_principal: caller,
                        submitted_at: now,
                    },
                );
                Ok(())
            }
            Err(error) => {
                if let Some(previous) = previous {
                    self.pending.insert(node_id, previous);
                }
                Err(error)
            }
        }
    }

    /// Governance lists a pending node. Bumps the document.
    ///
    /// A node that was removed earlier continues its generation numbers, so
    /// its key history never has two generation ones.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller is not governance, nothing is pending
    /// under the id, or the registry is full.
    pub fn approve_entry(
        &mut self,
        is_governance: bool,
        node_id: &str,
        now: u64,
    ) -> Result<(), StateError> {
        if !is_governance {
            return Err(StateError::NotGovernance);
        }
        if self.nodes.len() >= MAX_NODES {
            return Err(StateError::TooManyNodes);
        }
        let cert = self
            .pending
            .get(node_id)
            .ok_or_else(|| StateError::NoPending(node_id.to_owned()))?
            .entry
            .signing_keys
            .first()
            .cloned()
            .ok_or_else(|| {
                StateError::InvalidEntry("pending entry has no certificate".to_owned())
            })?;
        let pending = self
            .pending
            .remove(node_id)
            .ok_or_else(|| StateError::NoPending(node_id.to_owned()))?;

        let mut keys = self
            .removed
            .remove(node_id)
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
            node_id.to_owned(),
            NodeRecord {
                operator: pending.entry.operator,
                operator_principal: pending.operator_principal,
                identity_pubkey: pending.entry.identity_pubkey,
                endpoints: pending.entry.endpoints,
                weight: pending.entry.weight,
                live: generation,
                keys,
            },
        );
        self.dirty = true;
        Ok(())
    }

    /// Governance drops a pending entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller is not governance or nothing is pending.
    pub fn reject_entry(&mut self, is_governance: bool, node_id: &str) -> Result<(), StateError> {
        if !is_governance {
            return Err(StateError::NotGovernance);
        }
        self.pending
            .remove(node_id)
            .map(|_| ())
            .ok_or_else(|| StateError::NoPending(node_id.to_owned()))
    }

    /// The operator swaps the node's signing key. Atomic: the new generation
    /// is live and the old one retired in the same call. Bumps the document.
    ///
    /// # Errors
    ///
    /// Returns an error if the node is unknown, the caller is not its
    /// operator, the certificate fails a check, or another rotation happened
    /// inside the rotation window.
    pub fn rotate_key(
        &mut self,
        caller: Principal,
        node_id: &str,
        cert: SigningKeyCert,
        now: u64,
    ) -> Result<(), StateError> {
        let node = self
            .nodes
            .get(node_id)
            .ok_or_else(|| StateError::UnknownNode(node_id.to_owned()))?;
        if node.operator_principal != caller {
            return Err(StateError::NotOperator(node_id.to_owned()));
        }
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

    /// `true` if any key of any node, listed, removed or pending, has this
    /// address.
    #[must_use]
    pub fn address_known(&self, address: Address) -> bool {
        let in_records = self
            .nodes
            .values()
            .chain(self.removed.values())
            .flat_map(|node| node.keys.values())
            .any(|record| record.cert.address == address);
        let in_pending = self
            .pending
            .values()
            .flat_map(|pending| pending.entry.signing_keys.iter())
            .any(|cert| cert.address == address);
        in_records || in_pending
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
        if let Some((other_id, _)) = self.pending.iter().find(|(id, pending)| {
            pending.entry.identity_pubkey == entry.identity_pubkey && **id != entry.node_id
        }) {
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
        principal: Principal,
        identity: Signer,
        signing: Signer,
        node_id: String,
    }

    impl Operator {
        fn new(seed: u8, node_id: &str) -> Self {
            Self {
                principal: Principal::self_authenticating([seed]),
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
            state
                .submit_entry(op.principal, op.entry(NOW), NOW)
                .expect("submits");
            state
                .approve_entry(true, &op.node_id, NOW)
                .expect("approves");
        }
        publish(&mut state, NOW);
        state
    }

    #[test]
    fn approved_nodes_publish_with_one_live_key_each() {
        let ops = [
            Operator::new(1, "a"),
            Operator::new(2, "b"),
            Operator::new(3, "c"),
        ];
        let mut state = State::new(config(), quorum(3)).expect("valid");
        assert!(state.needs_publish());
        for op in &ops {
            state
                .submit_entry(op.principal, op.entry(NOW), NOW)
                .expect("submits");
        }
        assert_eq!(state.pending.len(), 3);
        assert_eq!(
            state.approve_entry(false, "a", NOW),
            Err(StateError::NotGovernance)
        );
        for op in &ops {
            state
                .approve_entry(true, &op.node_id, NOW)
                .expect("approves");
        }
        assert!(state.pending.is_empty());

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
            state.submit_entry(b.principal, entry, NOW),
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
            state.rotate_key(
                Principal::self_authenticating([9]),
                "a",
                cert.clone(),
                NOW + 10
            ),
            Err(StateError::NotOperator("a".to_owned()))
        );
        state
            .rotate_key(a.principal, "a", cert.clone(), NOW + 10)
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
            state.rotate_key(a.principal, "a", revived, NOW + WINDOW + 20),
            Err(StateError::AddressInUse(old_address))
        );
    }

    #[test]
    fn rotations_are_serialised_fleet_wide() {
        let mut a = Operator::new(1, "a");
        let mut b = Operator::new(2, "b");
        let mut state = listed(&[Operator::new(1, "a"), Operator::new(2, "b")], 2);

        state
            .rotate_key(a.principal, "a", a.rotate(50, NOW), NOW)
            .expect("rotates");
        let cert_b = b.rotate(51, NOW + 1);
        assert_eq!(
            state.rotate_key(b.principal, "b", cert_b.clone(), NOW + 1),
            Err(StateError::RotationTooSoon {
                last: NOW,
                next_allowed: NOW + WINDOW,
            })
        );
        state
            .rotate_key(b.principal, "b", cert_b, NOW + WINDOW)
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
        state
            .submit_entry(c.principal, entry, NOW + 2)
            .expect("submits");
        state.approve_entry(true, "c", NOW + 2).expect("approves");
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
            state.submit_entry(a.principal, stale, NOW),
            Err(StateError::InvalidCert(_))
        ));

        let impostor = Operator::new(7, "a");
        let mut forged = a.entry(NOW);
        forged.signing_keys = vec![impostor.cert_for(&a.signing, NOW)];
        assert!(matches!(
            state.submit_entry(a.principal, forged, NOW),
            Err(StateError::InvalidCert(_))
        ));

        let mut two_keys = a.entry(NOW);
        two_keys
            .signing_keys
            .push(a.cert_for(&impostor.signing, NOW));
        assert!(matches!(
            state.submit_entry(a.principal, two_keys, NOW),
            Err(StateError::InvalidEntry(_))
        ));

        state
            .submit_entry(a.principal, a.entry(NOW), NOW)
            .expect("a well-formed entry is accepted");
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
