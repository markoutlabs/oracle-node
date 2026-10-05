//! The node registry: the trust root.
//!
//! A [`Registry`] is a signed list of the nodes whose price updates a consumer
//! will accept. Everything else in this crate establishes *authorship*; the
//! registry is the only thing that establishes *trust*.
//!
//! Two rules follow from that, and both are enforced by the API rather than
//! documented and hoped for:
//!
//! 1. A registry served by a node is not authoritative. Verification requires a
//!    governance address the caller supplies from its own pinned configuration.
//!    A node that could vouch for its own registry could add itself.
//! 2. Registry versions only move forward. [`Registry::verify`] demands a
//!    minimum version, so replaying an old registry cannot reinstate a revoked
//!    key.
//!
//! A node is its signing key: the address is the node's id (SPEC §3.5).

use std::collections::HashMap;

use crate::codec::Sink as _;
use crate::payload::{KIND_REGISTRY, PAYLOAD_VERSION};
use crate::{Address, Signature, Signer, VerifyError, WireError, signer};

/// Maximum nodes in one registry.
pub const MAX_NODES: usize = 256;
/// Maximum length of an operator name, in bytes.
pub const MAX_OPERATOR_LEN: usize = 64;
/// Maximum length of an endpoint URL, in bytes.
pub const MAX_ENDPOINT_LEN: usize = 256;
/// Maximum endpoints per node.
pub const MAX_ENDPOINTS: usize = 16;

/// Quorum guidance published alongside the node list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quorum {
    /// Fewest distinct nodes a consumer should require before trusting a price.
    pub min_nodes: u16,
    /// The operator's recommended quorum.
    pub recommended: u16,
}

/// When the registry canister listed a signing address, as it serves it.
///
/// Live frames never consult this. It exists for stored-frame verification
/// (SPEC §3.5). The times are the canister's word and carry no signature.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeListing {
    /// The node's signing address.
    pub address: Address,
    /// Who ran it.
    pub operator: String,
    /// When the address was listed, unix seconds.
    pub added_at: u64,
    /// When it stopped being listed, unix seconds. `None` while listed.
    pub removed_at: Option<u64>,
}

/// One node in the registry.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeEntry {
    /// The node's signing address. It is also the node's id.
    pub address: Address,
    /// Who runs it. Operator diversity is what makes the median meaningful.
    pub operator: String,
    /// WebSocket endpoints.
    pub endpoints: Vec<String>,
    /// Relative weight hint for consumers that weight rather than plain-median.
    pub weight: u16,
}

impl NodeEntry {
    /// Checks the rules a listing needs beyond the encoding's caps.
    ///
    /// # Errors
    ///
    /// Returns the first [`EntryError`] found.
    pub fn validate(&self) -> Result<(), EntryError> {
        check_operator(&self.operator)?;
        if self.endpoints.is_empty() || self.endpoints.len() > MAX_ENDPOINTS {
            return Err(EntryError::EndpointCount);
        }
        for endpoint in &self.endpoints {
            check_endpoint(endpoint)?;
        }
        if self.weight == 0 {
            return Err(EntryError::Weight);
        }
        Ok(())
    }
}

/// A node entry the registry cannot list.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EntryError {
    /// The operator name is blank or too long.
    #[error("the operator must be 1 to {MAX_OPERATOR_LEN} bytes and not blank")]
    Operator,
    /// There are no endpoints, or too many.
    #[error("a node needs 1 to {MAX_ENDPOINTS} endpoints")]
    EndpointCount,
    /// An endpoint is too long.
    #[error("endpoint `{0}` is longer than {MAX_ENDPOINT_LEN} bytes")]
    EndpointTooLong(String),
    /// An endpoint is not a WebSocket URL.
    #[error("endpoint `{0}` is not a ws:// or wss:// URL")]
    EndpointScheme(String),
    /// The weight is zero.
    #[error("the weight must be at least 1")]
    Weight,
}

/// Checks an operator name: 1 to [`MAX_OPERATOR_LEN`] bytes, not blank.
///
/// # Errors
///
/// Returns [`EntryError::Operator`].
pub fn check_operator(operator: &str) -> Result<(), EntryError> {
    if operator.trim().is_empty() || operator.len() > MAX_OPERATOR_LEN {
        return Err(EntryError::Operator);
    }
    Ok(())
}

/// Checks an endpoint: a `ws://` or `wss://` URL of at most [`MAX_ENDPOINT_LEN`] bytes.
///
/// # Errors
///
/// Returns [`EntryError::EndpointTooLong`] or [`EntryError::EndpointScheme`].
pub fn check_endpoint(endpoint: &str) -> Result<(), EntryError> {
    if endpoint.len() > MAX_ENDPOINT_LEN {
        return Err(EntryError::EndpointTooLong(endpoint.to_owned()));
    }
    if !(endpoint.starts_with("wss://") || endpoint.starts_with("ws://")) {
        return Err(EntryError::EndpointScheme(endpoint.to_owned()));
    }
    Ok(())
}

/// A signed list of trusted nodes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    /// Monotonic version. Consumers reject anything not strictly newer.
    pub version: u64,
    /// When this version takes effect, unix seconds.
    pub effective_from: u64,
    /// The nodes.
    pub nodes: Vec<NodeEntry>,
    /// Quorum guidance.
    pub quorum: Quorum,
    /// Governance signature over the canonical encoding.
    pub governance_signature: Signature,
}

impl Registry {
    /// Builds the canonical bytes the governance key signs.
    ///
    /// Nodes are sorted by address so that the encoding is independent of the
    /// order fields happen to appear in JSON. JSON is transport; these bytes
    /// are the artifact.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::FieldTooLong`] if any field exceeds its cap. The
    /// caps bound the work an untrusted registry can cause.
    pub fn signing_bytes(
        version: u64,
        effective_from: u64,
        nodes: &[NodeEntry],
        quorum: Quorum,
    ) -> Result<Vec<u8>, WireError> {
        let too_many = || WireError::FieldTooLong {
            field: "nodes",
            actual: nodes.len(),
            limit: MAX_NODES,
        };
        if nodes.len() > MAX_NODES {
            return Err(too_many());
        }

        let mut ordered: Vec<&NodeEntry> = nodes.iter().collect();
        ordered.sort_by_key(|node| node.address);

        let mut out = Vec::with_capacity(64 + nodes.len() * 128);
        out.put_u8(PAYLOAD_VERSION);
        out.put_u8(KIND_REGISTRY);
        out.put_u64(version);
        out.put_u64(effective_from);
        out.put_u16(quorum.min_nodes);
        out.put_u16(quorum.recommended);
        out.put_u32(u32::try_from(ordered.len()).map_err(|_| too_many())?);

        for node in ordered {
            out.put_bytes(node.address.as_bytes());
            out.try_put_str("operator", &node.operator, MAX_OPERATOR_LEN)?;
            out.put_u16(node.weight);

            let too_many_endpoints = || WireError::FieldTooLong {
                field: "endpoints",
                actual: node.endpoints.len(),
                limit: MAX_ENDPOINTS,
            };
            if node.endpoints.len() > MAX_ENDPOINTS {
                return Err(too_many_endpoints());
            }
            out.put_u16(u16::try_from(node.endpoints.len()).map_err(|_| too_many_endpoints())?);
            for endpoint in &node.endpoints {
                out.try_put_str("endpoint", endpoint, MAX_ENDPOINT_LEN)?;
            }
        }
        Ok(out)
    }

    /// Assembles and signs a registry.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if any field exceeds its cap.
    pub fn sign(
        governance: &Signer,
        version: u64,
        effective_from: u64,
        nodes: Vec<NodeEntry>,
        quorum: Quorum,
    ) -> Result<Self, WireError> {
        let bytes = Self::signing_bytes(version, effective_from, &nodes, quorum)?;
        let governance_signature = governance.sign_payload(&bytes);
        Ok(Self {
            version,
            effective_from,
            nodes,
            quorum,
            governance_signature,
        })
    }

    /// Returns this registry's canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if any field exceeds its cap.
    pub fn to_signing_bytes(&self) -> Result<Vec<u8>, WireError> {
        Self::signing_bytes(self.version, self.effective_from, &self.nodes, self.quorum)
    }

    /// Verifies the registry against a pinned governance address and a version floor.
    ///
    /// Pass `0` as `min_version` for an initial load, and the currently-trusted
    /// version on every refresh — the new registry must be **strictly** newer.
    ///
    /// # Errors
    ///
    /// - [`VerifyError::StaleRegistry`] if `version` is not above `min_version`.
    /// - [`VerifyError::UntrustedGovernance`] if the signature is not the pinned key's.
    /// - [`VerifyError::MalformedRegistry`] if one address is listed twice.
    pub fn verify(
        &self,
        governance: Address,
        min_version: u64,
    ) -> Result<VerifiedRegistry, VerifyError> {
        if self.version <= min_version {
            return Err(VerifyError::StaleRegistry {
                found: self.version,
                minimum: min_version,
            });
        }

        check_governance(
            &self.to_signing_bytes()?,
            &self.governance_signature,
            governance,
        )?;

        let mut by_address: HashMap<Address, usize> = HashMap::with_capacity(self.nodes.len());
        for (index, node) in self.nodes.iter().enumerate() {
            // One key counted as two nodes would defeat the quorum it is
            // counted against.
            if by_address.insert(node.address, index).is_some() {
                return Err(VerifyError::MalformedRegistry(format!(
                    "node {} is listed twice",
                    node.address
                )));
            }
        }

        Ok(VerifiedRegistry {
            registry: self.clone(),
            by_address,
            governance,
        })
    }
}

/// Checks that `signature` over `payload` recovers to the pinned governance address.
pub(crate) fn check_governance(
    payload: &[u8],
    signature: &Signature,
    governance: Address,
) -> Result<(), VerifyError> {
    let found = signer::recover_payload_signer(payload, signature)?;
    if found != governance {
        return Err(VerifyError::UntrustedGovernance {
            found,
            expected: governance,
        });
    }
    Ok(())
}

/// A registry whose governance signature and structure have been checked.
///
/// Obtaining one is the only way to verify a price update, which makes the trust
/// check unskippable rather than merely recommended.
#[derive(Clone, Debug)]
pub struct VerifiedRegistry {
    registry: Registry,
    by_address: HashMap<Address, usize>,
    governance: Address,
}

impl VerifiedRegistry {
    /// Returns the registry version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.registry.version
    }

    /// Returns the governance address this registry was verified against.
    ///
    /// Carried along so a refresh can re-verify against the same pinned trust
    /// root. A refresh that took its governance key from anywhere else would let
    /// whoever supplied the new document also supply the key that vouches for it.
    #[must_use]
    pub const fn governance(&self) -> Address {
        self.governance
    }

    /// Verifies a replacement registry against this one's governance key and version.
    ///
    /// The successor must be **strictly** newer, which is what stops an old
    /// document from being replayed to reinstate a revoked signing key.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Registry::verify`].
    pub fn accept_successor(&self, next: &Registry) -> Result<Self, VerifyError> {
        next.verify(self.governance, self.registry.version)
    }

    /// Returns the quorum guidance.
    #[must_use]
    pub const fn quorum(&self) -> Quorum {
        self.registry.quorum
    }

    /// Returns the nodes.
    #[must_use]
    pub fn nodes(&self) -> &[NodeEntry] {
        &self.registry.nodes
    }

    /// Returns a node by index.
    #[must_use]
    pub fn node(&self, index: usize) -> Option<&NodeEntry> {
        self.registry.nodes.get(index)
    }

    /// Returns the underlying registry.
    #[must_use]
    pub const fn as_registry(&self) -> &Registry {
        &self.registry
    }

    /// Resolves a recovered signer to the index of its node.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::UnknownSigner`] if no node has this address.
    pub fn authorize(&self, signer: Address) -> Result<usize, VerifyError> {
        self.by_address
            .get(&signer)
            .copied()
            .ok_or(VerifyError::UnknownSigner { signer })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn governance() -> Signer {
        Signer::from_secret_bytes([0x91; 32]).expect("valid key")
    }

    fn node(index: u8) -> (NodeEntry, Signer) {
        let key = Signer::from_secret_bytes([index; 32]).expect("valid key");
        (
            NodeEntry {
                address: key.address(),
                operator: format!("operator-{index}"),
                endpoints: vec![format!("wss://node{index}.example/v2/ws")],
                weight: 1,
            },
            key,
        )
    }

    fn registry(now: u64) -> (Registry, Vec<Signer>) {
        let (nodes, keys): (Vec<_>, Vec<_>) = (1..=3_u8).map(node).unzip();
        let quorum = Quorum {
            min_nodes: 2,
            recommended: 3,
        };
        (
            Registry::sign(&governance(), 7, now, nodes, quorum).expect("signs"),
            keys,
        )
    }

    fn resign(registry: &Registry) -> Registry {
        Registry::sign(
            &governance(),
            registry.version,
            registry.effective_from,
            registry.nodes.clone(),
            registry.quorum,
        )
        .expect("signs")
    }

    #[test]
    fn verifies_against_the_pinned_governance_key() {
        let (registry, _) = registry(1_000_000);
        let verified = registry
            .verify(governance().address(), 0)
            .expect("verifies");
        assert_eq!(verified.version(), 7);
        assert_eq!(verified.nodes().len(), 3);
    }

    #[test]
    fn rejects_a_different_governance_key() {
        let (registry, _) = registry(1_000_000);
        let impostor = Signer::from_secret_bytes([0x99; 32]).expect("valid key");
        assert!(matches!(
            registry.verify(impostor.address(), 0),
            Err(VerifyError::UntrustedGovernance { .. })
        ));
    }

    #[test]
    fn rejects_a_replayed_older_version() {
        let (registry, _) = registry(1_000_000);
        // Trusting version 7 already: the same registry must not be re-accepted,
        // or an attacker could reinstate a revoked key by replaying it.
        assert!(matches!(
            registry.verify(governance().address(), 7),
            Err(VerifyError::StaleRegistry {
                found: 7,
                minimum: 7
            })
        ));
        assert!(registry.verify(governance().address(), 6).is_ok());
    }

    #[test]
    fn rejects_tampering_with_any_node_field() {
        let now = 1_000_000;
        let expected = governance().address();
        let mutations: [fn(&mut Registry); 8] = [
            |r| {
                if let Some(node) = r.nodes.first_mut() {
                    node.weight = 99;
                }
            },
            |r| {
                if let Some(node) = r.nodes.first_mut() {
                    node.operator = "attacker".to_owned();
                }
            },
            |r| {
                if let Some(node) = r.nodes.first_mut() {
                    node.endpoints = vec!["wss://evil.example".to_owned()];
                }
            },
            |r| {
                if let Some(node) = r.nodes.first_mut() {
                    node.address = Address::from_bytes([0xEE; 20]);
                }
            },
            |r| r.version = 8,
            |r| r.effective_from = 0,
            |r| r.quorum.min_nodes = 1,
            |r| {
                r.nodes.pop();
            },
        ];
        for mutate in mutations {
            let (mut registry, _) = registry(now);
            mutate(&mut registry);
            assert!(
                matches!(
                    registry.verify(expected, 0),
                    Err(VerifyError::UntrustedGovernance { .. })
                ),
                "tampering went undetected"
            );
        }
    }

    #[test]
    fn node_order_does_not_change_the_signature() {
        let (mut registry, _) = registry(1_000_000);
        registry.nodes.reverse();
        // The canonical encoding sorts, so a reordered JSON still verifies.
        assert!(registry.verify(governance().address(), 0).is_ok());
    }

    #[test]
    fn rejects_one_address_listed_twice() {
        let (mut registry, _) = registry(1_000_000);
        let first = registry.nodes.first().expect("a node").address;
        if let Some(node) = registry.nodes.get_mut(1) {
            node.address = first;
        }
        let err = resign(&registry)
            .verify(governance().address(), 0)
            .expect_err("must reject");
        assert!(
            matches!(err, VerifyError::MalformedRegistry(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn authorizes_listed_addresses_only() {
        let (registry, keys) = registry(1_000_000);
        let verified = registry
            .verify(governance().address(), 0)
            .expect("verifies");
        for key in &keys {
            let index = verified.authorize(key.address()).expect("authorized");
            assert_eq!(
                verified.node(index).map(|node| node.address),
                Some(key.address())
            );
        }
        let stranger = Signer::from_secret_bytes([0xAA; 32]).expect("valid key");
        assert!(matches!(
            verified.authorize(stranger.address()),
            Err(VerifyError::UnknownSigner { .. })
        ));
    }

    #[test]
    fn a_successor_is_checked_against_the_pinned_governance_key() {
        let now = 1_000_000;
        let (current, _) = registry(now);
        let (spare, _) = registry(now);
        let verified = current.verify(governance().address(), 0).expect("verifies");
        assert_eq!(verified.governance(), governance().address());

        // A newer version signed by the same governance key is accepted.
        let next = Registry::sign(&governance(), 8, now, spare.nodes.clone(), spare.quorum)
            .expect("signs");
        assert_eq!(
            verified
                .accept_successor(&next)
                .expect("accepted")
                .version(),
            8
        );

        // The same version is not "newer", so it cannot be replayed to reinstate
        // a key the successor revoked.
        assert!(matches!(
            verified.accept_successor(&current),
            Err(VerifyError::StaleRegistry { .. })
        ));

        // A newer version signed by anyone else is refused, which is the whole
        // point of carrying the governance key rather than accepting one
        // alongside the document it is supposed to vouch for.
        let impostor = Signer::from_secret_bytes([0x99; 32]).expect("valid key");
        let forged = Registry::sign(&impostor, 9, now, spare.nodes, spare.quorum).expect("signs");
        assert!(matches!(
            verified.accept_successor(&forged),
            Err(VerifyError::UntrustedGovernance { .. })
        ));
    }

    #[test]
    fn entries_follow_the_listing_rules() {
        let (good, _) = node(1);
        assert_eq!(good.validate(), Ok(()));
        type Mutation = fn(&mut NodeEntry);
        let mutations: [(Mutation, EntryError); 6] = [
            (|e| e.operator = " ".to_owned(), EntryError::Operator),
            (|e| e.operator = "x".repeat(65), EntryError::Operator),
            (|e| e.endpoints.clear(), EntryError::EndpointCount),
            (
                |e| e.endpoints = vec!["https://node.example".to_owned()],
                EntryError::EndpointScheme("https://node.example".to_owned()),
            ),
            (
                |e| e.endpoints = vec![format!("wss://{}", "x".repeat(251))],
                EntryError::EndpointTooLong(format!("wss://{}", "x".repeat(251))),
            ),
            (|e| e.weight = 0, EntryError::Weight),
        ];
        for (mutate, expected) in mutations {
            let mut entry = good.clone();
            mutate(&mut entry);
            assert_eq!(entry.validate(), Err(expected));
        }
    }

    #[test]
    fn json_round_trips() {
        let (registry, _) = registry(1_000_000);
        let json = serde_json::to_string_pretty(&registry).expect("serializes");
        let back: Registry = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, registry);
        assert!(back.verify(governance().address(), 0).is_ok());
    }
}
