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

use std::collections::HashMap;

use crate::cert::{MAX_NODE_ID_LEN, SigningKeyCert};
use crate::codec::Sink as _;
use crate::payload::{KIND_REGISTRY, PAYLOAD_VERSION};
use crate::{Address, CompressedPublicKey, Signature, Signer, VerifyError, WireError, signer};

/// Maximum nodes in one registry.
pub const MAX_NODES: usize = 256;
/// Maximum length of an operator name, in bytes.
pub const MAX_OPERATOR_LEN: usize = 64;
/// Maximum length of an endpoint URL, in bytes.
pub const MAX_ENDPOINT_LEN: usize = 256;
/// Maximum endpoints per node.
pub const MAX_ENDPOINTS: usize = 16;
/// Maximum concurrently-listed signing keys per node.
///
/// Rotation needs two (outgoing and incoming); the rest is headroom.
pub const MAX_CERTS_PER_NODE: usize = 16;

/// Quorum guidance published alongside the node list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quorum {
    /// Fewest distinct nodes a consumer should require before trusting a price.
    pub min_nodes: u16,
    /// The operator's recommended quorum.
    pub recommended: u16,
}

/// One node in the registry.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeEntry {
    /// Stable node identifier.
    pub node_id: String,
    /// Who runs it. Operator diversity is what makes the median meaningful.
    pub operator: String,
    /// The node's long-lived identity key, which issues its certificates.
    pub identity_pubkey: CompressedPublicKey,
    /// WebSocket endpoints.
    pub endpoints: Vec<String>,
    /// Currently-listed signing keys.
    pub signing_keys: Vec<SigningKeyCert>,
    /// Relative weight hint for consumers that weight rather than plain-median.
    pub weight: u16,
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
    /// Nodes are sorted by `node_id` and certificates by `(not_before, address)`
    /// so that the encoding is independent of the order fields happen to appear
    /// in JSON. JSON is transport; these bytes are the artifact.
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
        if nodes.len() > MAX_NODES {
            return Err(WireError::FieldTooLong {
                field: "nodes",
                actual: nodes.len(),
                limit: MAX_NODES,
            });
        }

        let mut ordered: Vec<&NodeEntry> = nodes.iter().collect();
        ordered.sort_by(|a, b| a.node_id.cmp(&b.node_id));

        let mut out = Vec::with_capacity(64 + nodes.len() * 256);
        out.put_u8(PAYLOAD_VERSION);
        out.put_u8(KIND_REGISTRY);
        out.put_u64(version);
        out.put_u64(effective_from);
        out.put_u16(quorum.min_nodes);
        out.put_u16(quorum.recommended);
        let node_count = u32::try_from(ordered.len()).map_err(|_| WireError::FieldTooLong {
            field: "nodes",
            actual: ordered.len(),
            limit: MAX_NODES,
        })?;
        out.put_u32(node_count);

        for node in ordered {
            out.try_put_str("node_id", &node.node_id, MAX_NODE_ID_LEN)?;
            out.try_put_str("operator", &node.operator, MAX_OPERATOR_LEN)?;
            out.put_bytes(node.identity_pubkey.as_bytes());
            out.put_u16(node.weight);

            if node.endpoints.len() > MAX_ENDPOINTS {
                return Err(WireError::FieldTooLong {
                    field: "endpoints",
                    actual: node.endpoints.len(),
                    limit: MAX_ENDPOINTS,
                });
            }
            let endpoint_count =
                u16::try_from(node.endpoints.len()).map_err(|_| WireError::FieldTooLong {
                    field: "endpoints",
                    actual: node.endpoints.len(),
                    limit: MAX_ENDPOINTS,
                })?;
            out.put_u16(endpoint_count);
            for endpoint in &node.endpoints {
                out.try_put_str("endpoint", endpoint, MAX_ENDPOINT_LEN)?;
            }

            if node.signing_keys.len() > MAX_CERTS_PER_NODE {
                return Err(WireError::FieldTooLong {
                    field: "signing_keys",
                    actual: node.signing_keys.len(),
                    limit: MAX_CERTS_PER_NODE,
                });
            }
            let cert_count =
                u16::try_from(node.signing_keys.len()).map_err(|_| WireError::FieldTooLong {
                    field: "signing_keys",
                    actual: node.signing_keys.len(),
                    limit: MAX_CERTS_PER_NODE,
                })?;
            out.put_u16(cert_count);

            let mut certs: Vec<&SigningKeyCert> = node.signing_keys.iter().collect();
            certs.sort_by_key(|c| (c.not_before, *c.address.as_bytes()));
            for cert in certs {
                out.put_bytes(&cert.to_signing_bytes()?);
                out.put_bytes(cert.signature.as_bytes());
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
    /// - [`VerifyError::CertificateIssuerMismatch`] if a certificate was not
    ///   issued by its own node's identity key.
    /// - [`VerifyError::MalformedRegistry`] for duplicate node ids, duplicate
    ///   signing addresses, inverted validity windows, or invalid identity keys.
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

        let bytes = self.to_signing_bytes()?;
        let found = signer::recover_payload_signer(&bytes, &self.governance_signature)?;
        if found != governance {
            return Err(VerifyError::UntrustedGovernance {
                found,
                expected: governance,
            });
        }

        let mut seen_nodes: HashMap<&str, ()> = HashMap::with_capacity(self.nodes.len());
        let mut by_address: HashMap<Address, usize> = HashMap::new();

        for (index, node) in self.nodes.iter().enumerate() {
            if seen_nodes.insert(node.node_id.as_str(), ()).is_some() {
                return Err(VerifyError::MalformedRegistry(format!(
                    "duplicate node id `{}`",
                    node.node_id
                )));
            }
            let identity = node.identity_pubkey.address().map_err(|_| {
                VerifyError::MalformedRegistry(format!(
                    "node `{}` has an invalid identity public key",
                    node.node_id
                ))
            })?;

            for cert in &node.signing_keys {
                if cert.node_id != node.node_id {
                    return Err(VerifyError::MalformedRegistry(format!(
                        "certificate for {} claims node `{}` but is listed under `{}`",
                        cert.address, cert.node_id, node.node_id
                    )));
                }
                if !cert.has_valid_window() {
                    return Err(VerifyError::MalformedRegistry(format!(
                        "certificate for {} has not_before >= not_after",
                        cert.address
                    )));
                }
                let issuer = cert.recover_issuer()?;
                if issuer != identity {
                    return Err(VerifyError::CertificateIssuerMismatch {
                        node_id: node.node_id.clone(),
                        address: cert.address,
                        issuer,
                        expected: identity,
                    });
                }
                // A signing address must belong to exactly one node. Otherwise a
                // single key could masquerade as two independent signers and
                // defeat the quorum it is supposed to be counted against.
                if let Some(existing) = by_address.insert(cert.address, index)
                    && existing != index
                {
                    return Err(VerifyError::MalformedRegistry(format!(
                        "signing address {} is listed under more than one node",
                        cert.address
                    )));
                }
            }
        }

        Ok(VerifiedRegistry {
            registry: self.clone(),
            by_address,
        })
    }
}

/// A registry whose governance signature and certificates have been checked.
///
/// Obtaining one is the only way to verify a price update, which makes the trust
/// check unskippable rather than merely recommended.
#[derive(Clone, Debug)]
pub struct VerifiedRegistry {
    registry: Registry,
    by_address: HashMap<Address, usize>,
}

impl VerifiedRegistry {
    /// Returns the registry version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.registry.version
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

    /// Resolves a recovered signer to the node index it is authorised for.
    ///
    /// # Errors
    ///
    /// - [`VerifyError::UnknownSigner`] if the address is in no certificate.
    /// - [`VerifyError::CertificateNotYetValid`] or
    ///   [`VerifyError::CertificateExpired`] if it is listed but not authorised
    ///   at `publish_time_ns`.
    pub fn authorize(&self, signer: Address, publish_time_ns: u64) -> Result<usize, VerifyError> {
        let index = *self
            .by_address
            .get(&signer)
            .ok_or(VerifyError::UnknownSigner { signer })?;
        let node = self
            .registry
            .nodes
            .get(index)
            .ok_or(VerifyError::UnknownSigner { signer })?;

        let mut candidates = node
            .signing_keys
            .iter()
            .filter(|cert| cert.address == signer)
            .peekable();
        if candidates.peek().is_none() {
            return Err(VerifyError::UnknownSigner { signer });
        }

        let mut first_error = None;
        for cert in candidates {
            match cert.check_covers(publish_time_ns) {
                Ok(()) => return Ok(index),
                // Report the window that came closest: an expired certificate is
                // a more useful diagnostic than one that has not started.
                Err(err) => {
                    let replace = matches!(
                        (&first_error, &err),
                        (None, _)
                            | (
                                Some(VerifyError::CertificateNotYetValid { .. }),
                                VerifyError::CertificateExpired { .. }
                            )
                    );
                    if replace {
                        first_error = Some(err);
                    }
                }
            }
        }
        Err(first_error.unwrap_or(VerifyError::UnknownSigner { signer }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    fn governance() -> Signer {
        Signer::from_secret_bytes([0x91; 32]).expect("valid key")
    }

    fn node(index: u8, now: u64) -> (NodeEntry, Signer) {
        let identity = Signer::from_secret_bytes([index; 32]).expect("valid key");
        let hot = Signer::from_secret_bytes([index.wrapping_add(100); 32]).expect("valid key");
        let node_id = format!("oracle-{index}");
        let cert = SigningKeyCert::issue(&identity, &node_id, hot.address(), now, now + 30 * DAY)
            .expect("issues");
        (
            NodeEntry {
                node_id,
                operator: format!("operator-{index}"),
                identity_pubkey: CompressedPublicKey::from_public_key(&identity.public_key()),
                endpoints: vec![format!("wss://node{index}.example/v1/ws")],
                signing_keys: vec![cert],
                weight: 1,
            },
            hot,
        )
    }

    fn registry(now: u64) -> (Registry, Vec<Signer>) {
        let mut nodes = Vec::new();
        let mut hots = Vec::new();
        for index in 1..=3_u8 {
            let (entry, hot) = node(index, now);
            nodes.push(entry);
            hots.push(hot);
        }
        let quorum = Quorum {
            min_nodes: 2,
            recommended: 3,
        };
        (
            Registry::sign(&governance(), 7, now, nodes, quorum).expect("signs"),
            hots,
        )
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
        let mutations: [fn(&mut Registry); 7] = [
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
    fn rejects_a_certificate_issued_by_the_wrong_identity() {
        let now = 1_000_000;
        let (mut registry, _) = registry(now);
        let rogue = Signer::from_secret_bytes([0x77; 32]).expect("valid key");
        let hot = Signer::from_secret_bytes([0x78; 32]).expect("valid key");
        if let Some(node) = registry.nodes.first_mut() {
            node.signing_keys = vec![
                SigningKeyCert::issue(&rogue, &node.node_id, hot.address(), now, now + DAY)
                    .expect("issues"),
            ];
        }
        // Re-sign so the governance check passes and the certificate check is
        // what actually fires.
        let resigned = Registry::sign(
            &governance(),
            registry.version,
            registry.effective_from,
            registry.nodes.clone(),
            registry.quorum,
        )
        .expect("signs");
        assert!(matches!(
            resigned.verify(governance().address(), 0),
            Err(VerifyError::CertificateIssuerMismatch { .. })
        ));
    }

    #[test]
    fn rejects_one_signing_key_shared_by_two_nodes() {
        let now = 1_000_000;
        let (mut registry, _) = registry(now);
        let shared = Signer::from_secret_bytes([0x55; 32]).expect("valid key");
        for index in 0..2 {
            let Some(node) = registry.nodes.get_mut(index) else {
                continue;
            };
            let identity = Signer::from_secret_bytes([u8::try_from(index + 1).unwrap_or(1); 32])
                .expect("valid key");
            node.signing_keys = vec![
                SigningKeyCert::issue(&identity, &node.node_id, shared.address(), now, now + DAY)
                    .expect("issues"),
            ];
        }
        let resigned = Registry::sign(
            &governance(),
            registry.version,
            registry.effective_from,
            registry.nodes.clone(),
            registry.quorum,
        )
        .expect("signs");
        let err = resigned
            .verify(governance().address(), 0)
            .expect_err("must reject");
        assert!(
            matches!(err, VerifyError::MalformedRegistry(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn authorizes_only_within_the_certificate_window() {
        let now = 1_000_000;
        let (registry, hots) = registry(now);
        let verified = registry
            .verify(governance().address(), 0)
            .expect("verifies");
        let hot = hots.first().expect("one node");

        let inside = (now + DAY) * oracle_types::NANOS_PER_SEC;
        assert_eq!(
            verified
                .authorize(hot.address(), inside)
                .expect("authorized"),
            0
        );

        let before = (now - 1) * oracle_types::NANOS_PER_SEC;
        assert!(matches!(
            verified.authorize(hot.address(), before),
            Err(VerifyError::CertificateNotYetValid { .. })
        ));

        let after = (now + 31 * DAY) * oracle_types::NANOS_PER_SEC;
        assert!(matches!(
            verified.authorize(hot.address(), after),
            Err(VerifyError::CertificateExpired { .. })
        ));
    }

    #[test]
    fn unknown_signers_are_rejected() {
        let (registry, _) = registry(1_000_000);
        let verified = registry
            .verify(governance().address(), 0)
            .expect("verifies");
        let stranger = Signer::from_secret_bytes([0xAA; 32]).expect("valid key");
        assert!(matches!(
            verified.authorize(stranger.address(), 1_000_000 * oracle_types::NANOS_PER_SEC),
            Err(VerifyError::UnknownSigner { .. })
        ));
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
