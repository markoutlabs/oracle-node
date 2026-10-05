//! The client allow-list: who may open a transport session, and until when.
//!
//! Governance signs it with the same key as the [`Registry`](crate::Registry),
//! under its own kind byte, and nodes verify it against the governance address
//! they already pin (SPEC §3.6).

use std::collections::HashMap;

use crate::codec::Sink as _;
use crate::payload::{KIND_CLIENT_LIST, PAYLOAD_VERSION};
use crate::registry::check_governance;
use crate::{Address, Signature, Signer, VerifyError, WireError};

/// Maximum clients in one list.
pub const MAX_CLIENTS: usize = 4096;

/// One authorised client.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientEntry {
    /// The address of the client's secp256k1 API key. It is also the client's id.
    pub address: Address,
    /// End of authorisation, unix seconds.
    pub expires_at: u64,
}

/// A governance-signed list of authorised clients.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientList {
    /// Monotonic version. Nodes reject anything not strictly newer.
    pub version: u64,
    /// Issue time, unix seconds. Nodes judge freshness by it.
    pub effective_from: u64,
    /// Broadcast-key epoch length, seconds. Session deadlines snap to it.
    pub epoch_secs: u64,
    /// The clients.
    pub clients: Vec<ClientEntry>,
    /// Governance signature over the canonical encoding.
    pub governance_signature: Signature,
}

impl ClientList {
    /// Builds the canonical bytes the governance key signs. Clients are sorted
    /// by address, so JSON order does not matter.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::FieldTooLong`] if any field exceeds its cap.
    pub fn signing_bytes(
        version: u64,
        effective_from: u64,
        epoch_secs: u64,
        clients: &[ClientEntry],
    ) -> Result<Vec<u8>, WireError> {
        let too_many = || WireError::FieldTooLong {
            field: "clients",
            actual: clients.len(),
            limit: MAX_CLIENTS,
        };
        if clients.len() > MAX_CLIENTS {
            return Err(too_many());
        }
        let mut ordered: Vec<&ClientEntry> = clients.iter().collect();
        ordered.sort_by_key(|client| client.address);

        let mut out = Vec::with_capacity(32 + clients.len() * 28);
        out.put_u8(PAYLOAD_VERSION);
        out.put_u8(KIND_CLIENT_LIST);
        out.put_u64(version);
        out.put_u64(effective_from);
        out.put_u64(epoch_secs);
        out.put_u32(u32::try_from(ordered.len()).map_err(|_| too_many())?);
        for client in ordered {
            out.put_bytes(client.address.as_bytes());
            out.put_u64(client.expires_at);
        }
        Ok(out)
    }

    /// Assembles and signs a client list.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if any field exceeds its cap.
    pub fn sign(
        governance: &Signer,
        version: u64,
        effective_from: u64,
        epoch_secs: u64,
        clients: Vec<ClientEntry>,
    ) -> Result<Self, WireError> {
        let bytes = Self::signing_bytes(version, effective_from, epoch_secs, &clients)?;
        Ok(Self {
            version,
            effective_from,
            epoch_secs,
            clients,
            governance_signature: governance.sign_payload(&bytes),
        })
    }

    /// Returns this list's canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if any field exceeds its cap.
    pub fn to_signing_bytes(&self) -> Result<Vec<u8>, WireError> {
        Self::signing_bytes(
            self.version,
            self.effective_from,
            self.epoch_secs,
            &self.clients,
        )
    }

    /// Verifies the list against a pinned governance address and a version floor.
    ///
    /// # Errors
    ///
    /// - [`VerifyError::StaleClientList`] if `version` is not above `min_version`.
    /// - [`VerifyError::UntrustedGovernance`] if the signature is not the pinned key's.
    /// - [`VerifyError::MalformedClientList`] for a zero epoch or a duplicate
    ///   address.
    pub fn verify(
        &self,
        governance: Address,
        min_version: u64,
    ) -> Result<VerifiedClientList, VerifyError> {
        if self.version <= min_version {
            return Err(VerifyError::StaleClientList {
                found: self.version,
                minimum: min_version,
            });
        }
        check_governance(
            &self.to_signing_bytes()?,
            &self.governance_signature,
            governance,
        )?;
        if self.epoch_secs == 0 {
            return Err(VerifyError::MalformedClientList(
                "epoch_secs must be at least 1".to_owned(),
            ));
        }

        let mut by_address = HashMap::with_capacity(self.clients.len());
        for (index, client) in self.clients.iter().enumerate() {
            if by_address.insert(client.address, index).is_some() {
                return Err(VerifyError::MalformedClientList(format!(
                    "client {} is listed twice",
                    client.address
                )));
            }
        }

        Ok(VerifiedClientList {
            list: self.clone(),
            by_address,
            governance,
        })
    }
}

/// A client list whose governance signature and structure have been checked.
#[derive(Clone, Debug)]
pub struct VerifiedClientList {
    list: ClientList,
    by_address: HashMap<Address, usize>,
    governance: Address,
}

impl VerifiedClientList {
    /// Returns the version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.list.version
    }

    /// Returns the issue time, unix seconds.
    #[must_use]
    pub const fn effective_from(&self) -> u64 {
        self.list.effective_from
    }

    /// Returns the epoch length, seconds.
    #[must_use]
    pub const fn epoch_secs(&self) -> u64 {
        self.list.epoch_secs
    }

    /// Returns the governance address this list was verified against.
    #[must_use]
    pub const fn governance(&self) -> Address {
        self.governance
    }

    /// Verifies a replacement against this list's governance key and version.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`ClientList::verify`].
    pub fn accept_successor(&self, next: &ClientList) -> Result<Self, VerifyError> {
        next.verify(self.governance, self.list.version)
    }

    /// Returns a client by address.
    #[must_use]
    pub fn get(&self, address: Address) -> Option<&ClientEntry> {
        self.by_address
            .get(&address)
            .and_then(|&index| self.list.clients.get(index))
    }

    /// Returns every client.
    #[must_use]
    pub fn clients(&self) -> &[ClientEntry] {
        &self.list.clients
    }

    /// Returns the underlying list.
    #[must_use]
    pub const fn as_client_list(&self) -> &ClientList {
        &self.list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_754_582_400;

    fn governance() -> Signer {
        Signer::from_secret_bytes([0xC0; 32]).expect("valid key")
    }

    fn address(seed: u8) -> Address {
        Signer::from_secret_bytes([seed; 32])
            .expect("valid key")
            .address()
    }

    fn client(seed: u8) -> ClientEntry {
        ClientEntry {
            address: address(seed),
            expires_at: NOW + 86_400,
        }
    }

    fn list(version: u64, clients: Vec<ClientEntry>) -> ClientList {
        ClientList::sign(&governance(), version, NOW, 60, clients).expect("signs")
    }

    #[test]
    fn a_signed_list_verifies_and_round_trips_through_json() {
        let signed = list(1, vec![client(1), client(2)]);
        let json = serde_json::to_string(&signed).expect("serialises");
        let parsed: ClientList = serde_json::from_str(&json).expect("parses");
        let verified = parsed.verify(governance().address(), 0).expect("verifies");
        assert_eq!(verified.version(), 1);
        assert_eq!(verified.epoch_secs(), 60);
        assert_eq!(
            verified.get(address(2)).map(|c| c.expires_at),
            Some(NOW + 86_400)
        );
        assert!(verified.get(address(3)).is_none());
    }

    #[test]
    fn the_encoding_ignores_client_order() {
        let a = ClientList::signing_bytes(1, NOW, 60, &[client(1), client(2)]);
        let b = ClientList::signing_bytes(1, NOW, 60, &[client(2), client(1)]);
        assert_eq!(a.expect("encodes"), b.expect("encodes"));
    }

    #[test]
    fn every_field_is_covered_by_the_signature() {
        let signed = list(2, vec![client(1), client(2)]);
        let gov = governance().address();
        let tampers: [fn(&mut ClientList); 4] = [
            |l| l.effective_from += 1,
            |l| l.epoch_secs += 1,
            |l| {
                if let Some(c) = l.clients.first_mut() {
                    c.expires_at += 1;
                }
            },
            |l| {
                if let Some(c) = l.clients.last_mut() {
                    c.address = address(9);
                }
            },
        ];
        for tamper in tampers {
            let mut changed = signed.clone();
            tamper(&mut changed);
            assert!(
                matches!(
                    changed.verify(gov, 0),
                    Err(VerifyError::UntrustedGovernance { .. })
                ),
                "{changed:?}"
            );
        }
    }

    #[test]
    fn a_list_must_be_newer_and_signed_by_governance() {
        let signed = list(3, vec![client(1)]);
        let gov = governance().address();
        assert!(matches!(
            signed.verify(gov, 3),
            Err(VerifyError::StaleClientList {
                found: 3,
                minimum: 3
            })
        ));
        let impostor = Signer::from_secret_bytes([0xF0; 32]).expect("valid key");
        let forged = ClientList::sign(&impostor, 4, NOW, 60, vec![client(1)]).expect("signs");
        assert!(matches!(
            forged.verify(gov, 3),
            Err(VerifyError::UntrustedGovernance { .. })
        ));
        let verified = signed.verify(gov, 0).expect("verifies");
        assert!(verified.accept_successor(&list(3, vec![])).is_err());
        assert!(verified.accept_successor(&list(4, vec![])).is_ok());
    }

    #[test]
    fn duplicate_addresses_and_a_zero_epoch_are_refused() {
        let gov = governance().address();
        let twice = list(1, vec![client(1), client(1)]);
        assert!(matches!(
            twice.verify(gov, 0),
            Err(VerifyError::MalformedClientList(_))
        ));
        let zero = ClientList::sign(&governance(), 1, NOW, 0, vec![]).expect("signs");
        assert!(matches!(
            zero.verify(gov, 0),
            Err(VerifyError::MalformedClientList(_))
        ));
    }

    #[test]
    fn a_registry_signature_cannot_pass_as_a_client_list() {
        let registry = crate::Registry::sign(
            &governance(),
            1,
            NOW,
            Vec::new(),
            crate::Quorum {
                min_nodes: 1,
                recommended: 1,
            },
        )
        .expect("signs");
        let borrowed = ClientList {
            version: 1,
            effective_from: NOW,
            epoch_secs: 60,
            clients: Vec::new(),
            governance_signature: registry.governance_signature,
        };
        assert!(matches!(
            borrowed.verify(governance().address(), 0),
            Err(VerifyError::UntrustedGovernance { .. })
        ));
    }
}
