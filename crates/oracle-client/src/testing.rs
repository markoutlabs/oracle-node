//! Fake nodes and registries, for testing consumers of this SDK.
//!
//! Deliberately public rather than `#[cfg(test)]`: anyone building on this crate
//! needs a way to exercise their halt and degrade handling without standing up
//! five signing nodes, and a hand-rolled fake will get the frame layout subtly
//! wrong.
//!
//! Every key here is derived from a small integer. **Never use these in
//! production** — the secrets are guessable by construction.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use oracle_types::{FeedId, Flags, NANOS_PER_SEC, PriceUpdate, Venue, VenueSet};
use oracle_wire::{
    Address, CompressedPublicKey, KeyHistoryEntry, NodeEntry, Quorum, Registry, Signer,
    SigningKeyCert, VerifiedRegistry,
};

use crate::source::{FetchError, RegistryFuture, RegistrySource};

/// A conventional node id for single-node tests.
pub const NODE_ID: &str = "oracle-test-1";

/// Issue time of test registries, unix seconds. Matches the `NOW` the tests
/// use, so a freshly built registry is never reported stale.
pub const REGISTRY_ISSUED_AT: u64 = 1_754_582_400;

/// Seed for the governance key that signs test registries.
const GOVERNANCE_SEED: u8 = 0xC0;

/// Validity window for test certificates: 1970 to far beyond any test clock.
const CERT_NOT_BEFORE: u64 = 0;
const CERT_NOT_AFTER: u64 = 4_102_444_800;

/// Returns the governance key test registries are signed with.
///
/// # Panics
///
/// Cannot panic: the seed is a valid curve scalar.
#[must_use]
pub fn governance() -> Signer {
    Signer::from_secret_bytes([GOVERNANCE_SEED; 32]).expect("valid test key")
}

/// A fake oracle node with an identity key and a hot signing key.
pub struct TestNode {
    identity: Signer,
    signing: Signer,
    outgoing: Option<Signer>,
    node_id: String,
    seed: u8,
}

impl TestNode {
    /// Builds a node from a seed. Distinct seeds give distinct keys.
    ///
    /// # Panics
    ///
    /// Panics if `seed` is zero, which is not a valid curve scalar.
    #[must_use]
    pub fn new(seed: u8, node_id: &str) -> Self {
        assert!(seed != 0, "seed 0 is not a valid secret key");
        Self {
            identity: Signer::from_secret_bytes([seed; 32]).expect("valid test key"),
            signing: Signer::from_secret_bytes([seed.wrapping_add(0x40).max(1); 32])
                .expect("valid test key"),
            outgoing: None,
            node_id: node_id.to_owned(),
            seed,
        }
    }

    /// Returns the address this node's updates recover to.
    #[must_use]
    pub fn signing_address(&self) -> Address {
        self.signing.address()
    }

    /// Returns the node id.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Returns the identity key, which issues this node's certificates.
    #[must_use]
    pub fn identity_key(&self) -> CompressedPublicKey {
        self.identity.public_key()
    }

    /// Rotates to a fresh signing key. The old one is remembered for
    /// [`TestNode::sign_outgoing`], so tests can produce frames a retired key
    /// signed, but [`TestNode::entry`] lists only the live key (SPEC §3.5).
    ///
    /// # Panics
    ///
    /// Panics if called twice on one node, which would need a third key this
    /// helper does not derive.
    pub fn rotate(&mut self) {
        assert!(
            self.outgoing.is_none(),
            "this helper models a single rotation"
        );
        // Derived from the node's own seed, so rotating one node can never
        // collide with another node's key and quietly turn a two-node test into
        // a one-node one.
        let next = Signer::from_secret_bytes([self.seed.wrapping_add(0x80).max(1); 32])
            .expect("valid test key");
        assert_ne!(
            next.address(),
            self.signing.address(),
            "the rotated key must differ from the outgoing one"
        );
        self.outgoing = Some(std::mem::replace(&mut self.signing, next));
    }

    /// Signs an update with the current key and returns the wire frame.
    #[must_use]
    pub fn sign(&self, update: &PriceUpdate) -> Vec<u8> {
        self.signing.sign_update(update).encode_frame().to_vec()
    }

    /// Signs an update with the pre-rotation key.
    ///
    /// # Panics
    ///
    /// Panics if the node has not rotated.
    #[must_use]
    pub fn sign_outgoing(&self, update: &PriceUpdate) -> Vec<u8> {
        self.outgoing
            .as_ref()
            .expect("node has not rotated")
            .sign_update(update)
            .encode_frame()
            .to_vec()
    }

    /// Builds this node's registry entry: one live key.
    ///
    /// # Panics
    ///
    /// Cannot panic: the node id is short enough for the certificate encoding.
    #[must_use]
    pub fn entry(&self) -> NodeEntry {
        NodeEntry {
            node_id: self.node_id.clone(),
            operator: "test".to_owned(),
            identity_pubkey: self.identity.public_key(),
            endpoints: vec![format!("wss://{}.test/v2/ws", self.node_id)],
            signing_keys: vec![self.cert(self.signing.address())],
            weight: 1,
        }
    }

    /// Builds this node's key history as the registry canister would serve it.
    ///
    /// `rotated_at` is when the outgoing key was retired, unix seconds. Ignored
    /// if the node has not rotated.
    #[must_use]
    pub fn history(&self, rotated_at: u64) -> Vec<KeyHistoryEntry> {
        let mut history = Vec::with_capacity(2);
        if let Some(outgoing) = &self.outgoing {
            history.push(KeyHistoryEntry {
                generation: 1,
                cert: self.cert(outgoing.address()),
                added_at: CERT_NOT_BEFORE,
                retired_at: Some(rotated_at),
            });
        }
        let generation = u32::try_from(history.len()).unwrap_or(0).saturating_add(1);
        history.push(KeyHistoryEntry {
            generation,
            cert: self.cert(self.signing.address()),
            added_at: if generation == 1 {
                CERT_NOT_BEFORE
            } else {
                rotated_at
            },
            retired_at: None,
        });
        history
    }

    fn cert(&self, address: Address) -> SigningKeyCert {
        SigningKeyCert::issue(
            &self.identity,
            &self.node_id,
            address,
            CERT_NOT_BEFORE,
            CERT_NOT_AFTER,
        )
        .expect("test node id is short enough")
    }
}

/// Serves whatever registry the test gives it, and counts fetches.
#[derive(Default)]
pub struct TestSource {
    document: Mutex<Option<Registry>>,
    fetches: AtomicUsize,
}

impl TestSource {
    /// A source that serves `registry`.
    #[must_use]
    pub fn serving(registry: Registry) -> Arc<Self> {
        Arc::new(Self {
            document: Mutex::new(Some(registry)),
            fetches: AtomicUsize::new(0),
        })
    }

    /// Serves `registry` from the next fetch on.
    ///
    /// # Panics
    ///
    /// Panics if a fetch panicked while holding the lock.
    pub fn serve(&self, registry: Registry) {
        *self.document.lock().expect("not poisoned") = Some(registry);
    }

    /// How many fetches were made.
    #[must_use]
    pub fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

impl RegistrySource for TestSource {
    fn fetch(&self) -> RegistryFuture<'_> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        let document = self.document.lock().expect("not poisoned").clone();
        Box::pin(async move {
            document.ok_or_else(|| FetchError::Transport("nothing to serve".to_owned()))
        })
    }
}

/// Builds a verified registry containing the given nodes.
///
/// # Panics
///
/// Panics if the nodes cannot form a valid registry, which would be a bug in
/// this module rather than in the caller.
#[must_use]
pub fn registry_with(nodes: &[&TestNode]) -> VerifiedRegistry {
    let entries: Vec<NodeEntry> = nodes.iter().map(|node| node.entry()).collect();
    signed_registry(1, entries)
        .verify(governance().address(), 0)
        .expect("test registry verifies")
}

/// Builds a signed but unverified registry at an explicit version.
///
/// The refresh path takes a [`Registry`] rather than a [`VerifiedRegistry`] —
/// verifying it is the client's job — so exercising that path needs a way to
/// produce one at a chosen version.
///
/// # Panics
///
/// Panics if the entries cannot form a valid registry.
#[must_use]
pub fn signed_registry(version: u64, entries: Vec<NodeEntry>) -> Registry {
    signed_registry_at(version, REGISTRY_ISSUED_AT, entries)
}

/// Builds a signed registry issued at an explicit time, for staleness tests.
///
/// # Panics
///
/// Panics if the entries cannot form a valid registry.
#[must_use]
pub fn signed_registry_at(version: u64, issued_at: u64, entries: Vec<NodeEntry>) -> Registry {
    let quorum = Quorum {
        min_nodes: u16::try_from(entries.len()).unwrap_or(u16::MAX),
        recommended: u16::try_from(entries.len()).unwrap_or(u16::MAX),
    };
    Registry::sign(&governance(), version, issued_at, entries, quorum)
        .expect("test registry encodes")
}

/// Signs a registry with a key that is not the pinned governance key.
///
/// # Panics
///
/// Panics if the entries cannot form a valid registry.
#[must_use]
pub fn forged_registry(version: u64, entries: Vec<NodeEntry>) -> Registry {
    let impostor = Signer::from_secret_bytes([0xF0; 32]).expect("valid test key");
    let quorum = Quorum {
        min_nodes: u16::try_from(entries.len()).unwrap_or(u16::MAX),
        recommended: u16::try_from(entries.len()).unwrap_or(u16::MAX),
    };
    Registry::sign(&impostor, version, REGISTRY_ISSUED_AT, entries, quorum)
        .expect("test registry encodes")
}

/// Builds a plain healthy price update.
#[must_use]
pub fn update_at(publish_time_ns: u64, seq: u64) -> PriceUpdate {
    PriceUpdate {
        feed_id: FeedId::from_bytes([7; 32]),
        flags: Flags::NONE,
        price: 6_400_000_000_000,
        conf: 50_000_000,
        expo: -8,
        publish_time_ns,
        observation_time_ns: publish_time_ns.saturating_sub(1_000_000),
        prev_publish_time_ns: publish_time_ns.saturating_sub(NANOS_PER_SEC),
        seq,
        num_sources: 5,
        sources: Venue::ALL.into_iter().collect::<VenueSet>(),
    }
}
