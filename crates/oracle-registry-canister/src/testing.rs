//! Support for tests that run this canister on PocketIC: this crate's own and
//! the end-to-end test in `oracle-node`. Native builds only.
//!
//! The `pocket-ic` crate finds its server through `POCKET_IC_BIN`, or
//! downloads the one version it accepts into the temp dir on the first run.

// Test support panics on what a test would unwrap anyway.
#![allow(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::LazyLock;
use std::time::Duration;

use candid::{CandidType, Decode, Encode, Principal};
use oracle_client::Certification;
use oracle_wire::{Address, NodeEntry, NodeListing, Registry};
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde::de::DeserializeOwned;

use crate::prices::{PriceRecord, Verdict};
use crate::{FeedInfo, InitArgs};

/// The canister wasm, built with cargo once for each test binary.
pub static WASM: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let status = Command::new(env!("CARGO"))
        .current_dir(&workspace)
        .args([
            "build",
            "-p",
            "oracle-registry-canister",
            "--target",
            "wasm32-unknown-unknown",
            "--release",
        ])
        .status()
        .expect("cargo runs");
    assert!(status.success(), "the canister wasm must build");
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| workspace.join("target"), PathBuf::from);
    std::fs::read(target.join("wasm32-unknown-unknown/release/oracle_registry_canister.wasm"))
        .expect("the canister wasm exists")
});

/// The canister installed on a PocketIC instance, with `governance` as its
/// controller.
pub struct Harness {
    /// The instance. The NNS subnet supplies the root key that certificates
    /// chain to; the fiduciary one holds the signing key.
    pub pic: PocketIc,
    /// The canister.
    pub canister: Principal,
    /// The controller, and so the only caller of update methods.
    pub governance: Principal,
    gateway: Option<String>,
}

impl Harness {
    /// Installs the canister with these init arguments.
    #[must_use]
    pub fn new(min_nodes: u16, key_name: &str, epoch_secs: Option<u64>) -> Self {
        let pic = PocketIcBuilder::new()
            .with_nns_subnet()
            .with_fiduciary_subnet()
            .with_application_subnet()
            .build();
        let governance = Principal::self_authenticating(b"governance");
        let app_subnet = pic
            .topology()
            .get_app_subnets()
            .first()
            .copied()
            .expect("an application subnet");
        let canister = pic.create_canister_on_subnet(Some(governance), None, app_subnet);
        pic.add_cycles(canister, 1_000_000_000_000_000);
        let args = Encode!(&InitArgs {
            key_name: key_name.to_owned(),
            min_nodes,
            recommended: 3,
            epoch_secs,
            feeds: None,
        })
        .expect("encodes");
        pic.install_canister(canister, WASM.clone(), args, Some(governance));
        Self {
            pic,
            canister,
            governance,
            gateway: None,
        }
    }

    /// Starts an HTTP gateway and lets the instance make rounds on its own.
    /// Returns the gateway URL.
    pub fn make_live(&mut self) -> String {
        let url = self.pic.make_live(None);
        let gateway = url.as_str().trim_end_matches('/').to_owned();
        self.gateway = Some(gateway.clone());
        gateway
    }

    /// The gateway URL of a document path such as `/registry.json`.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        let gateway = self.gateway.as_deref().expect("make_live first");
        format!(
            "{gateway}/{}?canisterId={}",
            path.trim_start_matches('/'),
            self.canister
        )
    }

    /// The network's root key, DER in hex.
    #[must_use]
    pub fn root_key(&self) -> String {
        hex::encode(self.pic.root_key().expect("the NNS subnet has a root key"))
    }

    /// The check the SDK and the nodes run on a fetched document.
    #[must_use]
    pub fn certification(&self) -> Certification {
        Certification::new(&self.canister.to_text(), &self.root_key()).expect("valid")
    }

    /// The instance's clock, unix nanoseconds.
    #[must_use]
    pub fn now_ns(&self) -> u64 {
        self.pic.get_time().as_nanos_since_unix_epoch()
    }

    /// The instance's clock, unix seconds.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.pic.get_time().as_nanos_since_unix_epoch() / 1_000_000_000
    }

    /// Moves the clock forward and runs a few rounds.
    pub fn pass_time(&self, secs: u64) {
        self.pic.advance_time(Duration::from_secs(secs));
        for _ in 0..3 {
            self.pic.tick();
        }
    }

    /// An update call, decoded.
    pub fn update<T: CandidType + DeserializeOwned>(
        &self,
        caller: Principal,
        method: &str,
        args: Vec<u8>,
    ) -> T {
        let message = self
            .pic
            .submit_call(self.canister, caller, method, args)
            .unwrap_or_else(|error| panic!("{method} rejected: {error}"));
        // A live instance makes rounds on its own and refuses a tick.
        let reply = if self.pic.auto_progress_enabled() {
            self.pic.await_call_no_ticks(message)
        } else {
            self.pic.await_call(message)
        };
        let bytes = reply.unwrap_or_else(|error| panic!("{method} rejected: {error}"));
        Decode!(&bytes, T).unwrap_or_else(|error| panic!("{method} reply decodes: {error}"))
    }

    /// An anonymous query, decoded.
    pub fn query<T: CandidType + DeserializeOwned>(&self, method: &str, args: Vec<u8>) -> T {
        let bytes = self
            .pic
            .query_call(self.canister, Principal::anonymous(), method, args)
            .unwrap_or_else(|error| panic!("{method} rejected: {error}"));
        Decode!(&bytes, T).unwrap_or_else(|error| panic!("{method} reply decodes: {error}"))
    }

    /// The Candid arguments of `add_node`.
    #[must_use]
    pub fn add_args(entry: &NodeEntry) -> Vec<u8> {
        let json = serde_json::to_string(entry).expect("serialises");
        Encode!(&json).expect("encodes")
    }

    /// Governance lists a node. Returns the registry version published.
    pub fn add_node(&self, entry: &NodeEntry) -> Result<u64, String> {
        self.update(self.governance, "add_node", Self::add_args(entry))
    }

    /// Governance rotates a node. Returns the registry version published.
    pub fn replace_node(&self, old: Address, new: Address) -> Result<u64, String> {
        self.update(
            self.governance,
            "replace_node",
            Encode!(&old.to_checksummed(), &new.to_checksummed()).expect("encodes"),
        )
    }

    /// Governance removes a node. Returns the registry version published.
    pub fn remove_node(&self, node: Address) -> Result<u64, String> {
        self.update(
            self.governance,
            "remove_node",
            Encode!(&node.to_checksummed()).expect("encodes"),
        )
    }

    /// Governance lists a client. Returns the client list version published.
    pub fn add_client(&self, client: Address, expires_at: u64) -> Result<u64, String> {
        self.update(
            self.governance,
            "add_client",
            Encode!(&client.to_checksummed(), &expires_at).expect("encodes"),
        )
    }

    /// Governance removes a client. Returns the client list version published.
    pub fn remove_client(&self, client: Address) -> Result<u64, String> {
        self.update(
            self.governance,
            "remove_client",
            Encode!(&client.to_checksummed()).expect("encodes"),
        )
    }

    /// Governance fetches the signing key, before anything is published.
    #[must_use]
    pub fn refresh_governance_key(&self) -> Address {
        let address: Result<String, String> = self.update(
            self.governance,
            "refresh_governance_key",
            Encode!().expect("encodes"),
        );
        address
            .expect("the key exists")
            .parse()
            .expect("an address")
    }

    /// The registry as published.
    #[must_use]
    pub fn registry(&self) -> Registry {
        let json: Option<String> = self.query("get_registry", Encode!().expect("encodes"));
        serde_json::from_str(&json.expect("a registry is published")).expect("parses")
    }

    /// The governance address, once the canister has fetched its key.
    #[must_use]
    pub fn governance_address(&self) -> Address {
        let text: Option<String> = self.query("get_governance", Encode!().expect("encodes"));
        text.expect("the key has been fetched")
            .parse()
            .expect("parses")
    }

    /// What the canister knows about a node address.
    #[must_use]
    pub fn listing(&self, node: Address) -> Option<NodeListing> {
        let json: Option<String> = self.query(
            "get_node_listing",
            Encode!(&node.to_checksummed()).expect("encodes"),
        );
        json.map(|json| serde_json::from_str(&json).expect("parses"))
    }

    /// Governance changes the quorum guidance. Returns the registry version published.
    pub fn set_quorum(&self, min_nodes: u16, recommended: u16) -> Result<u64, String> {
        self.update(
            self.governance,
            "set_quorum",
            Encode!(&min_nodes, &recommended).expect("encodes"),
        )
    }

    /// Governance sets the price window, in seconds.
    pub fn set_price_window(&self, secs: u64) -> Result<(), String> {
        self.update(
            self.governance,
            "set_price_window",
            Encode!(&secs).expect("encodes"),
        )
    }

    /// The price window, in seconds.
    #[must_use]
    pub fn price_window(&self) -> u64 {
        self.query("get_price_window", Encode!().expect("encodes"))
    }

    /// Governance sets the priced feeds.
    pub fn set_feeds(&self, symbols: &[&str]) -> Result<(), String> {
        let symbols: Vec<String> = symbols.iter().map(|symbol| (*symbol).to_owned()).collect();
        self.update(
            self.governance,
            "set_feeds",
            Encode!(&symbols).expect("encodes"),
        )
    }

    /// A push as the anonymous identity, as a node makes it. `Err` holds the
    /// reason the IC or the canister refused the whole push.
    pub fn push(&self, frames: &[Vec<u8>]) -> Result<Vec<Verdict>, String> {
        self.push_as(Principal::anonymous(), frames)
    }

    /// A push from another caller.
    pub fn push_as(&self, caller: Principal, frames: &[Vec<u8>]) -> Result<Vec<Verdict>, String> {
        let frames: Vec<serde_bytes::ByteBuf> = frames
            .iter()
            .map(|frame| serde_bytes::ByteBuf::from(frame.clone()))
            .collect();
        let args = Encode!(&frames).expect("encodes");
        let message = self
            .pic
            .submit_call(self.canister, caller, "push", args)
            .map_err(|error| error.to_string())?;
        let reply = if self.pic.auto_progress_enabled() {
            self.pic.await_call_no_ticks(message)
        } else {
            self.pic.await_call(message)
        };
        let bytes = reply.map_err(|error| error.to_string())?;
        Decode!(&bytes, Result<Vec<Verdict>, String>).expect("the reply decodes")
    }

    /// The listed feeds.
    #[must_use]
    pub fn feeds(&self) -> Vec<FeedInfo> {
        self.query("get_feeds", Encode!().expect("encodes"))
    }

    /// One feed's price, by symbol.
    #[must_use]
    pub fn price(&self, symbol: &str) -> Option<PriceRecord> {
        let symbol: oracle_types::Symbol = symbol.parse().expect("a valid symbol");
        let id = serde_bytes::ByteBuf::from(oracle_wire::feed_id(&symbol).as_bytes().to_vec());
        self.query("get_price", Encode!(&id).expect("encodes"))
    }

    /// Upgrades the canister to the same wasm, with no arguments.
    pub fn upgrade(&self) {
        self.pic
            .upgrade_canister(
                self.canister,
                WASM.clone(),
                Encode!().expect("encodes"),
                Some(self.governance),
            )
            .expect("the upgrade succeeds");
    }

    /// The canister's cycle balance.
    #[must_use]
    pub fn cycles(&self) -> u128 {
        self.pic.cycle_balance(self.canister)
    }
}
