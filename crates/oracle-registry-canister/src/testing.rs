//! Support for tests that run this canister on PocketIC: this crate's own and
//! the end-to-end test in `oracle-node`. Native builds only.
//!
//! [`Harness`] wraps the canister's methods. [`Scenario`] adds listed test
//! nodes that track their own `seq` and push interval, so a test never picks
//! one. [`Caller`] is a second canister that calls this one.
//!
//! The `pocket-ic` crate finds its server through `POCKET_IC_BIN`, or
//! downloads the one version it accepts into the temp dir on the first run.

// Test support panics on what a test would unwrap anyway.
#![allow(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

use std::cell::Cell;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;
use std::time::Duration;

use candid::{CandidType, Decode, Encode, Principal};
use oracle_client::Certification;
use oracle_client::testing::{TestNode, update_at};
use oracle_registry_api::UNPACED_MIN_INTERVAL;
use oracle_types::{NANOS_PER_SEC, PriceUpdate, Symbol};
use oracle_wire::{Address, FRAME_SIZE, FeedSet, NodeEntry, NodeListing, PushPolicy, Registry};
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde::de::DeserializeOwned;

use crate::prices::{PriceRecord, Verdict};
use crate::{FeedInfo, InitArgs};

/// The variable that names a prebuilt canister wasm, such as the one `make
/// test` builds. A relative path starts at the workspace root.
pub const WASM_ENV: &str = "ORACLE_CANISTER_WASM";

/// The canister wasm, read once for each test binary. `make test` builds it
/// first, so a build error shows before the tests; without [`WASM_ENV`], the tests build it.
pub static WASM: LazyLock<Vec<u8>> = LazyLock::new(|| match std::env::var_os(WASM_ENV) {
    Some(path) => read_prebuilt(WASM_ENV, &workspace_root().join(path), BUILT_IN_TEST),
    None => build(&["--lib"], "oracle_registry_canister.wasm"),
});

/// The variable that names a prebuilt [`CALLER_WASM`].
pub const CALLER_WASM_ENV: &str = "ORACLE_CALLER_WASM";

/// The canister of `examples/price_caller.rs`, which forwards one call to
/// another canister. The first [`Harness::caller`] reads it, or builds it without [`CALLER_WASM_ENV`].
pub static CALLER_WASM: LazyLock<Vec<u8>> =
    LazyLock::new(|| match std::env::var_os(CALLER_WASM_ENV) {
        Some(path) => read_prebuilt(CALLER_WASM_ENV, &workspace_root().join(path), BUILT_IN_TEST),
        None => build(&["--example", "price_caller"], "examples/price_caller.wasm"),
    });

/// The variable that names the wasm of the previous release, for the upgrade
/// and rollback test. The tests never download it.
pub const PREVIOUS_WASM_ENV: &str = "ORACLE_PREVIOUS_WASM";

/// The wasm of the previous release, when [`PREVIOUS_WASM_ENV`] names one.
#[must_use]
pub fn previous_wasm() -> Option<Vec<u8>> {
    let path = std::env::var_os(PREVIOUS_WASM_ENV)?;
    Some(read_prebuilt(
        PREVIOUS_WASM_ENV,
        &workspace_root().join(path),
        "Point it at the previous release wasm, or unset it to skip the test.",
    ))
}

/// Cycles for the test canister: enough that no test runs it dry.
const CANISTER_CYCLES: u128 = 1_000_000_000_000_000;
/// The rounds `pass_time` runs, so that the timers due at the new time fire.
const ROUNDS_AFTER_TIME: usize = 3;
/// The threshold key of a local network and of PocketIC.
const TEST_KEY: &str = "dfx_test_key";
/// The recommended quorum in the init arguments of every test canister.
const RECOMMENDED_QUORUM: u16 = 3;
/// The seed of the one test node that no scenario lists.
const STRANGER_SEED: u8 = 9;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

/// The fix for a prebuilt wasm that the tests can also build.
const BUILT_IN_TEST: &str =
    "Run `make test`, which builds it, or unset the variable to build it in the test.";

fn read_prebuilt(variable: &str, path: &Path, fix: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| {
        panic!(
            "{variable} names {}, which cannot be read: {error}. {fix}",
            path.display()
        )
    })
}

fn build(what: &[&str], artifact: &str) -> Vec<u8> {
    let workspace = workspace_root();
    let status = Command::new(env!("CARGO"))
        .current_dir(&workspace)
        .args(["build", "-p", "oracle-registry-canister"])
        .args(what)
        .args(["--target", "wasm32-unknown-unknown", "--release"])
        .status()
        .expect("cargo runs");
    assert!(status.success(), "the {artifact} wasm must build");
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| workspace.join("target"), PathBuf::from);
    std::fs::read(target.join("wasm32-unknown-unknown/release").join(artifact))
        .unwrap_or_else(|error| panic!("{artifact} exists: {error}"))
}

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
        Self::install(&WASM, min_nodes, key_name, epoch_secs, CANISTER_CYCLES)
    }

    fn install(
        wasm: &[u8],
        min_nodes: u16,
        key_name: &str,
        epoch_secs: Option<u64>,
        cycles: u128,
    ) -> Self {
        let pic = PocketIcBuilder::new()
            .with_nns_subnet()
            .with_fiduciary_subnet()
            .with_application_subnet()
            .build();
        let governance = Principal::self_authenticating(b"governance");
        let canister = pic.create_canister_on_subnet(Some(governance), None, app_subnet(&pic));
        pic.add_cycles(canister, cycles);
        let args = Encode!(&InitArgs {
            key_name: key_name.to_owned(),
            min_nodes,
            recommended: RECOMMENDED_QUORUM,
            epoch_secs,
            feeds: None,
        })
        .expect("encodes");
        pic.install_canister(canister, wasm.to_vec(), args, Some(governance));
        Self {
            pic,
            canister,
            governance,
            gateway: None,
        }
    }

    /// Installs [`CALLER_WASM`] on the canister's subnet.
    #[must_use]
    pub fn caller(&self) -> Caller<'_> {
        let canister = self
            .pic
            .create_canister_on_subnet(None, None, app_subnet(&self.pic));
        self.pic.add_cycles(canister, CANISTER_CYCLES);
        self.pic.install_canister(
            canister,
            CALLER_WASM.clone(),
            Encode!().expect("encodes"),
            None,
        );
        Caller {
            harness: self,
            canister,
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
        self.now_ns() / NANOS_PER_SEC
    }

    /// Moves the clock forward and runs a few rounds.
    pub fn pass_time(&self, secs: u64) {
        self.pic.advance_time(Duration::from_secs(secs));
        for _ in 0..ROUNDS_AFTER_TIME {
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

    /// An update call from `caller`, not decoded. `Err` holds the reject.
    pub fn update_as(
        &self,
        caller: Principal,
        method: &str,
        args: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.pic
            .update_call(self.canister, caller, method, args)
            .map_err(|error| error.to_string())
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

    /// The registry version, 0 before the first publish.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.query("get_version", Encode!().expect("encodes"))
    }

    /// Governance signs the client list again. Returns the version published.
    pub fn republish_clients(&self) -> Result<u64, String> {
        self.update(
            self.governance,
            "republish_clients",
            Encode!().expect("encodes"),
        )
    }

    /// Governance signs the feed set again. Returns the version published.
    pub fn republish_feeds(&self) -> Result<u64, String> {
        self.update(
            self.governance,
            "republish_feeds",
            Encode!().expect("encodes"),
        )
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

    /// Governance publishes a feed set from its JSON content. Returns the version.
    pub fn set_feed_set(&self, content_json: &str) -> Result<u64, String> {
        self.update(
            self.governance,
            "set_feed_set",
            Encode!(&content_json.to_owned()).expect("encodes"),
        )
    }

    /// The published feed set, if any.
    #[must_use]
    pub fn feed_set(&self) -> Option<FeedSet> {
        let json: Option<String> = self.query("get_feed_set", Encode!().expect("encodes"));
        json.map(|json| serde_json::from_str(&json).expect("the feed set parses"))
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
        let symbol: Symbol = symbol.parse().expect("a valid symbol");
        let id = serde_bytes::ByteBuf::from(oracle_wire::feed_id(&symbol).as_bytes().to_vec());
        self.query("get_price", Encode!(&id).expect("encodes"))
    }

    /// Upgrades the canister to the same wasm, with no arguments.
    pub fn upgrade(&self) {
        self.upgrade_to(&WASM).expect("the upgrade succeeds");
    }

    /// Upgrades the canister to `wasm`, with no arguments: a rollback when it
    /// is an older wasm. `Err` holds the reject, such as a trap in `post_upgrade`.
    pub fn upgrade_to(&self, wasm: &[u8]) -> Result<(), String> {
        self.pic
            .upgrade_canister(
                self.canister,
                wasm.to_vec(),
                Encode!().expect("encodes"),
                Some(self.governance),
            )
            .map_err(|error| error.to_string())
    }

    /// The canister's cycle balance.
    #[must_use]
    pub fn cycles(&self) -> u128 {
        self.pic.cycle_balance(self.canister)
    }
}

fn app_subnet(pic: &PocketIc) -> Principal {
    pic.topology()
        .get_app_subnets()
        .first()
        .copied()
        .expect("an application subnet")
}

/// A second canister, not a controller, that calls the registry canister.
pub struct Caller<'a> {
    harness: &'a Harness,
    /// The calling canister.
    pub canister: Principal,
}

impl Caller<'_> {
    /// Calls `method` of the registry canister with these Candid arguments and
    /// these cycles attached. `Err` holds the reject that the caller got.
    pub fn call(&self, method: &str, arg: Vec<u8>, cycles: u128) -> Result<Vec<u8>, String> {
        let args = Encode!(
            &self.harness.canister,
            &method.to_owned(),
            &serde_bytes::ByteBuf::from(arg),
            &cycles
        )
        .expect("encodes");
        let reply: Result<serde_bytes::ByteBuf, String> = {
            let message = self
                .harness
                .pic
                .submit_call(self.canister, Principal::anonymous(), "forward", args)
                .unwrap_or_else(|error| panic!("forward rejected: {error}"));
            let bytes = self
                .harness
                .pic
                .await_call(message)
                .unwrap_or_else(|error| panic!("forward rejected: {error}"));
            Decode!(&bytes, Result<serde_bytes::ByteBuf, String>).expect("the reply decodes")
        };
        reply.map(serde_bytes::ByteBuf::into_vec)
    }

    /// The calling canister's cycle balance.
    #[must_use]
    pub fn cycles(&self) -> u128 {
        self.harness.pic.cycle_balance(self.canister)
    }
}

/// A caller that is not a controller of the canister.
#[must_use]
pub fn outsider() -> Principal {
    Principal::self_authenticating(b"stranger")
}

/// A price in whole dollars, at the expo -8 of every test update.
#[must_use]
pub const fn usd(dollars: i64) -> i64 {
    dollars * 100_000_000
}

/// Zeros the size of a price frame: no frame type parses them.
#[must_use]
pub fn junk_frame() -> Vec<u8> {
    vec![0; FRAME_SIZE]
}

/// The canister with listed test nodes and priced feeds. Each node signs at
/// the canister's clock with its next `seq`.
pub struct Scenario {
    harness: Harness,
    seats: Vec<Seat>,
    stranger: Seat,
}

struct Seat {
    key: TestNode,
    next_seq: Cell<u64>,
    last_batch_ns: Cell<Option<u64>>,
}

impl Seat {
    fn new(seed: u8) -> Self {
        Self {
            key: TestNode::new(seed),
            next_seq: Cell::new(1),
            last_batch_ns: Cell::new(None),
        }
    }

    fn take_seq(&self) -> u64 {
        let seq = self.next_seq.get();
        self.next_seq.set(seq + 1);
        seq
    }
}

impl Scenario {
    /// A canister with no nodes and no priced feeds, until the builder adds them.
    pub fn builder() -> ScenarioBuilder {
        ScenarioBuilder {
            min_nodes: 1,
            key_name: TEST_KEY.to_owned(),
            epoch_secs: None,
            nodes: 0,
            priced: Vec::new(),
            cycles: CANISTER_CYCLES,
            wasm: None,
        }
    }

    /// The listed node at `index`, from 0.
    pub fn node(&self, index: usize) -> ScenarioNode<'_> {
        let seat = self
            .seats
            .get(index)
            .unwrap_or_else(|| panic!("the scenario lists {} nodes", self.seats.len()));
        self.seat(seat)
    }

    /// Every listed node, in index order.
    pub fn nodes(&self) -> impl Iterator<Item = ScenarioNode<'_>> {
        self.seats.iter().map(|seat| self.seat(seat))
    }

    /// A test node that the registry does not list.
    pub fn stranger(&self) -> ScenarioNode<'_> {
        self.seat(&self.stranger)
    }

    fn seat<'a>(&'a self, seat: &'a Seat) -> ScenarioNode<'a> {
        ScenarioNode {
            harness: &self.harness,
            seat,
        }
    }
}

impl Deref for Scenario {
    type Target = Harness;

    fn deref(&self) -> &Harness {
        &self.harness
    }
}

impl DerefMut for Scenario {
    fn deref_mut(&mut self) -> &mut Harness {
        &mut self.harness
    }
}

/// The setup of a [`Scenario`].
#[must_use]
pub struct ScenarioBuilder {
    min_nodes: u16,
    key_name: String,
    epoch_secs: Option<u64>,
    nodes: u8,
    priced: Vec<String>,
    cycles: u128,
    wasm: Option<Vec<u8>>,
}

impl ScenarioBuilder {
    /// Lists this many test nodes, with seeds from 1.
    pub fn nodes(mut self, count: u8) -> Self {
        assert!(count < STRANGER_SEED, "the stranger's seed comes next");
        self.nodes = count;
        self
    }

    /// The feeds the canister prices. The build publishes [`scenario_feed_set`]
    /// of them first, because the canister prices feeds only under a paced set.
    pub fn priced(mut self, feeds: &[&str]) -> Self {
        self.priced = feeds.iter().map(|feed| (*feed).to_owned()).collect();
        self
    }

    /// The fewest nodes, in the init arguments. Default 1.
    pub fn min_nodes(mut self, min_nodes: u16) -> Self {
        self.min_nodes = min_nodes;
        self
    }

    /// The threshold key that signs the documents. Default `dfx_test_key`.
    pub fn key_name(mut self, key_name: &str) -> Self {
        key_name.clone_into(&mut self.key_name);
        self
    }

    /// The broadcast-key epoch of the client list. Default 60 s.
    pub fn epoch_secs(mut self, secs: u64) -> Self {
        self.epoch_secs = Some(secs);
        self
    }

    /// The canister's cycles at install. Default: enough that no test runs it dry.
    pub fn cycles(mut self, cycles: u128) -> Self {
        self.cycles = cycles;
        self
    }

    /// Installs this wasm instead of [`WASM`], such as the previous release.
    pub fn wasm(mut self, wasm: Vec<u8>) -> Self {
        self.wasm = Some(wasm);
        self
    }

    /// Installs the canister, then lists the nodes and sets the priced feeds.
    pub fn build(self) -> Scenario {
        let wasm = self.wasm.as_deref().unwrap_or(&WASM);
        let harness = Harness::install(
            wasm,
            self.min_nodes,
            &self.key_name,
            self.epoch_secs,
            self.cycles,
        );
        let seats: Vec<Seat> = (1..=self.nodes).map(Seat::new).collect();
        for (version, seat) in (1..).zip(&seats) {
            assert_eq!(
                harness.add_node(&seat.key.entry()),
                Ok(version),
                "each listing publishes the next registry version"
            );
        }
        if !self.priced.is_empty() {
            let feeds: Vec<&str> = self.priced.iter().map(String::as_str).collect();
            harness
                .set_feed_set(&scenario_feed_set(&feeds))
                .expect("governance publishes the feed set of the priced feeds");
            harness
                .set_feeds(&feeds)
                .expect("governance sets the priced feeds");
        }
        Scenario {
            harness,
            seats,
            stranger: Seat::new(STRANGER_SEED),
        }
    }
}

/// The push pace of the feed set that [`ScenarioBuilder::priced`] publishes:
/// faster than production, so a test sees several pushes in seconds.
pub const SCENARIO_PUSH: PushPolicy = PushPolicy {
    heartbeat_secs: 2,
    deviation_bps: 10,
    min_interval_secs: 1,
};

/// A feed set of these feeds with [`SCENARIO_PUSH`], one spot source each.
#[must_use]
pub fn scenario_feed_set(feeds: &[&str]) -> String {
    let feeds: Vec<serde_json::Value> = feeds
        .iter()
        .map(|feed| {
            serde_json::json!({
                "symbol": feed,
                "sources": [{ "venue": "coinbase", "market": "spot", "symbol": feed }],
            })
        })
        .collect();
    serde_json::json!({ "push": SCENARIO_PUSH, "feeds": feeds }).to_string()
}

/// One test node of a [`Scenario`].
#[derive(Clone, Copy)]
pub struct ScenarioNode<'a> {
    harness: &'a Harness,
    seat: &'a Seat,
}

impl ScenarioNode<'_> {
    /// The address that the node's frames recover to.
    pub fn address(&self) -> Address {
        self.seat.key.signing_address()
    }

    /// The node's registry entry.
    pub fn entry(&self) -> NodeEntry {
        self.seat.key.entry()
    }

    /// A single price frame of `feed` at `price`, as the node streams it to
    /// its clients. It takes the node's next `seq`; `push` refuses it.
    pub fn frame(&self, feed: &str, price: i64) -> Vec<u8> {
        self.seat
            .key
            .sign(&self.update(feed, price, self.seat.take_seq()))
    }

    /// A signed batch of `feeds` at `price`, with the node's next `seq` for all.
    /// The clock first moves past the node's push interval, as a node's own pace does.
    pub fn batch(&self, feeds: &[&str], price: i64) -> Vec<u8> {
        self.space_out();
        let seq = self.seat.take_seq();
        let updates: Vec<PriceUpdate> = feeds
            .iter()
            .map(|feed| self.update(feed, price, seq))
            .collect();
        self.seat.key.sign_batch(&updates)
    }

    /// Pushes a new batch of `feeds`, all at `price`.
    pub fn push_batch(&self, feeds: &[&str], price: i64) -> Result<Vec<Verdict>, String> {
        self.harness.push(&[self.batch(feeds, price)])
    }

    fn space_out(&self) {
        let pic = &self.harness.pic;
        let now = self.harness.now_ns();
        if let Some(last) = self.seat.last_batch_ns.get() {
            let due = last.saturating_add(
                u64::try_from(UNPACED_MIN_INTERVAL.as_nanos()).expect("fits in u64"),
            );
            // A live instance follows the wall clock, which a test does not move.
            if now < due && !pic.auto_progress_enabled() {
                pic.advance_time(Duration::from_nanos(due - now));
                // `inspect_message` reads the time of the last round, so one round runs.
                pic.tick();
            }
        }
        self.seat.last_batch_ns.set(Some(self.harness.now_ns()));
    }

    fn update(&self, feed: &str, price: i64, seq: u64) -> PriceUpdate {
        let symbol: Symbol = feed.parse().expect("a valid symbol");
        let mut update = update_at(self.harness.now_ns(), seq);
        update.feed_id = oracle_wire::feed_id(&symbol);
        update.price = price;
        update
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[should_panic(expected = "Run `make test`")]
    fn a_missing_prebuilt_wasm_names_the_fix() {
        let _ = super::read_prebuilt(
            super::WASM_ENV,
            std::path::Path::new("/no/such/canister.wasm"),
            super::BUILT_IN_TEST,
        );
    }
}
