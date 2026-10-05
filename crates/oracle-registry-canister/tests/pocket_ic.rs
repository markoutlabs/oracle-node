//! The canister end to end on PocketIC, with real threshold ECDSA.
//!
//! The assertion that matters most: the document the canister publishes
//! verifies with the unchanged `Registry::verify` against the governance
//! address the canister reports. Everything else in M5.5 rests on that.
//!
//! Needs the PocketIC server. Set `POCKET_IC_BIN`, or have a `dfx` install
//! whose cache bundles it. The canister wasm is built by this test.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use candid::{CandidType, Decode, Encode, Principal};
use ic_http_certification::StatusCode;
use ic_response_verification::types::VerificationInfo;
use ic_response_verification::{ResponseVerificationError, verify_request_response_pair};
use oracle_client::{
    Certification, FetchError, HttpDocumentSource, HttpRegistrySource, RegistrySource as _,
};
use oracle_registry_canister::{HttpRequest, HttpResponse, InitArgs};
use oracle_wire::{Address, ClientList, NodeEntry, NodeListing, Registry, Signer, VerifyError};
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde::de::DeserializeOwned;

const REGISTRY: &str = "/registry.json";
const CLIENTS: &str = "/clients.json";
const MAX_CERT_AGE_NS: u128 = 300 * 1_000_000_000;

fn server_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("POCKET_IC_BIN") {
        return PathBuf::from(path);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .expect("HOME is set");
    let versions = home.join(".cache/dfinity/versions");
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(&versions)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path().join("pocket-ic"))
                .filter(|path| path.is_file())
                .collect()
        })
        .unwrap_or_default();
    candidates.sort();
    candidates.pop().unwrap_or_else(|| {
        panic!(
            "no PocketIC server found: set POCKET_IC_BIN or install dfx (looked in {})",
            versions.display()
        )
    })
}

fn build_wasm() -> Vec<u8> {
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
}

struct Harness {
    pic: PocketIc,
    canister: Principal,
    governance: Principal,
}

impl Harness {
    fn new(min_nodes: u16) -> Self {
        Self::with_key(min_nodes, "dfx_test_key")
    }

    fn with_key(min_nodes: u16, key_name: &str) -> Self {
        // The NNS subnet supplies the root key that certificates chain to.
        let pic = PocketIcBuilder::new()
            .with_server_binary(server_binary())
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
            epoch_secs: None,
        })
        .expect("encodes");
        pic.install_canister(canister, build_wasm(), args, Some(governance));
        Self {
            pic,
            canister,
            governance,
        }
    }

    fn now(&self) -> u64 {
        self.pic.get_time().as_nanos_since_unix_epoch() / 1_000_000_000
    }

    fn update<T: CandidType + DeserializeOwned>(
        &self,
        caller: Principal,
        method: &str,
        args: Vec<u8>,
    ) -> T {
        let bytes = self
            .pic
            .update_call(self.canister, caller, method, args)
            .unwrap_or_else(|error| panic!("{method} rejected: {error}"));
        Decode!(&bytes, T).unwrap_or_else(|error| panic!("{method} reply decodes: {error}"))
    }

    fn query<T: CandidType + DeserializeOwned>(&self, method: &str, args: Vec<u8>) -> T {
        let bytes = self
            .pic
            .query_call(self.canister, Principal::anonymous(), method, args)
            .unwrap_or_else(|error| panic!("{method} rejected: {error}"));
        Decode!(&bytes, T).unwrap_or_else(|error| panic!("{method} reply decodes: {error}"))
    }

    fn get_json(&self, path: &str) -> HttpResponse<'static> {
        let request = HttpRequest::get(format!("{path}?x=1")).build();
        self.query("http_request", Encode!(&request).expect("encodes"))
    }

    /// The check an HTTP gateway runs on a query response.
    fn verify_http(
        &self,
        path: &str,
        response: HttpResponse<'static>,
    ) -> Result<VerificationInfo, ResponseVerificationError> {
        let root_key = self.pic.root_key().expect("the NNS subnet has a root key");
        verify_request_response_pair(
            HttpRequest::get(format!("{path}?x=1")).build(),
            response,
            self.canister.as_slice(),
            u128::from(self.pic.get_time().as_nanos_since_unix_epoch()),
            MAX_CERT_AGE_NS,
            &root_key,
            2,
        )
    }

    /// The check the SDK and the nodes run on a fetched document, at `now_ns`.
    fn sdk_check(
        &self,
        path: &str,
        response: &HttpResponse<'static>,
        now_ns: u64,
    ) -> Result<Vec<u8>, FetchError> {
        self.certification().verify(
            path,
            response.status_code().as_u16(),
            response.headers().to_vec(),
            response.body().to_vec(),
            now_ns,
        )
    }

    fn certification(&self) -> Certification {
        let root_key = self.pic.root_key().expect("the NNS subnet has a root key");
        Certification::new(&self.canister.to_text(), &hex::encode(root_key)).expect("valid")
    }

    fn add_args(entry: &NodeEntry) -> Vec<u8> {
        let json = serde_json::to_string(entry).expect("serialises");
        Encode!(&json).expect("encodes")
    }

    fn add(&self, entry: &NodeEntry) -> Result<u64, String> {
        self.update(self.governance, "add_node", Self::add_args(entry))
    }

    fn replace(&self, old: Address, new: Address) -> Result<u64, String> {
        self.update(
            self.governance,
            "replace_node",
            Encode!(&old.to_checksummed(), &new.to_checksummed()).expect("encodes"),
        )
    }

    fn remove(&self, node: Address) -> Result<u64, String> {
        self.update(
            self.governance,
            "remove_node",
            Encode!(&node.to_checksummed()).expect("encodes"),
        )
    }

    fn add_client(&self, client: Address, expires_at: u64) -> Result<u64, String> {
        self.update(
            self.governance,
            "add_client",
            Encode!(&client.to_checksummed(), &expires_at).expect("encodes"),
        )
    }

    fn registry(&self) -> Registry {
        let json: Option<String> = self.query("get_registry", Encode!().expect("encodes"));
        serde_json::from_str(&json.expect("a registry is published")).expect("parses")
    }

    fn governance_address(&self) -> oracle_wire::Address {
        let text: Option<String> = self.query("get_governance", Encode!().expect("encodes"));
        text.expect("the key has been fetched")
            .parse()
            .expect("parses")
    }

    fn listing(&self, node: Address) -> Option<NodeListing> {
        let json: Option<String> = self.query(
            "get_node_listing",
            Encode!(&node.to_string()).expect("encodes"),
        );
        json.map(|json| serde_json::from_str(&json).expect("parses"))
    }

    fn pass_time(&self, secs: u64) {
        self.pic.advance_time(Duration::from_secs(secs));
        for _ in 0..3 {
            self.pic.tick();
        }
    }
}

fn key(seed: u8) -> Signer {
    Signer::from_secret_bytes([seed; 32]).expect("valid key")
}

fn node(seed: u8) -> NodeEntry {
    NodeEntry {
        address: key(seed).address(),
        operator: format!("op-{seed}"),
        endpoints: vec![format!("wss://node{seed}.example/v2/ws")],
        weight: 1,
    }
}

#[test]
fn the_canister_publishes_a_registry_that_verifies_with_oracle_wire() {
    let h = Harness::new(3);
    let empty = h.get_json(REGISTRY);
    assert_eq!(empty.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    h.verify_http(REGISTRY, empty)
        .expect("the empty state is certified at init");
    let (a, b, c) = (node(1), node(2), node(3));

    // Ingress from anyone but governance is dropped before it executes.
    let stranger = Principal::self_authenticating(b"stranger");
    for (method, args) in [
        ("add_node", Harness::add_args(&a)),
        ("refresh_governance_key", Encode!().expect("encodes")),
    ] {
        assert!(
            h.pic
                .update_call(h.canister, stranger, method, args)
                .is_err(),
            "{method} must refuse a non-controller"
        );
    }
    let version: u64 = h.query("get_version", Encode!().expect("encodes"));
    assert_eq!(version, 0);

    assert_eq!(h.add(&a), Ok(1));
    assert_eq!(h.add(&b), Ok(2));
    assert_eq!(h.add(&c), Ok(3));
    assert!(
        h.add(&a)
            .expect_err("listed once")
            .contains("already in the registry")
    );

    // The crux: the threshold signature verifies through the unchanged path.
    let governance = h.governance_address();
    let registry = h.registry();
    assert_eq!(registry.version, 3);
    let verified = registry
        .verify(governance, 0)
        .expect("the threshold signature verifies");
    assert_eq!(verified.nodes().len(), 3);
    assert!(matches!(
        registry.verify(governance, 3),
        Err(VerifyError::StaleRegistry { .. })
    ));

    // A plain query, certified the way an HTTP gateway checks it.
    let response = h.get_json(REGISTRY);
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(response.upgrade(), None);
    let served: Registry = serde_json::from_slice(response.body()).expect("parses");
    assert_eq!(served, registry);
    let tampered = HttpResponse::builder()
        .with_status_code(StatusCode::OK)
        .with_headers(response.headers().to_vec())
        .with_body(b"{}".to_vec())
        .build();
    let checked = h
        .verify_http(REGISTRY, response)
        .expect("the gateway accepts it");
    assert_eq!(checked.verification_version, 2);
    assert!(
        h.verify_http(REGISTRY, tampered).is_err(),
        "a changed body must fail"
    );
    // Every other path gets a 404 that is certified too, or a gateway would
    // answer with a verification error instead.
    for other in ["/other", "/", "/registry.json/x"] {
        let missing = h.get_json(other);
        assert_eq!(missing.status_code(), StatusCode::NOT_FOUND, "{other}");
        h.verify_http(other, missing)
            .unwrap_or_else(|error| panic!("{other}: the 404 is certified: {error}"));
    }

    // Rotation: one call puts a new address in place of the old one.
    let new_a = key(50).address();
    assert!(
        h.pic
            .update_call(
                h.canister,
                stranger,
                "replace_node",
                Encode!(&a.address.to_string(), &new_a.to_string()).expect("encodes"),
            )
            .is_err(),
        "only governance may rotate"
    );
    assert_eq!(h.replace(a.address, new_a), Ok(4));
    let registry = h.registry();
    registry.verify(governance, 3).expect("v4 verifies");
    let response = h.get_json(REGISTRY);
    let served: Registry = serde_json::from_slice(response.body()).expect("parses");
    assert_eq!(served, registry, "each publish re-certifies");
    h.verify_http(REGISTRY, response).expect("v4 is certified");
    assert_eq!(registry.nodes.len(), 3);
    let listed_a = registry
        .nodes
        .iter()
        .find(|n| n.address == new_a)
        .expect("the new address is listed");
    assert_eq!(listed_a.endpoints, a.endpoints);
    assert!(registry.nodes.iter().all(|n| n.address != a.address));
    let retired = h.listing(a.address).expect("the old address is known");
    assert!(retired.removed_at.is_some());
    assert_eq!(h.listing(new_a).map(|l| l.removed_at), Some(None));

    // Removal never goes below min_nodes; the listing survives it.
    assert!(h.remove(c.address).expect_err("3 of 3").contains("below"));
    let version: Result<u64, String> = h.update(
        h.governance,
        "set_quorum",
        Encode!(&2_u16, &3_u16).expect("encodes"),
    );
    assert_eq!(version, Ok(5));
    assert_eq!(h.remove(c.address), Ok(6));
    let registry = h.registry();
    assert_eq!(registry.nodes.len(), 2);
    registry.verify(governance, 5).expect("v6 verifies");
    assert!(
        h.listing(c.address)
            .is_some_and(|listing| listing.removed_at.is_some())
    );

    // A retired address can never be listed again, not even by governance.
    for refused in [h.add(&a), h.replace(b.address, c.address)] {
        assert!(
            refused
                .expect_err("retired")
                .contains("already in the registry")
        );
    }

    // Publication is on demand: a quiet day signs nothing. Freshness comes from
    // the certificate, which the subnet renews with its state.
    let before = h.registry();
    h.pass_time(86_400);
    let after = h.registry();
    assert_eq!(after, before, "nothing re-signs on a timer");
    let response = h.get_json(REGISTRY);
    let now_ns = h.pic.get_time().as_nanos_since_unix_epoch();
    let body = h
        .sdk_check(REGISTRY, &response, now_ns)
        .expect("the unchanged document is certified as current");
    assert_eq!(
        serde_json::from_slice::<Registry>(&body).expect("parses"),
        after
    );
    let replayed_later = now_ns + 6 * 60 * 1_000_000_000;
    assert!(
        matches!(
            h.sdk_check(REGISTRY, &response, replayed_later),
            Err(FetchError::Uncertified(_))
        ),
        "a replayed response goes stale with its certificate"
    );

    // The certification tree is not in stable memory. `post_upgrade` rebuilds it.
    h.pic
        .upgrade_canister(
            h.canister,
            build_wasm(),
            Encode!().expect("encodes"),
            Some(h.governance),
        )
        .expect("upgrades");
    let response = h.get_json(REGISTRY);
    let served: Registry = serde_json::from_slice(response.body()).expect("parses");
    assert_eq!(served, after);
    h.verify_http(REGISTRY, response)
        .expect("certified after an upgrade");
}

#[test]
fn the_canister_publishes_a_certified_client_list() {
    let h = Harness::new(1);
    let empty = h.get_json(CLIENTS);
    assert_eq!(empty.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    h.verify_http(CLIENTS, empty)
        .expect("the empty state is certified at init");

    let client = key(0x42).address();
    let expires_at = h.now() + 86_400;
    let args = Encode!(&client.to_checksummed(), &expires_at).expect("encodes");
    let stranger = Principal::self_authenticating(b"stranger");
    assert!(
        h.pic
            .update_call(h.canister, stranger, "add_client", args.clone())
            .is_err(),
        "only governance may add a client"
    );
    let bad = Encode!(&"0x1234", &expires_at).expect("encodes");
    let refused: Result<u64, String> = h.update(h.governance, "add_client", bad);
    assert!(refused.expect_err("bad address").contains("address"));
    let version: Result<u64, String> = h.update(h.governance, "add_client", args);
    assert_eq!(version, Ok(1));

    let governance = h.governance_address();
    let response = h.get_json(CLIENTS);
    assert_eq!(response.status_code(), StatusCode::OK);
    let served: ClientList = serde_json::from_slice(response.body()).expect("parses");
    h.verify_http(CLIENTS, response).expect("certified");
    let verified = served.verify(governance, 0).expect("governance signed it");
    assert_eq!(verified.get(client).map(|c| c.expires_at), Some(expires_at));
    assert_eq!(verified.epoch_secs(), 60);
    // The other document stays certified in the same tree.
    h.verify_http(REGISTRY, h.get_json(REGISTRY))
        .expect("the registry path is still certified");

    let version: Result<u64, String> = h.update(
        h.governance,
        "set_client_expiry",
        Encode!(&client.to_string(), &(expires_at + 60)).expect("encodes"),
    );
    assert_eq!(version, Ok(2));
    let version: Result<u64, String> = h.update(
        h.governance,
        "remove_client",
        Encode!(&client.to_string()).expect("encodes"),
    );
    assert_eq!(version, Ok(3));
    assert!(
        h.add_client(client, expires_at)
            .expect_err("revoked for good")
            .contains("already in the registry")
    );
    let removed: ClientList = serde_json::from_slice(h.get_json(CLIENTS).body()).expect("parses");
    assert!(
        removed
            .verify(governance, 2)
            .expect("verifies")
            .clients()
            .is_empty()
    );

    // Nothing re-signs on a timer; governance can re-sign on demand.
    h.pass_time(3_600);
    let quiet: ClientList = serde_json::from_slice(h.get_json(CLIENTS).body()).expect("parses");
    assert_eq!(quiet, removed);
    let version: Result<u64, String> = h.update(
        h.governance,
        "republish_clients",
        Encode!().expect("encodes"),
    );
    assert_eq!(version, Ok(4));
    let beat: ClientList = serde_json::from_slice(h.get_json(CLIENTS).body()).expect("parses");
    assert_eq!(beat.clients, removed.clients);

    h.pic
        .upgrade_canister(
            h.canister,
            build_wasm(),
            Encode!().expect("encodes"),
            Some(h.governance),
        )
        .expect("upgrades");
    for path in [CLIENTS, REGISTRY] {
        h.verify_http(path, h.get_json(path))
            .expect("certified after an upgrade");
    }
    let after: ClientList = serde_json::from_slice(h.get_json(CLIENTS).body()).expect("parses");
    assert_eq!(after, beat);
}

/// A round works on a copy, so a signature that fails leaves no trace and
/// governance retries the same call.
#[test]
fn a_failed_signing_round_changes_nothing() {
    let h = Harness::with_key(1, "no_such_key");
    let a = node(1);
    let refused = h.add(&a).expect_err("the key does not exist");
    assert!(refused.contains("ecdsa_public_key"), "{refused}");
    let version: u64 = h.query("get_version", Encode!().expect("encodes"));
    assert_eq!(version, 0);
    assert_eq!(h.listing(a.address), None, "the node was not listed");
    assert!(
        h.add(&a).expect_err("still no key").contains("ecdsa"),
        "a retry runs the whole round again, not `already in the registry`"
    );
}

/// The SDK and the nodes fetch through a real HTTP gateway and check the
/// certificate themselves.
#[test]
fn the_sdk_checks_the_certificate_through_the_http_gateway() {
    let mut h = Harness::new(1);
    assert_eq!(h.add(&node(1)), Ok(1));
    assert_eq!(h.add_client(key(0x42).address(), h.now() + 86_400), Ok(1));
    let registry = h.registry();
    let certification = h.certification();
    let gateway = h.pic.make_live(None);
    let url = |path: &str| format!("{gateway}{}?canisterId={}", &path[1..], h.canister);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fetched = runtime
        .block_on(
            HttpRegistrySource::new(&url(REGISTRY), certification.clone())
                .expect("builds")
                .fetch(),
        )
        .expect("certified registry");
    assert_eq!(fetched, registry);
    let clients: ClientList = runtime
        .block_on(
            HttpDocumentSource::new(&url(CLIENTS), certification)
                .expect("builds")
                .fetch(),
        )
        .expect("certified client list");
    assert_eq!(clients.version, 1);
    let missing = runtime.block_on(
        HttpDocumentSource::new(&url("/other"), h.certification())
            .expect("builds")
            .fetch::<serde_json::Value>(),
    );
    assert!(
        matches!(&missing, Err(FetchError::Transport(error)) if error.contains("404")),
        "the gateway passes a certified 404 through: {missing:?}"
    );

    let root_key = hex::encode(h.pic.root_key().expect("root key"));
    for (label, wrong) in [
        (
            "another canister",
            Certification::new("aaaaa-aa", &root_key).expect("valid"),
        ),
        (
            "another network",
            Certification::mainnet(&h.canister.to_text()).expect("valid"),
        ),
    ] {
        let result = runtime.block_on(
            HttpRegistrySource::new(&url(REGISTRY), wrong)
                .expect("builds")
                .fetch(),
        );
        assert!(
            matches!(result, Err(FetchError::Uncertified(_))),
            "{label}: {result:?}"
        );
    }
}
