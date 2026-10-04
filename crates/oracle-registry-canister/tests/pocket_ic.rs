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
use oracle_registry_canister::{HttpRequest, HttpResponse, InitArgs};
use oracle_wire::{ClientList, NodeEntry, Registry, Signer, SigningKeyCert, VerifyError};
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde::de::DeserializeOwned;

const ROTATION_WINDOW: u64 = 600;
const HEARTBEAT: u64 = 86_400;
const CLIENTS_HEARTBEAT: u64 = 3_600;
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
            key_name: "dfx_test_key".to_owned(),
            rotation_window_secs: ROTATION_WINDOW,
            heartbeat_secs: HEARTBEAT,
            min_nodes,
            recommended: 3,
            epoch_secs: None,
            clients_heartbeat_secs: Some(CLIENTS_HEARTBEAT),
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

    fn add_args(&self, op: &Operator) -> Vec<u8> {
        let json = serde_json::to_string(&op.entry(self.now())).expect("serialises");
        Encode!(&json).expect("encodes")
    }

    fn add(&self, op: &Operator) -> Result<u64, String> {
        self.update(self.governance, "add_node", self.add_args(op))
    }

    fn rotate(&self, node_id: &str, cert: &SigningKeyCert) -> Result<u64, String> {
        let json = serde_json::to_string(cert).expect("serialises");
        self.update(
            self.governance,
            "rotate_key",
            Encode!(&node_id, &json).expect("encodes"),
        )
    }

    fn remove(&self, node_id: &str) -> Result<u64, String> {
        self.update(
            self.governance,
            "remove_node",
            Encode!(&node_id).expect("encodes"),
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

    fn history(&self, node_id: &str) -> Vec<serde_json::Value> {
        let json: Option<String> =
            self.query("get_key_history", Encode!(&node_id).expect("encodes"));
        serde_json::from_str(&json.expect("known node")).expect("parses")
    }

    fn pass_time(&self, secs: u64) {
        self.pic.advance_time(Duration::from_secs(secs));
        for _ in 0..3 {
            self.pic.tick();
        }
    }
}

struct Operator {
    identity: Signer,
    signing: Signer,
    node_id: String,
}

impl Operator {
    fn new(seed: u8, node_id: &str) -> Self {
        Self {
            identity: Signer::from_secret_bytes([seed; 32]).expect("valid key"),
            signing: Signer::from_secret_bytes([seed.wrapping_add(100); 32]).expect("valid key"),
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

#[test]
fn the_canister_publishes_a_registry_that_verifies_with_oracle_wire() {
    let h = Harness::new(3);
    let empty = h.get_json(REGISTRY);
    assert_eq!(empty.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    h.verify_http(REGISTRY, empty)
        .expect("the empty state is certified at init");
    let mut a = Operator::new(1, "oracle-a");
    let mut b = Operator::new(2, "oracle-b");
    let c = Operator::new(3, "oracle-c");

    // Ingress from anyone but governance is dropped before it executes.
    let stranger = Principal::self_authenticating(b"stranger");
    for (method, args) in [
        ("add_node", h.add_args(&a)),
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
            .contains("already listed")
    );

    // The crux: the threshold signature verifies through the unchanged path.
    let governance = h.governance_address();
    let registry = h.registry();
    assert_eq!(registry.version, 3);
    let verified = registry
        .verify(governance, 0)
        .expect("the threshold signature verifies");
    assert_eq!(verified.nodes().len(), 3);
    assert!(verified.nodes().iter().all(|n| n.signing_keys.len() == 1));
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
    let missing: HttpResponse = h.query(
        "http_request",
        Encode!(&HttpRequest::get("/other").build()).expect("encodes"),
    );
    assert_eq!(missing.status_code(), StatusCode::NOT_FOUND);

    // Rotation: atomic swap, one live key, history kept, retired_at set.
    let old_a = a.signing.address();
    let cert = a.rotate(50, h.now());
    assert!(
        h.pic
            .update_call(
                h.canister,
                stranger,
                "rotate_key",
                Encode!(
                    &"oracle-a",
                    &serde_json::to_string(&cert).expect("serialises")
                )
                .expect("encodes"),
            )
            .is_err(),
        "only governance may rotate"
    );
    assert_eq!(h.rotate("oracle-a", &cert), Ok(4));
    let registry = h.registry();
    registry.verify(governance, 3).expect("v4 verifies");
    let response = h.get_json(REGISTRY);
    let served: Registry = serde_json::from_slice(response.body()).expect("parses");
    assert_eq!(served, registry, "each publish re-certifies");
    h.verify_http(REGISTRY, response).expect("v4 is certified");
    let listed_a = registry
        .nodes
        .iter()
        .find(|n| n.node_id == "oracle-a")
        .expect("listed");
    assert_eq!(listed_a.signing_keys.len(), 1);
    assert_eq!(
        listed_a.signing_keys.first().map(|c| c.address),
        Some(cert.address)
    );
    let history = h.history("oracle-a");
    assert_eq!(history.len(), 2);
    let gen1 = history.first().expect("generation 1");
    let gen2 = history.get(1).expect("generation 2");
    assert_eq!(
        gen1.pointer("/cert/address").and_then(|v| v.as_str()),
        Some(old_a.to_string().as_str())
    );
    assert!(gen1["retired_at"].is_u64());
    assert!(gen2["retired_at"].is_null());

    // Rotations are serialised fleet-wide.
    let cert_b = b.rotate(51, h.now());
    assert!(
        h.rotate("oracle-b", &cert_b)
            .expect_err("inside the rotation window")
            .contains("rotation")
    );
    h.pass_time(ROTATION_WINDOW + 1);
    let cert_b = b.rotate(51, h.now());
    assert_eq!(h.rotate("oracle-b", &cert_b), Ok(5));

    // Removal never goes below min_nodes; history survives it.
    assert!(h.remove("oracle-c").expect_err("3 of 3").contains("below"));
    let version: Result<u64, String> = h.update(
        h.governance,
        "set_quorum",
        Encode!(&2_u16, &3_u16).expect("encodes"),
    );
    assert_eq!(version, Ok(6));
    assert_eq!(h.remove("oracle-c"), Ok(7));
    let registry = h.registry();
    assert_eq!(registry.nodes.len(), 2);
    registry.verify(governance, 6).expect("v7 verifies");
    let removed = h.history("oracle-c");
    assert!(removed.first().expect("generation 1")["retired_at"].is_u64());

    // A retired address can never be listed again, not even by governance.
    let mut revived = Operator::new(9, "oracle-z");
    revived.signing = Signer::from_secret_bytes([101; 32]).expect("valid key");
    assert!(
        h.add(&revived)
            .expect_err("old_a is known")
            .contains("already known")
    );

    // The heartbeat re-signs even with nothing changed, so a withheld document
    // is detectable by age.
    let before = h.registry();
    h.pass_time(HEARTBEAT + 5);
    let after = h.registry();
    assert!(after.version > before.version, "heartbeat published");
    assert!(after.effective_from > before.effective_from);
    assert_eq!(after.nodes, before.nodes);
    after
        .verify(governance, before.version)
        .expect("heartbeat version verifies");

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

    let client = Signer::from_secret_bytes([0x42; 32]).expect("valid key");
    let pubkey = client.public_key().to_string();
    let expires_at = h.now() + 86_400;
    let args = Encode!(&"c-1", &pubkey, &expires_at).expect("encodes");
    let stranger = Principal::self_authenticating(b"stranger");
    assert!(
        h.pic
            .update_call(h.canister, stranger, "add_client", args.clone())
            .is_err(),
        "only governance may add a client"
    );
    let bad = Encode!(&"c-1", &"0x1234", &expires_at).expect("encodes");
    let refused: Result<u64, String> = h.update(h.governance, "add_client", bad);
    assert!(refused.expect_err("bad key").contains("pubkey"));
    let version: Result<u64, String> = h.update(h.governance, "add_client", args);
    assert_eq!(version, Ok(1));

    let governance = h.governance_address();
    let response = h.get_json(CLIENTS);
    assert_eq!(response.status_code(), StatusCode::OK);
    let served: ClientList = serde_json::from_slice(response.body()).expect("parses");
    h.verify_http(CLIENTS, response).expect("certified");
    let verified = served.verify(governance, 0).expect("governance signed it");
    assert_eq!(verified.get("c-1").map(|c| c.expires_at), Some(expires_at));
    assert_eq!(verified.epoch_secs(), 60);
    // The other document stays certified in the same tree.
    h.verify_http(REGISTRY, h.get_json(REGISTRY))
        .expect("the registry path is still certified");

    let version: Result<u64, String> = h.update(
        h.governance,
        "set_client_expiry",
        Encode!(&"c-1", &(expires_at + 60)).expect("encodes"),
    );
    assert_eq!(version, Ok(2));
    let version: Result<u64, String> = h.update(
        h.governance,
        "remove_client",
        Encode!(&"c-1").expect("encodes"),
    );
    assert_eq!(version, Ok(3));
    let removed: ClientList = serde_json::from_slice(h.get_json(CLIENTS).body()).expect("parses");
    assert!(
        removed
            .verify(governance, 2)
            .expect("verifies")
            .clients()
            .is_empty()
    );

    // The hourly heartbeat re-signs the list with nothing changed. It signs the
    // registry first, so allow a few more rounds than one signature needs.
    h.pass_time(CLIENTS_HEARTBEAT + 5);
    let mut beat = removed.clone();
    for _ in 0..30 {
        beat = serde_json::from_slice(h.get_json(CLIENTS).body()).expect("parses");
        if beat.version > 3 {
            break;
        }
        h.pic.tick();
    }
    assert!(beat.version > 3, "heartbeat published");
    assert!(beat.effective_from > removed.effective_from);

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
