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
use oracle_wire::{NodeEntry, Registry, Signer, SigningKeyCert, VerifyError};
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde::de::DeserializeOwned;

const ROTATION_WINDOW: u64 = 600;
const HEARTBEAT: u64 = 86_400;
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

    fn get_registry_json(&self) -> HttpResponse<'static> {
        let request = HttpRequest::get("/registry.json?x=1").build();
        self.query("http_request", Encode!(&request).expect("encodes"))
    }

    /// The check an HTTP gateway runs on a query response.
    fn verify_http(
        &self,
        response: HttpResponse<'static>,
    ) -> Result<VerificationInfo, ResponseVerificationError> {
        let root_key = self.pic.root_key().expect("the NNS subnet has a root key");
        verify_request_response_pair(
            HttpRequest::get("/registry.json?x=1").build(),
            response,
            self.canister.as_slice(),
            u128::from(self.pic.get_time().as_nanos_since_unix_epoch()),
            MAX_CERT_AGE_NS,
            &root_key,
            2,
        )
    }

    fn submit(&self, op: &Operator) -> Result<(), String> {
        let json = serde_json::to_string(&op.entry(self.now())).expect("serialises");
        self.update(
            op.principal,
            "submit_entry",
            Encode!(&json).expect("encodes"),
        )
    }

    fn approve(&self, caller: Principal, node_id: &str) -> Result<u64, String> {
        self.update(caller, "approve_entry", Encode!(&node_id).expect("encodes"))
    }

    fn rotate(
        &self,
        caller: Principal,
        node_id: &str,
        cert: &SigningKeyCert,
    ) -> Result<u64, String> {
        let json = serde_json::to_string(cert).expect("serialises");
        self.update(
            caller,
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
    let empty = h.get_registry_json();
    assert_eq!(empty.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    h.verify_http(empty)
        .expect("the empty state is certified at init");
    let mut a = Operator::new(1, "oracle-a");
    let mut b = Operator::new(2, "oracle-b");
    let c = Operator::new(3, "oracle-c");

    // Submission is open to any principal; listing is not.
    for op in [&a, &b, &c] {
        h.submit(op).expect("submits");
    }
    let pending: String = h.query("get_pending", Encode!().expect("encodes"));
    assert_eq!(
        serde_json::from_str::<Vec<serde_json::Value>>(&pending)
            .expect("parses")
            .len(),
        3
    );
    assert!(
        h.approve(a.principal, "oracle-a")
            .expect_err("an operator is not governance")
            .contains("governance")
    );
    assert_eq!(h.approve(h.governance, "oracle-a"), Ok(1));
    assert_eq!(h.approve(h.governance, "oracle-b"), Ok(2));
    assert_eq!(h.approve(h.governance, "oracle-c"), Ok(3));

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
    let response = h.get_registry_json();
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(response.upgrade(), None);
    let served: Registry = serde_json::from_slice(response.body()).expect("parses");
    assert_eq!(served, registry);
    let tampered = HttpResponse::builder()
        .with_status_code(StatusCode::OK)
        .with_headers(response.headers().to_vec())
        .with_body(b"{}".to_vec())
        .build();
    let checked = h.verify_http(response).expect("the gateway accepts it");
    assert_eq!(checked.verification_version, 2);
    assert!(h.verify_http(tampered).is_err(), "a changed body must fail");
    let missing: HttpResponse = h.query(
        "http_request",
        Encode!(&HttpRequest::get("/other").build()).expect("encodes"),
    );
    assert_eq!(missing.status_code(), StatusCode::NOT_FOUND);

    // Rotation: atomic swap, one live key, history kept, retired_at set.
    let old_a = a.signing.address();
    let cert = a.rotate(50, h.now());
    assert!(
        h.rotate(b.principal, "oracle-a", &cert)
            .expect_err("only the node's operator may rotate")
            .contains("operator")
    );
    assert_eq!(h.rotate(a.principal, "oracle-a", &cert), Ok(4));
    let registry = h.registry();
    registry.verify(governance, 3).expect("v4 verifies");
    let response = h.get_registry_json();
    let served: Registry = serde_json::from_slice(response.body()).expect("parses");
    assert_eq!(served, registry, "each publish re-certifies");
    h.verify_http(response).expect("v4 is certified");
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
        h.rotate(b.principal, "oracle-b", &cert_b)
            .expect_err("inside the rotation window")
            .contains("rotation")
    );
    h.pass_time(ROTATION_WINDOW + 1);
    let cert_b = b.rotate(51, h.now());
    assert_eq!(h.rotate(b.principal, "oracle-b", &cert_b), Ok(5));

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

    // A retired address can never be listed again, by anyone.
    let mut revived = Operator::new(9, "oracle-z");
    revived.signing = Signer::from_secret_bytes([101; 32]).expect("valid key");
    assert!(
        h.submit(&revived)
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
    let response = h.get_registry_json();
    let served: Registry = serde_json::from_slice(response.body()).expect("parses");
    assert_eq!(served, after);
    h.verify_http(response).expect("certified after an upgrade");
}
