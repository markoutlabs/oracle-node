//! The canister end to end on PocketIC, with real threshold ECDSA.
//!
//! The assertion that matters most: the document the canister publishes
//! verifies with the unchanged `Registry::verify` against the governance
//! address the canister reports. Everything else in M5.5 rests on that.
//!
//! The canister wasm is built by `oracle_registry_canister::testing`, which
//! also says how the PocketIC server is found.

use candid::{Encode, Principal};
use ic_http_certification::StatusCode;
use ic_response_verification::types::VerificationInfo;
use ic_response_verification::{ResponseVerificationError, verify_request_response_pair};
use oracle_client::{
    Certification, FetchError, HttpDocumentSource, HttpRegistrySource, RegistrySource as _,
};
use oracle_registry_canister::testing::{Harness, WASM};
use oracle_registry_canister::{HttpRequest, HttpResponse};
use oracle_wire::{ClientList, NodeEntry, Registry, Signer, VerifyError};

const REGISTRY: &str = "/registry.json";
const CLIENTS: &str = "/clients.json";
const MAX_CERT_AGE_NS: u128 = 300 * 1_000_000_000;

/// The HTTP side: what a gateway, the SDK and the nodes check on a response.
trait Http {
    fn get_json(&self, path: &str) -> HttpResponse<'static>;
    fn verify_http(
        &self,
        path: &str,
        response: HttpResponse<'static>,
    ) -> Result<VerificationInfo, ResponseVerificationError>;
    fn sdk_check(
        &self,
        path: &str,
        response: &HttpResponse<'static>,
        now_ns: u64,
    ) -> Result<Vec<u8>, FetchError>;
}

impl Http for Harness {
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
    let h = Harness::new(3, "dfx_test_key", None);
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

    assert_eq!(h.add_node(&a), Ok(1));
    assert_eq!(h.add_node(&b), Ok(2));
    assert_eq!(h.add_node(&c), Ok(3));
    assert!(
        h.add_node(&a)
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
    assert_eq!(h.replace_node(a.address, new_a), Ok(4));
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
    assert!(
        h.remove_node(c.address)
            .expect_err("3 of 3")
            .contains("below")
    );
    let version: Result<u64, String> = h.update(
        h.governance,
        "set_quorum",
        Encode!(&2_u16, &3_u16).expect("encodes"),
    );
    assert_eq!(version, Ok(5));
    assert_eq!(h.remove_node(c.address), Ok(6));
    let registry = h.registry();
    assert_eq!(registry.nodes.len(), 2);
    registry.verify(governance, 5).expect("v6 verifies");
    assert!(
        h.listing(c.address)
            .is_some_and(|listing| listing.removed_at.is_some())
    );

    // A retired address can never be listed again, not even by governance.
    for refused in [h.add_node(&a), h.replace_node(b.address, c.address)] {
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
            WASM.clone(),
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
    let h = Harness::new(1, "dfx_test_key", None);
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
            WASM.clone(),
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
    let h = Harness::new(1, "no_such_key", None);
    let a = node(1);
    let refused = h.add_node(&a).expect_err("the key does not exist");
    assert!(refused.contains("ecdsa_public_key"), "{refused}");
    let version: u64 = h.query("get_version", Encode!().expect("encodes"));
    assert_eq!(version, 0);
    assert_eq!(h.listing(a.address), None, "the node was not listed");
    assert!(
        h.add_node(&a).expect_err("still no key").contains("ecdsa"),
        "a retry runs the whole round again, not `already in the registry`"
    );
}

/// The SDK and the nodes fetch through a real HTTP gateway and check the
/// certificate themselves.
#[test]
fn the_sdk_checks_the_certificate_through_the_http_gateway() {
    let mut h = Harness::new(1, "dfx_test_key", None);
    assert_eq!(h.add_node(&node(1)), Ok(1));
    assert_eq!(h.add_client(key(0x42).address(), h.now() + 86_400), Ok(1));
    let registry = h.registry();
    let certification = h.certification();
    h.make_live();
    let url = |path: &str| h.url(path);

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

    let root_key = h.root_key();
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
