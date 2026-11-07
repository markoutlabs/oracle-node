//! The canister end to end on PocketIC, with real threshold ECDSA.
//!
//! The assertion that matters most: the document the canister publishes
//! verifies with the unchanged `Registry::verify` against the governance
//! address the canister reports. Everything else in M5.5 rests on that.
//!
//! `oracle_registry_canister::testing` supplies the canister wasm and says how
//! the PocketIC server is found.

use candid::Encode;
use ic_http_certification::StatusCode;
use ic_response_verification::types::VerificationInfo;
use ic_response_verification::{ResponseVerificationError, verify_request_response_pair};
use oracle_client::{
    Certification, FetchError, HttpDocumentSource, HttpRegistrySource, RegistrySource as _,
};
use oracle_registry_canister::testing::{Harness, Scenario, WASM, outsider};
use oracle_registry_canister::{HttpRequest, HttpResponse, InitArgs};
use oracle_types::NANOS_PER_SEC;
use oracle_wire::{ClientList, FeedSet, Registry, Signer, VerifyError};
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

const REGISTRY: &str = "/registry.json";
const CLIENTS: &str = "/clients.json";
const FEEDS: &str = "/feeds.json";
const DOCUMENTS: [&str; 3] = [REGISTRY, CLIENTS, FEEDS];
/// The certificate age that an HTTP gateway accepts.
const MAX_CERT_AGE_NS: u128 = 300 * 1_000_000_000;
/// Response verification v2, which certifies the request path too.
const CERTIFICATE_VERSION: u8 = 2;
/// One minute past the 5 min certificate age that the SDK accepts.
const REPLAY_DELAY_NS: u64 = 6 * 60 * NANOS_PER_SEC;
const DAY_SECS: u64 = 86_400;
/// The broadcast-key epoch until governance sets another.
const DEFAULT_EPOCH_SECS: u64 = 60;
/// The key that a rotation moves a node to.
const ROTATED_SEED: u8 = 50;
const CLIENT_SEED: u8 = 0x42;
/// The push heartbeat of the test feed set.
const HEARTBEAT_SECS: u64 = 30;
/// Below two heartbeats, so a quiet feed would fall out of the price window.
const SHORT_WINDOW_SECS: u64 = 40;
/// A price window that two heartbeats of the test feed set fit in.
const NARROW_WINDOW_SECS: u64 = 100;
/// More than half of the narrow price window.
const SLOW_HEARTBEAT_SECS: u64 = 60;

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
    /// The document at `path`, served and certified the way a gateway checks it.
    fn certified<T: DeserializeOwned>(&self, path: &str) -> T;
}

impl Http for Harness {
    fn get_json(&self, path: &str) -> HttpResponse<'static> {
        let request = HttpRequest::get(format!("{path}?x=1")).build();
        self.query("http_request", Encode!(&request).expect("encodes"))
    }

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
            u128::from(self.now_ns()),
            MAX_CERT_AGE_NS,
            &root_key,
            CERTIFICATE_VERSION,
        )
    }

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

    fn certified<T: DeserializeOwned>(&self, path: &str) -> T {
        let response = self.get_json(path);
        assert_eq!(response.status_code(), StatusCode::OK, "{path}");
        let document = serde_json::from_slice(response.body()).expect("parses");
        self.verify_http(path, response)
            .unwrap_or_else(|error| panic!("{path} is certified: {error}"));
        document
    }
}

fn key(seed: u8) -> Signer {
    Signer::from_secret(&Zeroizing::new([seed; 32])).expect("valid key")
}

/// Two feeds: the peg, and a feed priced through it, with a decimal in a
/// non-canonical spelling.
fn feed_content(push_heartbeat: u64, with_usdc: bool) -> String {
    let mut feeds = vec![serde_json::json!({
        "symbol": "CRYPTO.USDT/USD",
        "min_sources": 1,
        "sources": [
            { "venue": "coinbase", "market": "spot", "symbol": "USDT-USD" },
            { "venue": "kraken", "market": "spot", "symbol": "USDT/USD" }
        ]
    })];
    if with_usdc {
        feeds.push(serde_json::json!({
            "symbol": "CRYPTO.USDC/USD",
            "peg": "CRYPTO.USDT/USD",
            "deviation_bps": "0.10",
            "sources": [
                { "venue": "kraken", "market": "spot", "symbol": "USDC/USD" },
                { "venue": "binance", "market": "spot", "symbol": "USDCUSDT", "converted": true }
            ]
        }));
    }
    serde_json::json!({
        "min_node_version": "0.1.0",
        "push": { "heartbeat_secs": push_heartbeat, "deviation_bps": 10, "min_interval_secs": 5 },
        "feeds": feeds,
    })
    .to_string()
}

/// Every other path gets a 404 that is certified too, or a gateway would
/// answer with a verification error instead.
fn assert_other_paths_get_a_certified_404(h: &Harness) {
    for other in ["/other", "/", "/registry.json/x"] {
        let missing = h.get_json(other);
        assert_eq!(missing.status_code(), StatusCode::NOT_FOUND, "{other}");
        h.verify_http(other, missing)
            .unwrap_or_else(|error| panic!("{other}: the 404 is certified: {error}"));
    }
}

fn assert_every_answer_is_certified(h: &Harness) {
    for path in DOCUMENTS {
        let empty = h.get_json(path);
        assert_eq!(
            empty.status_code(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{path}"
        );
        h.verify_http(path, empty)
            .unwrap_or_else(|error| panic!("{path}: the empty state is certified: {error}"));
    }
    assert_other_paths_get_a_certified_404(h);
}

/// A gateway answers an uncertified response with a verification error, so
/// every answer is certified at init and again after an upgrade.
#[test]
fn every_path_is_certified_before_the_first_publish() {
    let s = Scenario::builder().build();
    assert_every_answer_is_certified(&s);
    // Governance fetches the key first, as `make governance` does. Its rounds
    // also lift PocketIC's limit on an upgrade right after the install.
    let _ = s.refresh_governance_key();
    s.upgrade();
    assert_every_answer_is_certified(&s);
}

/// Ingress from anyone but governance is dropped before it executes.
#[test]
fn only_governance_calls_the_update_methods() {
    let s = Scenario::builder().nodes(1).build();
    let listed = s.node(0).address().to_string();
    let rotated = key(ROTATED_SEED).address().to_string();
    let client = key(CLIENT_SEED).address().to_checksummed();
    for (method, args) in [
        ("add_node", Harness::add_args(&s.stranger().entry())),
        ("refresh_governance_key", Encode!().expect("encodes")),
        ("replace_node", Encode!(&listed, &rotated).expect("encodes")),
        (
            "add_client",
            Encode!(&client, &(s.now() + DAY_SECS)).expect("encodes"),
        ),
        (
            "set_feed_set",
            Encode!(&feed_content(HEARTBEAT_SECS, true)).expect("encodes"),
        ),
    ] {
        assert!(
            s.update_as(outsider(), method, args).is_err(),
            "{method} must refuse a non-controller"
        );
    }
    assert_eq!(s.version(), 1, "nothing was published");
}

/// The crux: the threshold signature verifies through the unchanged path.
#[test]
fn the_published_registry_verifies_with_oracle_wire() {
    let s = Scenario::builder().nodes(3).min_nodes(3).build();
    let governance = s.governance_address();
    let registry = s.registry();
    assert_eq!(registry.version, 3);
    let verified = registry
        .verify(governance, 0)
        .expect("the threshold signature verifies");
    assert_eq!(verified.nodes().len(), 3);
    assert!(matches!(
        registry.verify(governance, 3),
        Err(VerifyError::StaleRegistry { .. })
    ));
    assert!(
        s.add_node(&s.node(0).entry())
            .expect_err("listed once")
            .contains("already in the registry")
    );
}

/// A plain query, certified the way an HTTP gateway checks it.
#[test]
fn a_gateway_accepts_the_registry_and_refuses_a_changed_body() {
    let s = Scenario::builder().nodes(1).build();
    let response = s.get_json(REGISTRY);
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(response.upgrade(), None);
    let served: Registry = serde_json::from_slice(response.body()).expect("parses");
    assert_eq!(served, s.registry());
    let tampered = HttpResponse::builder()
        .with_status_code(StatusCode::OK)
        .with_headers(response.headers().to_vec())
        .with_body(b"{}".to_vec())
        .build();
    let checked = s
        .verify_http(REGISTRY, response)
        .expect("the gateway accepts it");
    assert_eq!(checked.verification_version, u16::from(CERTIFICATE_VERSION));
    assert!(
        s.verify_http(REGISTRY, tampered).is_err(),
        "a changed body must fail"
    );
    assert_other_paths_get_a_certified_404(&s);
}

/// One call puts a new address in place of the old one, and the publish
/// certifies the new version. The old address is retired for good.
#[test]
fn a_rotation_puts_the_new_address_in_place_of_the_old_one() {
    let s = Scenario::builder().nodes(3).min_nodes(3).build();
    let old = s.node(0).entry();
    let new = key(ROTATED_SEED).address();
    assert_eq!(s.replace_node(old.address, new), Ok(4));

    let registry = s.registry();
    registry
        .verify(s.governance_address(), 3)
        .expect("v4 verifies");
    assert_eq!(s.certified::<Registry>(REGISTRY), registry);
    assert_eq!(registry.nodes.len(), 3);
    let listed = registry
        .nodes
        .iter()
        .find(|node| node.address == new)
        .expect("the new address is listed");
    assert_eq!(listed.endpoints, old.endpoints);
    assert!(
        registry
            .nodes
            .iter()
            .all(|node| node.address != old.address)
    );
    let retired = s.listing(old.address).expect("the old address is known");
    assert!(retired.removed_at.is_some());
    assert_eq!(s.listing(new).map(|listing| listing.removed_at), Some(None));
    assert!(
        s.add_node(&old)
            .expect_err("retired, even for governance")
            .contains("already in the registry")
    );
}

/// The canister prices with `recommended`, so a removal never goes below it.
/// The listing survives the removal, and the address is retired for good.
#[test]
fn a_removal_never_goes_below_the_price_quorum() {
    let s = Scenario::builder().nodes(3).min_nodes(3).build();
    let removed = s.node(2).address();
    assert!(
        s.remove_node(removed)
            .expect_err("3 of 3")
            .contains("below")
    );
    assert_eq!(s.set_quorum(2, 3), Ok(4));
    assert!(
        s.remove_node(removed)
            .expect_err("min_nodes alone does not decide")
            .contains("set_quorum")
    );
    assert_eq!(s.set_quorum(2, 2), Ok(5));
    assert_eq!(s.remove_node(removed), Ok(6));
    let registry = s.registry();
    assert_eq!(registry.nodes.len(), 2);
    registry
        .verify(s.governance_address(), 5)
        .expect("v6 verifies");
    assert!(
        s.listing(removed)
            .is_some_and(|listing| listing.removed_at.is_some())
    );
    assert!(
        s.replace_node(s.node(0).address(), removed)
            .expect_err("retired, even for governance")
            .contains("already in the registry")
    );
    assert!(
        s.set_quorum(2, 3)
            .expect_err("above the two listed nodes")
            .contains("halts every priced feed")
    );
}

/// The certification tree is not in stable memory. `post_upgrade` rebuilds it.
#[test]
fn an_upgrade_keeps_every_document_and_its_certificate() {
    let s = Scenario::builder().nodes(1).build();
    s.add_client(key(CLIENT_SEED).address(), s.now() + DAY_SECS)
        .expect("listed");
    s.set_feed_set(&feed_content(HEARTBEAT_SECS, true))
        .expect("published");
    let registry: Registry = s.certified(REGISTRY);
    let clients: ClientList = s.certified(CLIENTS);
    let feeds: FeedSet = s.certified(FEEDS);

    s.upgrade();
    assert_eq!(s.certified::<Registry>(REGISTRY), registry);
    assert_eq!(s.certified::<ClientList>(CLIENTS), clients);
    assert_eq!(s.certified::<FeedSet>(FEEDS), feeds);
}

#[test]
fn the_canister_publishes_a_certified_client_list() {
    let s = Scenario::builder().build();
    let client = key(CLIENT_SEED).address();
    let expires_at = s.now() + DAY_SECS;
    let bad = Encode!(&"0x1234", &expires_at).expect("encodes");
    let refused: Result<u64, String> = s.update(s.governance, "add_client", bad);
    assert!(refused.expect_err("bad address").contains("address"));
    assert_eq!(s.add_client(client, expires_at), Ok(1));

    let served: ClientList = s.certified(CLIENTS);
    let verified = served
        .verify(s.governance_address(), 0)
        .expect("governance signed it");
    assert_eq!(verified.get(client).map(|c| c.expires_at), Some(expires_at));
    assert_eq!(verified.epoch_secs(), DEFAULT_EPOCH_SECS);
    s.verify_http(REGISTRY, s.get_json(REGISTRY))
        .expect("the other document stays certified in the same tree");
}

/// A removed client's address is retired, as a node's is.
#[test]
fn a_removed_client_is_revoked_for_good() {
    let s = Scenario::builder().build();
    let client = key(CLIENT_SEED).address();
    let expires_at = s.now() + DAY_SECS;
    assert_eq!(s.add_client(client, expires_at), Ok(1));
    // Lowercase, as `Address` displays: the canister takes either case.
    let lowercase = client.to_string();
    let moved: Result<u64, String> = s.update(
        s.governance,
        "set_client_expiry",
        Encode!(&lowercase, &(expires_at + 60)).expect("encodes"),
    );
    assert_eq!(moved, Ok(2));
    let removed: Result<u64, String> = s.update(
        s.governance,
        "remove_client",
        Encode!(&lowercase).expect("encodes"),
    );
    assert_eq!(removed, Ok(3));

    assert!(
        s.add_client(client, expires_at)
            .expect_err("revoked for good")
            .contains("already in the registry")
    );
    let list: ClientList = s.certified(CLIENTS);
    assert!(
        list.verify(s.governance_address(), 2)
            .expect("verifies")
            .clients()
            .is_empty()
    );
}

/// Publication is on demand: a quiet day signs nothing, and governance
/// re-signs on request. Freshness comes from the certificate, which the subnet
/// renews with its state.
#[test]
fn nothing_re_signs_on_a_timer() {
    let s = Scenario::builder().nodes(1).build();
    assert_eq!(
        s.add_client(key(CLIENT_SEED).address(), s.now() + DAY_SECS),
        Ok(1)
    );
    assert_eq!(s.set_feed_set(&feed_content(HEARTBEAT_SECS, true)), Ok(1));
    let registry = s.registry();
    let clients: ClientList = s.certified(CLIENTS);
    let feeds: FeedSet = s.certified(FEEDS);

    s.pass_time(DAY_SECS);
    assert_eq!(s.registry(), registry);
    assert_eq!(s.certified::<ClientList>(CLIENTS), clients);
    assert_eq!(s.certified::<FeedSet>(FEEDS), feeds);

    let response = s.get_json(REGISTRY);
    let now_ns = s.now_ns();
    let body = s
        .sdk_check(REGISTRY, &response, now_ns)
        .expect("the unchanged document is certified as current");
    assert_eq!(
        serde_json::from_slice::<Registry>(&body).expect("parses"),
        registry
    );
    assert!(
        matches!(
            s.sdk_check(REGISTRY, &response, now_ns + REPLAY_DELAY_NS),
            Err(FetchError::Uncertified(_))
        ),
        "a replayed response goes stale with its certificate"
    );

    assert_eq!(s.republish_clients(), Ok(2));
    assert_eq!(s.certified::<ClientList>(CLIENTS).clients, clients.clients);
    assert_eq!(s.republish_feeds(), Ok(2));
    let again: FeedSet = s.certified(FEEDS);
    assert_eq!(again.feeds, feeds.feeds);
    again
        .verify(s.governance_address(), 1)
        .expect("the next version verifies");
}

#[test]
fn the_canister_publishes_a_certified_feed_set() {
    let s = Scenario::builder().build();
    let content = feed_content(HEARTBEAT_SECS, true);
    assert!(
        s.set_feed_set("{")
            .expect_err("not JSON")
            .contains("not valid JSON")
    );
    let unpegged = content.replace("\"peg\":\"CRYPTO.USDT/USD\",", "");
    assert_ne!(unpegged, content, "the peg is gone");
    assert!(
        s.set_feed_set(&unpegged)
            .expect_err("a converted source without a peg")
            .contains("invalid feed set")
    );
    assert_eq!(s.set_feed_set(&content), Ok(1));

    let served: FeedSet = s.certified(FEEDS);
    let verified = served
        .verify(s.governance_address(), 0)
        .expect("governance signed it");
    assert_eq!(verified.feeds().len(), 2);
    assert_eq!(
        verified
            .feeds()
            .get(1)
            .and_then(|feed| feed.deviation_bps.as_deref()),
        Some("0.1"),
        "stored and signed in canonical form"
    );
    assert_eq!(s.feed_set(), Some(served));
    for path in [REGISTRY, CLIENTS] {
        s.verify_http(path, s.get_json(path))
            .expect("the other documents stay certified in the same tree");
    }
}

#[test]
fn the_priced_feeds_and_the_window_must_fit_the_feed_set() {
    let s = Scenario::builder().build();
    assert_eq!(s.set_feed_set(&feed_content(HEARTBEAT_SECS, true)), Ok(1));
    assert!(
        s.set_feeds(&["CRYPTO.BTC/USD"])
            .expect_err("not in the set")
            .contains("not in the feed set")
    );
    s.set_feeds(&["CRYPTO.USDC/USD"]).expect("in the set");
    assert!(
        s.set_feed_set(&feed_content(HEARTBEAT_SECS, false))
            .expect_err("drops a priced feed")
            .contains("priced on-chain")
    );
    assert!(
        s.set_price_window(SHORT_WINDOW_SECS)
            .expect_err("below twice the heartbeat")
            .contains("drops quiet feeds")
    );
    assert_eq!(s.set_price_window(NARROW_WINDOW_SECS), Ok(()));
    assert!(
        s.set_feed_set(&feed_content(SLOW_HEARTBEAT_SECS, true))
            .expect_err("more than half the window")
            .contains("half the price window")
    );
}

/// The test feed set without its push pace.
fn set_unpaced_feed_set(s: &Harness) -> Result<u64, String> {
    let mut content: serde_json::Value =
        serde_json::from_str(&feed_content(HEARTBEAT_SECS, true)).expect("JSON");
    content
        .as_object_mut()
        .expect("an object")
        .remove("push")
        .expect("the pace");
    s.set_feed_set(&content.to_string())
}

/// SPEC §3.7 P11: before the first feed set no pace exists, so the canister
/// prices no feed, from `set_feeds` or from the install arguments.
#[test]
fn the_canister_prices_no_feed_before_a_feed_set_with_a_pace() {
    let s = Scenario::builder().build();
    assert!(
        s.set_feeds(&["CRYPTO.USDC/USD"])
            .expect_err("no feed set yet")
            .contains("push")
    );
    assert_eq!(s.set_feeds(&[]), Ok(()), "pricing nothing needs no pace");
    let priced = Encode!(&InitArgs {
        key_name: "dfx_test_key".to_owned(),
        min_nodes: 1,
        recommended: 1,
        epoch_secs: None,
        feeds: Some(vec!["CRYPTO.BTC/USD".to_owned()]),
    })
    .expect("encodes");
    let refused = s
        .pic
        .reinstall_canister(s.canister, WASM.clone(), priced, Some(s.governance))
        .expect_err("an install that prices feeds without a feed set");
    assert!(refused.reject_message.contains("push"), "{refused:?}");
}

/// SPEC §3.7 P11: without a pace in the feed set, each node pushes at its own
/// pace, and the canister pays for each push.
#[test]
fn a_feed_set_without_a_pace_is_refused_while_the_canister_prices_feeds() {
    let s = Scenario::builder().build();
    assert_eq!(set_unpaced_feed_set(&s), Ok(1), "nothing is priced yet");
    assert!(
        s.set_feeds(&["CRYPTO.USDC/USD"])
            .expect_err("the set has no pace")
            .contains("push")
    );
    assert_eq!(s.set_feed_set(&feed_content(HEARTBEAT_SECS, true)), Ok(2));
    s.set_feeds(&["CRYPTO.USDC/USD"])
        .expect("the set has a pace");
    assert!(
        set_unpaced_feed_set(&s)
            .expect_err("feeds are priced")
            .contains("PUSH")
    );
}

/// While a feed set is being signed, `set_feeds` and `set_price_window` would
/// check against the set that the round replaces, so they wait for it.
#[test]
fn the_priced_feeds_and_the_window_wait_for_a_signing_round() {
    let s = Scenario::builder().build();
    let content = feed_content(HEARTBEAT_SECS, true);
    let round = s
        .pic
        .submit_call(
            s.canister,
            s.governance,
            "set_feed_set",
            Encode!(&content).expect("encodes"),
        )
        .expect("submits");
    // One round starts it; the threshold signature takes several more.
    s.pic.tick();
    let during = s.set_feeds(&["CRYPTO.USDC/USD"]);
    assert!(
        during
            .as_ref()
            .is_err_and(|error| error.contains("in flight")),
        "{during:?}"
    );
    let window = s.set_price_window(20);
    assert!(
        window
            .as_ref()
            .is_err_and(|error| error.contains("in flight")),
        "{window:?}"
    );
    let reply = s.pic.await_call(round).expect("the round ends");
    let version: Result<u64, String> = candid::decode_one(&reply).expect("decodes");
    assert_eq!(version, Ok(1));
    s.set_feeds(&["CRYPTO.USDC/USD"]).expect("after the round");
}

/// A round works on a copy, so a signature that fails leaves no trace and
/// governance retries the same call.
#[test]
fn a_failed_signing_round_changes_nothing() {
    let s = Scenario::builder().key_name("no_such_key").build();
    let node = s.stranger().entry();
    let refused = s.add_node(&node).expect_err("the key does not exist");
    assert!(refused.contains("ecdsa_public_key"), "{refused}");
    assert_eq!(s.version(), 0);
    assert_eq!(s.listing(node.address), None, "the node was not listed");
    assert!(
        s.add_node(&node)
            .expect_err("still no key")
            .contains("ecdsa"),
        "a retry runs the whole round again, not `already in the registry`"
    );
}

/// The SDK and the nodes fetch through a real HTTP gateway and check the
/// certificate themselves.
#[test]
fn the_sdk_checks_the_certificate_through_the_http_gateway() {
    let mut s = Scenario::builder().nodes(1).build();
    assert_eq!(
        s.add_client(key(CLIENT_SEED).address(), s.now() + DAY_SECS),
        Ok(1)
    );
    let registry = s.registry();
    let certification = s.certification();
    s.make_live();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fetch_registry = |certification: Certification| {
        runtime.block_on(
            HttpRegistrySource::new(&s.url(REGISTRY), certification)
                .expect("builds")
                .fetch(),
        )
    };
    let fetch = |path: &str| {
        runtime.block_on(
            HttpDocumentSource::new(&s.url(path), s.certification())
                .expect("builds")
                .fetch::<serde_json::Value>(),
        )
    };

    assert_eq!(
        fetch_registry(certification).expect("certified registry"),
        registry
    );
    let clients: ClientList =
        serde_json::from_value(fetch(CLIENTS).expect("certified client list"))
            .expect("a client list");
    assert_eq!(clients.version, 1);
    let missing = fetch("/other");
    assert!(
        matches!(&missing, Err(FetchError::Transport(error)) if error.contains("404")),
        "the gateway passes a certified 404 through: {missing:?}"
    );

    let root_key = s.root_key();
    for (label, wrong) in [
        (
            "another canister",
            Certification::new("aaaaa-aa", &root_key).expect("valid"),
        ),
        (
            "another network",
            Certification::mainnet(&s.canister.to_text()).expect("valid"),
        ),
    ] {
        let result = fetch_registry(wrong);
        assert!(
            matches!(result, Err(FetchError::Uncertified(_))),
            "{label}: {result:?}"
        );
    }
}
