//! M5.5: five nodes, a quorum of three, and a key rotation (SPEC §3.5).
//!
//! A rotation is governance's `replace_node`: the registry lists the node's
//! new address in place of the old one. The consumer learns about it from the
//! first frame it cannot verify, fetches the registry once, and carries on.
//! The ways that can go wrong, each a test here:
//!
//! - The consumer never learns about the new key, or fetches on every unknown
//!   frame and becomes a load generator against the registry.
//! - The retired key keeps verifying, or triggers fetches forever.
//! - The old and the new address both count toward the quorum.
//! - A de-listed node keeps counting until its last update ages out.
//! - A registry the source stops confirming is reported as healthy.

use std::sync::Arc;

use oracle_client::testing::{
    REGISTRY_ISSUED_AT, TestNode, TestSource, forged_registry, governance, registry_with,
    signed_registry, update_at,
};
use oracle_client::{ClientError, Concern, OracleClient, RejectReason, Status, now_unix_nanos};
use oracle_types::NANOS_PER_SEC;
use oracle_wire::{NodeEntry, VerifyError};

const NOW: u64 = REGISTRY_ISSUED_AT * NANOS_PER_SEC;

/// The deployment §9.2 calls for: five nodes, quorum of three.
fn fleet() -> Vec<TestNode> {
    (1..=5_u8).map(TestNode::new).collect()
}

fn entries(nodes: &[TestNode]) -> Vec<NodeEntry> {
    nodes.iter().map(TestNode::entry).collect()
}

fn client(nodes: &[TestNode]) -> OracleClient {
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    OracleClient::builder(registry)
        .quorum(3)
        .build()
        .expect("five nodes satisfy a quorum of three")
}

fn client_with_source(nodes: &[TestNode], source: Arc<TestSource>) -> OracleClient {
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    OracleClient::builder(registry)
        .quorum(3)
        .registry_source(source)
        .build()
        .expect("five nodes satisfy a quorum of three")
}

#[test]
fn five_nodes_resolve_at_a_quorum_of_three() {
    let nodes = fleet();
    let mut client = client(&nodes);

    let mut resolved = None;
    for node in &nodes {
        resolved = Some(
            client
                .ingest(&node.sign(&update_at(NOW, 1)), NOW)
                .expect("accepted"),
        );
    }
    let resolved = resolved.expect("resolved");
    assert_eq!(resolved.status, Status::Ok);
    assert_eq!(resolved.nodes, 5);
}

/// The whole rotation story from the consumer's side: one unknown frame, one
/// fetch, and the node is back with its new key. The old key is retired, not
/// unknown, so it never costs another fetch.
#[tokio::test]
async fn a_rotation_costs_the_consumer_one_fetch() {
    let mut nodes = fleet();
    let source = TestSource::serving(signed_registry(1, entries(&nodes)));
    let mut client = client_with_source(&nodes, Arc::clone(&source));

    for node in &nodes {
        client
            .ingest_with_refresh(&node.sign(&update_at(NOW, 1)), NOW)
            .await
            .expect("accepted");
    }
    assert_eq!(source.fetches(), 0, "known signers never fetch");

    // Governance replaces node 1's address. The canister publishes v2 with
    // only the new one. The consumer has no idea yet.
    nodes.first_mut().expect("a node").rotate();
    source.serve(signed_registry(2, entries(&nodes)));

    let rotated = nodes.first().expect("a node");
    let resolved = client
        .ingest_with_refresh(&rotated.sign(&update_at(NOW, 2)), NOW)
        .await
        .expect("the new key is accepted after one refresh");
    assert_eq!(source.fetches(), 1);
    assert_eq!(client.registry_version(), 2);
    assert_eq!(resolved.nodes, 5, "the seat moved to the new address");
    assert_eq!(resolved.status, Status::Ok);

    // A frame that was in flight under the old key: refused, and no fetch.
    let old_key = client
        .ingest_with_refresh(&rotated.sign_outgoing(&update_at(NOW, 3)), NOW)
        .await
        .expect_err("the retired key must not verify");
    assert!(
        matches!(old_key, RejectReason::RetiredKey { .. }),
        "{old_key:?}"
    );
    assert_eq!(
        source.fetches(),
        1,
        "a retired key is not a reason to fetch"
    );
    assert_eq!(client.stats().retired, 1);

    // Everyone publishes again. Still five nodes, not six and not four.
    let mut last = None;
    for node in &nodes {
        last = Some(
            client
                .ingest_with_refresh(&node.sign(&update_at(NOW, 4)), NOW)
                .await
                .expect("accepted"),
        );
    }
    assert_eq!(last.expect("resolved").nodes, 5);
}

/// Anyone who can inject a frame can make the signer unknown. The fetch is
/// rate-limited so that costs the registry one request per interval, not one
/// per frame.
#[tokio::test]
async fn unknown_signers_fetch_at_most_once_per_interval() {
    let nodes = fleet();
    let source = TestSource::serving(signed_registry(1, entries(&nodes)));
    let mut client = client_with_source(&nodes, Arc::clone(&source));
    let impostor = TestNode::new(200);

    for seq in 1..=5 {
        let error = client
            .ingest_with_refresh(&impostor.sign(&update_at(NOW, seq)), NOW + seq)
            .await
            .expect_err("an impostor stays unknown");
        assert!(matches!(
            error,
            RejectReason::Untrusted(VerifyError::UnknownSigner { .. })
        ));
    }
    assert_eq!(source.fetches(), 1, "five unknown frames, one fetch");
    assert_eq!(client.stats().untrusted, 5);

    // Once the interval has passed, one more.
    let later = NOW + 11 * NANOS_PER_SEC;
    let _ = client
        .ingest_with_refresh(&impostor.sign(&update_at(later, 9)), later)
        .await;
    assert_eq!(source.fetches(), 2);
    assert_eq!(client.stats().refreshes, 2);
}

/// Revocation has to take effect on adoption, not once the revoked node's last
/// update happens to fall outside the staleness window.
#[test]
fn a_de_listed_node_stops_counting_immediately() {
    let nodes = fleet();
    let mut client = client(&nodes);

    for node in &nodes {
        client
            .ingest(&node.sign(&update_at(NOW, 1)), NOW)
            .expect("accepted");
    }

    // Governance removes two nodes. Their updates are seconds old and would
    // otherwise still be counted.
    let remaining: Vec<NodeEntry> = entries(&nodes).into_iter().take(3).collect();
    client
        .refresh_registry(&signed_registry(2, remaining))
        .expect("adopted");

    let survivor = nodes.first().expect("a node");
    let resolved = client
        .ingest(&survivor.sign(&update_at(NOW, 2)), NOW)
        .expect("accepted");
    assert_eq!(
        resolved.nodes, 3,
        "the two de-listed nodes must be gone from the view at once"
    );

    // And their keys are retired, not unknown.
    let removed = nodes.last().expect("a node");
    assert!(matches!(
        client.ingest(&removed.sign(&update_at(NOW, 2)), NOW),
        Err(RejectReason::RetiredKey { .. })
    ));
}

#[test]
fn a_refresh_that_would_break_the_quorum_is_refused() {
    let nodes = fleet();
    let mut client = client(&nodes);

    let too_few: Vec<NodeEntry> = entries(&nodes).into_iter().take(2).collect();
    let error = client
        .refresh_registry(&signed_registry(2, too_few))
        .expect_err("must refuse");
    assert!(
        matches!(
            error,
            ClientError::UnreachableQuorum {
                requested: 3,
                available: 2
            }
        ),
        "got {error:?}"
    );
    assert_eq!(
        client.registry_version(),
        1,
        "a refused refresh must leave the client on its existing registry"
    );
}

#[test]
fn a_replayed_older_registry_is_refused() {
    let nodes = fleet();
    let mut client = client(&nodes);
    client
        .refresh_registry(&signed_registry(5, entries(&nodes)))
        .expect("adopted");

    for version in [1, 4, 5] {
        let error = client
            .refresh_registry(&signed_registry(version, entries(&nodes)))
            .expect_err("must refuse a registry that is not strictly newer");
        assert!(matches!(error, ClientError::Registry(_)), "got {error:?}");
    }
    assert_eq!(client.registry_version(), 5);
}

/// The refresh path must be anchored to the governance key the client was pinned
/// to. If it were not, whoever supplied the new registry could supply the key
/// that vouches for it, and the trust root would be whatever arrived last.
#[test]
fn a_registry_signed_by_anyone_else_is_refused() {
    let nodes = fleet();
    let mut client = client(&nodes);

    let error = client
        .refresh_registry(&forged_registry(2, entries(&nodes)))
        .expect_err("must refuse");
    assert!(matches!(error, ClientError::Registry(_)), "got {error:?}");
    assert_eq!(client.registry_version(), 1);
}

/// The same anchor applies when the client is built from a source.
#[tokio::test]
async fn building_from_a_source_verifies_against_the_pinned_governance_key() {
    let nodes = fleet();
    let good = TestSource::serving(signed_registry(1, entries(&nodes)));
    let client = OracleClient::builder_from_source(good, governance().address())
        .await
        .expect("fetched and verified")
        .quorum(3)
        .build()
        .expect("builds");
    assert_eq!(client.registry_version(), 1);

    let forged = TestSource::serving(forged_registry(1, entries(&nodes)));
    let error = OracleClient::builder_from_source(forged, governance().address())
        .await
        .err()
        .expect("must refuse");
    assert!(matches!(error, ClientError::Registry(_)), "got {error:?}");

    let empty = Arc::new(TestSource::default());
    let error = OracleClient::builder_from_source(empty, governance().address())
        .await
        .err()
        .expect("must fail");
    assert!(matches!(error, ClientError::Fetch(_)), "got {error:?}");
}

/// A registry swap is exactly the moment an attacker would hope the replay
/// window reopened.
#[test]
fn a_refresh_does_not_reopen_the_replay_window() {
    let nodes = fleet();
    let mut client = client(&nodes);
    let node = nodes.first().expect("a node");

    let frame = node.sign(&update_at(NOW, 9));
    client.ingest(&frame, NOW).expect("accepted");

    client
        .refresh_registry(&signed_registry(2, entries(&nodes)))
        .expect("adopted");

    assert!(
        client.ingest(&frame, NOW).is_err(),
        "the sequence floor must survive the swap"
    );
    assert_eq!(client.stats().replayed, 1);
}

/// The canister publishes only on change, so freshness is each certified
/// fetch. A source that stops confirming leaves the consumer blind to
/// membership changes, and that must show.
#[tokio::test]
async fn an_unconfirmed_registry_degrades_every_feed() {
    let nodes = fleet();
    let source = TestSource::serving(signed_registry(1, entries(&nodes)));
    let mut client = client_with_source(&nodes, source);
    // Confirmations use the wall clock, so these frames are two days past it.
    let later = now_unix_nanos() + 49 * 3_600 * NANOS_PER_SEC;
    assert!(client.registry_is_stale(later));

    for node in &nodes {
        client
            .ingest(&node.sign(&update_at(later, 1)), later)
            .expect("accepted");
    }
    let resolved = client
        .ingest(
            &nodes.first().expect("a node").sign(&update_at(later, 2)),
            later,
        )
        .expect("accepted");
    assert_eq!(resolved.status, Status::Degraded);
    assert!(resolved.concerns.contains(&Concern::RegistryStale));
    assert_eq!(resolved.nodes, 5, "the prices themselves are fine");

    // The same version, served again, confirms it.
    let before = client.registry_age(now_unix_nanos());
    assert_eq!(client.refresh_from_source().await.expect("fetches"), None);
    assert!(client.registry_age(now_unix_nanos()) <= before);
    assert!(!client.registry_is_stale(now_unix_nanos()));

    // A pinned registry has nothing to confirm it, and never goes stale.
    assert!(!self::client(&nodes).registry_is_stale(later));
}
