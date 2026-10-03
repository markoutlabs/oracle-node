//! M5: five nodes, a quorum of three, and a signing-key rotation the consumer
//! never notices.
//!
//! The milestone's exit criterion is "rotation with zero consumer impact", and
//! the interesting failures are all ways that phrase can be satisfied on paper
//! while being false in practice:
//!
//! - The rotating node keeps publishing, but occupies *two* quorum seats while
//!   both its keys are valid — so three agreeing "nodes" are really two machines.
//! - The rotation lands, but the consumer's replay floor resets with the new key.
//! - The new registry is adopted, but a de-listed node keeps counting until its
//!   last update ages out.
//!
//! Each of those is a test here.

use oracle_client::testing::{
    TestNode, forged_registry, registry_with, signed_registry, update_at,
};
use oracle_client::{ClientError, OracleClient, Status};
use oracle_types::NANOS_PER_SEC;
use oracle_wire::NodeEntry;

const NOW: u64 = 1_754_582_400 * NANOS_PER_SEC;

/// The deployment §9.2 calls for: five nodes, quorum of three.
fn fleet() -> Vec<TestNode> {
    (1..=5_u8)
        .map(|seed| TestNode::new(seed, &format!("oracle-{seed}")))
        .collect()
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

/// The core rotation hazard. A node mid-overlap holds two authorised keys; if
/// the client counted keys it would seat that one machine twice, and a quorum of
/// three could be satisfied by two nodes — one of them simply rotating.
#[test]
fn a_rotating_node_does_not_occupy_two_quorum_seats() {
    let mut nodes = fleet();
    nodes.truncate(3);
    if let Some(node) = nodes.first_mut() {
        node.rotate();
    }
    let mut client = client(&nodes);

    // Three nodes are registered; only two of them will publish. The third stays
    // silent, so the quorum has to come from the two that speak — or not at all.
    let [rotating, other, _silent] = nodes.as_slice() else {
        panic!("three nodes")
    };

    // Three accepted frames, two of them from the same machine under different
    // keys. That must not be a quorum.
    client
        .ingest(&rotating.sign_outgoing(&update_at(NOW, 1)), NOW)
        .expect("accepted");
    client
        .ingest(&rotating.sign(&update_at(NOW, 2)), NOW)
        .expect("accepted");
    let resolved = client
        .ingest(&other.sign(&update_at(NOW, 1)), NOW)
        .expect("accepted");

    assert_eq!(client.stats().accepted, 3, "three frames really did verify");
    assert_eq!(resolved.nodes, 2, "but they came from two nodes");
    assert_eq!(resolved.status, Status::Halted);
}

/// The milestone criterion. A node rotates its key mid-stream while the registry
/// is refreshed underneath a running consumer; the feed must stay `Ok` the whole
/// way through, with no reconnect and no lost state.
#[test]
fn rotation_never_drops_the_consumer_below_quorum() {
    let mut nodes = fleet();
    let mut client = client(&nodes);

    // Before: everyone on their original key.
    let mut seq = 1;
    for node in &nodes {
        client
            .ingest(&node.sign(&update_at(NOW, seq)), NOW)
            .expect("accepted");
    }
    // Governance publishes v2, listing node 1's incoming key alongside its
    // outgoing one. The consumer adopts it in place.
    if let Some(node) = nodes.first_mut() {
        node.rotate();
    }
    let overlap = signed_registry(2, entries(&nodes));
    assert_eq!(client.refresh_registry(&overlap).expect("adopted"), 2);

    // Node 1 moves to the new key; everyone else is unchanged. The feed must not
    // so much as flicker.
    seq += 1;
    let mut last = None;
    for node in &nodes {
        last = Some(
            client
                .ingest(&node.sign(&update_at(NOW, seq)), NOW)
                .expect("accepted"),
        );
    }
    let resolved = last.expect("resolved");
    assert_eq!(resolved.status, Status::Ok);
    assert_eq!(resolved.nodes, 5, "still five nodes, not six");

    // The overlap closes: v3 drops the outgoing key.
    let closed: Vec<NodeEntry> = nodes.iter().map(TestNode::entry_without_outgoing).collect();
    let final_registry = signed_registry(3, closed);
    assert_eq!(
        client.refresh_registry(&final_registry).expect("adopted"),
        3
    );

    seq += 1;
    let mut last = None;
    for node in &nodes {
        last = Some(
            client
                .ingest(&node.sign(&update_at(NOW, seq)), NOW)
                .expect("accepted"),
        );
    }
    let resolved = last.expect("resolved");
    assert_eq!(resolved.status, Status::Ok);
    assert_eq!(resolved.nodes, 5);

    // And the revoked key is now genuinely revoked.
    let rotating = nodes.first().expect("a node");
    assert!(
        client
            .ingest(&rotating.sign_outgoing(&update_at(NOW, seq + 1)), NOW)
            .is_err(),
        "the outgoing key must stop verifying once it is de-listed"
    );
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
