//! Check 5: transport decryption never vouches for a price.

use std::sync::Arc;

use oracle_client::testing::{TestNode, registry_with, update_at};
use oracle_client::{OracleClient, RejectReason};
use oracle_transport::{BroadcastSealer, KeyGrant, KeyRing, NodeKeySchedule, os_rng};
use oracle_types::NANOS_PER_SEC;

const NOW_S: u64 = 1_754_582_400;
const NOW: u64 = NOW_S * NANOS_PER_SEC;

/// Every authorised client holds the broadcast key, so any of them can seal a
/// frame that decrypts. The node signature is what the verifier checks.
#[test]
fn a_frame_that_decrypts_is_still_refused_unless_the_node_signed_it() {
    let node = TestNode::new(1);
    let mut client = OracleClient::builder(registry_with(&[&node]))
        .quorum(1)
        .i_understand_this_provides_no_protection_against_a_bad_node()
        .build()
        .expect("builds");

    let schedule = NodeKeySchedule::new(node.signing_address(), 60, NOW_S, &mut os_rng());
    let sealer = BroadcastSealer::new(Arc::clone(schedule.current()));
    let mut ring = KeyRing::new(node.signing_address());
    ring.insert(KeyGrant::from_key(schedule.current()));

    // A key holder signs a price with its own key and seals it.
    let impostor = TestNode::new(200);
    let forged = sealer.seal(&impostor.sign(&update_at(NOW, 1)), &mut os_rng());
    let opened = ring.open(&forged).expect("it decrypts");
    assert!(matches!(
        client.ingest(&opened, NOW),
        Err(RejectReason::Untrusted(_))
    ));

    let genuine = sealer.seal(&node.sign(&update_at(NOW, 2)), &mut os_rng());
    let opened = ring.open(&genuine).expect("it decrypts");
    client
        .ingest(&opened, NOW)
        .expect("the node's own frame verifies");
}
