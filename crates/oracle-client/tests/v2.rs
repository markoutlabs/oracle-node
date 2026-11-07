//! Check 5: transport decryption never vouches for a price.

use std::sync::Arc;

use oracle_client::testing::{TestNode, governance, registry_with, update_at};
use oracle_client::{OracleClient, RejectReason};
use oracle_transport::{
    BroadcastSealer, ClientHandshake, HandshakeMessage, KEY_LEAD_SECS, KeyGrant, KeyRing,
    NodeHandshake, NodeKeySchedule, os_rng,
};
use oracle_types::NANOS_PER_SEC;
use oracle_wire::{
    ClientEntry, ClientList, Signer, auth_ok_payload, auth_ok_transcript, client_auth_transcript,
    initial_keys_digest, recover_payload_signer,
};

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

/// The node signs its sealed initial keys through `initial_keys_digest`, the
/// rule that the wire golden vector pins (SPEC §6.1).
#[test]
fn auth_ok_signs_the_initial_keys_by_the_wire_digest() {
    let node = TestNode::new(1);
    let client_key = Signer::from_secret(&[0x51; 32].into()).expect("a valid key");
    let clients = ClientList::sign(
        &governance(),
        1,
        NOW_S,
        60,
        vec![ClientEntry {
            address: client_key.address(),
            expires_at: NOW_S + 3_600,
        }],
    )
    .expect("signs")
    .verify(governance().address(), 0)
    .expect("verifies");
    let mut schedule = NodeKeySchedule::new(node.signing_address(), 60, NOW_S, &mut os_rng());
    let lead = schedule.current().context().not_after - KEY_LEAD_SECS;
    let _ = schedule.tick(lead, &mut os_rng());
    let keys = [
        Arc::clone(schedule.current()),
        Arc::clone(schedule.next().expect("the next key")),
    ];

    let (handshake, challenge) = NodeHandshake::start(node.signing_address(), &mut os_rng());
    let (auth, _waiting) = ClientHandshake::new(node.signing_address(), &mut os_rng())
        .respond(&challenge, &client_key)
        .expect("responds");
    let (ok, _session) = handshake
        .verify(&auth, &clients, NOW_S)
        .expect("a listed client")
        .accept(node.signer(), &keys, &mut os_rng())
        .expect("accepts");
    let (
        HandshakeMessage::Challenge { challenge, .. },
        HandshakeMessage::Auth {
            client_pubkey,
            eph,
            client_nonce,
            ..
        },
        HandshakeMessage::AuthOk {
            enc,
            session_deadline,
            initial,
            node_sig,
        },
    ) = (challenge, auth, ok)
    else {
        panic!("a challenge, an auth and an auth_ok");
    };
    assert_eq!(initial.len(), 2);
    let client_auth = client_auth_transcript(
        node.signing_address(),
        &challenge,
        &client_nonce,
        &client_pubkey,
        &eph,
    )
    .expect("hashes");
    let auth_ok = auth_ok_transcript(
        &client_auth,
        &enc,
        session_deadline,
        &initial_keys_digest(&initial),
    )
    .expect("hashes");
    assert_eq!(
        recover_payload_signer(&auth_ok_payload(&auth_ok), &node_sig).ok(),
        Some(node.signing_address())
    );
}
