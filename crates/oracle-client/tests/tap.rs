//! The frame copies for an archive: exact bytes, the verdict, and no waiting.

use oracle_client::testing::{TestNode, governance, signed_registry, update_at};
use oracle_client::{FrameKind, OracleClient, Verdict, now_unix_nanos};
use oracle_wire::{NodeEntry, Signer};

fn client(nodes: &[&TestNode]) -> OracleClient {
    let entries = nodes
        .iter()
        .map(|node| NodeEntry {
            endpoints: vec!["ws://127.0.0.1:9/v2/ws".to_owned()],
            ..node.entry()
        })
        .collect();
    let verified = signed_registry(1, entries)
        .verify(governance().address(), 0)
        .expect("test registry verifies");
    OracleClient::builder(verified)
        .quorum(1)
        .i_understand_this_provides_no_protection_against_a_bad_node()
        .client_key(Signer::from_secret_bytes([0x51; 32]).expect("valid key"))
        .build()
        .expect("builds")
}

#[tokio::test]
async fn each_verified_frame_is_copied_with_its_verdict() {
    let node = TestNode::new(1);
    let mut client = client(&[&node]);
    let mut frames = client.frames(8);

    let at = now_unix_nanos();
    let frame = node.sign(&update_at(at, 1));
    client.ingest(&frame, at).expect("accepted");
    let copy = frames.try_recv().expect("a copy");
    assert_eq!(copy.bytes, frame, "byte for byte");
    assert_eq!(copy.signer, node.signing_address());
    assert_eq!(copy.kind, FrameKind::Price);
    assert_eq!(copy.received_ns, at);
    assert_eq!(copy.verdict, Verdict::Accepted);

    // A second frame with the same sequence number is still the node's frame.
    assert!(client.ingest(&frame, at).is_err());
    let copy = frames.try_recv().expect("a copy of the replay");
    assert_eq!(copy.verdict, Verdict::Replayed);

    // A key that the registry does not list signs no node's frame.
    let stranger = TestNode::new(9);
    assert!(
        client
            .ingest(&stranger.sign(&update_at(at, 2)), at)
            .is_err()
    );
    assert!(frames.try_recv().is_err(), "no copy of an untrusted frame");
}

#[tokio::test]
async fn a_full_channel_drops_and_counts_but_never_blocks() {
    let node = TestNode::new(1);
    let mut client = client(&[&node]);
    let mut frames = client.frames(1);

    let at = now_unix_nanos();
    for seq in 1..=3 {
        client
            .ingest(&node.sign(&update_at(at, seq)), at)
            .expect("the price path does not wait for the archive");
    }
    assert_eq!(client.stats().accepted, 3);
    assert_eq!(client.stats().tap_dropped, 2);
    assert_eq!(
        frames.try_recv().map(|copy| copy.verdict),
        Ok(Verdict::Accepted)
    );
}

/// An archive that keeps one kind asks for that kind only, so the drop counter
/// counts only copies it would keep.
#[tokio::test]
async fn a_kind_filter_copies_and_counts_only_that_kind() {
    let node = TestNode::new(1);
    let mut client = client(&[&node]);
    let mut venues = client.frames_of(1, &[FrameKind::VenueReport]);
    let at = now_unix_nanos();
    for seq in 1..=3 {
        client
            .ingest(&node.sign(&update_at(at, seq)), at)
            .expect("accepted");
    }
    assert!(venues.try_recv().is_err(), "no price copy");
    assert_eq!(client.stats().tap_dropped, 0, "a skipped kind is no loss");

    let mut prices = client.frames_of(1, &[FrameKind::Price]);
    client
        .ingest(&node.sign(&update_at(at, 4)), at)
        .expect("accepted");
    assert_eq!(prices.try_recv().expect("a copy").kind, FrameKind::Price);
}
