//! Generates a single-node registry and prints the keys, for local runs.
//!
//! The keys are derived from small integers. **Never use them anywhere real.**

fn main() {
    let identity = oracle_wire::Signer::from_secret_bytes([0x11; 32]).expect("key");
    let signing = oracle_wire::Signer::from_secret_bytes([0x22; 32]).expect("key");
    let governance = oracle_wire::Signer::from_secret_bytes([0x33; 32]).expect("key");
    let cert = oracle_wire::SigningKeyCert::issue(
        &identity,
        "oracle-local-1",
        signing.address(),
        0,
        4_102_444_800,
    )
    .expect("cert");
    let node = oracle_wire::NodeEntry {
        node_id: "oracle-local-1".to_owned(),
        operator: "local".to_owned(),
        identity_pubkey: oracle_wire::CompressedPublicKey::from_public_key(&identity.public_key()),
        endpoints: vec!["ws://127.0.0.1:8791/v1/ws".to_owned()],
        signing_keys: vec![cert],
        weight: 1,
    };
    let registry = oracle_wire::Registry::sign(
        &governance,
        1,
        0,
        vec![node],
        oracle_wire::Quorum {
            min_nodes: 1,
            recommended: 3,
        },
    )
    .expect("registry");
    println!("{}", serde_json::to_string_pretty(&registry).expect("json"));
    eprintln!("SIGNING_KEY=2222222222222222222222222222222222222222222222222222222222222222");
    eprintln!("GOVERNANCE={}", governance.address());
}
