//! An upgrade from the previous release and a rollback to it. It catches a
//! stable layout or a field that the older wasm cannot read, which would trap
//! in its `post_upgrade` and stop the rollback.
//!
//! The test needs the previous release wasm, the file that its `SHA256SUMS`
//! entry names, in `ORACLE_PREVIOUS_WASM`. It never downloads one. Without the
//! variable it says so and passes, except when `CI` is set: then it fails.

use candid::Encode;
use oracle_registry_canister::prices::{PriceStatus, Verdict};
use oracle_registry_canister::testing::{PREVIOUS_WASM_ENV, Scenario, WASM, previous_wasm, usd};
use oracle_wire::Signer;
use zeroize::Zeroizing;

const BTC: &str = "CRYPTO.BTC/USD";
const DAY_SECS: u64 = 86_400;
/// Not a seed of a test node: those sign with seed + 0x40.
const CLIENT_SEED: u8 = 0x70;

fn feed_set() -> String {
    serde_json::json!({
        "push": { "heartbeat_secs": 2, "deviation_bps": 10, "min_interval_secs": 1 },
        "feeds": [{ "symbol": BTC, "sources": [{ "venue": "coinbase", "market": "spot", "symbol": "BTC-USD" }] }],
    })
    .to_string()
}

/// Every signed document and the BTC price, as the canister serves them.
fn served(s: &Scenario) -> (String, Option<String>, Option<String>, Option<i64>) {
    let clients: Option<String> = s.query("get_clients", Encode!().expect("encodes"));
    let feeds: Option<String> = s.query("get_feed_set", Encode!().expect("encodes"));
    let registry = serde_json::to_string(&s.registry()).expect("serialises");
    let price = s.price(BTC).and_then(|record| record.price);
    (registry, clients, feeds, price)
}

#[test]
fn an_upgrade_from_the_previous_release_and_a_rollback_keep_every_document() {
    let Some(previous) = previous_wasm() else {
        // A CI run must not pass without the one test that sees the old wasm's own types.
        assert!(
            std::env::var_os("CI").is_none(),
            "{PREVIOUS_WASM_ENV} must name the previous release wasm when CI is set"
        );
        eprintln!(
            "skipped: {PREVIOUS_WASM_ENV} is not set; set it to the previous release wasm to run this test"
        );
        return;
    };
    let s = Scenario::builder()
        .wasm(previous.clone())
        .nodes(3)
        .priced(&[BTC])
        .build();
    let client = Signer::from_secret(&Zeroizing::new([CLIENT_SEED; 32]))
        .expect("valid key")
        .address();
    assert!(s.add_client(client, s.now() + DAY_SECS).is_ok());
    assert!(s.set_feed_set(&feed_set()).is_ok());
    for (node, price) in s.nodes().zip([usd(64_000), usd(64_010), usd(64_020)]) {
        assert_eq!(node.push_batch(&[BTC], price), Ok(vec![Verdict::Accepted]));
    }
    let before = served(&s);
    assert_eq!(before.3, Some(usd(64_010)));

    s.upgrade_to(&WASM)
        .expect("the upgrade to this wasm succeeds");
    assert_eq!(
        served(&s),
        before,
        "the upgrade keeps every document and price"
    );
    assert_eq!(
        s.node(0).push_batch(&[BTC], usd(64_005)),
        Ok(vec![Verdict::Accepted])
    );

    s.upgrade_to(&previous)
        .expect("the rollback to the previous release succeeds");
    let rolled_back = served(&s);
    assert_eq!(
        (&rolled_back.0, &rolled_back.1, &rolled_back.2),
        (&before.0, &before.1, &before.2),
        "the rollback keeps every document"
    );
    assert_eq!(
        s.price(BTC).map(|record| record.status),
        Some(PriceStatus::Ok)
    );

    s.upgrade_to(&WASM).expect("this wasm again");
    assert_eq!(served(&s).0, before.0);
}
