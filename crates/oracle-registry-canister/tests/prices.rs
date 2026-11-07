//! Prices on PocketIC: nodes push signed batches as the anonymous identity,
//! and the canister serves each feed's median.
//!
//! What matters most here: a push that breaks an admission rule (SPEC §3.7)
//! never reaches the canister, so it costs no cycles, and the prices survive
//! an upgrade.

use std::collections::BTreeMap;

use candid::Encode;
use oracle_client::HttpDocumentSource;
use oracle_registry_api::{CYCLES_RESERVE, DEFAULT_PRICE_WINDOW, MIN_PRICE_WINDOW};
use oracle_registry_canister::prices::{MAX_FRAMES_PER_PUSH, PriceStatus, Verdict};
use oracle_registry_canister::testing::{Scenario, junk_frame, usd};

const BTC: &str = "CRYPTO.BTC/USD";
const ETH: &str = "CRYPTO.ETH/USD";
/// A feed that no scenario prices.
const SOL: &str = "CRYPTO.SOL/USD";
/// One quote from each of the three nodes; their median is the middle one.
const BTC_QUOTES: [i64; 3] = [usd(64_000), usd(64_010), usd(64_020)];
const BTC_MEDIAN: i64 = usd(64_010);
/// The fourteen feeds of the cost tests, as many as the canister prices on mainnet.
const COST_ASSETS: [&str; 14] = [
    "BTC", "ETH", "SOL", "XRP", "BNB", "DOGE", "ADA", "TRX", "AVAX", "LINK", "DOT", "LTC", "BCH",
    "UNI",
];
/// The cycles that each push shape cost when the baseline was measured.
const COST_BASELINE: &str = include_str!("fixtures/push-cycles.json");
/// How far a measured cost can move from the baseline before the test fails.
const COST_TOLERANCE_PERCENT: u128 = 10;
/// The production pace: the canister allows one batch per node every 30 s, half its interval.
const PRODUCTION_PACE: &str =
    r#"{ "heartbeat_secs": 60, "deviation_bps": 2, "min_interval_secs": 60 }"#;
/// Inside half the production interval.
const TOO_SOON_SECS: u64 = 20;
/// Past half the production interval.
const DUE_SECS: u64 = 31;

/// Three listed nodes; BTC and ETH priced.
fn three_nodes() -> Scenario {
    Scenario::builder().nodes(3).priced(&[BTC, ETH]).build()
}

/// Each node pushes one BTC batch at its quote.
fn quote_btc(s: &Scenario) {
    for (node, price) in s.nodes().zip(BTC_QUOTES) {
        assert_eq!(node.push_batch(&[BTC], price), Ok(vec![Verdict::Accepted]));
    }
}

#[test]
fn three_nodes_push_and_the_canister_resolves_their_median() {
    let s = three_nodes();
    quote_btc(&s);
    let btc = s.price(BTC).expect("BTC is listed");
    assert_eq!(btc.status, PriceStatus::Ok);
    assert_eq!(btc.price, Some(BTC_MEDIAN));
    assert_eq!((btc.expo, btc.nodes), (-8, 3));
}

#[test]
fn the_canister_prices_only_its_feeds_and_halts_one_with_no_pushes() {
    let s = three_nodes();
    let symbols: Vec<String> = s.feeds().into_iter().map(|feed| feed.symbol).collect();
    assert_eq!(symbols, [BTC, ETH]);
    let eth = s.price(ETH).expect("ETH is listed");
    assert_eq!(
        (eth.status, eth.concerns),
        (PriceStatus::Halted, vec!["insufficient_nodes".to_owned()])
    );
    assert!(s.price(SOL).is_none());
}

/// SPEC §3.7 P3: a node streams single frames to its clients, so a client
/// could make the canister pay for each one.
#[test]
fn a_client_relayed_single_frame_is_refused() {
    let s = three_nodes();
    let relayed = s.node(0).frame(BTC, usd(64_000));
    let before = s.cycles();
    let refused = s.push(std::slice::from_ref(&relayed));
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(s.cycles(), before, "the refusal costs nothing");
    assert_eq!(s.price(BTC).expect("listed").nodes, 0);
}

#[test]
fn a_push_with_nothing_new_never_reaches_the_canister() {
    let s = three_nodes();
    let (node, other) = (s.node(0), s.node(1));
    // Signed first, so its `seq` is below that of the batch pushed next.
    let older = node.batch(&[BTC], 1);
    let accepted = node.batch(&[BTC, ETH], usd(64_000));
    assert_eq!(
        s.push(std::slice::from_ref(&accepted)),
        Ok(vec![Verdict::Accepted; 2])
    );
    // Past the node's interval, so the replay checks refuse, not the pace.
    s.pass_time(1);
    let fresh = || node.batch(&[BTC], 1);
    let cases = [
        ("a replay", vec![accepted.clone()]),
        ("a stranger's batch", vec![s.stranger().batch(&[BTC], 1)]),
        ("an older sequence", vec![older]),
        ("a single frame", vec![other.frame(BTC, 1)]),
        ("an unlisted feed", vec![other.batch(&[SOL], 1)]),
        ("junk", vec![junk_frame()]),
        ("no frame", Vec::new()),
        (
            "too many frames",
            vec![accepted.clone(); MAX_FRAMES_PER_PUSH + 1],
        ),
        ("a fresh batch with junk", vec![fresh(), junk_frame()]),
        (
            "a fresh batch with a replay",
            vec![other.batch(&[BTC], 1), accepted.clone()],
        ),
        ("two batches of one node", vec![fresh(), fresh()]),
    ];
    let before = s.cycles();
    for (label, frames) in cases {
        assert!(
            s.push(&frames).is_err(),
            "{label} is refused before execution"
        );
    }
    assert_eq!(s.cycles(), before, "a refused push costs nothing");
}

/// `inspect_message` traps with the rule that refused the push, so an
/// operator sees the reason in the node's log.
#[test]
fn a_refused_push_says_which_rule_refused_it() {
    let s = three_nodes();
    let node = s.node(0);
    let accepted = node.batch(&[BTC], 1);
    s.push(std::slice::from_ref(&accepted)).expect("accepted");
    s.pass_time(1);
    for (frames, reason) in [
        (vec![accepted.clone()], "no new and valid update"),
        (vec![node.frame(BTC, 1)], "price batches"),
        (
            vec![accepted; MAX_FRAMES_PER_PUSH + 1],
            "a push carries 1 to",
        ),
        (
            vec![node.batch(&[BTC], 1), node.batch(&[ETH], 1)],
            "two batches of node",
        ),
    ] {
        let refused = s.push(&frames);
        assert!(
            refused.as_ref().is_err_and(|error| error.contains(reason)),
            "{reason}: {refused:?}"
        );
    }
}

#[test]
fn only_the_anonymous_identity_pushes() {
    let s = three_nodes();
    let refused = s.push_as(s.governance, &[s.node(1).batch(&[BTC], 1)]);
    assert!(
        matches!(&refused, Err(error) if error.contains("anonymous")),
        "{refused:?}"
    );
}

#[test]
fn a_push_of_several_batches_needs_each_one_new() {
    let s = three_nodes();
    let (node, other, third) = (s.node(0), s.node(1), s.node(2));
    let first = node.batch(&[BTC], 1);
    s.push(std::slice::from_ref(&first)).expect("accepted");
    s.pass_time(1);
    let fresh = other.batch(&[ETH], 1);
    assert!(
        s.push(&[first, fresh.clone(), third.batch(&[SOL], 1)])
            .is_err()
    );
    assert_eq!(
        s.push(&[fresh, third.batch(&[ETH], 1)]),
        Ok(vec![Verdict::Accepted; 2])
    );
}

/// SPEC §3.7 P5: the canister holds the feed set's pace itself, so a node with
/// a bad config cannot push faster.
#[test]
fn a_node_cannot_push_faster_than_the_feed_set_pace() {
    let s = three_nodes();
    let content = format!(
        r#"{{ "push": {PRODUCTION_PACE}, "feeds": [
            {{ "symbol": "{BTC}", "sources": [{{ "venue": "coinbase", "market": "spot", "symbol": "BTC-USD" }}] }},
            {{ "symbol": "{ETH}", "sources": [{{ "venue": "coinbase", "market": "spot", "symbol": "ETH-USD" }}] }}
        ] }}"#
    );
    s.set_feed_set(&content).expect("published");
    let node = s.node(0);
    assert_eq!(node.push_batch(&[BTC], 1), Ok(vec![Verdict::Accepted]));
    s.pass_time(TOO_SOON_SECS);
    let before = s.cycles();
    let early = node.push_batch(&[BTC], 1);
    assert!(
        early
            .as_ref()
            .is_err_and(|error| error.contains("pushed too recently")),
        "{early:?}"
    );
    assert_eq!(s.cycles(), before, "the early push costs nothing");
    assert_eq!(
        s.node(1).push_batch(&[BTC], 1),
        Ok(vec![Verdict::Accepted]),
        "each node has its own interval"
    );
    s.pass_time(DUE_SECS - TOO_SOON_SECS);
    assert_eq!(node.push_batch(&[BTC], 1), Ok(vec![Verdict::Accepted]));
}

/// SPEC §3.7 P4: below the reserve the prices halt, and governance can still
/// sign the change that stops the drain.
#[test]
fn below_the_cycles_reserve_pushes_stop_and_governance_still_signs() {
    let s = Scenario::builder()
        .nodes(1)
        .priced(&[BTC])
        // Enough for the install and its freezing threshold, and under the reserve.
        .cycles(CYCLES_RESERVE * 4 / 5)
        .build();
    assert!(s.cycles() < CYCLES_RESERVE);
    let refused = s.node(0).push_batch(&[BTC], 1);
    assert!(
        refused
            .as_ref()
            .is_err_and(|error| error.contains("below the reserve")),
        "{refused:?}"
    );
    assert_eq!(s.set_quorum(1, 1), Ok(2), "governance still signs");

    s.pic.add_cycles(s.canister, CYCLES_RESERVE);
    assert_eq!(s.node(0).push_batch(&[BTC], 1), Ok(vec![Verdict::Accepted]));
}

fn cost_scenario() -> (Scenario, Vec<String>) {
    let feeds: Vec<String> = COST_ASSETS
        .iter()
        .map(|asset| format!("CRYPTO.{asset}/USD"))
        .collect();
    let symbols: Vec<&str> = feeds.iter().map(String::as_str).collect();
    let s = Scenario::builder().nodes(4).priced(&symbols).build();
    (s, feeds)
}

/// What each push shape costs the canister, in cycles.
fn push_costs(s: &Scenario, feeds: &[String]) -> BTreeMap<String, u128> {
    let symbols: Vec<&str> = feeds.iter().map(String::as_str).collect();
    let first = |count: usize| symbols.get(..count).expect("14 feeds");
    let cost = |pushed: Vec<Vec<u8>>, updates: usize| {
        let before = s.cycles();
        let verdicts = s.push(&pushed).expect("accepted");
        assert_eq!(verdicts, vec![Verdict::Accepted; updates]);
        before - s.cycles()
    };
    let node = s.node(0);
    let mut costs = BTreeMap::new();
    costs.insert(
        "batch_of_1".to_owned(),
        cost(vec![node.batch(first(1), 1)], 1),
    );
    costs.insert(
        "batch_of_4".to_owned(),
        cost(vec![node.batch(first(4), 1)], 4),
    );
    costs.insert(
        "batch_of_10".to_owned(),
        cost(vec![node.batch(first(10), 1)], 10),
    );
    costs.insert(
        "batch_of_14".to_owned(),
        cost(vec![node.batch(&symbols, 1)], 14),
    );
    let four_nodes: Vec<Vec<u8>> = s.nodes().map(|node| node.batch(first(1), 1)).collect();
    costs.insert("four_batches_of_1".to_owned(), cost(four_nodes, 4));
    costs
}

#[test]
fn a_batch_costs_one_signature_for_all_its_updates() {
    let (s, feeds) = cost_scenario();
    let costs = push_costs(&s, &feeds);
    let of = |shape: &str| *costs.get(shape).expect("measured");
    assert!(
        of("batch_of_14") < 2 * of("batch_of_1"),
        "fourteen updates in one batch cost less than two batches: {costs:?}"
    );
    assert!(
        2 * of("batch_of_4") < of("four_batches_of_1"),
        "one batch of 4 costs far less than 4 batches: {costs:?}"
    );
}

/// The absolute cycle figures, against `tests/fixtures/push-cycles.json`.
/// After a change that moves them on purpose, write the printed figures there.
#[test]
#[ignore = "cycle figures move with PocketIC and the compiler; run it before a release"]
fn push_costs_stay_near_the_baseline() {
    let baseline: BTreeMap<String, u128> =
        serde_json::from_str(COST_BASELINE).expect("the baseline parses");
    let (s, feeds) = cost_scenario();
    let costs = push_costs(&s, &feeds);
    println!(
        "{}",
        serde_json::to_string_pretty(&costs).expect("serialises")
    );
    for (shape, expected) in &baseline {
        let measured = *costs.get(shape).expect("every baseline shape is measured");
        let tolerance = expected * COST_TOLERANCE_PERCENT / 100;
        assert!(
            measured.abs_diff(*expected) <= tolerance,
            "{shape}: {measured} cycles, the baseline is {expected}"
        );
    }
}

#[test]
fn the_prices_are_certified_through_the_gateway() {
    let mut s = three_nodes();
    quote_btc(&s);
    let certification = s.certification();
    s.make_live();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fetch = |path: &str| {
        runtime
            .block_on(
                HttpDocumentSource::new(&s.url(path), certification.clone())
                    .expect("builds")
                    .fetch::<serde_json::Value>(),
            )
            .unwrap_or_else(|error| panic!("{path} is certified: {error}"))
    };
    let prices = fetch("/prices.json");
    let field = |pointer: &str| prices.pointer(pointer).and_then(serde_json::Value::as_str);
    assert_eq!(field("/prices/0/symbol"), Some(BTC));
    assert_eq!(field("/prices/0/status"), Some("ok"));
    assert_eq!(field("/prices/0/price"), Some("64010"));
    assert!(field("/resolved_at_ns").is_some());

    let frames = fetch("/frames.json");
    let frames = frames
        .pointer("/frames")
        .and_then(serde_json::Value::as_array)
        .expect("a list");
    assert_eq!(frames.len(), 3);
    assert!(frames.iter().all(|frame| {
        frame
            .pointer("/symbols/0")
            .and_then(serde_json::Value::as_str)
            == Some(BTC)
            && frame.pointer("/kind").and_then(serde_json::Value::as_str) == Some("batch")
    }));
}

#[test]
fn an_upgrade_keeps_the_prices_and_the_replay_marks() {
    let s = three_nodes();
    let first = s.node(0).batch(&[BTC], usd(64_000));
    s.push(std::slice::from_ref(&first)).expect("accepted");
    quote_btc(&s);
    let before = s.price(BTC).expect("listed");
    let registry = s.registry();

    s.upgrade();
    assert_eq!(s.registry(), registry);
    let after = s.price(BTC).expect("still listed");
    assert_eq!((after.status, after.price), (before.status, before.price));
    assert!(s.push(&[first]).is_err(), "the replay mark survives");
    quote_btc(&s);
}

/// SPEC §3.6: the canister prices with `recommended`, so a removal below it
/// would halt every priced feed at once.
#[test]
fn remove_node_keeps_priced_feeds_alive() {
    let s = three_nodes();
    quote_btc(&s);
    let removed = s.node(2).address();
    let refused = s.remove_node(removed).expect_err("below the price quorum");
    assert!(refused.contains("set_quorum"), "{refused}");
    assert_eq!(s.price(BTC).expect("listed").status, PriceStatus::Ok);

    assert_eq!(
        s.set_quorum(1, 2),
        Ok(4),
        "governance lowers the quorum first"
    );
    assert_eq!(s.remove_node(removed), Ok(5));
    let btc = s.price(BTC).expect("listed");
    assert_eq!((btc.status, btc.nodes), (PriceStatus::Ok, 2));
    assert!(s.node(2).push_batch(&[BTC], 1).is_err());
}

#[test]
fn governance_sets_the_price_window() {
    const WINDOW_SECS: u64 = 25;
    let s = three_nodes();
    assert_eq!(s.price_window(), DEFAULT_PRICE_WINDOW.as_secs());
    quote_btc(&s);
    assert_eq!(s.set_price_window(WINDOW_SECS), Ok(()));
    assert_eq!(s.price_window(), WINDOW_SECS);
    assert!(s.set_price_window(MIN_PRICE_WINDOW.as_secs() - 1).is_err());
    s.pass_time(WINDOW_SECS - 5);
    assert_eq!(s.price(BTC).expect("listed").status, PriceStatus::Ok);
    s.pass_time(10);
    assert_eq!(
        s.price(BTC).expect("listed").status,
        PriceStatus::Halted,
        "no push for 30 s, past the 25 s window"
    );
    s.upgrade();
    assert_eq!(s.price_window(), WINDOW_SECS, "an upgrade keeps it");
}

/// The push argument is a `vec blob`; anything else never reaches the canister.
#[test]
fn a_push_that_is_not_a_vec_blob_is_refused() {
    let s = three_nodes();
    let before = s.cycles();
    let refused = s.update_as(
        candid::Principal::anonymous(),
        "push",
        Encode!(&"not frames").expect("encodes"),
    );
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(s.cycles(), before);
}
