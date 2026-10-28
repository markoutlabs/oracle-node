//! Prices on PocketIC: nodes push signed frames as the anonymous identity, and
//! the canister serves each feed's median.
//!
//! What matters most here: a push that carries nothing new never reaches the
//! canister, so it costs no cycles, and the prices survive an upgrade.

use oracle_client::testing::{TestNode, update_at};
use oracle_client::{Certification, HttpDocumentSource};
use oracle_registry_canister::prices::{PriceStatus, Verdict};
use oracle_registry_canister::testing::Harness;
use oracle_types::{PriceUpdate, Symbol};
use oracle_wire::feed_id;

const BTC: &str = "CRYPTO.BTC/USD";
const ETH: &str = "CRYPTO.ETH/USD";

fn update(h: &Harness, symbol: &str, seq: u64, price: i64) -> PriceUpdate {
    let symbol: Symbol = symbol.parse().expect("a valid symbol");
    let mut update = update_at(h.now_ns(), seq);
    update.feed_id = feed_id(&symbol);
    update.price = price;
    update
}

fn frame(h: &Harness, node: &TestNode, symbol: &str, seq: u64, price: i64) -> Vec<u8> {
    node.sign(&update(h, symbol, seq, price))
}

/// One node's push of these feeds as one batch.
fn batch(h: &Harness, node: &TestNode, symbols: &[&str], seq: u64) -> Vec<u8> {
    let updates: Vec<PriceUpdate> = symbols
        .iter()
        .map(|symbol| update(h, symbol, seq, 6_400_000_000_000))
        .collect();
    node.sign_batch(&updates)
}

/// Three listed nodes and two priced feeds.
fn three_nodes() -> (Harness, [TestNode; 3]) {
    let h = Harness::new(1, "dfx_test_key", None);
    let nodes = [TestNode::new(1), TestNode::new(2), TestNode::new(3)];
    for node in &nodes {
        h.add_node(&node.entry())
            .expect("governance lists the node");
    }
    h.set_feeds(&[BTC, ETH]).expect("governance sets the feeds");
    (h, nodes)
}

fn push_btc(h: &Harness, nodes: &[TestNode], seq: u64) {
    for (node, price) in nodes
        .iter()
        .zip([6_400_000_000_000, 6_401_000_000_000, 6_402_000_000_000])
    {
        assert_eq!(
            h.push(&[frame(h, node, BTC, seq, price)]),
            Ok(vec![Verdict::Accepted])
        );
    }
}

#[test]
fn three_nodes_push_and_the_canister_resolves_their_median() {
    let (h, nodes) = three_nodes();
    let symbols: Vec<String> = h.feeds().into_iter().map(|feed| feed.symbol).collect();
    assert_eq!(symbols, [BTC, ETH]);

    let before = h.cycles();
    push_btc(&h, &nodes, 1);
    let per_push = (before - h.cycles()) / 3;
    eprintln!("one push of one frame: {per_push} cycles");

    let btc = h.price(BTC).expect("BTC is listed");
    assert_eq!(btc.status, PriceStatus::Ok);
    assert_eq!(btc.price, Some(6_401_000_000_000));
    assert_eq!((btc.expo, btc.nodes), (-8, 3));
    let eth = h.price(ETH).expect("ETH is listed");
    assert_eq!(
        (eth.status, eth.concerns),
        (PriceStatus::Halted, vec!["insufficient_nodes".to_owned()])
    );
    assert!(h.price("CRYPTO.SOL/USD").is_none());
}

#[test]
fn a_push_with_nothing_new_never_reaches_the_canister() {
    let (h, nodes) = three_nodes();
    let accepted = frame(&h, &nodes[0], BTC, 1, 6_400_000_000_000);
    assert_eq!(
        h.push(std::slice::from_ref(&accepted)),
        Ok(vec![Verdict::Accepted])
    );

    let stranger = frame(&h, &TestNode::new(9), BTC, 1, 1);
    let unlisted = frame(&h, &nodes[0], "CRYPTO.SOL/USD", 1, 1);
    let older = frame(&h, &nodes[0], BTC, 0, 1);
    let pushed = batch(&h, &nodes[1], &[BTC, ETH], 1);
    assert_eq!(
        h.push(std::slice::from_ref(&pushed)),
        Ok(vec![Verdict::Accepted; 2])
    );
    let before = h.cycles();
    for (label, frames) in [
        ("a replay", vec![accepted.clone()]),
        ("a batch replay", vec![pushed]),
        (
            "a stranger's batch",
            vec![batch(&h, &TestNode::new(9), &[BTC], 1)],
        ),
        ("an older sequence", vec![older]),
        ("a stranger's frame", vec![stranger]),
        ("an unlisted feed", vec![unlisted]),
        ("junk", vec![vec![0; 182]]),
        ("too many frames", vec![accepted.clone(); 5]),
        (
            "a fresh frame with junk",
            vec![frame(&h, &nodes[0], BTC, 2, 1), vec![0; 182]],
        ),
        (
            "a fresh frame with a replay",
            vec![frame(&h, &nodes[0], BTC, 3, 1), accepted.clone()],
        ),
    ] {
        assert!(
            h.push(&frames).is_err(),
            "{label} is refused before execution"
        );
    }
    assert_eq!(h.cycles(), before, "a refused push costs nothing");

    let refused = h.push_as(h.governance, &[frame(&h, &nodes[1], BTC, 1, 1)]);
    assert!(
        matches!(&refused, Err(error) if error.contains("anonymous")),
        "only the anonymous identity pushes: {refused:?}"
    );
}

#[test]
fn a_push_of_several_frames_needs_each_one_new() {
    let (h, nodes) = three_nodes();
    let first = frame(&h, &nodes[0], BTC, 1, 1);
    h.push(std::slice::from_ref(&first)).expect("accepted");
    let fresh = frame(&h, &nodes[0], ETH, 1, 1);
    let unlisted = frame(&h, &nodes[1], "CRYPTO.SOL/USD", 1, 1);
    assert!(h.push(&[first, fresh.clone(), unlisted]).is_err());
    assert_eq!(
        h.push(&[fresh, frame(&h, &nodes[1], ETH, 1, 1)]),
        Ok(vec![Verdict::Accepted; 2])
    );
}

#[test]
fn a_batch_costs_one_signature_for_all_its_updates() {
    let h = Harness::new(1, "dfx_test_key", None);
    let node = TestNode::new(1);
    h.add_node(&node.entry()).expect("listed");
    let symbols: Vec<String> = [
        "BTC", "ETH", "SOL", "XRP", "BNB", "DOGE", "ADA", "TRX", "AVAX", "LINK", "DOT", "LTC",
        "BCH", "UNI",
    ]
    .iter()
    .map(|asset| format!("CRYPTO.{asset}/USD"))
    .collect();
    let refs: Vec<&str> = symbols.iter().map(String::as_str).collect();
    h.set_feeds(&refs).expect("governance sets the feeds");

    let first = refs.get(..1).expect("14 feeds");
    let ten_feeds = refs.get(..10).expect("14 feeds");
    let cost = |pushed: Vec<Vec<u8>>, updates: usize| {
        let before = h.cycles();
        let verdicts = h.push(&pushed).expect("accepted");
        assert_eq!(verdicts, vec![Verdict::Accepted; updates]);
        before - h.cycles()
    };
    let four_feeds = refs.get(..4).expect("14 feeds");
    let one = cost(vec![batch(&h, &node, first, 1)], 1);
    let ten = cost(vec![batch(&h, &node, ten_feeds, 2)], 10);
    let fourteen = cost(vec![batch(&h, &node, &refs, 3)], 14);
    let four = cost(vec![batch(&h, &node, four_feeds, 4)], 4);
    let singles: Vec<Vec<u8>> = four_feeds
        .iter()
        .map(|symbol| frame(&h, &node, symbol, 5, 1))
        .collect();
    let four_frames = cost(singles, 4);
    eprintln!(
        "one batch of 1 update: {one} cycles; of 4: {four}; of 10: {ten}; of 14: {fourteen}; \
         4 single frames: {four_frames}"
    );
    // One recovery for the batch: its updates add bytes and bookkeeping only.
    assert!(ten < 40_000_000, "a batch of 10 cost {ten} cycles");
    assert!(
        four * 2 < four_frames,
        "a batch of 4 must cost far less than 4 frames"
    );
}

#[test]
fn the_prices_are_certified_through_the_gateway() {
    let (mut h, nodes) = three_nodes();
    push_btc(&h, &nodes, 1);
    let certification: Certification = h.certification();
    h.make_live();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fetch = |path: &str| {
        runtime
            .block_on(
                HttpDocumentSource::new(&h.url(path), certification.clone())
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
    }));
}

#[test]
fn an_upgrade_keeps_the_prices_and_the_replay_marks() {
    let (h, nodes) = three_nodes();
    let first = frame(&h, &nodes[0], BTC, 1, 6_400_000_000_000);
    h.push(std::slice::from_ref(&first)).expect("accepted");
    push_btc(&h, &nodes, 2);
    let before = h.price(BTC).expect("listed");
    let registry = h.registry();

    h.upgrade();
    assert_eq!(h.registry(), registry);
    let after = h.price(BTC).expect("still listed");
    assert_eq!((after.status, after.price), (before.status, before.price));
    assert!(h.push(&[first]).is_err(), "the replay mark survives");
    push_btc(&h, &nodes, 3);
}

#[test]
fn a_removed_node_loses_its_seat_at_once() {
    let (h, nodes) = three_nodes();
    push_btc(&h, &nodes, 1);
    h.remove_node(nodes[2].signing_address()).expect("removed");
    let btc = h.price(BTC).expect("listed");
    assert_eq!((btc.status, btc.nodes), (PriceStatus::Halted, 2));
    assert!(h.push(&[frame(&h, &nodes[2], BTC, 2, 1)]).is_err());
}

#[test]
fn governance_sets_the_price_window() {
    let (h, nodes) = three_nodes();
    assert_eq!(h.price_window(), 75, "the default");
    push_btc(&h, &nodes, 1);
    assert_eq!(h.set_price_window(25), Ok(()));
    assert_eq!(h.price_window(), 25);
    assert!(h.set_price_window(5).is_err(), "below the minimum");
    h.pass_time(20);
    assert_eq!(h.price(BTC).expect("listed").status, PriceStatus::Ok);
    h.pass_time(10);
    assert_eq!(
        h.price(BTC).expect("listed").status,
        PriceStatus::Halted,
        "no push for 30 s, past the 25 s window"
    );
    h.upgrade();
    assert_eq!(h.price_window(), 25, "an upgrade keeps it");
}
