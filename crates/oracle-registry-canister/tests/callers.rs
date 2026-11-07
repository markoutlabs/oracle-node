//! Calls from other canisters (SPEC §3.7, rules Q1 and Q2). Such a call skips
//! `inspect_message`, so the guards alone decide, and the canister pays the
//! execution fee of each call that it takes.
//!
//! `oracle_registry_canister::testing::Caller` is the calling canister.

use candid::{Decode, Encode};
use oracle_registry_api::{PRICE_CALL_CYCLES, PriceRecord, PriceStatus};
use oracle_registry_canister::testing::{Scenario, usd};
use serde_bytes::ByteBuf;

const BTC: &str = "CRYPTO.BTC/USD";
/// The interface that the canister serves; `make canister` writes it from the wasm.
const DID: &str = include_str!("../oracle-registry-canister.did");
/// The methods that serve another canister, for a fee.
const PRICE_METHODS: [&str; 2] = ["get_price", "get_prices"];

/// Each method of the `.did` service, and `true` for a query.
fn methods() -> Vec<(&'static str, bool)> {
    let (_, service) = DID.split_once("service :").expect("the .did has a service");
    service
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .filter_map(|line| line.split_once(" : "))
        .map(|(name, signature)| (name, signature.trim_end_matches(';').ends_with("query")))
        .collect()
}

/// SPEC §3.6: each guard, checked at run time against the method list of the
/// `.did`, which the crate checks against its exported interface.
#[test]
fn every_method_refuses_a_canister_that_is_not_governance() {
    let s = Scenario::builder().nodes(1).priced(&[BTC]).build();
    let caller = s.caller();
    let methods = methods();
    assert!(
        methods.iter().any(|(name, _)| *name == "push")
            && methods.iter().any(|(name, _)| *name == "http_request"),
        "the .did lists the service: {methods:?}"
    );
    for (method, query) in methods {
        // A guard runs before the arguments decode, so no method needs its own.
        let refused = caller
            .call(method, Encode!().expect("encodes"), 0)
            .expect_err(method);
        let expected = match (method, query) {
            ("push", false) => "anonymous identity only",
            (_, false) => "only governance",
            (price, true) if PRICE_METHODS.contains(&price) => "attach",
            (_, true) => "query the rest",
        };
        assert!(refused.contains(expected), "{method}: {refused}");
    }
}

fn btc_id() -> ByteBuf {
    let symbol = BTC.parse().expect("a symbol");
    ByteBuf::from(oracle_wire::feed_id(&symbol).as_bytes().to_vec())
}

/// SPEC §3.7 Q2: a canister pays for each price call with attached cycles, so
/// the calls cost the canister nothing.
#[test]
fn a_canister_pays_for_its_price_calls() {
    let s = Scenario::builder().nodes(1).priced(&[BTC]).build();
    assert_eq!(s.set_quorum(1, 1), Ok(2));
    assert!(s.node(0).push_batch(&[BTC], usd(64_000)).is_ok());
    let caller = s.caller();

    let before = s.cycles();
    let reply = caller
        .call(
            "get_price",
            Encode!(&btc_id()).expect("encodes"),
            PRICE_CALL_CYCLES,
        )
        .expect("a paid call");
    let record = Decode!(&reply, Option<PriceRecord>)
        .expect("decodes")
        .expect("BTC is listed");
    assert_eq!(
        (record.status, record.price),
        (PriceStatus::Ok, Some(usd(64_000)))
    );
    let paid = s.cycles();
    eprintln!(
        "a paid get_price: the canister has {} cycles more",
        i128::try_from(paid).unwrap_or(i128::MAX) - i128::try_from(before).unwrap_or(0)
    );
    assert!(
        paid >= before,
        "the fee pays for the call: {before} then {paid}"
    );

    let caller_before = caller.cycles();
    let reply = caller
        .call("get_prices", Encode!().expect("encodes"), PRICE_CALL_CYCLES)
        .expect("a paid call");
    let paid_by_caller = caller_before - caller.cycles();
    let records = Decode!(&reply, Vec<PriceRecord>).expect("decodes");
    assert_eq!(records.len(), 1);
    assert!(s.cycles() >= paid, "get_prices pays for itself too");

    let caller_before = caller.cycles();
    let before = s.cycles();
    let refused = caller
        .call(
            "get_prices",
            Encode!().expect("encodes"),
            PRICE_CALL_CYCLES - 1,
        )
        .expect_err("too few cycles");
    assert!(refused.contains("attach"), "{refused}");
    let refused_by_caller = caller_before - caller.cycles();
    let cost = before.saturating_sub(s.cycles());
    eprintln!(
        "a refused call from a canister costs the canister {cost} cycles; \
         the caller paid {paid_by_caller} for a paid call and {refused_by_caller} for a refused one"
    );
    assert!(
        cost < PRICE_CALL_CYCLES,
        "a refusal costs only the base fee: {cost}"
    );
    assert!(
        refused_by_caller < paid_by_caller,
        "the refused cycles go back to the caller"
    );

    assert_eq!(
        s.price(BTC).map(|record| record.status),
        Some(PriceStatus::Ok),
        "a plain query needs no cycles"
    );
}

/// `n` priced feeds with a synthetic asset each, all pushed by one node.
fn many_feeds(n: usize) -> (Scenario, Vec<String>) {
    let feeds: Vec<String> = (0..n)
        .map(|i| {
            let letter =
                |shift: usize| char::from(b'A' + u8::try_from((i / shift) % 26).expect("a letter"));
            format!("CRYPTO.Z{}{}{}/USD", letter(676), letter(26), letter(1))
        })
        .collect();
    let symbols: Vec<&str> = feeds.iter().map(String::as_str).collect();
    let s = Scenario::builder().nodes(1).priced(&symbols).build();
    assert_eq!(s.set_quorum(1, 1), Ok(2));
    for chunk in symbols.chunks(oracle_wire::MAX_BATCH_UPDATES) {
        assert!(s.node(0).push_batch(chunk, usd(1)).is_ok());
    }
    (s, feeds)
}

/// What one `get_prices` call from a canister costs the canister, in cycles.
fn get_prices_cost(s: &Scenario, attached: u128) -> i128 {
    let caller = s.caller();
    let before = i128::try_from(s.cycles()).expect("fits");
    caller
        .call("get_prices", Encode!().expect("encodes"), attached)
        .expect("a paid call");
    let after = i128::try_from(s.cycles()).expect("fits");
    let fee = i128::try_from(attached).expect("fits");
    fee - (after - before)
}

/// The flat fee covers `get_prices` with the 14 curated feeds and with all
/// 225 of the feed set; past about 300 feeds it would not.
#[test]
fn get_prices_pays_for_itself_with_every_feed_of_the_set() {
    for n in [14, 225] {
        let (s, _) = many_feeds(n);
        let cost = get_prices_cost(&s, PRICE_CALL_CYCLES);
        eprintln!("get_prices with {n} feeds costs the canister {cost} cycles");
        assert!(
            cost < i128::try_from(PRICE_CALL_CYCLES).expect("fits"),
            "{n} feeds cost {cost} cycles, more than the fee"
        );
    }
}
