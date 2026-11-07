use super::*;
use crate::Status;
use crate::testing::{TestNode, book_at, funding_at, governance, registry_with, update_at};
use oracle_types::{
    BookLevel, BookUpdate, FundingUpdate, MarketKind, NANOS_PER_SEC, PriceUpdate, Venue,
};
use oracle_wire::{FeedSet, FeedSettings, SourceSettings};

const NOW: u64 = 1_754_582_400 * NANOS_PER_SEC;

#[test]
fn book_frames_build_each_node_book_and_a_gap_hands_the_book_on() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .build()
        .expect("three nodes");
    let [a, b, _] = nodes.as_slice() else {
        panic!("three nodes");
    };
    let instrument = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");

    for (frame, at) in [
        (a.sign_book(&book_at(NOW, 1, true, 100)), NOW),
        (a.sign_book(&book_at(NOW + 10, 2, false, 300)), NOW + 10),
        (b.sign_book(&book_at(NOW + 5, 7, true, 200)), NOW + 5),
    ] {
        assert!(matches!(
            client.ingest_event(&frame, at),
            Ok(Event::Book(_))
        ));
    }
    assert_eq!(
        client.book(&instrument, NOW + 20).map(|book| book.node),
        Some(a.signing_address().min(b.signing_address())),
        "equal books: the lower address"
    );

    // Node A skips seq 3: its book is unknown, so node B's serves.
    let gap = a.sign_book(&book_at(NOW + 30, 4, false, 900));
    assert!(client.ingest_event(&gap, NOW + 30).is_ok());
    let book = client.book(&instrument, NOW + 40).expect("node B's book");
    assert_eq!(book.node, b.signing_address());
    assert_eq!(book.best_bid().map(|level| level.qty), Some(200));
    assert_eq!(client.stats().book_updates, 4);

    let later = NOW + 10 * NANOS_PER_SEC;
    assert!(client.book(&instrument, later).is_none(), "too old");
}

const BID: i64 = 6_399_990_000_000;

const MS: u64 = NANOS_PER_SEC / 1_000;

/// One tick of the test books: 0.1 at the book exponent.
const TICK: i64 = 10_000_000;

/// A snapshot whose bid and ask are `ticks` above `book_at`, with depth: a
/// small top level, and a deep one ten ticks out.
fn deep(publish_time_ns: u64, seq: u64, ticks: i64, top_qty: u64) -> BookUpdate {
    let bid = BID + ticks * TICK;
    let ask = bid + 2 * TICK;
    BookUpdate {
        bids: vec![
            BookLevel {
                price: bid,
                qty: top_qty,
            },
            BookLevel {
                price: bid - 100 * TICK,
                qty: 1_000_000_000,
            },
        ],
        asks: vec![
            BookLevel {
                price: ask,
                qty: top_qty,
            },
            BookLevel {
                price: ask + 100 * TICK,
                qty: 1_000_000_000,
            },
        ],
        ..book_at(publish_time_ns, seq, true, 100)
    }
}

/// The top size of an honest test book: 0.01 base units.
const TOP_QTY: u64 = 1_000_000;

/// The nodes in address order: the order that decides a tie.
fn by_address(nodes: &[TestNode]) -> Vec<&TestNode> {
    let mut sorted: Vec<&TestNode> = nodes.iter().collect();
    sorted.sort_by_key(|node| node.signing_address());
    sorted
}

#[test]
fn the_book_stays_with_its_node_while_its_top_stays_near_the_median() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .build()
        .expect("three nodes");
    let [first, second, third] = by_address(&nodes)[..] else {
        panic!("three nodes");
    };
    let instrument = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");

    let steps = [
        (third, deep(NOW, 1, 0, TOP_QTY), third, "the only book"),
        (
            first,
            deep(NOW + 200 * MS, 1, 0, TOP_QTY),
            third,
            "a tie keeps the choice",
        ),
        (
            second,
            deep(NOW + 300 * MS, 1, 0, TOP_QTY),
            third,
            "a tie keeps the choice",
        ),
        (
            third,
            deep(NOW + 400 * MS, 2, -100, TOP_QTY),
            third,
            "away for less than 1 s",
        ),
        (
            third,
            deep(NOW + 1_500 * MS, 3, -100, TOP_QTY),
            first,
            "away for 1.1 s",
        ),
        (
            third,
            deep(NOW + 1_600 * MS, 4, 0, TOP_QTY),
            first,
            "no move back",
        ),
    ];
    for (node, frame, expected, why) in steps {
        let at = frame.publish_time_ns;
        assert!(client.ingest_event(&node.sign_book(&frame), at).is_ok());
        let chosen = client.book(&instrument, at).map(|book| book.node);
        assert_eq!(chosen, Some(expected.signing_address()), "{why}");
    }
}

/// In a trend, the current node is one frame behind at every other tick. The
/// choice must not move at each of those ticks.
#[test]
fn a_node_one_frame_behind_in_a_trend_keeps_the_book() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .build()
        .expect("three nodes");
    let [first, second, third] = by_address(&nodes)[..] else {
        panic!("three nodes");
    };
    let instrument = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");
    let send = |client: &mut OracleClient, node: &TestNode, frame: &BookUpdate| {
        let at = frame.publish_time_ns;
        assert!(client.ingest_event(&node.sign_book(frame), at).is_ok());
    };
    send(&mut client, third, &deep(NOW, 1, 0, TOP_QTY));
    assert_eq!(
        client.book(&instrument, NOW).map(|book| book.node),
        Some(third.signing_address())
    );
    for tick in 1..20_u64 {
        let at = NOW + tick * 100 * MS;
        let ticks = i64::try_from(tick).expect("small") * 2;
        for node in [first, second] {
            send(&mut client, node, &deep(at, tick, ticks, TOP_QTY));
        }
        if tick % 2 == 0 {
            send(&mut client, third, &deep(at, tick / 2 + 1, ticks, TOP_QTY));
        }
        let chosen = client.book(&instrument, at).map(|book| book.node);
        assert_eq!(chosen, Some(third.signing_address()), "tick {tick}");
    }
}

/// SPEC §7: one node's book whole. A node that copies the book exactly and
/// stamps newer times must not take it.
#[test]
fn a_node_that_copies_the_book_and_stamps_newer_times_does_not_take_it() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .build()
        .expect("three nodes");
    let [first, second, liar] = by_address(&nodes)[..] else {
        panic!("three nodes");
    };
    let instrument = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");
    let hour = 3_600 * NANOS_PER_SEC;
    for node in [first, second] {
        let honest = BookUpdate {
            exchange_time_ns: Some(NOW),
            ..deep(NOW, 1, 0, TOP_QTY)
        };
        assert!(client.ingest_event(&node.sign_book(&honest), NOW).is_ok());
    }
    let copy = BookUpdate {
        exchange_time_ns: Some(NOW + hour),
        local_recv_ns: NOW + 400 * MS,
        ..deep(NOW + 400 * MS, 1, 0, TOP_QTY)
    };
    assert!(
        client
            .ingest_event(&liar.sign_book(&copy), NOW + 400 * MS)
            .is_ok()
    );
    let chosen = client.book(&instrument, NOW + 400 * MS).expect("a book");
    assert_eq!(chosen.node, first.signing_address());
}

/// A node that copies the top but invents depth is not nearest, and loses the
/// book it held alone once it stays far for the switch margin.
#[test]
fn a_node_that_copies_the_top_but_invents_depth_loses_the_book() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .build()
        .expect("three nodes");
    let [first, second, liar] = by_address(&nodes)[..] else {
        panic!("three nodes");
    };
    let instrument = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");
    let invented = 10_000_000_000;
    let lie = |seq: u64, at: u64| BookUpdate {
        exchange_time_ns: Some(at + 3_600 * NANOS_PER_SEC),
        ..deep(at, seq, 0, invented)
    };
    assert!(
        client
            .ingest_event(&liar.sign_book(&lie(1, NOW)), NOW)
            .is_ok()
    );
    assert_eq!(
        client.book(&instrument, NOW).map(|book| book.node),
        Some(liar.signing_address()),
        "the only book"
    );
    for node in [first, second] {
        let honest = deep(NOW + MS, 1, 0, TOP_QTY);
        assert!(
            client
                .ingest_event(&node.sign_book(&honest), NOW + MS)
                .is_ok()
        );
    }
    for (seq, at, holds) in [(2, NOW + 100 * MS, true), (3, NOW + 1_200 * MS, false)] {
        assert!(
            client
                .ingest_event(&liar.sign_book(&lie(seq, at)), at)
                .is_ok()
        );
        let chosen = client.book(&instrument, at).map(|book| book.node);
        assert_eq!(chosen == Some(liar.signing_address()), holds, "at {at}");
    }
    let chosen = client.book(&instrument, NOW + 1_200 * MS).expect("a book");
    assert_eq!(chosen.node, first.signing_address());
    assert_eq!(chosen.best_bid().map(|level| level.qty), Some(TOP_QTY));
}

#[test]
fn a_node_that_copies_the_funding_and_stamps_newer_times_does_not_take_it() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .build()
        .expect("three nodes");
    let [first, second, liar] = by_address(&nodes)[..] else {
        panic!("three nodes");
    };
    let perpetual = InstrumentId::new(Venue::Bybit, MarketKind::LinearPerp, "BTCUSDT");
    let ahead = NOW + 499 * MS;
    for (node, update) in [
        (first, funding_at(NOW - MS, 1, 100)),
        (second, funding_at(NOW, 1, 100)),
        (liar, funding_at(ahead, 1, 100)),
    ] {
        assert!(
            client
                .ingest_event(&node.sign_funding(&update), NOW)
                .is_ok()
        );
    }
    let chosen = client.funding(&perpetual, NOW).expect("fresh funding");
    assert_eq!(chosen.signer, first.signing_address());
}

/// The rate is the same, but the next funding time is the node's own.
#[test]
fn a_node_off_the_median_on_any_funding_field_does_not_take_it() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .build()
        .expect("three nodes");
    let [liar, first, second] = by_address(&nodes)[..] else {
        panic!("three nodes");
    };
    let perpetual = InstrumentId::new(Venue::Bybit, MarketKind::LinearPerp, "BTCUSDT");
    let at = |time: u64, next: u64| FundingUpdate {
        next_funding_time_ns: Some(next),
        ..funding_at(time, 1, 100)
    };
    let next = NOW + 3_600 * NANOS_PER_SEC;
    for (node, update) in [
        (first, at(NOW - MS, next)),
        (second, at(NOW, next)),
        (liar, at(NOW + 499 * MS, next + 60 * NANOS_PER_SEC)),
    ] {
        assert!(
            client
                .ingest_event(&node.sign_funding(&update), NOW)
                .is_ok()
        );
    }
    let chosen = client.funding(&perpetual, NOW).expect("fresh funding");
    assert_eq!(chosen.signer, first.signing_address());
}

fn feed_set(sources: &[(&str, &str, &str)]) -> oracle_wire::VerifiedFeedSet {
    feed_set_of("CRYPTO.BTC/USD", sources)
}

fn feed_set_of(symbol: &str, sources: &[(&str, &str, &str)]) -> oracle_wire::VerifiedFeedSet {
    let feed = FeedSettings {
        symbol: symbol.to_owned(),
        sources: sources
            .iter()
            .map(|(venue, market, symbol)| SourceSettings {
                venue: (*venue).to_owned(),
                market: (*market).to_owned(),
                symbol: (*symbol).to_owned(),
                ..SourceSettings::default()
            })
            .collect(),
        ..FeedSettings::default()
    };
    FeedSet::sign(
        &governance(),
        1,
        NOW / NANOS_PER_SEC,
        String::new(),
        None,
        vec![feed],
    )
    .expect("signs")
    .verify(governance().address(), 0)
    .expect("verifies")
}

/// A listed node can name any instrument, and each one would stay in memory.
#[test]
fn a_feed_set_limits_books_and_funding_to_its_instruments() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let set = feed_set(&[("binance", "spot", "BTCUSDT")]);
    let mut client = OracleClient::builder(registry)
        .feed_set(set.clone())
        .build()
        .expect("three nodes");
    let [a, ..] = nodes.as_slice() else {
        panic!("three nodes");
    };
    assert!(
        client
            .ingest_event(&a.sign_book(&book_at(NOW, 1, true, 100)), NOW)
            .is_ok()
    );
    assert!(matches!(
        client.ingest_event(&a.sign_funding(&funding_at(NOW, 1, 100)), NOW),
        Err(RejectReason::Unlisted { .. })
    ));
    assert_eq!(client.stats().unlisted, 1);
    assert_eq!(client.funding_instruments().count(), 0);
    assert_eq!(client.set_feed_set(&set).ok(), Some(false), "not newer");
    assert_eq!(client.feed_set_version(), Some(1));
}

#[test]
fn a_slow_feed_ingested_before_the_feed_set_takes_the_slow_limit_from_it() {
    const FUNDING: &str = "CRYPTO.BTC/USD.FUNDING_8H";
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .build()
        .expect("three nodes");
    let symbol: Symbol = FUNDING.parse().expect("a symbol");
    for node in &nodes {
        let update = PriceUpdate {
            feed_id: feed_id(&symbol),
            ..update_at(NOW, 1)
        };
        assert!(client.ingest(&node.sign(&update), NOW).is_ok());
    }
    let set = feed_set_of(FUNDING, &[("bybit", "linear_perp", "BTCUSDT")]);
    assert_eq!(client.set_feed_set(&set).ok(), Some(true));
    let between_heartbeats = client
        .resolve(&symbol, NOW + 9 * NANOS_PER_SEC)
        .expect("a view");
    assert_eq!(between_heartbeats.nodes, 3);
}

#[test]
fn a_local_subscription_names_each_feed_and_sets_its_age_limit_with_no_connection() {
    const FUNDING: &str = "CRYPTO.BTC/USD.FUNDING_8H";
    let node = TestNode::new(1);
    let mut client = OracleClient::builder(registry_with(&[&node]))
        .quorum(1)
        .i_understand_this_provides_no_protection_against_a_bad_node()
        .build()
        .expect("one node, acknowledged");
    let bad = Subscription {
        prices: &["CRYPTO.BTC/USDT", "not a symbol"],
        ..Subscription::default()
    };
    assert!(client.subscribe_local(bad).is_err());
    assert!(client.symbols.is_empty(), "a bad symbol changes nothing");

    // No client key: `subscribe_all` would refuse, and this dials nothing.
    let prices = ["CRYPTO.BTC/USDT", FUNDING];
    let local = Subscription {
        prices: &prices,
        ..Subscription::default()
    };
    client.subscribe_local(local).expect("valid symbols");
    assert!(client.connections.is_empty() && client.subscription.is_none());
    for text in prices {
        let symbol: Symbol = text.parse().expect("a symbol");
        let update = PriceUpdate {
            feed_id: feed_id(&symbol),
            ..update_at(NOW, 1)
        };
        let resolved = client.ingest(&node.sign(&update), NOW).expect("accepted");
        assert_eq!(resolved.symbol, Some(symbol));
    }
    let funding: Symbol = FUNDING.parse().expect("a symbol");
    let between_heartbeats = client
        .resolve(&funding, NOW + 9 * NANOS_PER_SEC)
        .expect("a view");
    assert_eq!(
        between_heartbeats.nodes, 1,
        "the slow limit, not the fast one"
    );
}

#[test]
fn a_new_feed_set_drops_the_books_and_funding_that_it_does_not_list() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .build()
        .expect("three nodes");
    let [a, ..] = nodes.as_slice() else {
        panic!("three nodes");
    };
    let book = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");
    let perpetual = InstrumentId::new(Venue::Bybit, MarketKind::LinearPerp, "BTCUSDT");
    assert!(
        client
            .ingest_event(&a.sign_book(&book_at(NOW, 1, true, 100)), NOW)
            .is_ok()
    );
    assert!(
        client
            .ingest_event(&a.sign_funding(&funding_at(NOW, 1, 100)), NOW)
            .is_ok()
    );
    assert!(client.funding(&perpetual, NOW).is_some());

    let set = feed_set(&[("binance", "spot", "BTCUSDT")]);
    assert_eq!(client.set_feed_set(&set).ok(), Some(true));
    assert_eq!(client.funding_instruments().count(), 0);
    assert!(client.funding(&perpetual, NOW).is_none());
    assert_eq!(client.book_instruments().collect::<Vec<_>>(), vec![&book]);
}

#[test]
fn a_feed_set_of_another_governance_is_refused() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let stranger = oracle_wire::Signer::from_secret(&[0xF1; 32].into()).expect("a valid key");
    let feed = FeedSettings {
        symbol: "CRYPTO.BTC/USD".to_owned(),
        sources: vec![SourceSettings {
            venue: "binance".to_owned(),
            market: "spot".to_owned(),
            symbol: "BTCUSDT".to_owned(),
            ..SourceSettings::default()
        }],
        ..FeedSettings::default()
    };
    let set = FeedSet::sign(
        &stranger,
        1,
        NOW / NANOS_PER_SEC,
        String::new(),
        None,
        vec![feed],
    )
    .expect("signs")
    .verify(stranger.address(), 0)
    .expect("verifies against its own key");
    let mut client = OracleClient::builder(registry.clone())
        .build()
        .expect("three nodes");
    assert!(matches!(
        client.set_feed_set(&set),
        Err(ClientError::FeedSet(
            VerifyError::UntrustedGovernance { .. }
        ))
    ));
    assert_eq!(client.feed_set_version(), None);
    assert!(matches!(
        OracleClient::builder(registry).feed_set(set).build(),
        Err(ClientError::FeedSet(_))
    ));
}

fn nodes() -> Vec<TestNode> {
    (1..=3_u8).map(TestNode::new).collect()
}

#[test]
fn funding_frames_keep_each_node_latest_and_refuse_replays() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .build()
        .expect("three nodes");
    let [a, b, _] = nodes.as_slice() else {
        panic!("three nodes");
    };
    let perpetual = InstrumentId::new(Venue::Bybit, MarketKind::LinearPerp, "BTCUSDT");
    let rate =
        |client: &mut OracleClient, at| client.funding(&perpetual, at).map(|f| f.update.rate);

    // A replayed frame of the server can be a heartbeat old, and passes.
    let old = a.sign_funding(&funding_at(NOW - 60 * NANOS_PER_SEC, 1, 100));
    assert!(matches!(
        client.ingest_event(&old, NOW),
        Ok(Event::Funding(_))
    ));
    let newer = b.sign_funding(&funding_at(NOW, 9, 200));
    assert!(client.ingest_event(&newer, NOW).is_ok());
    let lower = if a.signing_address() < b.signing_address() {
        100
    } else {
        200
    };
    assert_eq!(
        rate(&mut client, NOW),
        Some(lower),
        "a tie: the lower address"
    );

    assert!(matches!(
        client.ingest_event(&old, NOW),
        Err(RejectReason::Replayed { .. })
    ));
    let stale = a.sign_funding(&funding_at(NOW - 121 * NANOS_PER_SEC, 2, 100));
    assert!(matches!(
        client.ingest_event(&stale, NOW),
        Err(RejectReason::TooOld { .. })
    ));
    assert_eq!(client.stats().funding_updates, 2);
    assert_eq!(client.funding_instruments().count(), 1);
    assert_eq!(
        rate(&mut client, NOW + 121 * NANOS_PER_SEC),
        None,
        "too old"
    );
}

#[test]
fn a_quorum_below_three_is_refused_by_default() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    for quorum in [0, 1, 2] {
        let error = OracleClient::builder(registry.clone())
            .quorum(quorum)
            .build()
            .err()
            .expect("must refuse an unsafe quorum");
        assert!(
            matches!(error, ClientError::UnsafeQuorum { .. }),
            "got {error:?}"
        );
    }
}

#[test]
fn a_low_quorum_is_permitted_only_with_an_explicit_acknowledgement() {
    let node = TestNode::new(1);
    let registry = registry_with(&[&node]);
    assert!(
        OracleClient::builder(registry)
            .quorum(1)
            .i_understand_this_provides_no_protection_against_a_bad_node()
            .build()
            .is_ok()
    );
}

#[test]
fn a_quorum_larger_than_the_registry_is_refused() {
    let node = TestNode::new(1);
    let registry = registry_with(&[&node]);
    let error = OracleClient::builder(registry)
        .quorum(3)
        .build()
        .err()
        .expect("must refuse an unreachable quorum");
    assert!(
        matches!(
            error,
            ClientError::UnreachableQuorum {
                requested: 3,
                available: 1
            }
        ),
        "got {error:?}"
    );
}

#[test]
fn three_agreeing_nodes_resolve_to_ok() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .quorum(3)
        .build()
        .expect("valid configuration");

    let mut last = None;
    for node in &nodes {
        last = Some(
            client
                .ingest(&node.sign(&update_at(NOW, 1)), NOW)
                .expect("accepted"),
        );
    }
    let resolved = last.expect("resolved");
    assert_eq!(resolved.status, Status::Ok);
    assert_eq!(resolved.nodes, 3);
    assert_eq!(client.stats().accepted, 3);
}

#[test]
fn an_impostor_is_counted_and_excluded() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .quorum(3)
        .build()
        .expect("valid configuration");

    let impostor = TestNode::new(200);
    assert!(
        client
            .ingest(&impostor.sign(&update_at(NOW, 1)), NOW)
            .is_err()
    );
    assert_eq!(client.stats().untrusted, 1);
    assert_eq!(client.stats().accepted, 0);
}

#[test]
fn a_replay_is_counted_and_refused() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .quorum(3)
        .build()
        .expect("valid configuration");

    let frame = nodes.first().expect("a node").sign(&update_at(NOW, 1));
    assert!(client.ingest(&frame, NOW).is_ok());
    assert!(client.ingest(&frame, NOW).is_err());
    assert_eq!(client.stats().replayed, 1);
}

#[test]
fn one_lying_node_cannot_move_the_resolved_price() {
    let nodes = nodes();
    let registry = registry_with(&nodes.iter().collect::<Vec<_>>());
    let mut client = OracleClient::builder(registry)
        .quorum(3)
        .build()
        .expect("valid configuration");

    let mut honest = update_at(NOW, 1);
    honest.price = 6_400_000_000_000;
    let mut liar = update_at(NOW, 1);
    liar.price = 1;

    let [first, second, third] = nodes.as_slice() else {
        panic!("three nodes")
    };
    client.ingest(&first.sign(&honest), NOW).expect("accepted");
    client.ingest(&second.sign(&honest), NOW).expect("accepted");
    let resolved = client.ingest(&third.sign(&liar), NOW).expect("accepted");

    assert_eq!(
        resolved.price.expect("a price"),
        honest.price_fixed().expect("representable"),
        "the median must ignore the liar"
    );
    // But the disagreement must be visible without anyone looking for it.
    assert_eq!(resolved.status, Status::Degraded);
    assert!(resolved.conf.expect("a band") > oracle_types::Fixed::from_int(1).expect("ok"));
}
