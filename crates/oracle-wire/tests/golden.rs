//! Frozen protocol vectors.
//!
//! Every value in `vectors/golden.json` is a commitment. If a change to this
//! crate alters any of them, the protocol has forked: signatures issued by the
//! old build will not verify against the new one, and vice versa. That is
//! occasionally the intent — but it must never be a side effect, which is what
//! this test exists to prevent.
//!
//! Regenerate deliberately, and read the resulting diff:
//!
//! ```text
//! REGENERATE_GOLDEN=1 cargo test -p oracle-wire --test golden
//! ```
//!
//! # On self-generated vectors
//!
//! These vectors are produced by the code they check, so on their own they prove
//! only that behaviour has not drifted — not that it was ever right. The
//! independent evidence lives elsewhere and is what makes them meaningful:
//!
//! - `keccak::tests` checks published Keccak-256 vectors, which distinguishes
//!   Keccak-256 from SHA3-256 (they differ only in padding).
//! - `address::tests` derives the canonical Ethereum address for secret key `1`.
//! - `domain::tests` matches a domain separator computed independently by
//!   `foundry` from the EIP-712 definition.
//! - `signature_matches_foundry` below checks a full signature against
//!   `cast wallet sign`, confirming the `r ‖ s ‖ v` layout and the `v` offset of
//!   27 are byte-identical to Ethereum's.
//! - `layout_matches_an_independent_encoder` runs `vectors/check_layout.py`. It
//!   builds every payload again from its JSON with Python's `struct`, from the
//!   SPEC tables, and hashes with `cast keccak`.

use std::fs;
use std::path::PathBuf;

use oracle_types::{
    BookLevel, BookUpdate, FeedId, Flags, FundingBasis, FundingUpdate, MarketKind, NANOS_PER_SEC,
    OpenInterest, OpenInterestUnit, PriceUpdate, SettledFunding, SourceStatus, Symbol, Venue,
    VenueEntry, VenueReport,
};
use oracle_wire::{
    NodeEntry, Quorum, Registry, Signer, UnverifiedBookFrame, UnverifiedFrame,
    UnverifiedFundingFrame, UnverifiedPriceBatch, UnverifiedVenueFrame, decode_book_update,
    decode_funding_update, decode_price_batch, decode_venue_report, domain, encode_book_update,
    encode_funding_update, encode_price_batch, encode_price_update, encode_venue_report, feed_id,
};
use serde::{Deserialize, Serialize};

const BASE_TIME_NS: u64 = 1_754_582_400_000_000_000;

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/golden.json")
}

// ---------------------------------------------------------------- file schema

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct GoldenFile {
    note: String,
    domain: DomainVector,
    feed_ids: Vec<FeedIdVector>,
    price_updates: Vec<UpdateVector>,
    registry: RegistryVector,
    venue_reports: Vec<VenueReportVector>,
    book_updates: Vec<BookUpdateVector>,
    funding_updates: Vec<FundingUpdateVector>,
    price_batches: Vec<PriceBatchVector>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct PriceBatchVector {
    name: String,
    secret_key: String,
    signer: String,
    updates: Vec<PriceUpdate>,
    payload: String,
    digest: String,
    signature: String,
    frame: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct VenueReportVector {
    name: String,
    secret_key: String,
    signer: String,
    report: VenueReport,
    payload: String,
    digest: String,
    signature: String,
    frame: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct BookUpdateVector {
    name: String,
    secret_key: String,
    signer: String,
    update: BookUpdate,
    payload: String,
    digest: String,
    signature: String,
    frame: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct FundingUpdateVector {
    name: String,
    secret_key: String,
    signer: String,
    update: FundingUpdate,
    payload: String,
    digest: String,
    signature: String,
    frame: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct DomainVector {
    name: String,
    version: String,
    chain_id: u64,
    separator: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct FeedIdVector {
    symbol: String,
    expo: i32,
    feed_id: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct UpdateVector {
    name: String,
    secret_key: String,
    signer: String,
    update: PriceUpdate,
    payload: String,
    digest: String,
    signature: String,
    frame: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RegistryVector {
    governance_secret_key: String,
    governance_address: String,
    registry: Registry,
    signing_bytes: String,
    digest: String,
}

// ------------------------------------------------------------------ generation

fn signer_from(seed: u8) -> ([u8; 32], Signer) {
    let secret = [seed; 32];
    (
        secret,
        Signer::from_secret_bytes(secret).expect("valid secret key"),
    )
}

fn sample_updates() -> Vec<(&'static str, u8, PriceUpdate)> {
    let btc = feed_id(&"CRYPTO.BTC/USD".parse::<Symbol>().expect("valid symbol"));
    let funding = feed_id(
        &"CRYPTO.BTC/USD.FUNDING_8H"
            .parse::<Symbol>()
            .expect("valid symbol"),
    );

    /// The five venues these vectors were minted with.
    ///
    /// Spelled out rather than taken from `Venue::ALL`, which grows: a vector
    /// built from a moving constant re-mints itself every time a venue is added
    /// and proves nothing about the bytes that were actually signed.
    const V1_VENUES: [Venue; 5] = [
        Venue::Binance,
        Venue::Bybit,
        Venue::Okx,
        Venue::Coinbase,
        Venue::Kraken,
    ];

    vec![
        (
            "btc_usd_healthy",
            0x11,
            PriceUpdate {
                feed_id: btc,
                flags: Flags::NONE,
                price: 6_431_250_000_000,
                conf: 3_200_000,
                expo: -8,
                publish_time_ns: BASE_TIME_NS,
                observation_time_ns: BASE_TIME_NS - 2_000_000,
                prev_publish_time_ns: BASE_TIME_NS - NANOS_PER_SEC,
                seq: 918_273,
                num_sources: 5,
                sources: V1_VENUES.into_iter().collect(),
            },
        ),
        (
            "btc_usd_degraded_synthetic",
            0x11,
            PriceUpdate {
                feed_id: btc,
                flags: Flags::DEGRADED | Flags::SYNTHETIC_QUOTE,
                price: 6_400_000_000_000,
                conf: 32_000_000_000,
                expo: -8,
                publish_time_ns: BASE_TIME_NS + NANOS_PER_SEC,
                observation_time_ns: BASE_TIME_NS + NANOS_PER_SEC - 900_000_000,
                prev_publish_time_ns: BASE_TIME_NS,
                seq: 918_274,
                num_sources: 2,
                sources: [Venue::Binance, Venue::Okx].into_iter().collect(),
            },
        ),
        (
            "btc_usd_halted",
            0x11,
            PriceUpdate {
                feed_id: btc,
                flags: Flags::HALTED,
                price: 6_400_000_000_000,
                conf: 640_000_000_000,
                expo: -8,
                publish_time_ns: BASE_TIME_NS + 2 * NANOS_PER_SEC,
                observation_time_ns: BASE_TIME_NS,
                prev_publish_time_ns: BASE_TIME_NS + NANOS_PER_SEC,
                seq: 918_275,
                num_sources: 0,
                sources: [].into_iter().collect(),
            },
        ),
        (
            "funding_rate_negative",
            0x12,
            PriceUpdate {
                feed_id: funding,
                flags: Flags::NONE,
                // -1.25 bps over 8h, at exponent -9.
                price: -125_000,
                conf: 4_000,
                expo: -9,
                publish_time_ns: BASE_TIME_NS,
                observation_time_ns: BASE_TIME_NS - 30 * NANOS_PER_SEC,
                prev_publish_time_ns: 0,
                seq: 1,
                num_sources: 3,
                sources: [Venue::Binance, Venue::Bybit, Venue::Okx]
                    .into_iter()
                    .collect(),
            },
        ),
        (
            "boundary_extremes",
            0x13,
            PriceUpdate {
                feed_id: FeedId::from_bytes([0xFF; 32]),
                flags: Flags::HALTED | Flags::DEGRADED | Flags::SYNTHETIC_QUOTE,
                price: i64::MIN,
                conf: u64::MAX,
                expo: i32::MIN,
                publish_time_ns: u64::MAX,
                observation_time_ns: u64::MAX,
                prev_publish_time_ns: u64::MAX,
                seq: u64::MAX,
                num_sources: u32::MAX,
                sources: V1_VENUES.into_iter().collect(),
            },
        ),
    ]
}

fn entry(venue: Venue, market: MarketKind, status: SourceStatus) -> VenueEntry {
    let symbol = match venue {
        Venue::Binance | Venue::Bybit => "BTCUSDT",
        Venue::Okx => "BTC-USDT",
        Venue::Coinbase => "BTC-USD",
        Venue::Kraken => "BTC/USD",
        Venue::Deribit => "BTC-PERPETUAL",
        Venue::Hyperliquid => "BTC",
        Venue::Bitfinex => "tBTCUSD",
        Venue::Mexc => "BTCUSDT",
        Venue::Kucoin => "BTC-USDT",
        // A venue added later; these vectors never use it.
        _ => "OTHER",
    };
    VenueEntry {
        venue,
        market,
        symbol: symbol.to_owned(),
        status,
        weight_bps: 0,
        bid: None,
        ask: None,
        bid_qty: None,
        ask_qty: None,
        impact_bid: None,
        impact_ask: None,
        mark: None,
        index: None,
        funding: None,
        exchange_time_ns: None,
        local_recv_ns: 0,
    }
}

fn sample_venue_reports() -> Vec<(&'static str, VenueReport)> {
    // The six venues these vectors were minted with; `Venue::ALL` grows.
    const MINTED: [Venue; 6] = [
        Venue::Binance,
        Venue::Bybit,
        Venue::Okx,
        Venue::Coinbase,
        Venue::Kraken,
        Venue::Deribit,
    ];
    let usdt: Symbol = "CRYPTO.BTC/USDT".parse().expect("valid symbol");
    let every_status = SourceStatus::ALL
        .into_iter()
        .zip(MINTED.into_iter().cycle())
        .map(|(status, venue)| VenueEntry {
            weight_bps: 10_000,
            bid: Some(i64::MAX),
            ask: Some(i64::MIN),
            bid_qty: Some(u64::MAX),
            ask_qty: Some(0),
            impact_bid: Some(-1),
            impact_ask: Some(1),
            mark: Some(i64::MAX),
            index: Some(i64::MIN),
            funding: Some(i64::MIN),
            exchange_time_ns: Some(u64::MAX),
            local_recv_ns: u64::MAX,
            symbol: "X".repeat(oracle_types::MAX_VENUE_SYMBOL),
            ..entry(venue, MarketKind::LinearPerp, status)
        })
        .collect();
    vec![
        (
            "btc_usdt_three_venues",
            VenueReport {
                feed_id: feed_id(&usdt),
                publish_time_ns: BASE_TIME_NS,
                seq: 1_754_582_400_000,
                expo: -8,
                entries: vec![
                    VenueEntry {
                        weight_bps: 6_000,
                        bid: Some(6_431_250_000_000),
                        ask: Some(6_431_251_000_000),
                        bid_qty: Some(107_005_000),
                        ask_qty: Some(466_373_000),
                        impact_bid: Some(6_431_240_000_000),
                        impact_ask: Some(6_431_262_000_000),
                        exchange_time_ns: Some(BASE_TIME_NS - 40_000_000),
                        local_recv_ns: BASE_TIME_NS - 2_000_000,
                        ..entry(Venue::Binance, MarketKind::Spot, SourceStatus::Used)
                    },
                    VenueEntry {
                        mark: Some(6_432_000_000_000),
                        index: Some(6_431_900_000_000),
                        funding: Some(-12_500),
                        local_recv_ns: BASE_TIME_NS - 3_000_000_000,
                        ..entry(Venue::Deribit, MarketKind::InversePerp, SourceStatus::Stale)
                    },
                    entry(Venue::Kraken, MarketKind::Spot, SourceStatus::NoData),
                ],
            },
        ),
        (
            "boundary_extremes",
            VenueReport {
                feed_id: FeedId::from_bytes([0xFF; 32]),
                publish_time_ns: u64::MAX,
                seq: u64::MAX,
                expo: i32::MIN,
                entries: every_status,
            },
        ),
        (
            "no_entries",
            VenueReport {
                feed_id: feed_id(&usdt),
                publish_time_ns: BASE_TIME_NS,
                seq: 1,
                expo: -8,
                entries: Vec::new(),
            },
        ),
    ]
}

fn sample_book_updates() -> Vec<(&'static str, BookUpdate)> {
    let level = |price, qty| BookLevel { price, qty };
    vec![
        (
            "binance_snapshot",
            BookUpdate {
                venue: Venue::Binance,
                market: MarketKind::Spot,
                symbol: "BTCUSDT".to_owned(),
                publish_time_ns: BASE_TIME_NS,
                seq: 1_754_582_400_001,
                snapshot: true,
                exchange_time_ns: Some(BASE_TIME_NS - 40_000_000),
                local_recv_ns: BASE_TIME_NS - 1_000_000,
                venue_seq: Some(73_514_215_042),
                bids: vec![
                    level(8_377_800_000_000, 494_541_000),
                    level(8_377_790_000_000, 12_000_000),
                ],
                asks: vec![
                    level(8_377_801_000_000, 842_661_000),
                    level(8_377_850_000_000, 3_000_000),
                ],
            },
        ),
        (
            "okx_swap_delta",
            BookUpdate {
                venue: Venue::Okx,
                market: MarketKind::LinearPerp,
                symbol: "BTC-USDT-SWAP".to_owned(),
                publish_time_ns: BASE_TIME_NS + 50_000_000,
                seq: 1_754_582_400_002,
                snapshot: false,
                exchange_time_ns: None,
                local_recv_ns: BASE_TIME_NS + 49_000_000,
                venue_seq: None,
                bids: vec![level(8_378_000_000_000, 0)],
                asks: vec![
                    level(8_378_010_000_000, 158_930_282),
                    level(8_378_100_000_000, 0),
                ],
            },
        ),
        (
            "boundary_extremes",
            BookUpdate {
                venue: Venue::Deribit,
                market: MarketKind::InversePerp,
                symbol: "X".repeat(oracle_types::MAX_VENUE_SYMBOL),
                publish_time_ns: u64::MAX,
                seq: u64::MAX,
                snapshot: false,
                exchange_time_ns: Some(u64::MAX),
                local_recv_ns: u64::MAX,
                venue_seq: Some(u64::MAX),
                bids: vec![level(i64::MAX, u64::MAX), level(i64::MIN, 0)],
                asks: vec![level(i64::MIN, 0), level(i64::MAX, u64::MAX)],
            },
        ),
    ]
}

fn sample_funding_updates() -> Vec<(&'static str, FundingUpdate)> {
    const HOUR_NS: u64 = 3_600 * NANOS_PER_SEC;
    vec![
        (
            "okx_swap_settled",
            FundingUpdate {
                venue: Venue::Okx,
                market: MarketKind::LinearPerp,
                symbol: "BTC-USDT-SWAP".to_owned(),
                publish_time_ns: BASE_TIME_NS,
                seq: 1_754_582_400_003,
                basis: FundingBasis::Interval,
                rate: -30_339_016,
                predicted_rate: None,
                interval_ns: Some(8 * HOUR_NS),
                next_funding_time_ns: Some(BASE_TIME_NS + 5 * HOUR_NS),
                settled: Some(SettledFunding {
                    rate: 6_729_944,
                    time_ns: BASE_TIME_NS - 3 * HOUR_NS,
                }),
                open_interest: None,
                exchange_time_ns: Some(BASE_TIME_NS - 17_000_000_000),
                local_recv_ns: BASE_TIME_NS - 16_900_000_000,
            },
        ),
        (
            "deribit_eight_hours",
            FundingUpdate {
                venue: Venue::Deribit,
                market: MarketKind::InversePerp,
                symbol: "BTC-PERPETUAL".to_owned(),
                publish_time_ns: BASE_TIME_NS + 1_000_000_000,
                seq: 1_754_582_400_004,
                basis: FundingBasis::EightHours,
                rate: 108_460_000,
                predicted_rate: None,
                interval_ns: None,
                next_funding_time_ns: None,
                settled: None,
                open_interest: Some(OpenInterest {
                    amount: 81_919_585_000_000_000,
                    unit: OpenInterestUnit::Quote,
                }),
                exchange_time_ns: Some(BASE_TIME_NS + 900_000_000),
                local_recv_ns: BASE_TIME_NS + 950_000_000,
            },
        ),
        (
            "boundary_extremes",
            FundingUpdate {
                venue: Venue::Kraken,
                market: MarketKind::LinearPerp,
                symbol: "X".repeat(oracle_types::MAX_VENUE_SYMBOL),
                publish_time_ns: u64::MAX,
                seq: u64::MAX,
                basis: FundingBasis::Interval,
                rate: i64::MIN,
                predicted_rate: Some(i64::MAX),
                interval_ns: Some(u64::MAX),
                next_funding_time_ns: Some(u64::MAX),
                settled: Some(SettledFunding {
                    rate: i64::MIN,
                    time_ns: u64::MAX,
                }),
                open_interest: Some(OpenInterest {
                    amount: u64::MAX,
                    unit: OpenInterestUnit::Contracts,
                }),
                exchange_time_ns: Some(u64::MAX),
                local_recv_ns: u64::MAX,
            },
        ),
    ]
}

fn build() -> GoldenFile {
    let feed_ids = [
        "CRYPTO.BTC/USD",
        "CRYPTO.ETH/USD",
        "CRYPTO.SOL/USD",
        "CRYPTO.USDT/USD",
        "CRYPTO.BTC/USD.PERP_MARK",
        "CRYPTO.BTC/USD.PERP_INDEX",
        "CRYPTO.BTC/USD.FUNDING_8H",
        "CRYPTO.BTC/USD.OPEN_INTEREST",
        "CRYPTO.1000PEPE/USDT.PERP_MARK",
    ]
    .into_iter()
    .map(|text| {
        let symbol: Symbol = text.parse().expect("valid symbol");
        FeedIdVector {
            symbol: text.to_owned(),
            expo: symbol.expo(),
            feed_id: feed_id(&symbol).to_string(),
        }
    })
    .collect();

    let price_updates = sample_updates()
        .into_iter()
        .map(|(name, seed, update)| {
            let (secret, signer) = signer_from(seed);
            let signed = signer.sign_update(&update);
            UpdateVector {
                name: name.to_owned(),
                secret_key: hex0x(&secret),
                signer: signer.address().to_string(),
                update,
                payload: hex0x(signed.payload()),
                digest: hex0x(&domain::digest(signed.payload())),
                signature: signed.signature().to_string(),
                frame: hex0x(&signed.encode_frame()),
            }
        })
        .collect();

    // The node that signed the `btc_usd_healthy` vector.
    let (_, node) = signer_from(0x11);
    let (governance_secret, governance) = signer_from(0x91);
    let registry = Registry::sign(
        &governance,
        1,
        BASE_TIME_NS / NANOS_PER_SEC,
        vec![NodeEntry {
            address: node.address(),
            endpoints: vec!["wss://eu1.oracle.example/v2/ws".to_owned()],
            weight: 1,
        }],
        Quorum {
            min_nodes: 3,
            recommended: 5,
        },
    )
    .expect("signs");
    let registry_bytes = registry.to_signing_bytes().expect("encodes");

    // The registry's node signs these too, so stored frames verify against it.
    let (node_secret, node) = signer_from(0x11);
    let venue_reports = sample_venue_reports()
        .into_iter()
        .map(|(name, report)| {
            let signed = node.sign_venue_report(&report).expect("encodes");
            VenueReportVector {
                name: name.to_owned(),
                secret_key: hex0x(&node_secret),
                signer: node.address().to_string(),
                report,
                payload: hex0x(signed.payload()),
                digest: hex0x(&domain::digest(signed.payload())),
                signature: signed.signature().to_string(),
                frame: hex0x(&signed.encode_frame()),
            }
        })
        .collect();
    let book_updates = sample_book_updates()
        .into_iter()
        .map(|(name, update)| {
            let signed = node.sign_book_update(&update).expect("encodes");
            BookUpdateVector {
                name: name.to_owned(),
                secret_key: hex0x(&node_secret),
                signer: node.address().to_string(),
                update,
                payload: hex0x(signed.payload()),
                digest: hex0x(&domain::digest(signed.payload())),
                signature: signed.signature().to_string(),
                frame: hex0x(&signed.encode_frame()),
            }
        })
        .collect();

    let funding_updates = sample_funding_updates()
        .into_iter()
        .map(|(name, update)| {
            let signed = node.sign_funding_update(&update).expect("encodes");
            FundingUpdateVector {
                name: name.to_owned(),
                secret_key: hex0x(&node_secret),
                signer: node.address().to_string(),
                update,
                payload: hex0x(signed.payload()),
                digest: hex0x(&domain::digest(signed.payload())),
                signature: signed.signature().to_string(),
                frame: hex0x(&signed.encode_frame()),
            }
        })
        .collect();

    let update = |name: &str| {
        sample_updates()
            .into_iter()
            .find(|(sample, _, _)| *sample == name)
            .map(|(_, _, update)| update)
            .expect("a sample update")
    };
    let price_batches = [
        (
            "btc_and_funding",
            vec![update("btc_usd_healthy"), update("funding_rate_negative")],
        ),
        ("one_halted_update", vec![update("btc_usd_halted")]),
    ]
    .into_iter()
    .map(|(name, updates)| {
        let signed = node.sign_price_batch(&updates).expect("encodes");
        PriceBatchVector {
            name: name.to_owned(),
            secret_key: hex0x(&node_secret),
            signer: node.address().to_string(),
            updates,
            payload: hex0x(signed.payload()),
            digest: hex0x(&domain::digest(signed.payload())),
            signature: signed.signature().to_string(),
            frame: hex0x(&signed.encode_frame()),
        }
    })
    .collect();

    GoldenFile {
        note: "Frozen protocol vectors. A diff here means the wire format changed \
               and previously-issued signatures no longer verify."
            .to_owned(),
        domain: DomainVector {
            name: domain::DOMAIN_NAME.to_owned(),
            version: domain::DOMAIN_VERSION.to_owned(),
            chain_id: domain::DOMAIN_CHAIN_ID,
            separator: hex0x(&domain::domain_separator()),
        },
        feed_ids,
        price_updates,
        registry: RegistryVector {
            governance_secret_key: hex0x(&governance_secret),
            governance_address: governance.address().to_string(),
            signing_bytes: hex0x(&registry_bytes),
            digest: hex0x(&domain::digest(&registry_bytes)),
            registry,
        },
        venue_reports,
        book_updates,
        funding_updates,
        price_batches,
    }
}

fn load() -> GoldenFile {
    let path = vectors_path();
    let text = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}. Regenerate with REGENERATE_GOLDEN=1",
            path.display()
        )
    });
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

// ----------------------------------------------------------------------- tests

#[test]
fn golden_vectors_are_unchanged() {
    let generated = build();

    if std::env::var_os("REGENERATE_GOLDEN").is_some() {
        let path = vectors_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("creates vector directory");
        }
        let mut json = serde_json::to_string_pretty(&generated).expect("serializes");
        json.push('\n');
        fs::write(&path, json).expect("writes vectors");
        eprintln!("regenerated {}", path.display());
        return;
    }

    let expected = load();

    assert_eq!(
        generated.domain, expected.domain,
        "domain separator changed"
    );

    assert_eq!(
        generated.feed_ids.len(),
        expected.feed_ids.len(),
        "feed id vector count changed"
    );
    for (got, want) in generated.feed_ids.iter().zip(&expected.feed_ids) {
        assert_eq!(got, want, "feed id derivation changed for {}", want.symbol);
    }

    assert_eq!(
        generated.price_updates.len(),
        expected.price_updates.len(),
        "price update vector count changed"
    );
    for (got, want) in generated.price_updates.iter().zip(&expected.price_updates) {
        assert_eq!(
            got.payload, want.payload,
            "payload encoding changed for `{}`",
            want.name
        );
        assert_eq!(
            got.digest, want.digest,
            "digest changed for `{}`",
            want.name
        );
        assert_eq!(
            got.signature, want.signature,
            "signature changed for `{}`",
            want.name
        );
        assert_eq!(
            got.frame, want.frame,
            "frame encoding changed for `{}`",
            want.name
        );
        assert_eq!(
            got.signer, want.signer,
            "address derivation changed for `{}`",
            want.name
        );
        assert_eq!(
            got.update, want.update,
            "update JSON changed for `{}`",
            want.name
        );
    }

    assert_eq!(
        generated.registry, expected.registry,
        "registry encoding changed"
    );
    assert_eq!(
        generated.venue_reports, expected.venue_reports,
        "venue report encoding changed"
    );
    assert_eq!(
        generated.book_updates, expected.book_updates,
        "book update encoding changed"
    );
    assert_eq!(
        generated.funding_updates, expected.funding_updates,
        "funding update encoding changed"
    );
    assert_eq!(
        generated.price_batches, expected.price_batches,
        "price batch encoding changed"
    );
}

/// The stored vectors must still verify end to end, not merely match byte for byte.
#[test]
fn stored_frames_verify_against_the_stored_registry() {
    let file = load();
    let governance = file
        .registry
        .governance_address
        .parse()
        .expect("valid governance address");
    let registry = file
        .registry
        .registry
        .verify(governance, 0)
        .expect("registry verifies");

    let vector = file
        .price_updates
        .iter()
        .find(|v| v.name == "btc_usd_healthy")
        .expect("healthy vector present");

    let frame = hex::decode(vector.frame.trim_start_matches("0x")).expect("valid hex");
    let parsed = UnverifiedFrame::parse(&frame).expect("frame parses");
    let verified = parsed.verify(&registry).expect("frame verifies");

    assert_eq!(verified.update(), &vector.update);
    assert_eq!(verified.signer().to_string(), vector.signer);

    for vector in &file.venue_reports {
        let frame = hex::decode(vector.frame.trim_start_matches("0x")).expect("valid hex");
        let verified = UnverifiedVenueFrame::parse(&frame)
            .expect("frame parses")
            .verify(&registry)
            .unwrap_or_else(|e| panic!("`{}` does not verify: {e}", vector.name));
        assert_eq!(verified.report(), &vector.report);
    }
    for vector in &file.book_updates {
        let frame = hex::decode(vector.frame.trim_start_matches("0x")).expect("valid hex");
        let verified = UnverifiedBookFrame::parse(&frame)
            .expect("frame parses")
            .verify(&registry)
            .unwrap_or_else(|e| panic!("`{}` does not verify: {e}", vector.name));
        assert_eq!(verified.update(), &vector.update);
    }
    for vector in &file.funding_updates {
        let frame = hex::decode(vector.frame.trim_start_matches("0x")).expect("valid hex");
        let verified = UnverifiedFundingFrame::parse(&frame)
            .expect("frame parses")
            .verify(&registry)
            .unwrap_or_else(|e| panic!("`{}` does not verify: {e}", vector.name));
        assert_eq!(verified.update(), &vector.update);
    }
    for vector in &file.price_batches {
        let frame = hex::decode(vector.frame.trim_start_matches("0x")).expect("valid hex");
        let verified = UnverifiedPriceBatch::parse(&frame)
            .expect("frame parses")
            .verify(&registry)
            .unwrap_or_else(|e| panic!("`{}` does not verify: {e}", vector.name));
        assert_eq!(verified.updates(), vector.updates.as_slice());
    }
}

/// Decoding the stored payload must reproduce the stored logical update, and
/// re-encoding it must reproduce the stored bytes.
#[test]
fn stored_payloads_round_trip() {
    for vector in load().price_updates {
        let bytes = hex::decode(vector.payload.trim_start_matches("0x")).expect("valid hex");
        let decoded = oracle_wire::decode_price_update(&bytes)
            .unwrap_or_else(|e| panic!("`{}` failed to decode: {e}", vector.name));
        assert_eq!(
            decoded, vector.update,
            "`{}` decoded to a different update",
            vector.name
        );
        assert_eq!(
            hex0x(&encode_price_update(&decoded)),
            vector.payload,
            "`{}` did not re-encode identically",
            vector.name
        );
    }
    let file = load();
    for vector in file.venue_reports {
        let bytes = hex::decode(vector.payload.trim_start_matches("0x")).expect("valid hex");
        let decoded = decode_venue_report(&bytes).expect("decodes");
        assert_eq!(decoded, vector.report, "`{}`", vector.name);
        assert_eq!(
            hex0x(&encode_venue_report(&decoded).expect("encodes")),
            vector.payload,
            "`{}` did not re-encode identically",
            vector.name
        );
    }
    for vector in file.book_updates {
        let bytes = hex::decode(vector.payload.trim_start_matches("0x")).expect("valid hex");
        let decoded = decode_book_update(&bytes).expect("decodes");
        assert_eq!(decoded, vector.update, "`{}`", vector.name);
        assert_eq!(
            hex0x(&encode_book_update(&decoded).expect("encodes")),
            vector.payload,
            "`{}` did not re-encode identically",
            vector.name
        );
    }
    for vector in file.price_batches {
        let bytes = hex::decode(vector.payload.trim_start_matches("0x")).expect("valid hex");
        let decoded = decode_price_batch(&bytes).expect("decodes");
        assert_eq!(decoded, vector.updates, "`{}`", vector.name);
        assert_eq!(
            hex0x(&encode_price_batch(&decoded).expect("encodes")),
            vector.payload,
            "`{}` did not re-encode identically",
            vector.name
        );
    }
    for vector in file.funding_updates {
        let bytes = hex::decode(vector.payload.trim_start_matches("0x")).expect("valid hex");
        let decoded = decode_funding_update(&bytes).expect("decodes");
        assert_eq!(decoded, vector.update, "`{}`", vector.name);
        assert_eq!(
            hex0x(&encode_funding_update(&decoded).expect("encodes")),
            vector.payload,
            "`{}` did not re-encode identically",
            vector.name
        );
    }
}

/// Cross-check against `foundry`, an independent secp256k1 and Keccak-256
/// implementation, that our signature bytes are exactly Ethereum's.
///
/// Skipped when `cast` is not installed, so it does not break a clean checkout.
/// The command signs the raw digest with no further hashing:
///
/// ```text
/// cast wallet sign --no-hash <digest> --private-key <secret>
/// ```
#[test]
fn signature_matches_foundry() {
    let Ok(cast) = which_cast() else {
        eprintln!("skipping: `cast` not found on PATH");
        return;
    };

    let file = load();
    let signed = file
        .price_updates
        .iter()
        .map(|v| (&v.name, &v.digest, &v.secret_key, &v.signature))
        .chain(
            file.venue_reports
                .iter()
                .map(|v| (&v.name, &v.digest, &v.secret_key, &v.signature)),
        )
        .chain(
            file.book_updates
                .iter()
                .map(|v| (&v.name, &v.digest, &v.secret_key, &v.signature)),
        )
        .chain(
            file.funding_updates
                .iter()
                .map(|v| (&v.name, &v.digest, &v.secret_key, &v.signature)),
        );
    for (name, digest, secret_key, signature) in signed {
        let output = std::process::Command::new(&cast)
            .args([
                "wallet",
                "sign",
                "--no-hash",
                digest,
                "--private-key",
                secret_key,
            ])
            .output()
            .expect("runs cast");
        assert!(
            output.status.success(),
            "cast failed for `{name}`: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let produced = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase();
        assert_eq!(
            &produced, signature,
            "`{name}`: our signature bytes differ from foundry's"
        );
    }
}

/// Builds every stored payload again in Python, from its JSON and the SPEC
/// tables, and hashes it with `cast keccak`: neither the layout nor the hash
/// comes from this crate.
///
/// Skipped when `python3` or `cast` is not installed.
#[test]
fn layout_matches_an_independent_encoder() {
    if which_cast().is_err() {
        eprintln!("skipping: `cast` not found on PATH");
        return;
    }
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/check_layout.py");
    let Ok(output) = std::process::Command::new("python3")
        .arg(&script)
        .arg(vectors_path())
        .output()
    else {
        eprintln!("skipping: `python3` not found");
        return;
    };
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn which_cast() -> Result<String, ()> {
    let output = std::process::Command::new("which")
        .arg("cast")
        .output()
        .map_err(|_| ())?;
    if !output.status.success() {
        return Err(());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
