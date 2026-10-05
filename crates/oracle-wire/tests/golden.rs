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

use std::fs;
use std::path::PathBuf;

use oracle_types::{FeedId, Flags, NANOS_PER_SEC, PriceUpdate, Symbol, Venue};
use oracle_wire::{
    NodeEntry, Quorum, Registry, Signer, UnverifiedFrame, domain, encode_price_update, feed_id,
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
            operator: "acme".to_owned(),
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
    for vector in &file.price_updates {
        let output = std::process::Command::new(&cast)
            .args([
                "wallet",
                "sign",
                "--no-hash",
                &vector.digest,
                "--private-key",
                &vector.secret_key,
            ])
            .output()
            .expect("runs cast");
        assert!(
            output.status.success(),
            "cast failed for `{}`: {}",
            vector.name,
            String::from_utf8_lossy(&output.stderr)
        );
        let produced = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase();
        assert_eq!(
            produced, vector.signature,
            "`{}`: our signature bytes differ from foundry's",
            vector.name
        );
    }
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
