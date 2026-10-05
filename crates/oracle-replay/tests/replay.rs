//! A recording replays to the same prices every time, and a changed recording
//! does not. That equality is SPEC §10's cross-node conformance check.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use oracle_ingest::Record;
use oracle_node::NodeConfig;
use oracle_types::NANOS_PER_SEC;
use oracle_wire::Signer;

/// The URL the Binance adapter derives for one spot BTCUSDT feed. Asserted
/// against the adapter's own plan below, so a change there fails loudly.
const BINANCE_SPOT: &str =
    "wss://stream.binance.com:9443/stream?streams=btcusdt@aggTrade/btcusdt@bookTicker";

const CONFIG: &str = r#"
tick_interval_ms = 25

[server]
listen = "127.0.0.1:0"

[signing]
key_env = "UNUSED"

[registry]
path = "unused.json"
governance_address = "0x0000000000000000000000000000000000000001"

[[feeds]]
symbol = "CRYPTO.BTC/USDT"
min_sources = 1
sources = [
  { venue = "binance", market = "spot", symbol = "BTCUSDT" },
]
"#;

static CONFIGS: AtomicUsize = AtomicUsize::new(0);

fn resolved() -> oracle_node::ResolvedConfig {
    let dir = std::env::temp_dir().join(format!("oracle-replay-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("creates");
    // One file per call: the tests run in parallel.
    let path = dir.join(format!(
        "config-{}.toml",
        CONFIGS.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::write(&path, CONFIG).expect("writes");
    NodeConfig::load(&path)
        .expect("loads")
        .resolve()
        .expect("resolves")
}

fn book(t: u64, bid: &str, ask: &str) -> Record {
    Record::Text {
        t,
        url: BINANCE_SPOT.to_owned(),
        text: format!(
            r#"{{"stream":"btcusdt@bookTicker","data":{{"u":1,"s":"BTCUSDT","b":"{bid}","B":"1.5","a":"{ask}","A":"0.7"}}}}"#
        ),
    }
}

/// Twenty quotes over two seconds, drifting up, with a disconnect in the middle.
fn recording() -> Vec<Record> {
    let start = 1_754_582_400 * NANOS_PER_SEC;
    let step = NANOS_PER_SEC / 10;
    let mut records = vec![Record::Connect {
        t: start,
        url: BINANCE_SPOT.to_owned(),
    }];
    for i in 0..10_u64 {
        let price = 64_000 + i * 5;
        records.push(book(
            start + (i + 1) * step,
            &price.to_string(),
            &(price + 1).to_string(),
        ));
    }
    records.push(Record::Close {
        t: start + 11 * step,
        url: BINANCE_SPOT.to_owned(),
        reason: "closed by peer".to_owned(),
    });
    records.push(Record::Connect {
        t: start + 12 * step,
        url: BINANCE_SPOT.to_owned(),
    });
    for i in 10..20_u64 {
        let price = 64_000 + i * 5;
        records.push(book(
            start + (i + 3) * step,
            &price.to_string(),
            &(price + 1).to_string(),
        ));
    }
    records
}

fn signer() -> Signer {
    Signer::from_secret_bytes([0x5E; 32]).expect("valid key")
}

#[tokio::test]
async fn the_binance_adapter_plans_the_url_the_recording_uses() {
    use oracle_ingest::binance::BinanceAdapter;
    use oracle_ingest::transport::WebSocketConnector;
    let adapter = BinanceAdapter::new(resolved().binance, WebSocketConnector).expect("valid");
    let urls: Vec<String> = adapter
        .plan()
        .expect("plans")
        .into_iter()
        .map(|(session, _, _)| session.url)
        .collect();
    assert_eq!(urls, [BINANCE_SPOT]);
}

#[tokio::test]
async fn a_recording_replays_deterministically() {
    let first = tokio::time::timeout(
        Duration::from_secs(30),
        oracle_replay::run(resolved(), recording(), signer(), false),
    )
    .await
    .expect("finishes")
    .expect("replays");
    assert!(
        first.updates.len() >= 2,
        "a drifting book over two seconds must publish: {:?}",
        first.stats
    );
    assert_eq!(first.stats.observations, 20);
    assert_eq!(first.stats.connects, 2);
    assert_eq!(
        first.stats.disconnects, 2,
        "the recorded close, and the end of the recording"
    );
    assert!(first.errors.is_empty(), "{:?}", first.errors);
    // Publish times come from the recording, not from the wall.
    let start = 1_754_582_400 * NANOS_PER_SEC;
    assert!(
        first.updates.iter().all(|u| {
            u.publish_time_ns > start && u.publish_time_ns <= start + 3 * NANOS_PER_SEC
        })
    );

    let second = oracle_replay::run(resolved(), recording(), signer(), false)
        .await
        .expect("replays");
    assert_eq!(second.digest, first.digest, "two replays, one digest");
    assert_eq!(second.updates, first.updates);

    // Change one quote and the digest moves: the digest is of the prices, not
    // of the record count.
    let mut changed = recording();
    if let Some(Record::Text { text, .. }) = changed.get_mut(5) {
        *text = text.replace("64020", "64320");
    }
    let third = oracle_replay::run(resolved(), changed, signer(), false)
        .await
        .expect("replays");
    assert_ne!(third.digest, first.digest);
}

#[tokio::test]
async fn an_empty_recording_is_refused() {
    assert!(matches!(
        oracle_replay::run(resolved(), Vec::new(), signer(), false).await,
        Err(oracle_replay::ReplayError::Empty)
    ));
}
