//! The public API of the registry canister (SPEC §3.6, §3.7): the Candid types
//! of its price methods and install arguments, and the limits that a push must
//! keep.
//!
//! No Internet Computer runtime here, so the canister, the node, the SDK and
//! other canisters can use one definition. The `const` assertions at the end
//! hold the limits that depend on each other.

use std::time::Duration;

use candid::{CandidType, Deserialize};
use serde::Serialize;
use serde_bytes::ByteBuf;

/// The most batches that one push carries: `inspect_message` recovers the signer of each.
pub const MAX_FRAMES_PER_PUSH: usize = 4;

/// The largest price batch frame: 32 updates under one signature (SPEC §3.4).
pub const MAX_BATCH_FRAME_BYTES: usize = 1 + 20 + 4 + 32 * 96 + 65;

/// The largest push argument that `inspect_message` decodes.
pub const MAX_PUSH_BYTES: usize = MAX_FRAMES_PER_PUSH * 4 * 1024;

/// How old an update can be when the canister checks the push.
pub const ACCEPT_MAX_AGE: Duration = Duration::from_secs(30);

/// How far ahead of the canister's clock an update can be. IC time can lag wall time.
pub const ACCEPT_MAX_SKEW: Duration = Duration::from_secs(10);

/// The oldest update that a node puts in a push. The rest of [`ACCEPT_MAX_AGE`] is for ingress.
pub const MAX_FRAME_AGE: Duration = Duration::from_secs(25);

/// The production push heartbeat, from `PUSH=60,2,60` (SPEC §3.7).
pub const PRODUCTION_HEARTBEAT_SECS: u64 = 60;

/// The production push deviation in basis points, from `PUSH=60,2,60`.
pub const PRODUCTION_DEVIATION_BPS: u32 = 2;

/// The production minimum push interval, from `PUSH=60,2,60`. One push a minute for each node holds the cycle cost.
pub const PRODUCTION_MIN_INTERVAL_SECS: u64 = 60;

/// The price window until governance sets one: three production heartbeats.
pub const DEFAULT_PRICE_WINDOW: Duration = Duration::from_secs(180);

/// The shortest price window: ingress alone takes some seconds.
pub const MIN_PRICE_WINDOW: Duration = Duration::from_secs(10);

/// The longest price window.
pub const MAX_PRICE_WINDOW: Duration = Duration::from_secs(600);

/// The minimum push interval while the feed set sets no pace, such as before the first feed set.
pub const UNPACED_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// The cycle balance below which the canister refuses pushes. Governance keeps the cycles for its threshold signatures.
pub const CYCLES_RESERVE: u128 = 500_000_000_000;

/// The cycles that another canister attaches to `get_price` or `get_prices`. They pay for the execution.
pub const PRICE_CALL_CYCLES: u128 = 10_000_000;

/// About what one `key_1` threshold signature costs on mainnet (SPEC §3.6).
pub const SIGNATURE_CYCLES: u128 = 26_153_846_153;

/// What `push` did with one update.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Stored as the node's latest batch for its feed.
    Accepted,
    /// The feed is not on the canister's list.
    UnknownFeed,
    /// No registry is published yet.
    NoRegistry,
    /// Malformed, a signature that is not valid, or a signer hint that is not the signer.
    Invalid,
    /// The signer is not a listed node.
    UnknownSigner,
    /// The signer is a key that the registry retired.
    RetiredKey,
    /// The sequence does not advance: the batch or a newer one is stored.
    Replayed,
    /// Published more than 30 s ago.
    TooOld,
    /// More than 10 s ahead of the canister's clock.
    FromTheFuture,
    /// Observed after it was published.
    Incoherent,
}

/// How much to trust a price, in Candid.
#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PriceStatus {
    /// Enough nodes agree.
    Ok,
    /// Usable, but act on `conf`.
    Degraded,
    /// Not usable.
    Halted,
}

/// One feed's price for another canister: integers at the feed's exponent.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PriceRecord {
    /// The 32-byte feed id: keccak256 of the symbol.
    pub feed_id: ByteBuf,
    /// The canonical symbol, such as `CRYPTO.BTC/USD`.
    pub symbol: String,
    /// How much to trust the price.
    pub status: PriceStatus,
    /// The median of the nodes, as a mantissa: price × 10^-expo.
    pub price: Option<i64>,
    /// The confidence half-width, as a mantissa.
    pub conf: Option<u64>,
    /// The decimal exponent of `price` and `conf`.
    pub expo: i32,
    /// The freshest contributing publish time, unix nanoseconds.
    pub publish_time_ns: u64,
    /// Nodes that contributed.
    pub nodes: u32,
    /// Nodes that reported the feed halted.
    pub halted_nodes: u32,
    /// Why the price is not `Ok`, such as `insufficient_nodes`.
    pub concerns: Vec<String>,
    /// The spread between the nodes, in basis points of the price.
    pub spread_bps: Option<String>,
    /// When the canister resolved the price, unix nanoseconds.
    pub resolved_at_ns: u64,
}

/// One listed feed.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FeedInfo {
    /// The 32-byte feed id: keccak256 of the symbol.
    pub feed_id: ByteBuf,
    /// The canonical symbol, such as `CRYPTO.BTC/USD`.
    pub symbol: String,
}

/// Install arguments.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArgs {
    /// Threshold ECDSA key name: `dfx_test_key` locally, `key_1` on mainnet.
    pub key_name: String,
    /// Fewest nodes a consumer should require.
    pub min_nodes: u16,
    /// Recommended quorum.
    pub recommended: u16,
    /// Broadcast-key epoch for the client list. Default 60.
    pub epoch_secs: Option<u64>,
    /// The feeds the canister prices, as canonical symbols. Default none.
    pub feeds: Option<Vec<String>>,
}

// A change to one limit that breaks another fails the build, not a push on mainnet.
const _: () = {
    // A node's oldest update still passes the canister's age check after ingress.
    assert!(MAX_FRAME_AGE.as_nanos() < ACCEPT_MAX_AGE.as_nanos());
    // Four full batches and their Candid framing fit in one push.
    assert!(MAX_FRAMES_PER_PUSH * MAX_BATCH_FRAME_BYTES < MAX_PUSH_BYTES);
    assert!(PRODUCTION_MIN_INTERVAL_SECS <= PRODUCTION_HEARTBEAT_SECS);
    // A quiet feed counts for two heartbeats, so one lost push does not halt it.
    assert!(DEFAULT_PRICE_WINDOW.as_secs() >= 2 * PRODUCTION_HEARTBEAT_SECS);
    assert!(MIN_PRICE_WINDOW.as_secs() <= DEFAULT_PRICE_WINDOW.as_secs());
    assert!(DEFAULT_PRICE_WINDOW.as_secs() <= MAX_PRICE_WINDOW.as_secs());
    // Governance can sign many changes from the reserve.
    assert!(CYCLES_RESERVE >= 10 * SIGNATURE_CYCLES);
};
