//! Pushes the node's latest updates to the registry canister.
//!
//! The node signs the due updates as one batch, so the canister checks one
//! signature for the push, and calls `push` as the anonymous identity: the
//! signature is the credential, and the node holds no Internet Computer key.
//! One push is in flight at a time, and a line each minute says how it went.

use std::sync::Arc;
use std::time::Duration;

use candid::{CandidType, Decode, Deserialize, Encode};
use ic_agent::Agent;
use ic_agent::export::Principal;
use oracle_ingest::clock::wall_clock_unix_nanos;
use oracle_node::publish::{PushPace, PushPlanner, PushTarget};
use oracle_server::ServerState;
use oracle_types::{FeedId, PriceUpdate};
use oracle_wire::Signer;
use serde_bytes::ByteBuf;
use tokio::sync::watch;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::status::STATUS_EVERY;

/// How long one push can take, ingress and execution.
const PUSH_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the node reads the canister's feed list again.
const FEEDS_EVERY: Duration = Duration::from_secs(600);
/// How soon the node reads the feed list again after a failed read.
const FEEDS_RETRY: Duration = Duration::from_secs(30);

/// The canister's `Verdict` on one frame.
#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Accepted,
    UnknownFeed,
    NoRegistry,
    Invalid,
    UnknownSigner,
    RetiredKey,
    Replayed,
    TooOld,
    FromTheFuture,
    Incoherent,
}

/// The part of the canister's `FeedInfo` that the node reads.
#[derive(CandidType, Deserialize)]
struct FeedInfo {
    feed_id: ByteBuf,
}

/// The pushes over one status interval.
#[derive(Default)]
struct Minute {
    pushes: u64,
    accepted: u64,
    refused: u64,
    failures: u64,
    last_refusal: Option<Verdict>,
    last_error: Option<String>,
}

impl Minute {
    fn failed(&mut self, error: String) {
        self.failures = self.failures.saturating_add(1);
        self.last_error = Some(error);
    }

    fn log(&self, feeds: usize) {
        if self.pushes == 0 && self.failures == 0 {
            return;
        }
        if self.refused == 0 && self.failures == 0 {
            info!(
                feeds,
                pushes = self.pushes,
                accepted = self.accepted,
                "canister pushes"
            );
        } else {
            warn!(
                feeds,
                pushes = self.pushes,
                accepted = self.accepted,
                refused = self.refused,
                failures = self.failures,
                last_refusal = ?self.last_refusal,
                error = self.last_error.as_deref().unwrap_or(""),
                "canister pushes"
            );
        }
    }
}

/// Starts the pushes. The task stops with `shutdown`.
pub(crate) fn spawn(
    state: Arc<ServerState>,
    signer: Arc<Signer>,
    target: PushTarget,
    pace: watch::Receiver<PushPace>,
    shutdown: CancellationToken,
) {
    tokio::spawn(run(state, signer, target, pace, shutdown));
}

async fn run(
    state: Arc<ServerState>,
    signer: Arc<Signer>,
    target: PushTarget,
    mut pace: watch::Receiver<PushPace>,
    shutdown: CancellationToken,
) {
    let agent = match agent(&target) {
        Ok(agent) => agent,
        Err(error) => {
            warn!(%error, "cannot build the agent for the canister; no pushes");
            return;
        }
    };
    let canister = target.canister;
    let mut planner = PushPlanner::new(*pace.borrow_and_update());
    let mut read_feeds_at = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut report = tokio::time::interval_at(Instant::now() + STATUS_EVERY, STATUS_EVERY);
    let mut minute = Minute::default();
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            Ok(()) = pace.changed() => {
                let next = *pace.borrow_and_update();
                info!(heartbeat_secs = next.heartbeat.as_secs(), deviation_bps = next.deviation_bps,
                      min_interval_secs = next.min_interval.as_secs(), "push pace changed with the network feed set");
                planner.set_pace(next);
                continue;
            }
            _ = report.tick() => {
                minute.log(planner.feed_count());
                minute = Minute::default();
                continue;
            }
            _ = ticker.tick() => {}
        }
        if Instant::now() >= read_feeds_at {
            match feeds(&agent, &canister).await {
                Ok(feeds) => {
                    planner.set_feeds(feeds);
                    read_feeds_at = Instant::now() + FEEDS_EVERY;
                    let heartbeat = pace.borrow().heartbeat;
                    check_window(&agent, &canister, heartbeat).await;
                }
                Err(error) => {
                    minute.failed(format!("get_feeds: {error}"));
                    read_feeds_at = Instant::now() + FEEDS_RETRY;
                }
            }
        }

        let latest: Vec<PriceUpdate> = state
            .hub()
            .latest_all()
            .iter()
            .map(|prepared| *prepared.signed().update())
            .collect();
        let now = wall_clock_unix_nanos();
        let due = planner.due(&latest, now);
        if due.is_empty() {
            continue;
        }
        planner.attempted(now);
        let batch = match signer.sign_price_batch(&due) {
            Ok(batch) => batch.encode_frame(),
            Err(error) => {
                minute.failed(format!("cannot sign the batch: {error}"));
                continue;
            }
        };
        let verdicts =
            match tokio::time::timeout(PUSH_TIMEOUT, push(&agent, &canister, batch)).await {
                Ok(Ok(verdicts)) => verdicts,
                Ok(Err(error)) => {
                    minute.failed(error);
                    continue;
                }
                Err(_) => {
                    minute.failed(format!("no reply in {} s", PUSH_TIMEOUT.as_secs()));
                    continue;
                }
            };
        minute.pushes = minute.pushes.saturating_add(1);
        for (update, verdict) in due.iter().zip(verdicts) {
            match verdict {
                // A replay means the canister holds this update or a newer one.
                Verdict::Accepted | Verdict::Replayed => {
                    planner.landed(update, now);
                    if verdict == Verdict::Accepted {
                        minute.accepted = minute.accepted.saturating_add(1);
                    }
                }
                refusal => {
                    minute.refused = minute.refused.saturating_add(1);
                    minute.last_refusal = Some(refusal);
                    if refusal == Verdict::UnknownFeed {
                        read_feeds_at = Instant::now();
                    }
                }
            }
        }
    }
}

fn agent(target: &PushTarget) -> Result<Agent, ic_agent::AgentError> {
    let agent = Agent::builder().with_url(target.gateway.clone()).build()?;
    if let Some(root_key) = &target.root_key {
        agent.set_root_key(root_key.clone());
    }
    Ok(agent)
}

/// Warns when a quiet feed could drop out of the canister's quorum: its node
/// pushes it only once each heartbeat.
async fn check_window(agent: &Agent, canister: &Principal, heartbeat: Duration) {
    let Ok(arg) = Encode!() else { return };
    let reply = agent
        .query(canister, "get_price_window")
        .with_arg(arg)
        .call()
        .await;
    let Some(window) = reply.ok().and_then(|reply| Decode!(&reply, u64).ok()) else {
        return;
    };
    if oracle_wire::PushPolicy::min_window_secs(heartbeat.as_secs()) > window {
        warn!(
            heartbeat_secs = heartbeat.as_secs(),
            window_secs = window,
            "the canister counts an update for less than two heartbeats; lower publish.heartbeat_secs"
        );
    }
}

async fn feeds(agent: &Agent, canister: &Principal) -> Result<Vec<FeedId>, String> {
    let arg = Encode!().map_err(|error| error.to_string())?;
    let reply = agent
        .query(canister, "get_feeds")
        .with_arg(arg)
        .call()
        .await
        .map_err(|error| error.to_string())?;
    let feeds = Decode!(&reply, Vec<FeedInfo>).map_err(|error| error.to_string())?;
    Ok(feeds
        .iter()
        .filter_map(|feed| <[u8; 32]>::try_from(feed.feed_id.as_slice()).ok())
        .map(FeedId::from_bytes)
        .collect())
}

async fn push(agent: &Agent, canister: &Principal, batch: Vec<u8>) -> Result<Vec<Verdict>, String> {
    let arg = Encode!(&vec![ByteBuf::from(batch)]).map_err(|error| error.to_string())?;
    let reply = agent
        .update(canister, "push")
        .with_arg(arg)
        .call_and_wait()
        .await
        .map_err(|error| error.to_string())?;
    Decode!(&reply, Result<Vec<Verdict>, String>).map_err(|error| error.to_string())?
}
