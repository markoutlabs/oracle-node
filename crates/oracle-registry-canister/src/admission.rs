//! Who can make the canister pay: the admission rules of the SPEC §3.7 table,
//! for pushes (P1 to P11) and for calls from other canisters (Q1, Q2).
//!
//! Each rule names its id. `inspect_message` runs the rules on one replica
//! before the canister pays, and `push` runs them again under consensus.
//! `Prices` runs P6 to P10, which need the stored batches and the registry.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use oracle_registry_api::{
    ACCEPT_MAX_AGE, ACCEPT_MAX_SKEW, CYCLES_RESERVE, MAX_BATCH_FRAME_BYTES, MAX_FRAMES_PER_PUSH,
    MAX_PUSH_BYTES, PRICE_CALL_CYCLES, PRODUCTION_HEARTBEAT_SECS, UNPACED_MIN_INTERVAL, Verdict,
};
use oracle_wire::{
    Address, FRAME_TYPE_PRICE_BATCH, MAX_BATCH_UPDATES, PRICE_UPDATE_SIZE, PushPolicy,
    SIGNATURE_LEN, UnverifiedPriceBatch,
};

/// Where the signed part of a frame starts: after the frame type and the unsigned signer hint.
pub const SIGNED_START: usize = 1 + Address::LEN;

/// The batch payload header: the version, the kind and the update count (SPEC §3.4).
const BATCH_HEADER_BYTES: usize = 4;

// The api crate states the push limits without the wire crate; these tie them together.
const _: () = {
    assert!(
        MAX_BATCH_FRAME_BYTES
            == SIGNED_START
                + BATCH_HEADER_BYTES
                + MAX_BATCH_UPDATES * PRICE_UPDATE_SIZE
                + SIGNATURE_LEN
    );
    assert!(PRODUCTION_HEARTBEAT_SECS <= PushPolicy::MAX_HEARTBEAT_SECS);
};

/// Why the canister refuses a whole push, or a call, before it checks a signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// P1: ingress for another method, or from a caller that is not anonymous.
    NotAPush,
    /// P2: the argument is too large to decode.
    TooLarge {
        /// The argument's size.
        bytes: usize,
    },
    /// P2: the argument is not a `vec blob`.
    Undecodable,
    /// P2: no frame, or more than [`MAX_FRAMES_PER_PUSH`].
    FrameCount {
        /// The frames in the push.
        count: usize,
    },
    /// P3: a frame that is not a price batch, such as a single price frame that a client relays.
    NotABatch,
    /// P4: the balance is below [`CYCLES_RESERVE`].
    LowCycles {
        /// The balance now.
        balance: u128,
    },
    /// P5: two batches of one node in one push.
    SameNode(Address),
    /// P5: the node pushed less than its minimum interval ago.
    TooSoon {
        /// The node that the batch names.
        node: Address,
        /// How long the node must still wait.
        wait: Duration,
    },
    /// P10: a batch that holds no update that `push` accepts.
    NothingNew,
    /// Q1: a replicated call from a canister that is not a controller.
    ReplicatedCall,
    /// Q2: a replicated price call with too few cycles attached.
    Unpaid {
        /// The cycles attached.
        attached: u128,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAPush => write!(f, "only `push` from the anonymous identity gets in"),
            Self::TooLarge { bytes } => {
                write!(f, "a push of {bytes} bytes; the limit is {MAX_PUSH_BYTES}")
            }
            Self::Undecodable => write!(f, "a push takes one `vec blob`"),
            Self::FrameCount { count } => write!(
                f,
                "a push of {count} frames; a push carries 1 to {MAX_FRAMES_PER_PUSH}"
            ),
            Self::NotABatch => write!(
                f,
                "a push takes price batches (frame type {FRAME_TYPE_PRICE_BATCH}) only"
            ),
            Self::LowCycles { balance } => write!(
                f,
                "the balance of {balance} cycles is below the reserve of {CYCLES_RESERVE}; pushes wait for a top-up"
            ),
            Self::SameNode(node) => write!(f, "two batches of node {node} in one push"),
            Self::TooSoon { node, wait } => write!(
                f,
                "node {node} pushed too recently; the feed set's pace allows the next push in {} ms",
                wait.as_millis()
            ),
            Self::NothingNew => write!(f, "a batch holds no new and valid update"),
            Self::ReplicatedCall => write!(
                f,
                "other canisters call only `get_price` and `get_prices`; query the rest"
            ),
            Self::Unpaid { attached } => write!(
                f,
                "attach {PRICE_CALL_CYCLES} cycles to a price call from a canister; {attached} were attached"
            ),
        }
    }
}

/// One ingress message, as `inspect_message` sees it.
#[derive(Clone, Copy, Debug)]
pub struct Ingress<'a> {
    /// The method it calls.
    pub method: &'a str,
    /// The caller is the anonymous identity.
    pub anonymous: bool,
    /// The size of the Candid argument.
    pub arg_bytes: usize,
}

/// A call to a query method.
#[derive(Clone, Copy, Debug)]
pub struct QueryCall {
    /// The call runs under consensus: another canister made it, or an update call did.
    pub replicated: bool,
    /// The caller controls the canister.
    pub controller: bool,
    /// The cycles attached to the call.
    pub cycles: u128,
}

/// The push rules that keep state: the pace of the feed set and each node's last push.
#[derive(Default)]
pub struct Admission {
    pace: Option<PushPolicy>,
    last_push_ns: BTreeMap<Address, u64>,
}

impl Admission {
    /// P1, P2: only `push`, only from the anonymous identity, and a bounded argument.
    ///
    /// # Errors
    ///
    /// Returns the rule that the message breaks.
    pub fn check_ingress(ingress: Ingress<'_>) -> Result<(), Refusal> {
        if ingress.method != "push" || !ingress.anonymous {
            return Err(Refusal::NotAPush);
        }
        // The canister pays for each ingress byte, and Candid skips extra arguments.
        if ingress.arg_bytes > MAX_PUSH_BYTES {
            return Err(Refusal::TooLarge {
                bytes: ingress.arg_bytes,
            });
        }
        Ok(())
    }

    /// P4: pushes stop above the reserve, so a drain halts prices before it stops governance.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::LowCycles`] below [`CYCLES_RESERVE`].
    pub fn check_balance(balance: u128) -> Result<(), Refusal> {
        if balance < CYCLES_RESERVE {
            return Err(Refusal::LowCycles { balance });
        }
        Ok(())
    }

    /// P2, P3, P5: the frames of one push, before any signature recovery.
    ///
    /// # Errors
    ///
    /// Returns the first rule that the push breaks.
    pub fn check_frames(&self, blobs: &[impl AsRef<[u8]>], now_ns: u64) -> Result<(), Refusal> {
        if blobs.is_empty() || blobs.len() > MAX_FRAMES_PER_PUSH {
            return Err(Refusal::FrameCount { count: blobs.len() });
        }
        let mut nodes = BTreeSet::new();
        for blob in blobs {
            let bytes = blob.as_ref();
            // SPEC §3.7 P3: a node never sends a batch to a client, so a client
            // can relay only single frames, and the canister refuses them.
            if bytes.first() != Some(&FRAME_TYPE_PRICE_BATCH) {
                return Err(Refusal::NotABatch);
            }
            // A batch that does not parse gets its `Invalid` verdict from `Prices`.
            let Ok(batch) = UnverifiedPriceBatch::parse(bytes) else {
                continue;
            };
            let node = batch.signer_hint();
            if !nodes.insert(node) {
                return Err(Refusal::SameNode(node));
            }
            self.check_interval(node, now_ns)?;
        }
        Ok(())
    }

    /// P5: the shortest time between two batches of one node: half the pace's
    /// interval, because one push can run late and the next one on time.
    #[must_use]
    pub fn min_interval(&self) -> Duration {
        let interval = self.pace.map_or(UNPACED_MIN_INTERVAL, |pace| {
            Duration::from_secs(pace.min_interval_secs)
        });
        interval / 2
    }

    fn check_interval(&self, node: Address, now_ns: u64) -> Result<(), Refusal> {
        let Some(&last) = self.last_push_ns.get(&node) else {
            return Ok(());
        };
        let due = last.saturating_add(nanos(self.min_interval()));
        if now_ns < due {
            return Err(Refusal::TooSoon {
                node,
                wait: Duration::from_nanos(due - now_ns),
            });
        }
        Ok(())
    }

    /// P5: starts the node's interval. `Prices` calls it once a recovery proved the node signed the batch.
    pub fn record_push(&mut self, node: Address, now_ns: u64) {
        self.last_push_ns.insert(node, now_ns);
    }

    /// Takes the push pace of a newly published feed set.
    pub fn set_pace(&mut self, pace: Option<PushPolicy>) {
        self.pace = pace;
    }

    /// Drops the intervals of the nodes that `keep` refuses.
    pub fn retain_nodes(&mut self, keep: impl Fn(&Address) -> bool) {
        self.last_push_ns.retain(|node, _| keep(node));
    }

    /// Drops every interval, after an upgrade rebuilt the prices from stored frames.
    pub fn forget_pushes(&mut self) {
        self.last_push_ns.clear();
    }

    /// P7: the clock windows. `None` when the publish time is inside them.
    #[must_use]
    pub fn clock(publish_time_ns: u64, now_ns: u64) -> Option<Verdict> {
        if publish_time_ns > now_ns {
            (publish_time_ns - now_ns > nanos(ACCEPT_MAX_SKEW)).then_some(Verdict::FromTheFuture)
        } else {
            (now_ns - publish_time_ns > nanos(ACCEPT_MAX_AGE)).then_some(Verdict::TooOld)
        }
    }

    /// P11: the canister prices feeds only under a published feed set with a push
    /// pace. Without one, each node pushes at its own pace, and the canister pays for each push.
    ///
    /// # Errors
    ///
    /// Returns the reason when `pace` is `None` and `priced_feeds` is not zero.
    pub fn check_pace(pace: Option<PushPolicy>, priced_feeds: usize) -> Result<(), String> {
        if pace.is_none() && priced_feeds > 0 {
            return Err(format!(
                "pricing {priced_feeds} feeds needs a published feed set that sets `push`; \
                 publish one with PUSH=heartbeat,deviation,interval first (SPEC §3.7 P11)"
            ));
        }
        Ok(())
    }

    /// Q1: a replicated call from a canister that is not a controller costs the
    /// canister an execution fee, so the methods other than the prices refuse it.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::ReplicatedCall`].
    pub fn check_query(call: QueryCall) -> Result<(), Refusal> {
        if call.replicated && !call.controller {
            return Err(Refusal::ReplicatedCall);
        }
        Ok(())
    }

    /// Q2: a replicated price call pays with attached cycles, as the exchange-rate canister asks.
    /// Returns the cycles to accept: none for a plain query or a controller, as Q1 exempts them.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::Unpaid`] when fewer than [`PRICE_CALL_CYCLES`] are attached.
    pub fn check_price_call(call: QueryCall) -> Result<u128, Refusal> {
        if !call.replicated || call.controller {
            return Ok(0);
        }
        if call.cycles < PRICE_CALL_CYCLES {
            return Err(Refusal::Unpaid {
                attached: call.cycles,
            });
        }
        Ok(PRICE_CALL_CYCLES)
    }
}

pub(crate) fn nanos(limit: Duration) -> u64 {
    u64::try_from(limit.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use oracle_quorum::testing::{NEXT_EPOCH_NS, TestNode, registry_with};
    use oracle_types::{FeedId, NANOS_PER_SEC, PriceUpdate, Symbol};
    use oracle_wire::feed_id;

    use super::*;
    use crate::prices::Prices;

    /// Ten steps of [`TestNode::next`] after its first publish time.
    const NOW: u64 = NEXT_EPOCH_NS + 10 * NANOS_PER_SEC;
    const BTC: &str = "CRYPTO.BTC/USD";
    const PRODUCTION: PushPolicy = PushPolicy {
        heartbeat_secs: 60,
        deviation_bps: 2,
        min_interval_secs: 60,
    };

    /// What one rule did with one input.
    #[derive(Debug, PartialEq, Eq)]
    enum Seen {
        Passes,
        Refused(Refusal),
        Verdicts(Vec<Verdict>),
        Fails,
        Interval(Duration),
        Fee(u128),
    }

    impl From<Result<u128, Refusal>> for Seen {
        fn from(result: Result<u128, Refusal>) -> Self {
            result.map_or_else(Self::Refused, Self::Fee)
        }
    }

    impl From<Result<(), Refusal>> for Seen {
        fn from(result: Result<(), Refusal>) -> Self {
            result.map_or_else(Self::Refused, |()| Self::Passes)
        }
    }

    impl From<Result<Vec<Verdict>, Refusal>> for Seen {
        fn from(result: Result<Vec<Verdict>, Refusal>) -> Self {
            result.map_or_else(Self::Refused, Self::Verdicts)
        }
    }

    fn btc() -> FeedId {
        let symbol: Symbol = BTC.parse().expect("a symbol");
        feed_id(&symbol)
    }

    /// The node's next batch of BTC.
    fn batch(signer: &TestNode) -> Vec<u8> {
        signer.sign_batch(&[signer.next(btc(), 1)])
    }

    /// The node's next batch of BTC, published at `published`.
    fn batch_at(signer: &TestNode, published: u64) -> Vec<u8> {
        signer.sign_batch(&[PriceUpdate {
            publish_time_ns: published,
            ..signer.next(btc(), 1)
        }])
    }

    fn with_hint(mut batch: Vec<u8>, hint: Address) -> Vec<u8> {
        batch.splice(1..SIGNED_START, hint.as_bytes().iter().copied());
        batch
    }

    fn ingress(method: &str, anonymous: bool, arg_bytes: usize) -> Seen {
        Admission::check_ingress(Ingress {
            method,
            anonymous,
            arg_bytes,
        })
        .into()
    }

    fn query(replicated: bool, controller: bool, cycles: u128) -> QueryCall {
        QueryCall {
            replicated,
            controller,
            cycles,
        }
    }

    /// Each rule of the SPEC §3.7 admission table, by its id.
    #[test]
    fn each_admission_rule_of_the_spec_holds() {
        let (node, other, stranger) = (TestNode::new(1), TestNode::new(2), TestNode::new(9));
        let mut prices = Prices::default();
        prices.set_feeds(&[BTC.parse().expect("a symbol")]);
        prices.set_registry(registry_with(&[&node, &other]));
        let second = |step: u64| NOW + step * NANOS_PER_SEC;
        let first = batch(&node);

        let mut paced = Admission::default();
        paced.set_pace(Some(PRODUCTION));
        let mut rows: Vec<(&str, &str, Seen, Seen)> = vec![
            ("P1", "a push", ingress("push", true, 100), Seen::Passes),
            (
                "P1",
                "another method",
                ingress("add_node", true, 100),
                Seen::Refused(Refusal::NotAPush),
            ),
            (
                "P1",
                "a caller that is not anonymous",
                ingress("push", false, 100),
                Seen::Refused(Refusal::NotAPush),
            ),
            (
                "P2",
                "an argument above the limit",
                ingress("push", true, MAX_PUSH_BYTES + 1),
                Seen::Refused(Refusal::TooLarge {
                    bytes: MAX_PUSH_BYTES + 1,
                }),
            ),
            (
                "P2",
                "no frame",
                prices.inspect(&Vec::<Vec<u8>>::new(), NOW).into(),
                Seen::Refused(Refusal::FrameCount { count: 0 }),
            ),
            (
                "P2",
                "more frames than the limit",
                prices
                    .inspect(&vec![first.clone(); MAX_FRAMES_PER_PUSH + 1], NOW)
                    .into(),
                Seen::Refused(Refusal::FrameCount {
                    count: MAX_FRAMES_PER_PUSH + 1,
                }),
            ),
            (
                "P3",
                "a single price frame",
                prices
                    .inspect(&[node.sign(&node.next(btc(), 1))], NOW)
                    .into(),
                Seen::Refused(Refusal::NotABatch),
            ),
            (
                "P4",
                "a balance below the reserve",
                Admission::check_balance(CYCLES_RESERVE - 1).into(),
                Seen::Refused(Refusal::LowCycles {
                    balance: CYCLES_RESERVE - 1,
                }),
            ),
            (
                "P4",
                "a balance at the reserve",
                Admission::check_balance(CYCLES_RESERVE).into(),
                Seen::Passes,
            ),
            (
                "P5",
                "two batches of one node",
                prices.inspect(&[first.clone(), batch(&node)], NOW).into(),
                Seen::Refused(Refusal::SameNode(node.signing_address())),
            ),
            (
                "P5",
                "a node's first batch",
                prices.push(&[&first], NOW).into(),
                Seen::Verdicts(vec![Verdict::Accepted]),
            ),
        ];
        rows.push((
            "P5",
            "the next batch inside the interval",
            prices.push(&[batch(&node)], NOW + 1).into(),
            Seen::Refused(Refusal::TooSoon {
                node: node.signing_address(),
                wait: prices.min_push_interval() - Duration::from_nanos(1),
            }),
        ));
        rows.extend([
            (
                "P5",
                "the production pace allows a batch every half interval",
                Seen::Interval(paced.min_interval()),
                Seen::Interval(Duration::from_secs(PRODUCTION.min_interval_secs / 2)),
            ),
            (
                "P6",
                "a copy with another hint",
                prices
                    .push(
                        &[with_hint(first.clone(), other.signing_address())],
                        second(1),
                    )
                    .into(),
                Seen::Verdicts(vec![Verdict::Replayed]),
            ),
            (
                "P7",
                "an update past the age limit",
                prices
                    .push(&[batch_at(&other, NOW - nanos(ACCEPT_MAX_AGE) - 1)], NOW)
                    .into(),
                Seen::Verdicts(vec![Verdict::TooOld]),
            ),
            (
                "P7",
                "an update ahead of the clock",
                prices
                    .push(&[batch_at(&other, NOW + nanos(ACCEPT_MAX_SKEW) + 1)], NOW)
                    .into(),
                Seen::Verdicts(vec![Verdict::FromTheFuture]),
            ),
            (
                "P8",
                "a hint that no listed node has",
                prices.push(&[batch(&stranger)], second(2)).into(),
                Seen::Verdicts(vec![Verdict::UnknownSigner]),
            ),
            (
                "P9",
                "a hint that is not the signer",
                prices
                    .push(
                        &[with_hint(batch(&node), other.signing_address())],
                        second(3),
                    )
                    .into(),
                Seen::Verdicts(vec![Verdict::Invalid]),
            ),
            (
                "P10",
                "a batch with nothing new",
                prices.inspect(&[&first], second(4)).into(),
                Seen::Refused(Refusal::NothingNew),
            ),
            (
                "P11",
                "a feed set without a pace while feeds are priced",
                Admission::check_pace(None, 1).map_or(Seen::Fails, |()| Seen::Passes),
                Seen::Fails,
            ),
            (
                "P11",
                "a feed set without a pace while nothing is priced",
                Admission::check_pace(None, 0).map_or(Seen::Fails, |()| Seen::Passes),
                Seen::Passes,
            ),
            (
                "P11",
                "a feed set with a pace",
                Admission::check_pace(Some(PRODUCTION), 1).map_or(Seen::Fails, |()| Seen::Passes),
                Seen::Passes,
            ),
            (
                "Q1",
                "a replicated call from another canister",
                Admission::check_query(query(true, false, 0)).into(),
                Seen::Refused(Refusal::ReplicatedCall),
            ),
            (
                "Q1",
                "a replicated call from a controller",
                Admission::check_query(query(true, true, 0)).into(),
                Seen::Passes,
            ),
            (
                "Q1",
                "a plain query",
                Admission::check_query(query(false, false, 0)).into(),
                Seen::Passes,
            ),
            (
                "Q2",
                "a price call with too few cycles",
                Admission::check_price_call(query(true, false, PRICE_CALL_CYCLES - 1)).into(),
                Seen::Refused(Refusal::Unpaid {
                    attached: PRICE_CALL_CYCLES - 1,
                }),
            ),
            (
                "Q2",
                "a paid price call takes the fee",
                Admission::check_price_call(query(true, false, 2 * PRICE_CALL_CYCLES)).into(),
                Seen::Fee(PRICE_CALL_CYCLES),
            ),
            (
                "Q2",
                "a replicated price call from a controller takes nothing",
                Admission::check_price_call(query(true, true, 0)).into(),
                Seen::Fee(0),
            ),
            (
                "Q2",
                "a plain price query takes nothing",
                Admission::check_price_call(query(false, false, 0)).into(),
                Seen::Fee(0),
            ),
        ]);
        for (rule, case, seen, expected) in rows {
            assert_eq!(seen, expected, "SPEC §3.7 {rule}: {case}");
        }
    }

    #[test]
    fn the_interval_is_half_the_pace() {
        let mut admission = Admission::default();
        assert_eq!(admission.min_interval(), UNPACED_MIN_INTERVAL / 2);
        for (interval, floor) in [(60, 30), (20, 10), (2, 1)] {
            admission.set_pace(Some(PushPolicy {
                heartbeat_secs: 60,
                deviation_bps: 2,
                min_interval_secs: interval,
            }));
            assert_eq!(
                admission.min_interval(),
                Duration::from_secs(floor),
                "{interval} s"
            );
        }
    }

    /// SPEC §3.7 P5: ingress time varies, so a push that runs 20 s late and the
    /// next one that runs 2 s late are both in pace.
    #[test]
    fn a_late_push_and_a_prompt_next_one_are_both_in_pace() {
        let node = TestNode::new(1);
        let mut admission = Admission::default();
        admission.set_pace(Some(PRODUCTION));
        let interval = PRODUCTION.min_interval_secs * NANOS_PER_SEC;
        admission.record_push(node.signing_address(), NOW + 20 * NANOS_PER_SEC);
        let next = NOW + interval + 2 * NANOS_PER_SEC;
        assert_eq!(admission.check_frames(&[batch(&node)], next), Ok(()));
    }
}
