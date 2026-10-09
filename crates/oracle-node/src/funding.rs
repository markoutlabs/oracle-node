//! Funding frames for subscribers: the latest funding state of each perpetual,
//! when it changes and at least once a minute.
//!
//! A frame always carries the whole state, so a client needs only the last one.

use std::collections::HashMap;
use std::time::Duration;

use oracle_types::{
    FUNDING_EXPO, FUNDING_HEARTBEAT, Fixed, FundingBasis, FundingInfo, FundingUpdate, InstrumentId,
    MarketKind, OPEN_INTEREST_EXPO, ObsKind, Observation, OpenInterest, SettledFunding, Venue,
};

/// The rate cap for each perpetual. Open interest moves with every trade, so
/// without a cap a busy contract would sign a frame for each ticker.
pub const MIN_INTERVAL: Duration = Duration::from_secs(1);

/// The longest time between two frames of one perpetual.
pub const HEARTBEAT: Duration = FUNDING_HEARTBEAT;

/// What a frame says, apart from its times. A change of any part sends a frame.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Content {
    basis: FundingBasis,
    rate: i64,
    predicted_rate: Option<i64>,
    interval_ns: Option<u64>,
    next_funding_time_ns: Option<u64>,
    settled: Option<SettledFunding>,
    open_interest: Option<OpenInterest>,
}

impl Content {
    /// `None` for a rate that does not fit the wire. An optional field that
    /// does not fit is left out.
    fn of(rate: Fixed, info: &FundingInfo) -> Option<Self> {
        let rate_of = |value: Fixed| value.to_scaled(FUNDING_EXPO).ok();
        Some(Self {
            basis: info.basis,
            rate: rate_of(rate)?,
            predicted_rate: info.predicted.and_then(rate_of),
            interval_ns: info.interval_ns,
            next_funding_time_ns: info.next_funding_time_ns,
            settled: info.settled.and_then(|(rate, time_ns)| {
                Some(SettledFunding {
                    rate: rate_of(rate)?,
                    time_ns,
                })
            }),
            open_interest: info.open_interest.and_then(|(amount, unit)| {
                Some(OpenInterest {
                    amount: amount.to_scaled_unsigned(OPEN_INTEREST_EXPO).ok()?,
                    unit,
                })
            }),
        })
    }
}

#[derive(Default)]
struct FundingState {
    /// The newest data, or `None` after a disconnect until new data arrives.
    current: Option<(Content, Option<u64>, u64)>,
    /// What the last frame said.
    sent: Option<Content>,
    seq: u64,
    last_sent_ns: Option<u64>,
}

/// Turns funding observations into funding frames.
pub struct FundingPublisher {
    instruments: HashMap<InstrumentId, FundingState>,
    seq_floor: u64,
}

impl FundingPublisher {
    /// Starts every sequence at `seq_floor`, as for prices.
    #[must_use]
    pub fn new(seq_floor: u64) -> Self {
        Self {
            instruments: HashMap::new(),
            seq_floor,
        }
    }

    /// Takes the latest funding of a perpetual.
    pub fn observe(&mut self, observation: &Observation) {
        if observation.kind != ObsKind::Funding || !observation.instrument.market.is_perp() {
            return;
        }
        let Some(content) = observation
            .funding
            .as_deref()
            .and_then(|info| Content::of(observation.price, info))
        else {
            return;
        };
        let seq_floor = self.seq_floor;
        let state = self
            .instruments
            .entry(observation.instrument.clone())
            .or_insert_with(|| FundingState {
                seq: seq_floor,
                ..FundingState::default()
            });
        state.current = Some((
            content,
            observation.exchange_time_ns,
            observation.local_recv_ns,
        ));
    }

    /// Forgets the data of a connection that dropped. Nothing is signed for
    /// its perpetuals until new data arrives.
    pub fn reset(&mut self, venue: Venue, market: MarketKind) {
        for (instrument, state) in &mut self.instruments {
            if instrument.venue == venue && instrument.market == market {
                state.current = None;
            }
        }
    }

    /// Returns the frames that are due: after a change, or after
    /// [`HEARTBEAT`] without one, and never within [`MIN_INTERVAL`] of the last.
    pub fn poll(&mut self, now_ns: u64) -> Vec<FundingUpdate> {
        let min_interval = nanos(MIN_INTERVAL);
        let heartbeat = nanos(HEARTBEAT);
        let mut updates = Vec::new();
        for (instrument, state) in &mut self.instruments {
            let Some((content, exchange_time_ns, local_recv_ns)) = &state.current else {
                continue;
            };
            let since = state
                .last_sent_ns
                .map_or(u64::MAX, |last| now_ns.saturating_sub(last));
            if since < min_interval {
                continue;
            }
            if state.sent.as_ref() == Some(content) && since < heartbeat {
                continue;
            }
            state.seq = state.seq.saturating_add(1);
            state.last_sent_ns = Some(now_ns);
            state.sent = Some(content.clone());
            updates.push(FundingUpdate {
                venue: instrument.venue,
                market: instrument.market,
                symbol: instrument.symbol.to_string(),
                publish_time_ns: now_ns,
                seq: state.seq,
                basis: content.basis,
                rate: content.rate,
                predicted_rate: content.predicted_rate,
                interval_ns: content.interval_ns,
                next_funding_time_ns: content.next_funding_time_ns,
                settled: content.settled,
                open_interest: content.open_interest,
                exchange_time_ns: *exchange_time_ns,
                local_recv_ns: (*local_recv_ns).min(now_ns),
            });
        }
        updates
    }
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use oracle_types::OpenInterestUnit;

    use super::*;

    const S: u64 = 1_000_000_000;
    const START: u64 = 1_791_542_600 * S;

    fn instrument() -> InstrumentId {
        InstrumentId::new(Venue::Bybit, MarketKind::LinearPerp, "BTCUSDT")
    }

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("a decimal")
    }

    fn funding(rate: &str, open_interest: &str, at: u64) -> Observation {
        Observation {
            instrument: instrument(),
            kind: ObsKind::Funding,
            price: fixed(rate),
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            depth_notional_1bp: None,
            exchange_time_ns: Some(at - S / 10),
            local_recv_ns: at,
            seq: None,
            book: None,
            funding: Some(Arc::new(FundingInfo {
                interval_ns: Some(8 * 3_600 * S),
                open_interest: Some((fixed(open_interest), OpenInterestUnit::Base)),
                ..FundingInfo::new(FundingBasis::Interval)
            })),
        }
    }

    #[test]
    fn a_change_sends_a_frame_with_the_whole_state() {
        let mut publisher = FundingPublisher::new(100);
        publisher.observe(&funding("0.0001", "57845.537", START));
        let first = publisher.poll(START);
        assert_eq!(first.len(), 1);
        let frame = first.first().expect("a frame");
        assert_eq!(frame.seq, 101);
        assert_eq!(frame.rate, 100_000_000);
        assert_eq!(frame.interval_ns, Some(8 * 3_600 * S));
        assert_eq!(
            frame.open_interest,
            Some(OpenInterest {
                amount: 5_784_553_700_000,
                unit: OpenInterestUnit::Base
            })
        );
        assert_eq!(frame.exchange_time_ns, Some(START - S / 10));

        // New open interest sends a frame, one second after the last one.
        publisher.observe(&funding("0.0001", "57823.041", START + S / 2));
        assert!(publisher.poll(START + S / 2).is_empty(), "the rate cap");
        let second = publisher.poll(START + S);
        assert_eq!(second.first().map(|frame| frame.seq), Some(102));
        // The same data again sends nothing.
        publisher.observe(&funding("0.0001", "57823.041", START + 2 * S));
        assert!(publisher.poll(START + 2 * S).is_empty());
    }

    #[test]
    fn a_quiet_perpetual_sends_a_heartbeat() {
        let mut publisher = FundingPublisher::new(0);
        publisher.observe(&funding("0.0001", "1", START));
        assert_eq!(publisher.poll(START).len(), 1);
        assert!(publisher.poll(START + 59 * S).is_empty());
        assert_eq!(publisher.poll(START + 60 * S).len(), 1);
    }

    #[test]
    fn a_disconnect_stops_the_frames_until_new_data() {
        let mut publisher = FundingPublisher::new(0);
        publisher.observe(&funding("0.0001", "1", START));
        assert_eq!(publisher.poll(START).len(), 1);
        publisher.reset(Venue::Bybit, MarketKind::LinearPerp);
        assert!(publisher.poll(START + 120 * S).is_empty());
        publisher.observe(&funding("0.0001", "1", START + 121 * S));
        let frames = publisher.poll(START + 121 * S);
        assert_eq!(frames.first().map(|frame| frame.seq), Some(2));
    }

    #[test]
    fn other_observations_are_ignored() {
        let mut publisher = FundingPublisher::new(0);
        let mut mark = funding("64000", "1", START);
        mark.kind = ObsKind::MarkPrice;
        publisher.observe(&mark);
        let mut bare = funding("0.0001", "1", START);
        bare.funding = None;
        publisher.observe(&bare);
        let mut spot = funding("0.0001", "1", START);
        spot.instrument = InstrumentId::new(Venue::Bybit, MarketKind::Spot, "BTCUSDT");
        publisher.observe(&spot);
        assert!(publisher.poll(START).is_empty());
    }
}
