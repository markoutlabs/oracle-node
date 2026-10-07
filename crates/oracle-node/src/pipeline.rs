//! The signing pipeline: ingest events in, signed updates out.
//!
//! This is the seam every other crate has been built around, and it is
//! deliberately synchronous and owned by a single task. No locks, no shared
//! aggregator, no concurrent mutation of feed state — the ordering guarantees
//! that `oracle-ingest` provides only mean something if nothing reorders them
//! afterwards.
//!
//! # The ordering that matters
//!
//! [`IngestEvent::Disconnected`] must reach the aggregator **before** any
//! observation from the reconnected socket. `oracle-ingest` emits it in-band for
//! exactly that reason, and this loop preserves it by handling events in arrival
//! order on one task. Anything that fans events across workers would break the
//! guarantee silently: a book carried across a gap looks live and is not.

use std::sync::Arc;

use oracle_agg::{AggError, Aggregator, FeedStats, Trigger};
use oracle_ingest::IngestEvent;
use oracle_types::{FeedId, PriceUpdate};
use oracle_wire::{SignedBookUpdate, SignedUpdate, SignedVenueReport, Signer, WireError};

use crate::books::BookPublisher;

/// Counters describing what the pipeline has done.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PipelineStats {
    /// Observations fed to the aggregator.
    pub observations: u64,
    /// Venue connections that came up.
    pub connects: u64,
    /// Venue connections that dropped, each invalidating that venue's state.
    pub disconnects: u64,
    /// Updates signed and published.
    pub published: u64,
    /// Feeds that could not be encoded at their configured exponent.
    pub encode_errors: u64,
}

impl PipelineStats {
    /// Venue connections up now. Every disconnect follows its connect.
    #[must_use]
    pub const fn connections_up(&self) -> u64 {
        self.connects.saturating_sub(self.disconnects)
    }
}

/// Owns the aggregator and the hot signing key.
pub struct Pipeline {
    aggregator: Aggregator,
    books: BookPublisher,
    signer: Arc<Signer>,
    stats: PipelineStats,
}

impl Pipeline {
    /// Builds a pipeline.
    #[must_use]
    pub fn new(aggregator: Aggregator, signer: Arc<Signer>) -> Self {
        Self {
            aggregator,
            books: BookPublisher::new(0),
            signer,
            stats: PipelineStats::default(),
        }
    }

    /// Starts every book's sequence at `floor`, for the same reason as
    /// [`Aggregator::with_sequence_floor`].
    #[must_use]
    pub fn with_book_sequence_floor(mut self, floor: u64) -> Self {
        self.books = BookPublisher::new(floor);
        self
    }

    /// Returns the counters.
    #[must_use]
    pub const fn stats(&self) -> PipelineStats {
        self.stats
    }

    /// Returns every feed's aggregation counters.
    #[must_use]
    pub fn feed_stats(&self) -> Vec<(FeedId, FeedStats)> {
        self.aggregator
            .feed_ids()
            .map(|id| (id, self.aggregator.stats(id).unwrap_or_default()))
            .collect()
    }

    /// Applies one ingest event.
    pub fn observe(&mut self, event: &IngestEvent) {
        match event {
            IngestEvent::Observation(observation) => {
                self.stats.observations = self.stats.observations.saturating_add(1);
                self.aggregator.observe(observation);
                self.books.observe(observation);
            }
            IngestEvent::Connected { .. } => {
                self.stats.connects = self.stats.connects.saturating_add(1);
            }
            IngestEvent::Disconnected { stream, .. } => {
                self.stats.disconnects = self.stats.disconnects.saturating_add(1);
                // Discard everything from this connection immediately. The venue
                // may have moved while we were blind, and the staleness filter
                // cannot help if the gap was shorter than its threshold.
                self.aggregator.invalidate(stream.venue, stream.market);
                self.books.reset(stream.venue, stream.market);
            }
            // `IngestEvent` is non-exhaustive; a new event kind is additive here.
            _ => {}
        }
    }

    /// Evaluates every feed and signs whatever policy says to publish. Run it
    /// on a timer: heartbeats and stale sources change nothing on input.
    ///
    /// Errors are returned alongside the updates rather than short-circuiting:
    /// one misconfigured feed must not stop the others from publishing.
    pub fn tick(&mut self, now_ns: u64) -> (Vec<SignedUpdate>, Vec<AggError>) {
        let polled = self.aggregator.poll_all(now_ns);
        self.sign(polled)
    }

    /// Evaluates only the feeds whose inputs changed, and those whose
    /// rate-capped publication is due. Run it after each batch of events, so a
    /// move publishes when it arrives.
    pub fn flush(&mut self, now_ns: u64) -> (Vec<SignedUpdate>, Vec<AggError>) {
        let polled = self.aggregator.poll_changed(now_ns);
        self.sign(polled)
    }

    /// Signs the venue reports that are due. Call it after [`Self::flush`] or
    /// [`Self::tick`], so that each report carries that evaluation's statuses.
    pub fn venue_reports(&mut self, now_ns: u64) -> (Vec<SignedVenueReport>, Vec<WireError>) {
        let mut signed = Vec::new();
        let mut errors = Vec::new();
        for report in self.aggregator.poll_venues(now_ns) {
            match self.signer.sign_venue_report(&report) {
                Ok(report) => signed.push(report),
                Err(error) => errors.push(error),
            }
        }
        (signed, errors)
    }

    /// Signs the book frames that are due.
    pub fn book_updates(&mut self, now_ns: u64) -> (Vec<SignedBookUpdate>, Vec<WireError>) {
        let mut signed = Vec::new();
        let mut errors = Vec::new();
        for update in self.books.poll(now_ns) {
            match self.signer.sign_book_update(&update) {
                Ok(update) => signed.push(update),
                Err(error) => errors.push(error),
            }
        }
        (signed, errors)
    }

    /// Returns why a feed last published.
    #[must_use]
    pub fn last_trigger(&self, feed_id: FeedId) -> Option<Trigger> {
        self.aggregator.last_trigger(feed_id)
    }

    /// When [`Self::flush`] next has a rate-capped publication to make.
    #[must_use]
    pub fn next_retry_ns(&self) -> Option<u64> {
        self.aggregator.next_retry_ns()
    }

    fn sign(
        &mut self,
        (updates, errors): (Vec<PriceUpdate>, Vec<AggError>),
    ) -> (Vec<SignedUpdate>, Vec<AggError>) {
        self.stats.encode_errors = self
            .stats
            .encode_errors
            .saturating_add(errors.len().try_into().unwrap_or(u64::MAX));
        self.stats.published = self
            .stats
            .published
            .saturating_add(updates.len().try_into().unwrap_or(u64::MAX));

        let signed = updates
            .iter()
            .map(|update| self.signer.sign_update(update))
            .collect();
        (signed, errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_agg::FeedConfig;
    use oracle_agg::config::SourceConfig;
    use oracle_ingest::StreamId;
    use oracle_types::{
        FeedId, Fixed, InstrumentId, MarketKind, ObsKind, Observation, Symbol, Venue,
    };
    use oracle_wire::feed_id;

    const SECOND: u64 = 1_000_000_000;
    const START: u64 = 1_754_582_400 * SECOND;

    fn symbol() -> Symbol {
        "CRYPTO.BTC/USDT".parse().expect("valid symbol")
    }

    fn instrument(venue: Venue) -> InstrumentId {
        InstrumentId::new(venue, MarketKind::Spot, "BTCUSDT")
    }

    fn pipeline(venues: &[Venue]) -> Pipeline {
        let sources = venues
            .iter()
            .map(|venue| {
                SourceConfig::new(instrument(*venue), vec![ObsKind::BookTop, ObsKind::Trade])
            })
            .collect();
        let mut config = FeedConfig::spot(symbol(), feed_id(&symbol()), sources);
        config.min_sources = 2;
        let aggregator = Aggregator::new(vec![config]).expect("valid config");
        let signer = Signer::from_secret_bytes([9; 32]).expect("valid key");
        Pipeline::new(aggregator, Arc::new(signer))
    }

    fn book(venue: Venue, mid: &str, recv_ns: u64) -> IngestEvent {
        let mid: Fixed = mid.parse().expect("valid decimal");
        let half = mid
            .checked_mul("0.00005".parse().expect("valid"))
            .expect("in range");
        IngestEvent::observation(Observation {
            instrument: instrument(venue),
            kind: ObsKind::BookTop,
            price: mid,
            bid: Some(mid.checked_sub(half).expect("in range")),
            ask: Some(mid.checked_add(half).expect("in range")),
            bid_qty: Some(Fixed::ONE),
            ask_qty: Some(Fixed::ONE),
            depth_notional_1bp: None,
            exchange_time_ns: None,
            local_recv_ns: recv_ns,
            seq: None,
            book: None,
        })
    }

    #[test]
    fn observations_flow_through_to_a_signed_update() {
        let mut pipeline = pipeline(&[Venue::Binance, Venue::Bybit]);
        pipeline.observe(&book(Venue::Binance, "64000", START));
        pipeline.observe(&book(Venue::Bybit, "64000", START));

        let (signed, errors) = pipeline.tick(START);
        assert!(errors.is_empty());
        assert_eq!(signed.len(), 1);

        let update = signed.first().expect("one update");
        assert_eq!(update.update().feed_id, feed_id(&symbol()));
        assert_eq!(
            update.signer(),
            Signer::from_secret_bytes([9; 32]).expect("key").address()
        );
        assert_eq!(update.update().num_sources, 2);
        assert_eq!(pipeline.stats().observations, 2);
        assert_eq!(pipeline.stats().published, 1);
    }

    /// Anything a signed update claims must survive a round trip through the
    /// wire format, or the node is publishing frames nobody can verify.
    #[test]
    fn signed_updates_verify_off_the_wire() {
        let mut pipeline = pipeline(&[Venue::Binance, Venue::Bybit]);
        pipeline.observe(&book(Venue::Binance, "64000", START));
        pipeline.observe(&book(Venue::Bybit, "64000", START));
        let (signed, _) = pipeline.tick(START);

        let update = signed.first().expect("one update");
        let frame = update.encode_frame();
        let parsed = oracle_wire::UnverifiedFrame::parse(&frame).expect("parses");
        assert_eq!(parsed.recover_signer().expect("recovers"), update.signer());
        assert_eq!(
            &parsed.decode_unverified().expect("decodes"),
            update.update()
        );
    }

    #[test]
    fn venue_reports_sign_after_the_evaluation() {
        let mut pipeline = pipeline(&[Venue::Binance, Venue::Bybit]);
        pipeline.observe(&book(Venue::Binance, "64000", START));
        pipeline.observe(&book(Venue::Bybit, "64000", START));
        let _ = pipeline.tick(START);
        let (reports, errors) = pipeline.venue_reports(START);
        assert!(errors.is_empty(), "{errors:?}");

        let report = reports.first().expect("one report");
        let parsed =
            oracle_wire::UnverifiedVenueFrame::parse(&report.encode_frame()).expect("parses");
        let decoded = parsed.decode_unverified().expect("decodes");
        assert_eq!(&decoded, report.report());
        assert!(
            decoded
                .entries
                .iter()
                .all(|entry| entry.status == oracle_types::SourceStatus::Used),
            "{decoded:?}"
        );
        assert!(
            pipeline.venue_reports(START).0.is_empty(),
            "nothing new, no report"
        );
    }

    /// The seam this whole crate exists to get right.
    #[test]
    fn a_disconnect_invalidates_that_venue_before_the_next_tick() {
        let mut pipeline = pipeline(&[Venue::Binance, Venue::Bybit]);
        pipeline.observe(&book(Venue::Binance, "64000", START));
        pipeline.observe(&book(Venue::Bybit, "64000", START));
        assert_eq!(pipeline.tick(START).0.len(), 1);

        // Binance drops. Its book is milliseconds old and would sail through the
        // staleness filter, but it must not survive the gap.
        pipeline.observe(&IngestEvent::Disconnected {
            stream: StreamId::new(Venue::Binance, MarketKind::Spot),
            reason: "connection reset".to_owned(),
        });

        let at = START + SECOND;
        pipeline.observe(&book(Venue::Bybit, "64000", at));
        let (signed, _) = pipeline.tick(at);

        let update = signed.first().expect("a halt publishes").update();
        assert!(
            update.flags.is_halted(),
            "one live venue is below the quorum of two"
        );
        assert_eq!(pipeline.stats().disconnects, 1);
    }

    #[test]
    fn a_reconnect_does_not_resurrect_pre_gap_quotes() {
        let mut pipeline = pipeline(&[Venue::Binance, Venue::Bybit]);
        pipeline.observe(&book(Venue::Binance, "64000", START));
        pipeline.observe(&book(Venue::Bybit, "64000", START));
        let _ = pipeline.tick(START);

        pipeline.observe(&IngestEvent::Disconnected {
            stream: StreamId::new(Venue::Binance, MarketKind::Spot),
            reason: "reset".to_owned(),
        });
        pipeline.observe(&IngestEvent::Connected {
            stream: StreamId::new(Venue::Binance, MarketKind::Spot),
        });

        // Reconnected but not yet quoting: still below quorum.
        let at = START + SECOND;
        pipeline.observe(&book(Venue::Bybit, "64000", at));
        assert!(
            pipeline
                .tick(at)
                .0
                .first()
                .expect("publishes")
                .update()
                .flags
                .is_halted(),
            "a reconnect alone must not restore the quorum"
        );

        // Once it quotes again, the feed recovers.
        let later = at + SECOND;
        pipeline.observe(&book(Venue::Binance, "64000", later));
        pipeline.observe(&book(Venue::Bybit, "64000", later));
        assert!(
            pipeline
                .tick(later)
                .0
                .first()
                .expect("publishes")
                .update()
                .flags
                .is_none(),
            "fresh quotes from both venues must clear the halt"
        );
    }

    #[test]
    fn a_tick_with_no_data_publishes_nothing() {
        let mut pipeline = pipeline(&[Venue::Binance, Venue::Bybit]);
        let (signed, errors) = pipeline.tick(START);
        assert!(signed.is_empty(), "silence must not be signed");
        assert!(errors.is_empty());
    }

    #[test]
    fn an_unencodable_feed_is_reported_and_does_not_stop_the_others() {
        let sources = vec![SourceConfig::new(
            instrument(Venue::Binance),
            vec![ObsKind::BookTop],
        )];
        let mut healthy = FeedConfig::spot(symbol(), feed_id(&symbol()), sources.clone());
        healthy.min_sources = 1;
        let mut broken = FeedConfig::spot(symbol(), FeedId::from_bytes([2; 32]), sources);
        broken.min_sources = 1;
        broken.expo = -18;

        let aggregator = Aggregator::new(vec![healthy, broken]).expect("valid config");
        let signer = Signer::from_secret_bytes([9; 32]).expect("valid key");
        let mut pipeline = Pipeline::new(aggregator, Arc::new(signer));

        pipeline.observe(&book(Venue::Binance, "64000", START));
        let (signed, errors) = pipeline.tick(START);
        assert_eq!(signed.len(), 1, "the healthy feed must still publish");
        assert_eq!(errors.len(), 1);
        assert_eq!(pipeline.stats().encode_errors, 1);
    }

    #[test]
    fn sequence_numbers_advance_across_ticks() {
        let mut pipeline = pipeline(&[Venue::Binance, Venue::Bybit]);
        let mut seqs = Vec::new();
        for tick in 0..6_u64 {
            let at = START + tick * SECOND;
            pipeline.observe(&book(Venue::Binance, "64000", at));
            pipeline.observe(&book(Venue::Bybit, "64000", at));
            for update in pipeline.tick(at).0 {
                seqs.push(update.update().seq);
            }
        }
        assert!(seqs.len() >= 5);
        assert!(
            seqs.windows(2)
                .all(|w| matches!((w.first(), w.get(1)), (Some(a), Some(b)) if b > a)),
            "sequence numbers must advance: {seqs:?}"
        );
    }
}
