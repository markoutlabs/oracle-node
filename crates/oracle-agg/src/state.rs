//! The stateful aggregator: routing, per-venue state, and publication policy.

use std::collections::HashMap;
use std::time::Duration;

use oracle_types::{
    FeedId, Fixed, FixedError, Flags, InstrumentId, MarketKind, ObsKind, Observation, PriceUpdate,
    Venue,
};

use crate::aggregate::{self, Outcome, Peg, Reasons};
use crate::config::{ConfigError, FeedConfig};
use crate::quote::{self, SourceQuote};

/// A failure forming a publishable update.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AggError {
    /// The price or confidence does not fit the feed's wire exponent.
    ///
    /// Never silently skipped: an unrepresentable price means the feed's exponent
    /// is wrong for the instrument, which is a configuration bug that would
    /// otherwise present as a feed that mysteriously never publishes.
    #[error("feed `{symbol}` value {value} is not representable at exponent {expo}")]
    Unrepresentable {
        /// The feed.
        symbol: String,
        /// The offending value.
        value: String,
        /// The feed's exponent.
        expo: i32,
        /// The underlying conversion failure.
        #[source]
        source: FixedError,
    },
}

/// What this node last published for a feed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Published {
    price: Fixed,
    publish_time_ns: u64,
    flags: Flags,
}

/// Per-venue latest observations, one slot per [`ObsKind`].
#[derive(Clone, Debug, Default)]
struct SourceSlots {
    latest: [Option<Observation>; ObsKind::COUNT],
}

impl SourceSlots {
    fn store(&mut self, observation: &Observation) {
        if let Some(slot) = self.latest.get_mut(observation.kind.index()) {
            *slot = Some(observation.clone());
        }
    }

    fn clear(&mut self) {
        self.latest = Default::default();
    }
}

/// Observability counters for one feed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeedStats {
    /// Updates published.
    pub published: u64,
    /// Polls that produced nothing because a publication trigger did not fire.
    pub suppressed: u64,
    /// Polls that halted.
    pub halted: u64,
    /// Polls that published a degraded price.
    pub degraded: u64,
    /// Quotes dropped by outlier rejection, cumulative.
    pub outliers_rejected: u64,
    /// Observations discarded because a connection dropped.
    pub invalidations: u64,
    /// Why the most recent poll degraded or halted, for metrics labels.
    pub last_reasons: Reasons,
}

/// One feed's runtime state.
struct FeedRuntime {
    config: FeedConfig,
    sources: Vec<SourceSlots>,
    last: Option<Published>,
    /// The most recent successful aggregation, published or not.
    ///
    /// Separate from `last` because a peg must be readable by dependent feeds on
    /// every tick, not only on the ticks where publication policy happened to
    /// fire.
    last_aggregate: Option<Peg>,
    reference: Option<Fixed>,
    reference_at_ns: u64,
    seq: u64,
    stats: FeedStats,
    /// An input changed since the last evaluation.
    dirty: bool,
    /// When a publication the rate cap held back becomes due.
    retry_at_ns: Option<u64>,
}

/// What the publication policy decided for one evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    Publish,
    Hold,
    /// A trigger fired inside the rate cap. Without a retry, a move that
    /// arrives just after a publish would wait for the next input or heartbeat.
    RateCapped {
        until_ns: u64,
    },
}

/// Aggregates observations from many venues into signed-ready price updates.
///
/// Deliberately holds no clock and performs no I/O: `now_ns` is passed in, and
/// output is returned rather than sent. A recorded observation sequence replayed
/// through this type reproduces its prices exactly, months later, on another
/// machine — which is what makes an incident reviewable.
pub struct Aggregator {
    feeds: Vec<FeedRuntime>,
    routes: HashMap<InstrumentId, Vec<(usize, usize)>>,
    by_id: HashMap<FeedId, usize>,
    /// Evaluation order: pegs before the feeds that depend on them, so a
    /// conversion reads a peg from this tick rather than the previous one.
    order: Vec<usize>,
    /// For each feed, the feeds converted through it.
    dependents: Vec<Vec<usize>>,
}

impl Aggregator {
    /// Starts every feed's sequence counter at `floor`.
    ///
    /// `seq` must never go backwards for a `(node, feed)`, and consumers refuse
    /// anything that does as a replay (SPEC §7). A counter that restarts at zero
    /// with the process therefore blinds every consumer to this node until it
    /// has published more updates than it ever had before. The node seeds the
    /// floor from its clock in milliseconds: a restart lands above the previous
    /// run as long as that run published fewer than one update per millisecond,
    /// and the rate caps make that certain.
    ///
    /// Replay tests leave the floor at zero so recorded sequences reproduce.
    #[must_use]
    pub fn with_sequence_floor(mut self, floor: u64) -> Self {
        for feed in &mut self.feeds {
            feed.seq = floor;
        }
        self
    }

    /// Builds an aggregator.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if any feed is invalid or two feeds share an id.
    pub fn new(configs: Vec<FeedConfig>) -> Result<Self, ConfigError> {
        let mut feeds = Vec::with_capacity(configs.len());
        let mut routes: HashMap<InstrumentId, Vec<(usize, usize)>> = HashMap::new();
        let mut by_id = HashMap::with_capacity(configs.len());

        for (feed_index, config) in configs.into_iter().enumerate() {
            config.validate()?;
            if by_id.insert(config.feed_id, feed_index).is_some() {
                return Err(ConfigError::DuplicateFeed {
                    symbol: config.symbol.to_string(),
                });
            }
            for (source_index, source) in config.sources.iter().enumerate() {
                routes
                    .entry(source.instrument.clone())
                    .or_default()
                    .push((feed_index, source_index));
            }
            feeds.push(FeedRuntime {
                sources: vec![SourceSlots::default(); config.sources.len()],
                config,
                last: None,
                last_aggregate: None,
                reference: None,
                reference_at_ns: 0,
                seq: 0,
                stats: FeedStats::default(),
                dirty: false,
                retry_at_ns: None,
            });
        }
        // Every peg must exist and must not itself need conversion.
        let mut dependents = vec![Vec::new(); feeds.len()];
        for (feed_index, feed) in feeds.iter().enumerate() {
            if !feed.config.needs_conversion() {
                continue;
            }
            let Some(conversion) = feed.config.quote_conversion else {
                continue;
            };
            let missing = || ConfigError::PegNotFound {
                symbol: feed.config.symbol.to_string(),
                peg: conversion.peg_feed.to_string(),
            };
            let peg_index = by_id
                .get(&conversion.peg_feed)
                .copied()
                .ok_or_else(missing)?;
            let peg = feeds.get(peg_index).ok_or_else(missing)?;
            if peg.config.needs_conversion() {
                return Err(ConfigError::ChainedPeg {
                    symbol: feed.config.symbol.to_string(),
                    peg: peg.config.symbol.to_string(),
                });
            }
            if let Some(list) = dependents.get_mut(peg_index) {
                list.push(feed_index);
            }
        }

        // Pegs first. With chaining forbidden, one pass is a complete ordering.
        let mut order: Vec<usize> = (0..feeds.len()).collect();
        order.sort_by_key(|index| {
            feeds
                .get(*index)
                .is_some_and(|feed| feed.config.needs_conversion())
        });

        Ok(Self {
            feeds,
            routes,
            by_id,
            order,
            dependents,
        })
    }

    /// Marks a feed for evaluation, and every feed converted through it.
    fn mark_dirty(&mut self, index: usize) {
        let dependents = self.dependents.get(index).cloned().unwrap_or_default();
        for target in std::iter::once(index).chain(dependents) {
            if let Some(feed) = self.feeds.get_mut(target) {
                feed.dirty = true;
            }
        }
    }

    /// Returns the peg reading a feed needs, if it needs one.
    fn peg_for(&self, index: usize) -> Option<Peg> {
        let feed = self.feeds.get(index)?;
        let conversion = feed.config.quote_conversion?;
        let peg_index = self.by_id.get(&conversion.peg_feed).copied()?;
        self.feeds.get(peg_index)?.last_aggregate
    }

    /// Returns the number of feeds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.feeds.len()
    }

    /// Returns `true` if no feeds are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.feeds.is_empty()
    }

    /// Returns the feed ids, in configuration order.
    pub fn feed_ids(&self) -> impl Iterator<Item = FeedId> + '_ {
        self.feeds.iter().map(|feed| feed.config.feed_id)
    }

    /// Returns a feed's counters.
    #[must_use]
    pub fn stats(&self, feed_id: FeedId) -> Option<FeedStats> {
        self.by_id
            .get(&feed_id)
            .and_then(|i| self.feeds.get(*i))
            .map(|feed| feed.stats)
    }

    /// Records an observation against every feed that consumes it.
    ///
    /// Observations for unconfigured instruments are ignored, which is normal:
    /// ingest may stream more than the aggregator is asked to price.
    pub fn observe(&mut self, observation: &Observation) {
        let Some(targets) = self.routes.get(&observation.instrument).cloned() else {
            return;
        };
        for (feed_index, source_index) in targets {
            if let Some(slots) = self
                .feeds
                .get_mut(feed_index)
                .and_then(|f| f.sources.get_mut(source_index))
            {
                slots.store(observation);
            }
            self.mark_dirty(feed_index);
        }
    }

    /// Discards everything known about a venue connection.
    ///
    /// Must be called the moment a connection drops. A book carried across a gap
    /// looks live and is not: the venue may have moved while we were blind, and
    /// the staleness filter cannot help if the gap was shorter than its threshold.
    pub fn invalidate(&mut self, venue: Venue, market: MarketKind) {
        let mut touched = Vec::new();
        for (feed_index, feed) in self.feeds.iter_mut().enumerate() {
            for (index, source) in feed.config.sources.iter().enumerate() {
                if source.instrument.venue == venue && source.instrument.market == market {
                    if let Some(slots) = feed.sources.get_mut(index) {
                        slots.clear();
                    }
                    feed.stats.invalidations = feed.stats.invalidations.saturating_add(1);
                    touched.push(feed_index);
                }
            }
        }
        for index in touched {
            self.mark_dirty(index);
        }
    }

    /// Evaluates one feed and returns an update if policy says to publish.
    ///
    /// # Errors
    ///
    /// Returns [`AggError::Unrepresentable`] if the price does not fit the feed's
    /// exponent.
    pub fn poll(&mut self, feed_id: FeedId, now_ns: u64) -> Result<Option<PriceUpdate>, AggError> {
        let Some(index) = self.by_id.get(&feed_id).copied() else {
            return Ok(None);
        };
        let peg = self.peg_for(index);
        let Some(feed) = self.feeds.get_mut(index) else {
            return Ok(None);
        };
        feed.poll(now_ns, peg)
    }

    /// Evaluates every feed.
    ///
    /// Errors are returned alongside the updates rather than short-circuiting: one
    /// misconfigured feed must not stop the others from publishing.
    pub fn poll_all(&mut self, now_ns: u64) -> (Vec<PriceUpdate>, Vec<AggError>) {
        self.poll_where(now_ns, |_| true)
    }

    /// Evaluates the feeds whose inputs changed since their last evaluation,
    /// and those whose rate-capped publication is now due.
    ///
    /// Call it after each batch of observations, so a move publishes when it
    /// arrives rather than on the next tick. [`Self::poll_all`] still has to
    /// run on a timer: heartbeats and stale sources change nothing on input.
    pub fn poll_changed(&mut self, now_ns: u64) -> (Vec<PriceUpdate>, Vec<AggError>) {
        self.poll_where(now_ns, |feed| {
            feed.dirty || feed.retry_at_ns.is_some_and(|at| at <= now_ns)
        })
    }

    /// The earliest moment a rate-capped publication becomes due.
    #[must_use]
    pub fn next_retry_ns(&self) -> Option<u64> {
        self.feeds.iter().filter_map(|feed| feed.retry_at_ns).min()
    }

    fn poll_where(
        &mut self,
        now_ns: u64,
        due: impl Fn(&FeedRuntime) -> bool,
    ) -> (Vec<PriceUpdate>, Vec<AggError>) {
        let mut updates = Vec::new();
        let mut errors = Vec::new();
        // Pegs first, so a dependent feed converts against this tick's reading.
        for position in 0..self.order.len() {
            let Some(index) = self.order.get(position).copied() else {
                continue;
            };
            if !self.feeds.get(index).is_some_and(&due) {
                continue;
            }
            let peg = self.peg_for(index);
            let Some(feed) = self.feeds.get_mut(index) else {
                continue;
            };
            match feed.poll(now_ns, peg) {
                Ok(Some(update)) => updates.push(update),
                Ok(None) => {}
                Err(error) => errors.push(error),
            }
        }
        (updates, errors)
    }
}

impl FeedRuntime {
    fn poll(&mut self, now_ns: u64, peg: Option<Peg>) -> Result<Option<PriceUpdate>, AggError> {
        self.dirty = false;
        self.retry_at_ns = None;
        let quotes = self.quotes(now_ns);
        let outcome = aggregate::aggregate(
            &self.config,
            quotes,
            self.reference,
            self.last.map(|l| l.price),
            peg,
        );

        let (price, conf, flags, reasons, sources, num_sources, observation_time_ns) = match outcome
        {
            Outcome::Priced(aggregation) => {
                self.stats.outliers_rejected = self
                    .stats
                    .outliers_rejected
                    .saturating_add(u64::from(aggregation.rejected));
                if aggregation.flags.is_degraded() {
                    self.stats.degraded = self.stats.degraded.saturating_add(1);
                }
                // Recorded on every successful aggregation, not only on publish,
                // so dependent feeds always have a peg to read.
                self.last_aggregate = Some(Peg {
                    price: aggregation.price,
                    conf: aggregation.conf,
                });
                (
                    aggregation.price,
                    aggregation.conf,
                    aggregation.flags,
                    aggregation.reasons,
                    aggregation.sources,
                    aggregation.num_sources,
                    aggregation.observation_time_ns,
                )
            }
            Outcome::Halted { reasons, .. } => {
                self.stats.halted = self.stats.halted.saturating_add(1);
                // A halted feed has no *current* reading, so it must stop being
                // usable as a peg. Leaving the last one in place would let a
                // dead peg silently convert dependent feeds forever, drifting by
                // however far the real rate had moved — with no signal anywhere.
                self.last_aggregate = None;
                // Carry the last good price so consumers have something to render,
                // flagged so nothing settles against it. With no history at all
                // there is nothing honest to say, so stay silent.
                let Some(last) = self.last else {
                    return Ok(None);
                };
                (
                    last.price,
                    // A halted feed's confidence is meaningless; make it loud
                    // rather than stale-narrow.
                    last.price.checked_abs().unwrap_or(Fixed::ZERO),
                    Flags::HALTED,
                    reasons,
                    oracle_types::VenueSet::EMPTY,
                    0,
                    0,
                )
            }
        };

        self.stats.last_reasons = reasons;
        match self.decide(price, flags, now_ns) {
            Decision::Publish => {}
            Decision::Hold => {
                self.stats.suppressed = self.stats.suppressed.saturating_add(1);
                return Ok(None);
            }
            Decision::RateCapped { until_ns } => {
                self.stats.suppressed = self.stats.suppressed.saturating_add(1);
                self.retry_at_ns = Some(until_ns);
                return Ok(None);
            }
        }

        let expo = self.config.expo;
        let price_mantissa = price
            .to_scaled(expo)
            .map_err(|source| AggError::Unrepresentable {
                symbol: self.config.symbol.to_string(),
                value: price.to_string(),
                expo,
                source,
            })?;
        let conf_mantissa =
            conf.to_scaled_unsigned(expo)
                .map_err(|source| AggError::Unrepresentable {
                    symbol: self.config.symbol.to_string(),
                    value: conf.to_string(),
                    expo,
                    source,
                })?;

        let prev_publish_time_ns = self.last.map_or(0, |last| last.publish_time_ns);
        self.seq = self.seq.saturating_add(1);
        self.stats.published = self.stats.published.saturating_add(1);
        self.update_reference(price, now_ns, flags);
        self.last = Some(Published {
            price,
            publish_time_ns: now_ns,
            flags,
        });

        Ok(Some(PriceUpdate {
            feed_id: self.config.feed_id,
            flags,
            price: price_mantissa,
            conf: conf_mantissa,
            expo,
            publish_time_ns: now_ns,
            observation_time_ns: observation_time_ns.min(now_ns),
            prev_publish_time_ns,
            seq: self.seq,
            num_sources,
            sources,
        }))
    }

    fn quotes(&self, now_ns: u64) -> Vec<SourceQuote> {
        self.config
            .sources
            .iter()
            .enumerate()
            .filter_map(|(index, source)| {
                let slots = self.sources.get(index)?;
                quote::derive(source, &self.config, &slots.latest, now_ns)
            })
            .collect()
    }

    /// Applies the publication policy from SPEC.md §5.6.
    ///
    /// The rate cap is checked **first**, before deviation, heartbeat, or a flag
    /// transition. It is what bounds signing cost and subscriber bandwidth under
    /// volatility — precisely when both are under the most stress. The cost is
    /// that a halt or degrade transition can be delayed by up to `min_interval`.
    fn decide(&self, price: Fixed, flags: Flags, now_ns: u64) -> Decision {
        let Some(last) = self.last else {
            return Decision::Publish;
        };

        let elapsed = now_ns.saturating_sub(last.publish_time_ns);
        let triggered = flags != last.flags
            || elapsed >= duration_ns(self.config.heartbeat)
            || price
                .checked_sub(last.price)
                .and_then(Fixed::checked_abs)
                .and_then(|delta| delta.to_bps_of(last.price))
                .is_some_and(|bps| bps >= self.config.deviation_bps);
        let min_interval = duration_ns(self.config.min_interval);
        match (triggered, elapsed < min_interval) {
            (false, _) => Decision::Hold,
            (true, false) => Decision::Publish,
            (true, true) => Decision::RateCapped {
                until_ns: last.publish_time_ns.saturating_add(min_interval),
            },
        }
    }

    /// Advances the sanity-band reference toward the published price.
    ///
    /// `alpha = dt / (half_life + dt)`: a hyperbolic approach rather than a true
    /// exponential, so it needs no transcendental function and replays exactly.
    /// The reference only bounds a 0.5×–2× band, so the approximation is far
    /// below the precision that matters.
    ///
    /// Halted prices are excluded — feeding a carried-forward value back into the
    /// reference would let a stuck feed slowly drag its own sanity band with it.
    fn update_reference(&mut self, price: Fixed, now_ns: u64, flags: Flags) {
        if flags.is_halted() {
            return;
        }
        let Some(reference) = self.reference else {
            self.reference = Some(price);
            self.reference_at_ns = now_ns;
            return;
        };
        let dt = now_ns.saturating_sub(self.reference_at_ns);
        let half_life = duration_ns(self.config.ema_half_life).max(1);
        let updated = (|| {
            let dt = Fixed::from_raw(i128::from(dt));
            let half_life = Fixed::from_raw(i128::from(half_life));
            let alpha = dt.checked_div(half_life.checked_add(dt)?)?;
            let delta = price.checked_sub(reference)?;
            reference.checked_add(delta.checked_mul(alpha)?)
        })();
        if let Some(updated) = updated {
            self.reference = Some(updated);
            self.reference_at_ns = now_ns;
        }
    }
}

/// Converts a duration to nanoseconds, saturating.
fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SourceConfig;
    use oracle_types::{Symbol, VenueSet};

    const SECOND: u64 = 1_000_000_000;

    fn fixed(text: &str) -> Fixed {
        text.parse().expect("valid decimal")
    }

    fn instrument(venue: Venue) -> InstrumentId {
        InstrumentId::new(venue, MarketKind::Spot, "BTCUSDT")
    }

    fn config(venues: &[Venue]) -> FeedConfig {
        let symbol: Symbol = "CRYPTO.BTC/USDT".parse().expect("valid");
        let sources = venues
            .iter()
            .map(|venue| {
                SourceConfig::new(instrument(*venue), vec![ObsKind::BookTop, ObsKind::Trade])
            })
            .collect();
        FeedConfig::spot(symbol, FeedId::from_bytes([1; 32]), sources)
    }

    fn book(venue: Venue, bid: &str, ask: &str, recv_ns: u64) -> Observation {
        Observation {
            instrument: instrument(venue),
            kind: ObsKind::BookTop,
            price: fixed(bid),
            bid: Some(fixed(bid)),
            ask: Some(fixed(ask)),
            bid_qty: Some(Fixed::ONE),
            ask_qty: Some(Fixed::ONE),
            depth_notional_1bp: None,
            exchange_time_ns: None,
            local_recv_ns: recv_ns,
            seq: None,
            book: None,
        }
    }

    const THREE: [Venue; 3] = [Venue::Binance, Venue::Bybit, Venue::Okx];

    fn feed_id() -> FeedId {
        FeedId::from_bytes([1; 32])
    }

    fn aggregator() -> Aggregator {
        Aggregator::new(vec![config(&THREE)]).expect("valid config")
    }

    fn feed(aggregator: &mut Aggregator, at_ns: u64, prices: &[(Venue, &str, &str)]) {
        for (venue, bid, ask) in prices {
            aggregator.observe(&book(*venue, bid, ask, at_ns));
        }
    }

    #[test]
    fn first_poll_publishes() {
        let mut aggregator = aggregator();
        feed(
            &mut aggregator,
            SECOND,
            &[
                (Venue::Binance, "100", "100.02"),
                (Venue::Bybit, "100.01", "100.03"),
                (Venue::Okx, "99.99", "100.01"),
            ],
        );
        let update = aggregator
            .poll(feed_id(), SECOND)
            .expect("no error")
            .expect("publishes");
        assert_eq!(update.seq, 1);
        assert_eq!(update.prev_publish_time_ns, 0);
        assert_eq!(update.num_sources, 3);
        assert_eq!(update.expo, -8);
        assert!(update.flags.is_none());
        assert!(update.sources_consistent());
        assert!(update.timestamps_coherent());
    }

    #[test]
    fn a_quiet_feed_is_suppressed_until_the_heartbeat() {
        let mut aggregator = aggregator();
        feed(
            &mut aggregator,
            SECOND,
            &[(Venue::Binance, "100", "100.02")],
        );
        feed(&mut aggregator, SECOND, &[(Venue::Bybit, "100", "100.02")]);
        assert!(
            aggregator
                .poll(feed_id(), SECOND)
                .expect("no error")
                .is_some()
        );

        // 100ms later, nothing has moved: past min_interval, short of heartbeat.
        let later = SECOND + 100_000_000;
        feed(&mut aggregator, later, &[(Venue::Binance, "100", "100.02")]);
        feed(&mut aggregator, later, &[(Venue::Bybit, "100", "100.02")]);
        assert!(
            aggregator
                .poll(feed_id(), later)
                .expect("no error")
                .is_none()
        );

        // A full second later the heartbeat fires.
        let heartbeat = SECOND + 1_000_000_000;
        feed(
            &mut aggregator,
            heartbeat,
            &[(Venue::Binance, "100", "100.02")],
        );
        feed(
            &mut aggregator,
            heartbeat,
            &[(Venue::Bybit, "100", "100.02")],
        );
        let update = aggregator
            .poll(feed_id(), heartbeat)
            .expect("no error")
            .expect("heartbeat publishes");
        assert_eq!(update.seq, 2);
        assert_eq!(update.prev_publish_time_ns, SECOND);
    }

    #[test]
    fn a_move_past_the_deviation_threshold_publishes_early() {
        let mut aggregator = aggregator();
        feed(
            &mut aggregator,
            SECOND,
            &[(Venue::Binance, "100", "100.02")],
        );
        feed(&mut aggregator, SECOND, &[(Venue::Bybit, "100", "100.02")]);
        assert!(
            aggregator
                .poll(feed_id(), SECOND)
                .expect("no error")
                .is_some()
        );

        // 10bp move, well past the 1bp threshold, only 100ms later.
        let later = SECOND + 100_000_000;
        feed(
            &mut aggregator,
            later,
            &[(Venue::Binance, "100.1", "100.12")],
        );
        feed(&mut aggregator, later, &[(Venue::Bybit, "100.1", "100.12")]);
        assert!(
            aggregator
                .poll(feed_id(), later)
                .expect("no error")
                .is_some()
        );
    }

    #[test]
    fn the_rate_cap_is_applied_before_every_other_trigger() {
        let mut aggregator = aggregator();
        feed(
            &mut aggregator,
            SECOND,
            &[(Venue::Binance, "100", "100.02")],
        );
        feed(&mut aggregator, SECOND, &[(Venue::Bybit, "100", "100.02")]);
        assert!(
            aggregator
                .poll(feed_id(), SECOND)
                .expect("no error")
                .is_some()
        );

        // A huge move 10ms later, inside the 50ms cap: suppressed regardless.
        let soon = SECOND + 10_000_000;
        feed(&mut aggregator, soon, &[(Venue::Binance, "200", "200.02")]);
        feed(&mut aggregator, soon, &[(Venue::Bybit, "200", "200.02")]);
        assert!(
            aggregator
                .poll(feed_id(), soon)
                .expect("no error")
                .is_none()
        );
    }

    #[test]
    fn poll_changed_evaluates_only_feeds_with_new_input() {
        let mut aggregator = aggregator();
        let both = |bid, ask| [(Venue::Binance, bid, ask), (Venue::Bybit, bid, ask)];
        feed(&mut aggregator, SECOND, &both("100", "100.02"));
        assert_eq!(aggregator.poll_changed(SECOND).0.len(), 1);

        let later = SECOND + 100_000_000;
        assert!(aggregator.poll_changed(later).0.is_empty());
        assert_eq!(
            aggregator.stats(feed_id()).map(|stats| stats.suppressed),
            Some(0),
            "nothing changed, so nothing was evaluated"
        );

        // 2bp, past the 1bp threshold: published when it arrives.
        feed(&mut aggregator, later, &both("100.02", "100.04"));
        assert_eq!(aggregator.poll_changed(later).0.len(), 1);
    }

    /// Without the retry, a move just after a publish waits for the next input
    /// or the heartbeat.
    #[test]
    fn a_rate_capped_move_is_due_when_the_cap_expires() {
        let mut aggregator = aggregator();
        let both = |bid, ask| [(Venue::Binance, bid, ask), (Venue::Bybit, bid, ask)];
        feed(&mut aggregator, SECOND, &both("100", "100.02"));
        assert_eq!(aggregator.poll_changed(SECOND).0.len(), 1);
        assert_eq!(aggregator.next_retry_ns(), None);

        let soon = SECOND + 10_000_000;
        feed(&mut aggregator, soon, &both("101", "101.02"));
        assert!(aggregator.poll_changed(soon).0.is_empty());
        let due = SECOND + 50_000_000;
        assert_eq!(aggregator.next_retry_ns(), Some(due));
        assert!(aggregator.poll_changed(due - 1).0.is_empty(), "not due yet");
        assert_eq!(aggregator.poll_changed(due).0.len(), 1);
        assert_eq!(aggregator.next_retry_ns(), None);
    }

    #[test]
    fn losing_quorum_halts_and_carries_the_last_good_price() {
        let mut aggregator = aggregator();
        feed(
            &mut aggregator,
            SECOND,
            &[(Venue::Binance, "100", "100.02")],
        );
        feed(&mut aggregator, SECOND, &[(Venue::Bybit, "100", "100.02")]);
        let good = aggregator
            .poll(feed_id(), SECOND)
            .expect("no error")
            .expect("publishes");

        // Three seconds on with no new data: everything is stale.
        let later = SECOND + 3 * SECOND;
        let halted = aggregator
            .poll(feed_id(), later)
            .expect("no error")
            .expect("halt publishes");
        assert!(halted.flags.is_halted());
        assert!(!halted.is_usable());
        assert_eq!(halted.price, good.price, "the last good price is carried");
        assert_eq!(halted.num_sources, 0);
        assert_eq!(halted.sources, VenueSet::EMPTY);
    }

    #[test]
    fn a_halt_with_no_history_stays_silent() {
        let mut aggregator = aggregator();
        // Only one venue, below the quorum of two, and nothing published before.
        feed(
            &mut aggregator,
            SECOND,
            &[(Venue::Binance, "100", "100.02")],
        );
        assert!(
            aggregator
                .poll(feed_id(), SECOND)
                .expect("no error")
                .is_none()
        );
        assert_eq!(aggregator.stats(feed_id()).expect("known feed").halted, 1);
    }

    #[test]
    fn a_disconnect_invalidates_that_venue_immediately() {
        let mut aggregator = aggregator();
        feed(
            &mut aggregator,
            SECOND,
            &[
                (Venue::Binance, "100", "100.02"),
                (Venue::Bybit, "100", "100.02"),
                (Venue::Okx, "100", "100.02"),
            ],
        );
        assert_eq!(
            aggregator
                .poll(feed_id(), SECOND)
                .expect("no error")
                .expect("publishes")
                .num_sources,
            3
        );

        // Binance drops. Its book must not survive the gap, even though it is
        // only milliseconds old and would sail through the staleness filter.
        aggregator.invalidate(Venue::Binance, MarketKind::Spot);
        let later = SECOND + SECOND;
        feed(&mut aggregator, later, &[(Venue::Bybit, "100", "100.02")]);
        feed(&mut aggregator, later, &[(Venue::Okx, "100", "100.02")]);
        let update = aggregator
            .poll(feed_id(), later)
            .expect("no error")
            .expect("publishes");
        assert_eq!(update.num_sources, 2);
        assert!(!update.sources.contains(Venue::Binance));
    }

    #[test]
    fn recovering_from_a_halt_publishes_the_transition_immediately() {
        let mut aggregator = aggregator();
        feed(
            &mut aggregator,
            SECOND,
            &[(Venue::Binance, "100", "100.02")],
        );
        feed(&mut aggregator, SECOND, &[(Venue::Bybit, "100", "100.02")]);
        assert!(
            aggregator
                .poll(feed_id(), SECOND)
                .expect("no error")
                .is_some()
        );

        let halt_at = SECOND + 3 * SECOND;
        assert!(
            aggregator
                .poll(feed_id(), halt_at)
                .expect("no error")
                .expect("halts")
                .flags
                .is_halted()
        );

        // Data returns 100ms later: past min_interval, well short of heartbeat.
        let recover = halt_at + 100_000_000;
        feed(
            &mut aggregator,
            recover,
            &[(Venue::Binance, "100", "100.02")],
        );
        feed(&mut aggregator, recover, &[(Venue::Bybit, "100", "100.02")]);
        let update = aggregator
            .poll(feed_id(), recover)
            .expect("no error")
            .expect("transition publishes");
        assert!(
            update.flags.is_none(),
            "recovery must be announced, not waited out"
        );
    }

    /// A restarted node must not reuse sequence numbers, or consumers refuse
    /// it as a replay until it catches up with its previous life.
    #[test]
    fn the_sequence_floor_puts_a_restart_above_the_previous_run() {
        let mut aggregator = aggregator().with_sequence_floor(1_000_000);
        feed(
            &mut aggregator,
            SECOND,
            &[(Venue::Binance, "100", "100.02")],
        );
        feed(&mut aggregator, SECOND, &[(Venue::Bybit, "100", "100.02")]);
        let first = aggregator
            .poll(feed_id(), SECOND)
            .expect("no error")
            .expect("published");
        assert_eq!(first.seq, 1_000_001);
    }

    #[test]
    fn sequence_numbers_are_monotonic_and_never_reused() {
        let mut aggregator = aggregator();
        let mut seen = Vec::new();
        for tick in 0..10_u64 {
            let at = SECOND + tick * SECOND;
            feed(&mut aggregator, at, &[(Venue::Binance, "100", "100.02")]);
            feed(&mut aggregator, at, &[(Venue::Bybit, "100", "100.02")]);
            if let Some(update) = aggregator.poll(feed_id(), at).expect("no error") {
                seen.push(update.seq);
            }
        }
        assert!(seen.len() >= 5);
        assert!(
            seen.windows(2)
                .all(|w| matches!((w.first(), w.get(1)), (Some(a), Some(b)) if b > a)),
            "sequence went backwards: {seen:?}"
        );
    }

    #[test]
    fn observations_for_unconfigured_instruments_are_ignored() {
        let mut aggregator = aggregator();
        let stranger = Observation {
            instrument: InstrumentId::new(Venue::Kraken, MarketKind::Spot, "XBTUSD"),
            ..book(Venue::Binance, "100", "100.02", SECOND)
        };
        aggregator.observe(&stranger);
        feed(
            &mut aggregator,
            SECOND,
            &[(Venue::Binance, "100", "100.02")],
        );
        feed(&mut aggregator, SECOND, &[(Venue::Bybit, "100", "100.02")]);
        let update = aggregator
            .poll(feed_id(), SECOND)
            .expect("no error")
            .expect("publishes");
        assert_eq!(update.num_sources, 2);
    }

    #[test]
    fn duplicate_feed_ids_are_rejected() {
        let configs = vec![config(&THREE), config(&THREE)];
        assert!(matches!(
            Aggregator::new(configs),
            Err(ConfigError::DuplicateFeed { .. })
        ));
    }

    #[test]
    fn an_unrepresentable_price_is_an_error_not_a_silent_skip() {
        let mut config = config(&THREE);
        // Exponent -18 cannot hold a price near 100 in an i64 mantissa.
        config.expo = -18;
        let mut aggregator = Aggregator::new(vec![config]).expect("valid config");
        feed(
            &mut aggregator,
            SECOND,
            &[(Venue::Binance, "100", "100.02")],
        );
        feed(&mut aggregator, SECOND, &[(Venue::Bybit, "100", "100.02")]);
        assert!(matches!(
            aggregator.poll(feed_id(), SECOND),
            Err(AggError::Unrepresentable { .. })
        ));
    }

    #[test]
    fn poll_all_reports_errors_without_stopping_healthy_feeds() {
        let healthy = config(&THREE);
        let mut broken = config(&THREE);
        broken.feed_id = FeedId::from_bytes([2; 32]);
        broken.expo = -18;
        let mut aggregator = Aggregator::new(vec![healthy, broken]).expect("valid config");
        feed(
            &mut aggregator,
            SECOND,
            &[(Venue::Binance, "100", "100.02")],
        );
        feed(&mut aggregator, SECOND, &[(Venue::Bybit, "100", "100.02")]);

        let (updates, errors) = aggregator.poll_all(SECOND);
        assert_eq!(updates.len(), 1, "the healthy feed must still publish");
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn the_reference_ignores_carried_forward_halt_prices() {
        let mut aggregator = aggregator();
        feed(
            &mut aggregator,
            SECOND,
            &[(Venue::Binance, "100", "100.02")],
        );
        feed(&mut aggregator, SECOND, &[(Venue::Bybit, "100", "100.02")]);
        assert!(
            aggregator
                .poll(feed_id(), SECOND)
                .expect("no error")
                .is_some()
        );

        // Halt for a long time. A stuck feed must not drag its own sanity band.
        for tick in 1..60_u64 {
            let _ = aggregator.poll(feed_id(), SECOND + tick * 10 * SECOND);
        }
        let feed_state = aggregator.feeds.first().expect("one feed");
        assert_eq!(feed_state.reference, Some(fixed("100.01")));
    }
}
