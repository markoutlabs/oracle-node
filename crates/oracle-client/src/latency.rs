//! Where the time goes between a venue and this client.
//!
//! Each update carries two node timestamps: when the node received the newest
//! venue data, and when it signed. With the time this client received the
//! frame, they split the path into the node, the network and the client.

use std::fmt;
use std::time::Duration;

use hdrhistogram::Histogram;
use oracle_types::PriceUpdate;

/// The largest value a histogram tells apart, in microseconds: one minute.
const MAX_MICROS: u64 = 60_000_000;

/// The percentiles of one latency.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Percentiles {
    /// How many values were recorded.
    pub count: u64,
    /// The median.
    pub p50: Duration,
    /// The 90th percentile.
    pub p90: Duration,
    /// The 99th percentile.
    pub p99: Duration,
    /// The largest value.
    pub max: Duration,
}

impl fmt::Display for Percentiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ms = |value: Duration| value.as_secs_f64() * 1_000.0;
        write!(
            f,
            "p50 {:.2} ms, p90 {:.2} ms, p99 {:.2} ms, max {:.2} ms (n={})",
            ms(self.p50),
            ms(self.p90),
            ms(self.p99),
            ms(self.max),
            self.count
        )
    }
}

/// A latency histogram with microsecond steps, up to one minute.
#[derive(Clone, Debug)]
pub struct LatencyHistogram(Histogram<u64>);

impl LatencyHistogram {
    /// Builds an empty histogram.
    ///
    /// # Panics
    ///
    /// Never: the bounds are constants that the crate accepts.
    #[must_use]
    pub fn new() -> Self {
        // Three significant digits: a 0.1% error in about 10 kB.
        Self(Histogram::new_with_bounds(1, MAX_MICROS, 3).expect("constant bounds are valid"))
    }

    /// Records one value. A value above one minute counts as one minute.
    pub fn record(&mut self, value: Duration) {
        self.0
            .saturating_record(u64::try_from(value.as_micros()).unwrap_or(u64::MAX));
    }

    /// Records the time from `from_ns` to `to_ns`, or zero if `to_ns` is earlier.
    pub fn record_between(&mut self, from_ns: u64, to_ns: u64) {
        self.record(Duration::from_nanos(to_ns.saturating_sub(from_ns)));
    }

    /// Returns the percentiles of what was recorded.
    #[must_use]
    pub fn percentiles(&self) -> Percentiles {
        let at = |quantile| Duration::from_micros(self.0.value_at_quantile(quantile));
        Percentiles {
            count: self.0.len(),
            p50: at(0.5),
            p90: at(0.9),
            p99: at(0.99),
            max: Duration::from_micros(self.0.max()),
        }
    }

    /// Empties the histogram.
    pub fn reset(&mut self) {
        self.0.reset();
    }
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Where the time went for the updates this client accepted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LatencyReport {
    /// From the node signing an update to this client receiving it.
    ///
    /// It compares the node clock with this one. Thus it is exact only on one
    /// machine, or with clocks in sync.
    pub delivery: Percentiles,
    /// From the node receiving the newest venue data to this client receiving
    /// the update.
    ///
    /// A heartbeat sends a price again on purpose. Thus this is the age of the
    /// data, not only the delay.
    pub data_age: Percentiles,
    /// From receipt to the resolved price: decryption, the queue, verification
    /// and the quorum.
    pub processing: Percentiles,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Latency {
    delivery: LatencyHistogram,
    data_age: LatencyHistogram,
    processing: LatencyHistogram,
}

impl Latency {
    pub(crate) fn arrived(&mut self, update: &PriceUpdate, received_ns: u64) {
        self.delivery
            .record_between(update.publish_time_ns, received_ns);
        // A halted update carries the last good price, not new data.
        if !update.flags.is_halted() {
            self.data_age
                .record_between(update.observation_time_ns, received_ns);
        }
    }

    pub(crate) fn resolved(&mut self, received_ns: u64, now_ns: u64) {
        self.processing.record_between(received_ns, now_ns);
    }

    pub(crate) fn report(&self) -> LatencyReport {
        LatencyReport {
            delivery: self.delivery.percentiles(),
            data_age: self.data_age.percentiles(),
            processing: self.processing.percentiles(),
        }
    }

    pub(crate) fn reset(&mut self) {
        self.delivery.reset();
        self.data_age.reset();
        self.processing.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_types::{FeedId, Flags, VenueSet};

    const MS: u64 = 1_000_000;

    fn update(observed_ns: u64, published_ns: u64, flags: Flags) -> PriceUpdate {
        PriceUpdate {
            feed_id: FeedId::from_bytes([7; 32]),
            flags,
            price: 1,
            conf: 0,
            expo: -8,
            publish_time_ns: published_ns,
            observation_time_ns: observed_ns,
            prev_publish_time_ns: 0,
            seq: 1,
            num_sources: 0,
            sources: VenueSet::EMPTY,
        }
    }

    #[test]
    fn each_stage_measures_its_own_span() {
        let mut latency = Latency::default();
        latency.arrived(&update(100 * MS, 102 * MS, Flags::NONE), 105 * MS);
        latency.resolved(105 * MS, 106 * MS);
        let report = latency.report();
        // Three significant digits: 3 ms reads as 3.001 ms.
        assert_eq!(report.delivery.p50.as_millis(), 3);
        assert_eq!(report.data_age.p50.as_millis(), 5);
        assert_eq!(report.processing.p50.as_millis(), 1);
        assert_eq!(report.delivery.count, 1);
    }

    #[test]
    fn a_halted_update_has_no_data_age() {
        let mut latency = Latency::default();
        latency.arrived(&update(0, 102 * MS, Flags::HALTED), 105 * MS);
        let report = latency.report();
        assert_eq!(report.delivery.count, 1);
        assert_eq!(report.data_age.count, 0);
    }

    #[test]
    fn a_clock_behind_the_node_reads_as_zero() {
        let mut latency = Latency::default();
        latency.arrived(&update(100 * MS, 110 * MS, Flags::NONE), 105 * MS);
        assert_eq!(latency.report().delivery.max, Duration::ZERO);
    }

    #[test]
    fn values_past_a_minute_count_as_a_minute() {
        let mut histogram = LatencyHistogram::new();
        histogram.record(Duration::from_secs(3_600));
        let max = histogram.percentiles().max;
        assert!(
            max >= Duration::from_secs(59) && max <= Duration::from_secs(61),
            "{max:?}"
        );
    }

    #[test]
    fn reset_empties_every_stage() {
        let mut latency = Latency::default();
        latency.arrived(&update(100 * MS, 102 * MS, Flags::NONE), 105 * MS);
        latency.resolved(105 * MS, 106 * MS);
        latency.reset();
        assert_eq!(latency.report(), LatencyReport::default());
    }
}
