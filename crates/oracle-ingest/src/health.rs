//! The counters of each venue connection, which the node reads while it runs.
//!
//! A decode error keeps the connection up, so only these counters and the
//! session's warning show a venue that changed its format (SPEC §9.3).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::StreamId;

/// A shared handle on one connection's counters. Clones share them.
#[derive(Clone, Debug)]
pub struct VenueHealth {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    stream: StreamId,
    url: String,
    connects: AtomicU64,
    decode_errors: AtomicU64,
    resyncs: AtomicU64,
    resubscribes: AtomicU64,
    idle_timeouts: AtomicU64,
}

/// The counters at one moment, each a total since the connection was built.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HealthCounts {
    /// Connections that came up.
    pub connects: u64,
    /// Payloads that did not decode, for a reason that is not routine.
    pub decode_errors: u64,
    /// Connections dropped because a book could not be proved.
    pub resyncs: u64,
    /// Connections recycled because an instrument fell silent.
    pub resubscribes: u64,
    /// Connections dropped because nothing arrived.
    pub idle_timeouts: u64,
}

/// One counter.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Counter {
    Connect,
    DecodeError,
    Resync,
    Resubscribe,
    IdleTimeout,
}

impl VenueHealth {
    /// Zeroed counters for the connection of `stream` at `url`.
    #[must_use]
    pub fn new(stream: StreamId, url: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(Inner {
                stream,
                url: url.into(),
                connects: AtomicU64::new(0),
                decode_errors: AtomicU64::new(0),
                resyncs: AtomicU64::new(0),
                resubscribes: AtomicU64::new(0),
                idle_timeouts: AtomicU64::new(0),
            }),
        }
    }

    /// The venue and market of the connection.
    #[must_use]
    pub fn stream(&self) -> StreamId {
        self.inner.stream
    }

    /// The endpoint of the connection.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.inner.url
    }

    /// The counters now.
    #[must_use]
    pub fn counts(&self) -> HealthCounts {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        HealthCounts {
            connects: read(&self.inner.connects),
            decode_errors: read(&self.inner.decode_errors),
            resyncs: read(&self.inner.resyncs),
            resubscribes: read(&self.inner.resubscribes),
            idle_timeouts: read(&self.inner.idle_timeouts),
        }
    }

    pub(crate) fn count(&self, counter: Counter) {
        let atomic = match counter {
            Counter::Connect => &self.inner.connects,
            Counter::DecodeError => &self.inner.decode_errors,
            Counter::Resync => &self.inner.resyncs,
            Counter::Resubscribe => &self.inner.resubscribes,
            Counter::IdleTimeout => &self.inner.idle_timeouts,
        };
        atomic.fetch_add(1, Ordering::Relaxed);
    }
}
