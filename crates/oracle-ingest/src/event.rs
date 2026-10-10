//! What an adapter emits downstream.

use std::sync::Arc;

use oracle_types::{InstrumentId, MarketKind, ObsKind, Observation, Venue};

/// Identifies one venue connection: a venue plus a market type.
///
/// Adapters hold one WebSocket per stream id, because venues split spot and
/// derivatives across different hosts and they fail independently.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct StreamId {
    /// The venue.
    pub venue: Venue,
    /// Spot or perpetual.
    pub market: MarketKind,
}

impl StreamId {
    /// Builds a stream id.
    #[must_use]
    pub const fn new(venue: Venue, market: MarketKind) -> Self {
        Self { venue, market }
    }
}

impl core::fmt::Display for StreamId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.venue, self.market)
    }
}

/// An event from an ingest adapter.
///
/// Connection transitions are in-band rather than a side channel because their
/// ordering relative to observations is the entire point: everything received
/// before a [`IngestEvent::Disconnected`] is suspect, and nothing may be carried
/// across it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IngestEvent {
    /// A normalized market observation.
    Observation(Box<Observation>),

    /// A connection came up. Any state for this stream should already have been
    /// discarded by the preceding [`IngestEvent::Disconnected`].
    Connected {
        /// Which connection.
        stream: StreamId,
    },

    /// A connection received something: data, a heartbeat or a reply.
    ///
    /// Venues send a value when it changes, so while its connection lives, an
    /// unchanged value is still the venue's current one. Without this, a quiet
    /// instrument would look dead after the staleness limit.
    Alive {
        /// Which connection.
        stream: StreamId,
        /// Each instrument and kind that this connection has delivered.
        sources: Arc<[(InstrumentId, ObsKind)]>,
        /// Our receipt time.
        local_recv_ns: u64,
    },

    /// A connection went away.
    ///
    /// **Consumers must immediately invalidate all state for this stream.** A
    /// book carried across a gap looks live and is not; the venue may have moved
    /// while we were blind, and the staleness filter cannot save us if the gap
    /// was shorter than its threshold.
    Disconnected {
        /// Which connection.
        stream: StreamId,
        /// Why, for logs and metrics.
        reason: String,
    },
}

impl IngestEvent {
    /// Wraps an observation.
    #[must_use]
    pub fn observation(observation: Observation) -> Self {
        Self::Observation(Box::new(observation))
    }

    /// Returns the observation, if this is one.
    #[must_use]
    pub fn as_observation(&self) -> Option<&Observation> {
        match self {
            Self::Observation(obs) => Some(obs),
            _ => None,
        }
    }

    /// Returns the stream this event concerns.
    #[must_use]
    pub fn stream(&self) -> StreamId {
        match self {
            Self::Observation(obs) => StreamId::new(obs.instrument.venue, obs.instrument.market),
            Self::Connected { stream }
            | Self::Disconnected { stream, .. }
            | Self::Alive { stream, .. } => *stream,
        }
    }
}
