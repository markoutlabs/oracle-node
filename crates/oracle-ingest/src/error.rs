//! Ingest error types.

use oracle_types::{InstrumentId, Venue};

/// A failure that retrying will not fix.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IngestError {
    /// The adapter was configured with no instruments.
    #[error("adapter for {venue} has no instruments configured")]
    NoInstruments {
        /// The venue.
        venue: Venue,
    },

    /// A venue symbol appeared twice in one adapter's configuration.
    #[error("duplicate instrument `{symbol}` for {venue}")]
    DuplicateInstrument {
        /// The venue.
        venue: Venue,
        /// The venue's own symbol.
        symbol: String,
    },

    /// The downstream receiver was dropped, so there is nobody left to feed.
    #[error("ingest output channel closed")]
    OutputClosed,

    /// A configuration value was rejected.
    #[error("invalid configuration: {0}")]
    Config(String),
}

/// A failure decoding one message.
///
/// These are per-message and never fatal: one malformed frame must not take down
/// a connection carrying hundreds of good ones. Callers count them and move on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The payload was not valid JSON, or not the shape expected.
    #[error("malformed payload: {0}")]
    Malformed(String),

    /// A required field was absent.
    #[error("missing field `{0}`")]
    MissingField(&'static str),

    /// A numeric field could not be parsed as a decimal.
    #[error("field `{field}` is not a valid decimal: `{value}`")]
    BadDecimal {
        /// Which field.
        field: &'static str,
        /// What arrived.
        value: String,
    },

    /// The message referred to an instrument this adapter does not track.
    ///
    /// Expected in normal operation: venues echo subscription confirmations and
    /// occasionally send streams nobody asked for.
    #[error("unknown instrument `{0}`")]
    UnknownInstrument(String),

    /// The stream name did not match anything this decoder handles.
    #[error("unhandled stream `{0}`")]
    UnhandledStream(String),

    /// The message was a control response, not market data.
    ///
    /// Not an error condition; callers skip these silently.
    #[error("control message")]
    Control,

    /// A local book can no longer be trusted: a checksum failed or an update was
    /// missed. The session drops the connection, and the reconnect brings a
    /// fresh snapshot.
    #[error("book out of sync: {0}")]
    Resync(String),

    /// The venue halted trading in this instrument, and the session stops
    /// confirming its last values, so they go stale.
    #[error("trading halted in {0}")]
    Halted(InstrumentId),
}

impl From<serde_json::Error> for DecodeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Malformed(error.to_string())
    }
}

impl From<prost::DecodeError> for DecodeError {
    fn from(error: prost::DecodeError) -> Self {
        Self::Malformed(error.to_string())
    }
}

impl DecodeError {
    /// Returns `true` if this outcome is routine and should not be logged as a fault.
    ///
    /// Subscription acknowledgements and streams we do not track arrive
    /// constantly. Counting them as decode failures would bury the malformed
    /// payloads that actually matter.
    #[must_use]
    pub const fn is_benign(&self) -> bool {
        matches!(
            self,
            Self::Control | Self::UnhandledStream(_) | Self::UnknownInstrument(_) | Self::Halted(_)
        )
    }
}
