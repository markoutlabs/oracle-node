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

    /// These instruments' books have an empty side, so they have no quote. The
    /// session keeps the other observations and stops confirming these books.
    #[error("no two-sided book in {}", joined(.0))]
    Halted(Vec<InstrumentId>),

    /// The venue suspended trading in this instrument. The session stops
    /// confirming all its values.
    #[error("trading suspended in {0}")]
    Suspended(InstrumentId),

    /// A book or quote message of this instrument did not decode. The session
    /// counts it and stops confirming the book, so an old quote cannot stay live.
    #[error("{instrument}: {error}")]
    Lost {
        /// The instrument whose book or quote is lost.
        instrument: InstrumentId,
        /// Why the message did not decode.
        error: Box<DecodeError>,
    },
}

fn joined(instruments: &[InstrumentId]) -> String {
    instruments
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
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
    /// A halt of one instrument's book.
    #[must_use]
    pub fn halted(instrument: &InstrumentId) -> Self {
        Self::Halted(vec![instrument.clone()])
    }

    /// `error` from a book or quote message of `instrument`. A benign error and
    /// a resync stay as they are.
    #[must_use]
    pub fn lost(instrument: &InstrumentId, error: Self) -> Self {
        if error.is_benign() || matches!(error, Self::Resync(_) | Self::Lost { .. }) {
            return error;
        }
        Self::Lost {
            instrument: instrument.clone(),
            error: Box::new(error),
        }
    }

    /// Returns `true` if this outcome is routine and should not be logged as a fault.
    ///
    /// Subscription acknowledgements and streams we do not track arrive
    /// constantly. Counting them as decode failures would bury the malformed
    /// payloads that actually matter.
    #[must_use]
    pub const fn is_benign(&self) -> bool {
        matches!(
            self,
            Self::Control
                | Self::UnhandledStream(_)
                | Self::UnknownInstrument(_)
                | Self::Halted(_)
                | Self::Suspended(_)
        )
    }
}
