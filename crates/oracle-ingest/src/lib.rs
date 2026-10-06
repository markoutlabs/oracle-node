//! Exchange WebSocket ingest.
//!
//! Every venue lives behind [`ExchangeAdapter`], so the aggregator downstream
//! never learns anything venue-specific. An adapter's job is narrow: hold a
//! connection open, decode what arrives, and emit [`IngestEvent`]s.
//!
//! # The parts that are pure, and why
//!
//! Decoding ([`binance::decode`]) and the reconnect policy ([`Backoff`]) are
//! plain functions with no clock, no socket, and no async. That is what makes
//! them testable against captured payloads and asserted schedules rather than
//! against a live exchange. The async layer around them
//! ([`Session`](session::Session)) is deliberately thin and is exercised through
//! a mock [`Connector`], so reconnect behaviour is covered by tests that run in
//! microseconds with no network.
//!
//! # Two rules that come from operating this, not designing it
//!
//! **Staleness is measured with our clock, never the venue's.** Exchange
//! timestamps skew, jump, and during incidents stop advancing while data keeps
//! flowing. [`Observation::local_recv_ns`](oracle_types::Observation::local_recv_ns)
//! is authoritative; `exchange_time_ns` is a diagnostic and is `Option` because
//! some feeds do not send one at all.
//!
//! **A reconnect invalidates state; it does not resume it.** Every session emits
//! [`IngestEvent::Disconnected`] when a connection drops, and consumers must
//! discard that venue's book rather than carry a pre-gap quote across the hole.
//! A stale book that looks live is worse than no book.

pub mod backoff;
pub mod binance;
pub mod clock;
mod depth;
mod error;
mod event;
mod instrument;
pub mod record;
pub mod session;
pub mod transport;
pub mod venues;

pub use backoff::{Backoff, BackoffConfig};
pub use error::{DecodeError, IngestError};
pub use event::{IngestEvent, StreamId};
pub use instrument::{InstrumentMap, InstrumentSpec};
pub use record::{Record, RecordError, Recorder, RecordingConnector};
pub use session::{Session, SessionConfig};
pub use transport::{Connector, Frame, Transport, TransportError};

use oracle_types::Venue;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// A venue-specific ingest adapter.
///
/// Implementations own their reconnect loop and never return on a transport
/// failure — only on shutdown, or on a configuration error that retrying cannot
/// fix.
#[async_trait::async_trait]
pub trait ExchangeAdapter: Send + Sync {
    /// The venue this adapter connects to.
    fn venue(&self) -> Venue;

    /// A short label for logs and metrics, unique per adapter instance.
    fn label(&self) -> &str;

    /// Runs until `shutdown` fires.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError`] only for failures that retrying cannot fix, such
    /// as an unmappable instrument or a malformed endpoint. Transport failures
    /// are handled internally by reconnecting.
    async fn run(
        self: Box<Self>,
        out: mpsc::Sender<IngestEvent>,
        shutdown: CancellationToken,
    ) -> Result<(), IngestError>;
}
