//! A copy of each frame that passed the signature and registry checks, for a
//! consumer that stores frames, such as an archive.
//!
//! The copy goes through a bounded channel that the client never waits on. A
//! full channel drops the copy and counts it in [`crate::ClientStats::tap_dropped`],
//! so a slow archive cannot slow the prices.

use oracle_wire::{
    Address, FRAME_TYPE_BOOK_UPDATE, FRAME_TYPE_FUNDING_UPDATE, FRAME_TYPE_VENUE_REPORT,
};
use tokio::sync::mpsc;

use crate::RejectReason;

/// The kind of a signed frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameKind {
    /// A price update.
    Price,
    /// A venue report.
    VenueReport,
    /// A book snapshot or delta.
    Book,
    /// A funding update.
    Funding,
}

impl FrameKind {
    /// The kind of a signed frame, from its first byte.
    #[must_use]
    pub fn of(frame: &[u8]) -> Self {
        match frame.first().copied() {
            Some(FRAME_TYPE_VENUE_REPORT) => Self::VenueReport,
            Some(FRAME_TYPE_BOOK_UPDATE) => Self::Book,
            Some(FRAME_TYPE_FUNDING_UPDATE) => Self::Funding,
            _ => Self::Price,
        }
    }
}

/// What the client decided about a frame whose signature verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// Accepted.
    Accepted,
    /// Older than the feed's staleness limit, or ahead of the client's clock.
    OutOfTime,
    /// A sequence number that does not advance: a duplicate, or a node that
    /// signed two frames with one number.
    Replayed,
    /// An observation time after the publish time.
    Incoherent,
}

impl Verdict {
    /// The verdict for a rejection, or `None` when the signature or the
    /// registry check failed: such a frame is not a node's frame.
    #[must_use]
    pub const fn of(reason: &RejectReason) -> Option<Self> {
        match reason {
            RejectReason::TooOld { .. } | RejectReason::FromTheFuture { .. } => {
                Some(Self::OutOfTime)
            }
            RejectReason::Replayed { .. } => Some(Self::Replayed),
            RejectReason::IncoherentTimestamps { .. } => Some(Self::Incoherent),
            RejectReason::Untrusted(_) | RejectReason::RetiredKey { .. } => None,
        }
    }
}

/// One signed frame, as [`crate::OracleClient::frames`] delivers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TappedFrame {
    /// The signed frame, byte for byte as the node sent it: frame type, signer
    /// hint, payload and signature.
    pub bytes: Vec<u8>,
    /// The node whose key signed it.
    pub signer: Address,
    /// The frame kind.
    pub kind: FrameKind,
    /// When this client received the frame, unix nanoseconds, by this host's
    /// wall clock.
    pub received_ns: u64,
    /// What the client decided.
    pub verdict: Verdict,
}

/// The sending side, owned by the client.
#[derive(Default)]
pub(crate) struct Tap {
    sender: Option<mpsc::Sender<TappedFrame>>,
}

impl Tap {
    pub(crate) fn open(&mut self, capacity: usize) -> mpsc::Receiver<TappedFrame> {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        self.sender = Some(sender);
        receiver
    }

    pub(crate) const fn is_open(&self) -> bool {
        self.sender.is_some()
    }

    /// Offers a copy without waiting. Returns `false` when it was dropped.
    pub(crate) fn offer(&mut self, frame: TappedFrame) -> bool {
        let Some(sender) = &self.sender else {
            return true;
        };
        match sender.try_send(frame) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => false,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The archive went away; stop copying.
                self.sender = None;
                true
            }
        }
    }
}
