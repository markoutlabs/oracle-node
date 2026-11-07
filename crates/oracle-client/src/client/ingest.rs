//! The trust path: the subscription filter, the verifier and the per-node maps.
//! Each frame enters here, from a node's task or from a direct `ingest` call.

use std::borrow::Cow;

use oracle_types::{BookUpdate, FundingUpdate, InstrumentId, PriceUpdate, VenueReport};
use oracle_wire::{
    Address, FRAME_TYPE_BOOK_UPDATE, FRAME_TYPE_FUNDING_UPDATE, FRAME_TYPE_PRICE_UPDATE,
    FRAME_TYPE_VENUE_REPORT, Recovered, UnverifiedBookFrame, UnverifiedFrame,
    UnverifiedFundingFrame, UnverifiedVenueFrame, VerifyError,
};
use tracing::{debug, info, warn};

use super::{Event, Inbound, OracleClient, now_unix_nanos};
use crate::book::Book;
use crate::nodes::rejected_node;
use crate::quorum::{Concern, FeedView, Resolved, Status};
use crate::tap::{FrameKind, TappedFrame, Verdict};
use crate::verify::RejectReason;

/// A frame's payload and signer, recovered in its node's task. Recovery is most
/// of the cost of a frame, so the nodes' frames recover on several cores at once.
pub(super) enum RecoveredFrame {
    Price(Recovered<PriceUpdate>),
    Venues(Recovered<VenueReport>),
    Book(Recovered<BookUpdate>),
    Funding(Recovered<FundingUpdate>),
}

impl RecoveredFrame {
    /// Any other frame type goes to the price path, whose parse refuses it.
    pub(super) fn of(frame: &[u8]) -> Result<Self, VerifyError> {
        Ok(match frame.first().copied() {
            Some(FRAME_TYPE_VENUE_REPORT) => {
                Self::Venues(UnverifiedVenueFrame::parse(frame)?.recover()?)
            }
            Some(FRAME_TYPE_BOOK_UPDATE) => {
                Self::Book(UnverifiedBookFrame::parse(frame)?.recover()?)
            }
            Some(FRAME_TYPE_FUNDING_UPDATE) => {
                Self::Funding(UnverifiedFundingFrame::parse(frame)?.recover()?)
            }
            _ => Self::Price(recover_price(frame)?),
        })
    }
}

fn recover_price(frame: &[u8]) -> Result<Recovered<PriceUpdate>, VerifyError> {
    UnverifiedFrame::parse(frame)?.recover()
}

impl OracleClient {
    /// Feeds one frame in directly, bypassing the network and the registry source.
    ///
    /// For tests and for consumers running their own transport. An unknown
    /// signer is a plain rejection here; [`OracleClient::ingest_with_refresh`]
    /// is the path that goes looking for a newer registry.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`] if the frame fails verification.
    pub fn ingest(&mut self, frame: &[u8], now_ns: u64) -> Result<Resolved, RejectReason> {
        let outcome = self.try_ingest_price(recover_price(frame), now_ns, now_ns);
        self.record(Cow::Borrowed(frame), now_ns, outcome)
    }

    /// Feeds one frame of any kind in directly, like [`OracleClient::ingest`].
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`] if the frame fails verification. A book or
    /// funding frame fails it too when a feed set from
    /// [`OracleClient::set_feed_set`] does not list its instrument.
    pub fn ingest_event(&mut self, frame: &[u8], now_ns: u64) -> Result<Event, RejectReason> {
        let outcome = self.try_ingest(RecoveredFrame::of(frame), now_ns, now_ns);
        self.record(Cow::Borrowed(frame), now_ns, outcome)
    }

    /// Feeds one frame in, refreshing the registry once if the signer is unknown.
    ///
    /// This is how a rotation reaches the consumer. The first frame from a node's
    /// new key is unknown; the client fetches the registry, adopts it if it is
    /// newer, and retries the frame. The fetch is rate-limited to one per
    /// `refresh_interval`, because anyone who can inject a frame can trigger it.
    /// A retired key never triggers a fetch: the registry already knows it.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`] if the frame still fails after the refresh.
    pub async fn ingest_with_refresh(
        &mut self,
        frame: &[u8],
        now_ns: u64,
    ) -> Result<Resolved, RejectReason> {
        let recovered = recover_price(frame);
        let mut outcome = self.try_ingest_price(recovered.clone(), now_ns, now_ns);
        if let Err(RejectReason::Untrusted(VerifyError::UnknownSigner { signer })) = &outcome
            && self.refresh_due(now_ns)
        {
            self.last_refresh_attempt_ns = Some(now_ns);
            match self.refresh_from_source().await {
                Ok(Some(version)) => debug!(%signer, version, "adopted a newer registry"),
                Ok(None) => debug!(%signer, "registry unchanged; signer stays unknown"),
                Err(error) => warn!(%signer, %error, "registry refresh failed"),
            }
            outcome = self.try_ingest_price(recovered, now_ns, now_ns);
        }
        self.record(Cow::Borrowed(frame), now_ns, outcome)
    }

    /// Accepts a frame now. An unknown signer starts a registry fetch on its
    /// own task, and this frame stays refused.
    fn ingest_now(
        &mut self,
        frame: Vec<u8>,
        recovered: Result<RecoveredFrame, VerifyError>,
        received_ns: u64,
        now_ns: u64,
    ) -> Result<Event, RejectReason> {
        let outcome = self.try_ingest(recovered, received_ns, now_ns);
        if let Err(RejectReason::Untrusted(VerifyError::UnknownSigner { .. })) = &outcome {
            self.refresh_in_background(now_ns);
        }
        self.record(Cow::Owned(frame), received_ns, outcome)
    }

    /// Copies a frame whose signature verified to [`OracleClient::frames`]. A
    /// frame that the client owns moves into the copy.
    fn copy(&mut self, frame: Cow<'_, [u8]>, signer: Address, received_ns: u64, verdict: Verdict) {
        let kind = FrameKind::of(&frame);
        if !self.tap.wants(kind) {
            return;
        }
        let copied = TappedFrame {
            bytes: frame.into_owned(),
            signer,
            kind,
            received_ns,
            verdict,
        };
        if !self.tap.offer(copied) {
            self.stats.tap_dropped = self.stats.tap_dropped.saturating_add(1);
        }
    }

    /// Returns the event and its signer: [`Self::record`] copies the frame.
    fn try_ingest(
        &mut self,
        recovered: Result<RecoveredFrame, VerifyError>,
        received_ns: u64,
        now_ns: u64,
    ) -> Result<(Event, Address), RejectReason> {
        match recovered? {
            RecoveredFrame::Venues(recovered) => {
                let accepted = self.verifier.accept_venues_recovered(recovered, now_ns)?;
                let signer = accepted.signer;
                self.stats.venue_reports = self.stats.venue_reports.saturating_add(1);
                let tally = self.tallies.entry(signer).or_default();
                tally.frames.venue_reports = tally.frames.venue_reports.saturating_add(1);
                tally.seen(received_ns);
                Ok((Event::Venues(accepted), signer))
            }
            RecoveredFrame::Book(recovered) => {
                let accepted = self.verifier.accept_book_recovered(recovered, now_ns)?;
                let signer = accepted.signer;
                self.stats.book_updates = self.stats.book_updates.saturating_add(1);
                let tally = self.tallies.entry(signer).or_default();
                tally.frames.book_updates = tally.frames.book_updates.saturating_add(1);
                tally.seen(received_ns);
                self.books
                    .entry((signer, accepted.instrument.clone()))
                    .or_insert_with(|| Book::new(signer, accepted.instrument.clone()))
                    .apply(&accepted.update);
                Ok((Event::Book(accepted), signer))
            }
            RecoveredFrame::Funding(recovered) => {
                let accepted = self.verifier.accept_funding_recovered(recovered, now_ns)?;
                let signer = accepted.signer;
                self.stats.funding_updates = self.stats.funding_updates.saturating_add(1);
                let tally = self.tallies.entry(signer).or_default();
                tally.frames.funding_updates = tally.frames.funding_updates.saturating_add(1);
                tally.seen(received_ns);
                let update = &accepted.update;
                let perpetual =
                    InstrumentId::new(update.venue, update.market, update.symbol.as_str());
                self.funding.insert((signer, perpetual), accepted.clone());
                Ok((Event::Funding(accepted), signer))
            }
            RecoveredFrame::Price(recovered) => self
                .try_ingest_price(Ok(recovered), received_ns, now_ns)
                .map(|(resolved, signer)| (Event::Price(resolved), signer)),
        }
    }

    fn try_ingest_price(
        &mut self,
        recovered: Result<Recovered<PriceUpdate>, VerifyError>,
        received_ns: u64,
        now_ns: u64,
    ) -> Result<(Resolved, Address), RejectReason> {
        let accepted = self.verifier.accept_recovered(recovered?, now_ns)?;
        self.stats.accepted = self.stats.accepted.saturating_add(1);
        self.latency.arrived(&accepted.update, received_ns);
        self.tallies
            .entry(accepted.signer)
            .or_default()
            .price(&accepted.update, received_ns);
        let feed = accepted.update.feed_id;
        let kind = self.verifier.feed_kind(feed);
        let view = self
            .views
            .entry(feed)
            .or_insert_with(|| FeedView::with_kind(feed, kind));
        view.record(accepted.signer, accepted.update);
        let mut resolved = view.resolve(&self.quorum_config, now_ns);
        self.annotate(&mut resolved, now_ns);
        Ok((resolved, accepted.signer))
    }

    /// Copies the frame to [`OracleClient::frames`] with its verdict, and counts
    /// a rejection once, after any refresh. Acceptances count where they happen.
    fn record<T>(
        &mut self,
        frame: Cow<'_, [u8]>,
        received_ns: u64,
        outcome: Result<(T, Address), RejectReason>,
    ) -> Result<T, RejectReason> {
        let reason = match outcome {
            Ok((value, signer)) => {
                self.copy(frame, signer, received_ns, Verdict::Accepted);
                return Ok(value);
            }
            Err(reason) => reason,
        };
        self.stats.record(&reason);
        if let Some(node) = rejected_node(&reason) {
            self.tallies.entry(node).or_default().frames.record(&reason);
            if let Some(verdict) = Verdict::of(&reason) {
                self.copy(frame, node, received_ns, verdict);
            }
        }
        Err(reason)
    }

    /// Adds what a feed view cannot know: the symbol, and the client-level
    /// concerns.
    pub(super) fn annotate(&self, resolved: &mut Resolved, now_ns: u64) {
        resolved.symbol = self.symbols.get(&resolved.feed_id).copied();
        if self.registry_is_stale(now_ns) {
            resolved.concerns.push(Concern::RegistryStale);
            if resolved.status == Status::Ok {
                resolved.status = Status::Degraded;
            }
        }
    }

    /// Returns the next resolved price.
    ///
    /// Yields one resolution per accepted frame, so a consumer sees the feed
    /// state change as soon as any node reports. Returns `None` after
    /// [`OracleClient::shutdown`]. Registry fetches are adopted here, so keep
    /// calling it. It skips the other events; [`OracleClient::next_event`]
    /// yields them.
    pub async fn next(&mut self) -> Option<Resolved> {
        loop {
            if let Event::Price(resolved) = self.next_event().await? {
                return Some(resolved);
            }
        }
    }

    /// Returns the next resolved price, venue report, book frame or funding
    /// frame.
    ///
    /// It is cancel-safe: a dropped call loses no frame, and a registry fetch
    /// runs on its own task. It returns `None` after [`OracleClient::shutdown`].
    pub async fn next_event(&mut self) -> Option<Event> {
        loop {
            let inbound = tokio::select! {
                biased;
                () = self.shutdown.cancelled() => return None,
                inbound = self.inbound_rx.recv() => inbound?,
            };
            let (frame, received_ns, recovered) = match inbound {
                Inbound::Frame {
                    frame,
                    received_ns,
                    recovered,
                } => (frame, received_ns, recovered),
                Inbound::Polled(fetched) => {
                    self.stats.polls = self.stats.polls.saturating_add(1);
                    match self.adopt_fetched(fetched) {
                        Ok(Some(version)) => info!(version, "adopted a newer registry"),
                        Ok(None) => debug!("registry unchanged"),
                        Err(error) => warn!(%error, "scheduled registry fetch failed"),
                    }
                    continue;
                }
                Inbound::Refreshed(fetched) => {
                    match self.adopt_fetched(fetched) {
                        Ok(Some(version)) => info!(version, "adopted a newer registry"),
                        Ok(None) => debug!("registry unchanged; the signer stays unknown"),
                        Err(error) => warn!(%error, "registry refresh failed"),
                    }
                    continue;
                }
                Inbound::NodeMoved { got } => {
                    // A retired address is the node before its restart: the
                    // registry is already ahead of it.
                    if !self.verifier.is_retired(got) {
                        self.refresh_in_background(now_unix_nanos());
                    }
                    continue;
                }
            };
            // A node sends only the feeds a client asked for, so another feed is
            // a faulty or hostile node, and it must not reach the maps.
            if !self.subscribed(&frame, &recovered) {
                debug!("dropped a frame of a feed this client did not ask for");
                continue;
            }
            let now_ns = now_unix_nanos();
            match self.ingest_now(frame, recovered, received_ns, now_ns) {
                Ok(event) => {
                    if let Event::Price(_) = event {
                        self.latency.resolved(received_ns, now_unix_nanos());
                    }
                    return Some(event);
                }
                Err(reason) => {
                    debug!(%reason, "rejected an update");
                }
            }
        }
    }

    fn subscribed(&self, frame: &[u8], recovered: &Result<RecoveredFrame, VerifyError>) -> bool {
        match recovered {
            Ok(RecoveredFrame::Price(update)) => {
                self.symbols.contains_key(&update.unverified().feed_id)
            }
            Ok(RecoveredFrame::Venues(report)) => self
                .venue_symbols
                .contains_key(&report.unverified().feed_id),
            // After `feed_set` or `set_feed_set`, the verifier refuses an
            // instrument that the feed set does not list. Before, only the limits apply.
            Ok(RecoveredFrame::Book(_) | RecoveredFrame::Funding(_)) => true,
            Err(_) => self.subscribed_unrecovered(frame),
        }
    }

    fn subscribed_unrecovered(&self, frame: &[u8]) -> bool {
        // A frame that does not parse goes on, so the verifier refuses and counts it.
        match frame.first().copied() {
            Some(FRAME_TYPE_PRICE_UPDATE) => UnverifiedFrame::parse(frame)
                .and_then(|frame| frame.decode_unverified())
                .map_or(true, |update| self.symbols.contains_key(&update.feed_id)),
            Some(FRAME_TYPE_VENUE_REPORT) => UnverifiedVenueFrame::parse(frame)
                .and_then(|frame| frame.decode_unverified())
                .map_or(true, |report| {
                    self.venue_symbols.contains_key(&report.feed_id)
                }),
            _ => true,
        }
    }
}
