//! The connect-decode-reconnect loop every adapter runs on.

use std::collections::{HashMap, HashSet};
use std::future::pending;
use std::sync::Arc;
use std::time::Duration;

use oracle_types::{InstrumentId, ObsKind, Observation};
use tokio::sync::mpsc;
use tokio::time::{Instant, interval_at, sleep, sleep_until, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::backoff::{Backoff, BackoffConfig};
use crate::clock::MonotonicClock;
use crate::{
    Connector, DecodeError, Frame, IngestError, IngestEvent, StreamId, Transport, TransportError,
};

/// How a session decodes the payloads it receives.
pub trait MessageHandler: Send {
    /// Decodes one payload, appending any observations produced.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] for malformed or unrecognised payloads. These are
    /// never fatal — one bad frame must not drop a connection carrying hundreds
    /// of good ones. [`DecodeError::Resync`] is the exception: it ends the
    /// connection, because only a fresh snapshot can repair a book.
    fn on_payload(
        &mut self,
        payload: &[u8],
        local_recv_ns: u64,
        out: &mut Vec<Observation>,
    ) -> Result<(), DecodeError>;

    /// Called when a connection opens, before subscribing. State carried from
    /// the previous connection must not survive the gap.
    fn on_connect(&mut self) {}
}

/// How often a session reports that its connection is alive.
const ALIVE_EVERY: Duration = Duration::from_millis(200);

/// Each instrument and kind that one connection delivered, and when it last
/// reported them alive.
struct Carried {
    seen: HashSet<(InstrumentId, ObsKind)>,
    list: Arc<[(InstrumentId, ObsKind)]>,
    last_sent_ns: Option<u64>,
    /// When each one last delivered a value, for the silence check.
    last_seen: HashMap<(InstrumentId, ObsKind), Instant>,
}

/// How often the session looks for a silent instrument.
const SILENCE_CHECK_EVERY: Duration = Duration::from_secs(30);

/// Values that change while the market is open. A trade or a funding rate can
/// rest for long, so its silence proves nothing.
const ALWAYS_MOVING: [ObsKind; 4] = [
    ObsKind::BookTop,
    ObsKind::Depth,
    ObsKind::MarkPrice,
    ObsKind::IndexPrice,
];

impl Carried {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
            list: Arc::from(Vec::new()),
            last_sent_ns: None,
            last_seen: HashMap::new(),
        }
    }

    fn learn(&mut self, observation: &Observation) {
        let key = (observation.instrument.clone(), observation.kind);
        self.last_seen.insert(key.clone(), Instant::now());
        if self.seen.insert(key) {
            self.list = self.seen.iter().cloned().collect();
        }
    }

    fn forget(&mut self, instrument: &InstrumentId) {
        let before = self.seen.len();
        self.seen.retain(|(seen, _)| seen != instrument);
        self.last_seen.retain(|(seen, _), _| seen != instrument);
        if self.seen.len() != before {
            self.list = self.seen.iter().cloned().collect();
        }
    }

    /// A value that changes while the market is open and has sent nothing for
    /// `after`, if any.
    fn silent(&self, now: Instant, after: Duration) -> Option<&(InstrumentId, ObsKind)> {
        self.last_seen
            .iter()
            .filter(|((_, kind), _)| ALWAYS_MOVING.contains(kind))
            .find(|(_, last)| now.saturating_duration_since(**last) >= after)
            .map(|(key, _)| key)
    }

    /// The liveness event that is due, if any.
    fn alive(&mut self, stream: StreamId, now_ns: u64) -> Option<IngestEvent> {
        let every = u64::try_from(ALIVE_EVERY.as_nanos()).unwrap_or(u64::MAX);
        if self.list.is_empty()
            || self
                .last_sent_ns
                .is_some_and(|last| now_ns.saturating_sub(last) < every)
        {
            return None;
        }
        self.last_sent_ns = Some(now_ns);
        Some(IngestEvent::Alive {
            stream,
            sources: Arc::clone(&self.list),
            local_recv_ns: now_ns,
        })
    }
}

/// Session tuning.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// Which connection this is, for events and logs.
    pub stream: StreamId,
    /// The endpoint URL.
    pub url: String,
    /// Text frames sent immediately after connecting, in order.
    pub subscribe: Vec<String>,
    /// Application-level keepalive: how often, and what to send.
    ///
    /// Separate from WebSocket ping frames because several venues — OKX and
    /// Bybit among them — require a JSON or text keepalive and will drop a
    /// connection that only answers protocol pings.
    pub keepalive: Option<(Duration, String)>,
    /// Send a WebSocket ping after this long with no frame.
    ///
    /// A quiet market sends nothing, and only a frame confirms the values that
    /// the connection carries (SPEC §5.2). The pong is that frame, so this must
    /// stay below half the staleness limit.
    pub probe_after: Duration,
    /// Reconnect when one instrument's book, mark or index has sent nothing for
    /// this long while the connection lives: the venue stopped that stream, and
    /// a new connection subscribes again. A connection must be this old first,
    /// so it recycles at most once per period. `None` for a channel that moves
    /// only on a trade, such as Coinbase's `ticker`.
    pub resubscribe_after: Option<Duration>,
    /// Reconnect if nothing at all arrives for this long.
    ///
    /// The probes make a healthy connection answer at least every
    /// `probe_after`, so this only has to cover a slow pong. A half-open
    /// socket, such as after a sleep, then ends in seconds, not when TCP notices.
    pub idle_timeout: Duration,
    /// Give up on a connect after this long and retry with backoff.
    ///
    /// A host can accept TCP and never finish TLS or the upgrade, such as after
    /// a network outage. Without a limit, the session would wait forever and
    /// its feeds would stay halted until a restart.
    pub connect_timeout: Duration,
    /// Recycle the connection after this long, before the venue does it for us.
    ///
    /// Binance closes streams at 24 hours. Reconnecting slightly early turns a
    /// forced disconnect at a moment of the venue's choosing into a planned one
    /// at ours.
    pub max_session: Duration,
    /// Reconnect backoff.
    pub backoff: BackoffConfig,
}

impl SessionConfig {
    /// Builds a config with sensible defaults for the given endpoint.
    #[must_use]
    pub fn new(stream: StreamId, url: impl Into<String>) -> Self {
        Self {
            stream,
            url: url.into(),
            subscribe: Vec::new(),
            keepalive: None,
            probe_after: Duration::from_secs(1),
            resubscribe_after: Some(Duration::from_secs(15 * 60)),
            idle_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            max_session: Duration::from_secs(23 * 3_600),
            backoff: BackoffConfig::default(),
        }
    }
}

/// Counters describing what a session did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Connections successfully established.
    pub connects: u64,
    /// Connection attempts that failed.
    pub connect_failures: u64,
    /// Connections that came up and later dropped.
    pub disconnects: u64,
    /// Payloads decoded without error.
    pub messages_decoded: u64,
    /// Observations emitted.
    pub observations: u64,
    /// Payloads rejected for a reason worth investigating.
    pub decode_errors: u64,
    /// Payloads skipped routinely: acks, untracked streams.
    pub decode_skipped: u64,
    /// Connections closed because nothing arrived within `idle_timeout`.
    pub idle_timeouts: u64,
    /// Pings sent to a quiet connection.
    pub probes: u64,
    /// Connections recycled because one instrument fell silent inside them.
    pub resubscribes: u64,
    /// Connections recycled at `max_session`.
    pub session_recycles: u64,
}

/// Runs one venue connection, reconnecting until shutdown.
pub struct Session<C, H> {
    config: SessionConfig,
    connector: C,
    handler: H,
    clock: MonotonicClock,
    stats: SessionStats,
}

impl<C: Connector, H: MessageHandler> Session<C, H> {
    /// Builds a session.
    pub fn new(config: SessionConfig, connector: C, handler: H, clock: MonotonicClock) -> Self {
        Self {
            config,
            connector,
            handler,
            clock,
            stats: SessionStats::default(),
        }
    }

    /// Runs until `shutdown` fires, then returns what happened.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError::OutputClosed`] if the downstream receiver is
    /// dropped. Everything else is handled by reconnecting.
    pub async fn run(
        mut self,
        out: mpsc::Sender<IngestEvent>,
        shutdown: CancellationToken,
    ) -> Result<SessionStats, IngestError> {
        let mut backoff = Backoff::new(self.config.backoff);
        let stream = self.config.stream;

        while !shutdown.is_cancelled() {
            let connected = tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                result = timeout(self.config.connect_timeout, self.connector.connect(&self.config.url)) => {
                    result.unwrap_or_else(|_| {
                        Err(TransportError::Connect(format!(
                            "no answer in {:?}",
                            self.config.connect_timeout
                        )))
                    })
                }
            };

            let mut conn = match connected {
                Ok(conn) => conn,
                Err(err) => {
                    self.stats.connect_failures = self.stats.connect_failures.saturating_add(1);
                    warn!(%stream, error = %err, "connect failed");
                    let delay = backoff.next_delay();
                    tokio::select! {
                        biased;
                        () = shutdown.cancelled() => break,
                        () = sleep(delay) => continue,
                    }
                }
            };

            self.stats.connects = self.stats.connects.saturating_add(1);
            info!(%stream, url = %self.config.url, "connected");
            self.handler.on_connect();
            send(&out, IngestEvent::Connected { stream }).await?;

            let started = Instant::now();
            let mut carried = Carried::new();
            let reason = match self.subscribe(&mut conn).await {
                Ok(()) => self.pump(&mut conn, &mut carried, &out, &shutdown).await?,
                Err(err) => format!("subscribe failed: {err}"),
            };
            let uptime = started.elapsed();

            self.stats.disconnects = self.stats.disconnects.saturating_add(1);
            info!(%stream, ?uptime, %reason, "disconnected");
            // Downstream must invalidate this venue's state before anything new
            // arrives, so the notice is in-band and ordered with the data.
            let sources = Arc::clone(&carried.list);
            send(
                &out,
                IngestEvent::Disconnected {
                    stream,
                    reason,
                    sources,
                },
            )
            .await?;

            if shutdown.is_cancelled() {
                break;
            }

            backoff.record_disconnect(uptime);
            let delay = backoff.next_delay();
            debug!(%stream, ?delay, "reconnecting");
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                () = sleep(delay) => {}
            }
        }

        Ok(self.stats)
    }

    /// Sends the configured subscription frames.
    async fn subscribe(&mut self, conn: &mut C::Conn) -> Result<(), crate::TransportError> {
        for frame in &self.config.subscribe {
            conn.send_text(frame.clone()).await?;
        }
        Ok(())
    }

    /// Reads until the connection ends, returning why.
    async fn pump(
        &mut self,
        conn: &mut C::Conn,
        carried: &mut Carried,
        out: &mpsc::Sender<IngestEvent>,
        shutdown: &CancellationToken,
    ) -> Result<String, IngestError> {
        let stream = self.config.stream;
        let recycle_at = Instant::now() + self.config.max_session;
        let mut keepalive = self
            .config
            .keepalive
            .as_ref()
            .map(|(period, _)| interval_at(Instant::now() + *period, *period));
        let mut observations: Vec<Observation> = Vec::with_capacity(8);
        let mut last_frame = Instant::now();
        let mut probe_at = last_frame + self.config.probe_after;
        let connected_at = last_frame;
        let mut silence_check = self
            .config
            .resubscribe_after
            .map(|_| interval_at(connected_at + SILENCE_CHECK_EVERY, SILENCE_CHECK_EVERY));

        loop {
            let received = tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok("shutdown".to_owned()),
                () = sleep_until(recycle_at) => {
                    self.stats.session_recycles = self.stats.session_recycles.saturating_add(1);
                    return Ok("session age limit".to_owned());
                }
                () = tick(keepalive.as_mut()) => {
                    if let Some((_, payload)) = self.config.keepalive.as_ref()
                        && let Err(err) = conn.send_text(payload.clone()).await
                    {
                        return Ok(format!("keepalive send failed: {err}"));
                    }
                    continue;
                }
                () = sleep_until(last_frame + self.config.idle_timeout) => {
                    self.stats.idle_timeouts = self.stats.idle_timeouts.saturating_add(1);
                    return Ok(format!("idle for {:?}", self.config.idle_timeout));
                }
                () = tick(silence_check.as_mut()) => {
                    let now = Instant::now();
                    if let Some(after) = self.config.resubscribe_after
                        && now.saturating_duration_since(connected_at) >= after
                        && let Some((instrument, kind)) = carried.silent(now, after)
                    {
                        self.stats.resubscribes = self.stats.resubscribes.saturating_add(1);
                        return Ok(format!(
                            "{instrument} {} silent for {after:?}; subscribing again",
                            kind.as_str()
                        ));
                    }
                    continue;
                }
                () = sleep_until(probe_at) => {
                    if let Err(err) = conn.send_ping().await {
                        return Ok(format!("probe send failed: {err}"));
                    }
                    self.stats.probes = self.stats.probes.saturating_add(1);
                    probe_at = Instant::now() + self.config.probe_after;
                    continue;
                }
                result = conn.recv() => result,
            };

            let frame = match received {
                Err(err) => return Ok(err.to_string()),
                Ok(None) => return Ok("closed by peer".to_owned()),
                Ok(Some(frame)) => frame,
            };
            // REST records arrive whether or not the socket lives, so only the
            // socket's own frames hold off the idle timeout and confirm values.
            let from_socket = !matches!(frame, Frame::Rest(_));
            if from_socket {
                last_frame = Instant::now();
                probe_at = last_frame + self.config.probe_after;
            }

            let local_recv_ns = self.clock.now_ns();
            // A ping carries no payload; the transport answers it.
            if let Some(payload) = frame.payload() {
                observations.clear();
                let decoded =
                    match self
                        .handler
                        .on_payload(payload, local_recv_ns, &mut observations)
                    {
                        Ok(()) => {
                            self.stats.messages_decoded =
                                self.stats.messages_decoded.saturating_add(1);
                            true
                        }
                        Err(DecodeError::Halted(instrument)) => {
                            carried.forget(&instrument);
                            self.stats.decode_skipped = self.stats.decode_skipped.saturating_add(1);
                            false
                        }
                        Err(err) if err.is_benign() => {
                            self.stats.decode_skipped = self.stats.decode_skipped.saturating_add(1);
                            false
                        }
                        Err(err @ DecodeError::Resync(_)) => {
                            // Observations decoded before the failure are dropped with it.
                            warn!(%stream, error = %err, "resyncing");
                            return Ok(err.to_string());
                        }
                        Err(err) => {
                            self.stats.decode_errors = self.stats.decode_errors.saturating_add(1);
                            debug!(%stream, error = %err, "decode failed");
                            false
                        }
                    };
                if decoded {
                    for observation in observations.drain(..) {
                        self.stats.observations = self.stats.observations.saturating_add(1);
                        carried.learn(&observation);
                        // Awaiting a full channel is deliberate backpressure: if
                        // the aggregator cannot keep up, stop reading the socket
                        // rather than buffer without bound.
                        send(out, IngestEvent::observation(observation)).await?;
                    }
                }
            }
            // Any socket frame proves the connection alive, a ping and an ack included.
            if from_socket && let Some(alive) = carried.alive(stream, local_recv_ns) {
                send(out, alive).await?;
            }
        }
    }
}

/// Sends downstream, mapping a closed channel to a fatal error.
async fn send(out: &mpsc::Sender<IngestEvent>, event: IngestEvent) -> Result<(), IngestError> {
    out.send(event).await.map_err(|_| IngestError::OutputClosed)
}

/// Ticks the keepalive interval, or waits forever when there is none.
async fn tick(interval: Option<&mut tokio::time::Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Frame, TransportError};
    use oracle_types::{Fixed, InstrumentId, MarketKind, ObsKind, Venue};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// One scripted connection's worth of frames.
    type Script = Vec<Result<Option<Frame>, TransportError>>;

    /// A scripted connection: yields queued frames, then ends.
    struct MockConn {
        frames: Script,
        sent: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl Transport for MockConn {
        async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
            if self.frames.is_empty() {
                // Nothing scripted left: stall so the idle timer decides.
                pending::<()>().await;
            }
            self.frames.remove(0)
        }

        async fn send_text(&mut self, text: String) -> Result<(), TransportError> {
            if let Ok(mut sent) = self.sent.lock() {
                sent.push(text);
            }
            Ok(())
        }

        async fn send_ping(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// One trade, then silence, except for a pong to each ping when `answers`.
    struct QuietConnector {
        answers: bool,
    }

    struct QuietConn {
        frames: Vec<Frame>,
        answers: bool,
    }

    impl Connector for QuietConnector {
        type Conn = QuietConn;

        async fn connect(&self, _url: &str) -> Result<Self::Conn, TransportError> {
            Ok(QuietConn {
                frames: vec![Frame::Text("100".to_owned())],
                answers: self.answers,
            })
        }
    }

    impl Transport for QuietConn {
        async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
            if self.frames.is_empty() {
                pending::<()>().await;
            }
            Ok(Some(self.frames.remove(0)))
        }

        async fn send_text(&mut self, _text: String) -> Result<(), TransportError> {
            Ok(())
        }

        async fn send_ping(&mut self) -> Result<(), TransportError> {
            if self.answers {
                self.frames.push(Frame::Pong);
            }
            Ok(())
        }
    }

    /// `A` sends a value each second for ever; `B` sends one, then nothing.
    /// `kind` is the kind of both.
    struct TickingConnector {
        kind: ObsKind,
    }

    struct TickingConn {
        kind: ObsKind,
        sent_b: bool,
        /// A stored deadline keeps `recv` cancel-safe, as the session needs.
        next_at: Instant,
    }

    impl Connector for TickingConnector {
        type Conn = TickingConn;

        async fn connect(&self, _url: &str) -> Result<Self::Conn, TransportError> {
            Ok(TickingConn {
                kind: self.kind,
                sent_b: false,
                next_at: Instant::now() + Duration::from_secs(1),
            })
        }
    }

    impl Transport for TickingConn {
        async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
            let symbol = if self.sent_b {
                sleep_until(self.next_at).await;
                self.next_at += Duration::from_secs(1);
                "A"
            } else {
                self.sent_b = true;
                "B"
            };
            let kind = if self.kind == ObsKind::Trade {
                "trade"
            } else {
                "book"
            };
            Ok(Some(Frame::Text(format!("{symbol} {kind}"))))
        }

        async fn send_text(&mut self, _text: String) -> Result<(), TransportError> {
            Ok(())
        }

        async fn send_ping(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// `SYMBOL book` or `SYMBOL trade`, at a price of 100.
    struct KeyedHandler;

    impl MessageHandler for KeyedHandler {
        fn on_payload(
            &mut self,
            payload: &[u8],
            local_recv_ns: u64,
            out: &mut Vec<Observation>,
        ) -> Result<(), DecodeError> {
            let text =
                core::str::from_utf8(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
            let (symbol, kind) = text
                .split_once(' ')
                .ok_or_else(|| DecodeError::Malformed(text.to_owned()))?;
            let price: Fixed = "100".parse().map_err(|_| DecodeError::Control)?;
            let book = kind == "book";
            out.push(Observation {
                instrument: InstrumentId::new(Venue::Binance, MarketKind::Spot, symbol),
                kind: if book {
                    ObsKind::BookTop
                } else {
                    ObsKind::Trade
                },
                price,
                bid: book.then_some(price),
                ask: book.then_some(price),
                bid_qty: None,
                ask_qty: None,
                depth_notional_1bp: None,
                exchange_time_ns: None,
                local_recv_ns,
                seq: None,
                book: None,
                funding: None,
            });
            Ok(())
        }
    }

    /// Runs a ticking session for `run`; returns its disconnect reasons and stats.
    async fn ticking(
        kind: ObsKind,
        resubscribe_after: Option<Duration>,
        run: Duration,
    ) -> (Vec<String>, SessionStats) {
        let (tx, mut rx) = mpsc::channel(4_096);
        let shutdown = CancellationToken::new();
        let mut config = config();
        config.idle_timeout = Duration::from_secs(10);
        config.resubscribe_after = resubscribe_after;
        let session = Session::new(
            config,
            TickingConnector { kind },
            KeyedHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let handle = tokio::spawn(session.run(tx, shutdown.clone()));
        let reasons = tokio::spawn(async move {
            let mut reasons = Vec::new();
            while let Some(event) = rx.recv().await {
                if let IngestEvent::Disconnected { reason, .. } = event {
                    reasons.push(reason);
                }
            }
            reasons
        });
        sleep(run).await;
        shutdown.cancel();
        let stats = handle.await.expect("joins").expect("runs");
        (reasons.await.expect("joins"), stats)
    }

    /// One instrument's book stops while the connection lives: after the
    /// period, the session reconnects, which subscribes again.
    #[tokio::test(start_paused = true)]
    async fn a_silent_book_inside_a_live_connection_reconnects() {
        let after = Duration::from_secs(15 * 60);
        let (reasons, stats) = ticking(ObsKind::BookTop, Some(after), after + 60 * SECOND_D).await;
        assert_eq!(stats.resubscribes, 1, "{reasons:?}");
        assert!(
            reasons.first().is_some_and(
                |reason| reason.contains("binance:spot:B") && reason.contains("silent")
            ),
            "{reasons:?}"
        );
    }

    /// A trade can rest for long; its silence is not a stopped stream.
    #[tokio::test(start_paused = true)]
    async fn silent_trades_do_not_reconnect() {
        let after = Duration::from_secs(15 * 60);
        let (reasons, stats) = ticking(ObsKind::Trade, Some(after), after + 60 * SECOND_D).await;
        assert_eq!(stats.resubscribes, 0);
        assert_eq!(reasons, ["shutdown"], "one connection, never dropped");
    }

    #[tokio::test(start_paused = true)]
    async fn the_silence_check_can_be_off() {
        let (_, stats) = ticking(ObsKind::BookTop, None, Duration::from_secs(20 * 60)).await;
        assert_eq!(stats.resubscribes, 0);
    }

    const SECOND_D: Duration = Duration::from_secs(1);

    /// Runs a quiet session for `run`, and returns its events and stats.
    async fn quiet_session(answers: bool, run: Duration) -> (Vec<IngestEvent>, SessionStats) {
        let (tx, mut rx) = mpsc::channel(1_024);
        let shutdown = CancellationToken::new();
        let mut config = config();
        config.probe_after = Duration::from_millis(100);
        config.idle_timeout = Duration::from_millis(500);
        let session = Session::new(
            config,
            QuietConnector { answers },
            CountingHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let handle = tokio::spawn(session.run(tx, shutdown.clone()));
        sleep(run).await;
        shutdown.cancel();
        let stats = handle.await.expect("joins").expect("runs");
        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        (events, stats)
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_connection_that_answers_probes_stays_alive() {
        let (events, stats) = quiet_session(true, Duration::from_secs(3)).await;
        let dropped = events.iter().any(|event| {
            matches!(event, IngestEvent::Disconnected { reason, .. } if reason != "shutdown")
        });
        // Six idle timeouts long, held open only by the pongs.
        assert!(!dropped, "{events:?}");
        assert_eq!(stats.idle_timeouts, 0);
        assert!(stats.probes >= 20, "{} probes", stats.probes);
        assert!(
            events
                .iter()
                .any(|event| matches!(event, IngestEvent::Alive { .. }))
        );
    }

    struct HaltConnector;

    struct HaltConn {
        sent_price: bool,
        next_at: Instant,
    }

    impl Connector for HaltConnector {
        type Conn = HaltConn;

        async fn connect(&self, _url: &str) -> Result<Self::Conn, TransportError> {
            Ok(HaltConn {
                sent_price: false,
                next_at: Instant::now(),
            })
        }
    }

    impl Transport for HaltConn {
        async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
            if !self.sent_price {
                self.sent_price = true;
                return Ok(Some(Frame::Text("100".to_owned())));
            }
            sleep_until(self.next_at).await;
            self.next_at += Duration::from_millis(100);
            Ok(Some(Frame::Text("halt".to_owned())))
        }

        async fn send_text(&mut self, _text: String) -> Result<(), TransportError> {
            Ok(())
        }

        async fn send_ping(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    struct HaltingHandler;

    impl MessageHandler for HaltingHandler {
        fn on_payload(
            &mut self,
            payload: &[u8],
            local_recv_ns: u64,
            out: &mut Vec<Observation>,
        ) -> Result<(), DecodeError> {
            if payload == b"halt" {
                let btc = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");
                return Err(DecodeError::Halted(btc));
            }
            CountingHandler.on_payload(payload, local_recv_ns, out)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_halted_instrument_is_no_longer_confirmed() {
        let (tx, mut rx) = mpsc::channel(1_024);
        let shutdown = CancellationToken::new();
        let mut config = config();
        config.idle_timeout = Duration::from_secs(10);
        let session = Session::new(
            config,
            HaltConnector,
            HaltingHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let handle = tokio::spawn(session.run(tx, shutdown.clone()));
        sleep(Duration::from_secs(1)).await;
        shutdown.cancel();
        handle.await.expect("joins").expect("runs");
        let mut alive = 0;
        while let Ok(event) = rx.try_recv() {
            alive += usize::from(matches!(event, IngestEvent::Alive { .. }));
        }
        assert_eq!(
            alive, 1,
            "only the frame before the halt confirms the price"
        );
    }

    struct RestOnlyConnector;

    struct RestOnlyConn {
        next_at: Instant,
    }

    impl Connector for RestOnlyConnector {
        type Conn = RestOnlyConn;

        async fn connect(&self, _url: &str) -> Result<Self::Conn, TransportError> {
            Ok(RestOnlyConn {
                next_at: Instant::now(),
            })
        }
    }

    impl Transport for RestOnlyConn {
        async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
            sleep_until(self.next_at).await;
            self.next_at += Duration::from_millis(100);
            Ok(Some(Frame::Rest("100".to_owned())))
        }

        async fn send_text(&mut self, _text: String) -> Result<(), TransportError> {
            Ok(())
        }

        async fn send_ping(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn rest_records_do_not_keep_a_silent_socket_alive() {
        let (tx, mut rx) = mpsc::channel(1_024);
        let shutdown = CancellationToken::new();
        let mut config = config();
        config.probe_after = Duration::from_millis(100);
        config.idle_timeout = Duration::from_millis(500);
        let session = Session::new(
            config,
            RestOnlyConnector,
            CountingHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let handle = tokio::spawn(session.run(tx, shutdown.clone()));
        sleep(Duration::from_millis(1_200)).await;
        shutdown.cancel();
        let stats = handle.await.expect("joins").expect("runs");
        assert!(stats.idle_timeouts >= 1, "{stats:?}");
        let mut alive = false;
        while let Ok(event) = rx.try_recv() {
            alive |= matches!(event, IngestEvent::Alive { .. });
        }
        assert!(!alive, "a REST record confirms nothing about the socket");
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_connection_that_ignores_probes_is_dropped() {
        let (events, stats) = quiet_session(false, Duration::from_millis(1_200)).await;
        assert!(stats.idle_timeouts >= 1, "{events:?}");
        assert!(events.iter().any(|event| {
            matches!(event, IngestEvent::Disconnected { reason, .. } if reason.contains("idle"))
        }));
    }

    /// A keepalive is our own frame, not the venue's. It must not hold a
    /// silent connection open.
    #[tokio::test(start_paused = true)]
    async fn a_keepalive_does_not_hide_a_silent_connection() {
        let (tx, mut rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let connector = MockConnector {
            fail_first: 0,
            attempts: Arc::new(AtomicUsize::new(0)),
            script: Arc::new(std::sync::Mutex::new(vec![vec![]])),
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let mut config = config();
        config.keepalive = Some((Duration::from_millis(10), "ping".to_owned()));
        let session = Session::new(
            config,
            connector,
            CountingHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let handle = tokio::spawn(session.run(tx, shutdown.clone()));
        assert!(matches!(
            next_event(&mut rx).await,
            Some(IngestEvent::Connected { .. })
        ));
        match next_event(&mut rx).await {
            Some(IngestEvent::Disconnected { reason, .. }) => assert!(reason.contains("idle")),
            other => panic!("expected an idle disconnect, got {other:?}"),
        }
        shutdown.cancel();
        let _ = handle.await;
    }

    /// A connector that fails a set number of times, then serves scripted sessions.
    struct MockConnector {
        fail_first: usize,
        attempts: Arc<AtomicUsize>,
        script: Arc<std::sync::Mutex<Vec<Script>>>,
        sent: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl Connector for MockConnector {
        type Conn = MockConn;

        async fn connect(&self, _url: &str) -> Result<Self::Conn, TransportError> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
            if attempt < self.fail_first {
                return Err(TransportError::Connect("scripted failure".to_owned()));
            }
            let frames = self
                .script
                .lock()
                .ok()
                .and_then(|mut s| {
                    if s.is_empty() {
                        None
                    } else {
                        Some(s.remove(0))
                    }
                })
                .unwrap_or_default();
            Ok(MockConn {
                frames,
                sent: Arc::clone(&self.sent),
            })
        }
    }

    /// Emits one observation per payload whose text is a decimal price.
    struct CountingHandler;

    impl MessageHandler for CountingHandler {
        fn on_payload(
            &mut self,
            payload: &[u8],
            local_recv_ns: u64,
            out: &mut Vec<Observation>,
        ) -> Result<(), DecodeError> {
            let text =
                core::str::from_utf8(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
            if text == "ack" {
                return Err(DecodeError::Control);
            }
            let price: Fixed = text.parse().map_err(|_| DecodeError::BadDecimal {
                field: "price",
                value: text.to_owned(),
            })?;
            out.push(Observation {
                instrument: InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT"),
                kind: ObsKind::Trade,
                price,
                bid: None,
                ask: None,
                bid_qty: None,
                ask_qty: None,
                depth_notional_1bp: None,
                exchange_time_ns: None,
                local_recv_ns,
                seq: None,
                book: None,
                funding: None,
            });
            Ok(())
        }
    }

    /// Asks for a resync on `resync`, and counts connects.
    struct ResyncingHandler {
        connects: Arc<AtomicUsize>,
    }

    impl MessageHandler for ResyncingHandler {
        fn on_payload(
            &mut self,
            payload: &[u8],
            local_recv_ns: u64,
            out: &mut Vec<Observation>,
        ) -> Result<(), DecodeError> {
            if payload == b"resync" {
                return Err(DecodeError::Resync("checksum".to_owned()));
            }
            CountingHandler.on_payload(payload, local_recv_ns, out)
        }

        fn on_connect(&mut self) {
            self.connects.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Only a fresh snapshot repairs a book, so a resync ends the connection
    /// and the next one starts clean.
    #[tokio::test(start_paused = true)]
    async fn a_resync_drops_the_connection_and_the_next_one_starts_clean() {
        let (tx, mut rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let connects = Arc::new(AtomicUsize::new(0));
        let connector = MockConnector {
            fail_first: 0,
            attempts: Arc::new(AtomicUsize::new(0)),
            script: Arc::new(std::sync::Mutex::new(vec![
                vec![text("100.5"), text("resync"), text("999")],
                vec![text("101.5")],
            ])),
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let handler = ResyncingHandler {
            connects: Arc::clone(&connects),
        };
        let session = Session::new(config(), connector, handler, MonotonicClock::anchored_at(1));
        let handle = tokio::spawn(session.run(tx, shutdown.clone()));

        let mut seen = Vec::new();
        while seen.len() < 5 {
            match next_event(&mut rx).await.expect("an event") {
                IngestEvent::Connected { .. } => seen.push("connected".to_owned()),
                IngestEvent::Disconnected { reason, .. } => seen.push(reason),
                event => seen.push(
                    event
                        .as_observation()
                        .map(|o| o.price.to_string())
                        .unwrap_or_default(),
                ),
            }
        }
        let [connected, first, reason, reconnected, second] = seen.as_slice() else {
            panic!("{seen:?}");
        };
        assert_eq!((connected.as_str(), first.as_str()), ("connected", "100.5"));
        assert!(reason.contains("book out of sync"), "{seen:?}");
        assert_eq!(reconnected, "connected");
        assert_eq!(second, "101.5", "the frame after the resync is never read");
        assert_eq!(connects.load(Ordering::SeqCst), 2);
        shutdown.cancel();
        let _ = handle.await;
    }

    fn config() -> SessionConfig {
        let mut config = SessionConfig::new(
            StreamId::new(Venue::Binance, MarketKind::Spot),
            "wss://example.invalid/ws",
        );
        config.idle_timeout = Duration::from_millis(50);
        config.max_session = Duration::from_secs(3_600);
        config.backoff = BackoffConfig {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(100),
            multiplier: 2,
            jitter: false,
            reset_after_stable: Duration::from_secs(60),
        };
        config
    }

    /// The next event that is not a liveness report.
    async fn next_event(rx: &mut mpsc::Receiver<IngestEvent>) -> Option<IngestEvent> {
        loop {
            match rx.recv().await? {
                IngestEvent::Alive { .. } => {}
                event => return Some(event),
            }
        }
    }

    fn text(payload: &str) -> Result<Option<Frame>, TransportError> {
        Ok(Some(Frame::Text(payload.to_owned())))
    }

    #[tokio::test(start_paused = true)]
    async fn decodes_frames_and_emits_observations() {
        let (tx, mut rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let connector = MockConnector {
            fail_first: 0,
            attempts: Arc::new(AtomicUsize::new(0)),
            script: Arc::new(std::sync::Mutex::new(vec![vec![
                text("100.5"),
                text("101.5"),
                Ok(None),
            ]])),
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        };

        let session = Session::new(
            config(),
            connector,
            CountingHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let handle = tokio::spawn(session.run(tx, shutdown.clone()));

        assert!(matches!(
            next_event(&mut rx).await,
            Some(IngestEvent::Connected { .. })
        ));
        let first = next_event(&mut rx).await.expect("observation");
        assert_eq!(
            first.as_observation().map(|o| o.price),
            Some("100.5".parse().expect("valid"))
        );
        assert!(
            next_event(&mut rx)
                .await
                .expect("observation")
                .as_observation()
                .is_some()
        );
        assert!(matches!(
            next_event(&mut rx).await,
            Some(IngestEvent::Disconnected { .. })
        ));

        shutdown.cancel();
        let stats = handle.await.expect("joins").expect("runs");
        assert_eq!(stats.observations, 2);
        assert_eq!(stats.messages_decoded, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn reconnects_after_connect_failures_and_backs_off() {
        let (tx, mut rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let attempts = Arc::new(AtomicUsize::new(0));
        let connector = MockConnector {
            fail_first: 3,
            attempts: Arc::clone(&attempts),
            script: Arc::new(std::sync::Mutex::new(vec![vec![text("42"), Ok(None)]])),
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        };

        let session = Session::new(
            config(),
            connector,
            CountingHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let handle = tokio::spawn(session.run(tx, shutdown.clone()));

        // Three failures, each followed by a Disconnected notice, then success.
        assert!(matches!(
            rx.recv().await,
            Some(IngestEvent::Connected { .. })
        ));
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            4,
            "should have retried three times"
        );

        shutdown.cancel();
        let stats = handle.await.expect("joins").expect("runs");
        assert_eq!(stats.connect_failures, 3);
        assert_eq!(stats.connects, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_connection_is_recycled_by_the_idle_timeout() {
        let (tx, mut rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let connector = MockConnector {
            fail_first: 0,
            attempts: Arc::new(AtomicUsize::new(0)),
            // Empty script: the connection opens and then says nothing at all.
            script: Arc::new(std::sync::Mutex::new(vec![vec![]])),
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        };

        let session = Session::new(
            config(),
            connector,
            CountingHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let handle = tokio::spawn(session.run(tx, shutdown.clone()));

        assert!(matches!(
            rx.recv().await,
            Some(IngestEvent::Connected { .. })
        ));
        let event = rx.recv().await.expect("event");
        match event {
            IngestEvent::Disconnected { reason, .. } => assert!(reason.contains("idle")),
            other => panic!("expected an idle disconnect, got {other:?}"),
        }

        shutdown.cancel();
        let stats = handle.await.expect("joins").expect("runs");
        assert_eq!(stats.idle_timeouts, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_reports_what_it_carries_while_it_lives() {
        let (tx, mut rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let connector = MockConnector {
            fail_first: 0,
            attempts: Arc::new(AtomicUsize::new(0)),
            // An ack before any data proves nothing about an instrument yet.
            script: Arc::new(std::sync::Mutex::new(vec![vec![
                text("ack"),
                text("1"),
                text("2"),
                text("ack"),
            ]])),
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let session = Session::new(
            config(),
            connector,
            CountingHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let handle = tokio::spawn(session.run(tx, shutdown.clone()));

        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            let done = matches!(event, IngestEvent::Disconnected { .. });
            events.push(event);
            if done {
                break;
            }
        }
        shutdown.cancel();
        let _ = handle.await;

        let alive: Vec<&IngestEvent> = events
            .iter()
            .filter(|event| matches!(event, IngestEvent::Alive { .. }))
            .collect();
        // The frames arrive together: one report, after the first observation.
        assert_eq!(alive.len(), 1, "{events:?}");
        let Some(IngestEvent::Alive { sources, .. }) = alive.first() else {
            panic!("an alive event");
        };
        let btc = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");
        assert_eq!(sources.as_ref(), [(btc, ObsKind::Trade)].as_slice());
        let first_observation = events
            .iter()
            .position(|event| matches!(event, IngestEvent::Observation(_)));
        let first_alive = events
            .iter()
            .position(|event| matches!(event, IngestEvent::Alive { .. }));
        assert!(first_observation < first_alive);
    }

    #[tokio::test(start_paused = true)]
    async fn disconnect_is_announced_before_the_next_connect() {
        // Ordering is the contract: a consumer must be told to drop its book
        // before any post-reconnect quote can reach it.
        let (tx, mut rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let connector = MockConnector {
            fail_first: 0,
            attempts: Arc::new(AtomicUsize::new(0)),
            script: Arc::new(std::sync::Mutex::new(vec![
                vec![text("1"), Ok(None)],
                vec![text("2"), Ok(None)],
            ])),
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        };

        let session = Session::new(
            config(),
            connector,
            CountingHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let handle = tokio::spawn(session.run(tx, shutdown.clone()));

        let mut sequence = Vec::new();
        while sequence.len() < 6 {
            match rx.recv().await {
                Some(IngestEvent::Connected { .. }) => sequence.push("connected"),
                Some(IngestEvent::Disconnected { .. }) => sequence.push("disconnected"),
                Some(IngestEvent::Observation(_)) => sequence.push("observation"),
                Some(IngestEvent::Alive { .. }) => {}
                None => break,
            }
        }
        assert_eq!(
            sequence,
            [
                "connected",
                "observation",
                "disconnected",
                "connected",
                "observation",
                "disconnected"
            ]
        );

        shutdown.cancel();
        handle.await.expect("joins").expect("runs");
    }

    #[tokio::test(start_paused = true)]
    async fn subscription_frames_are_sent_on_every_connect() {
        let (tx, mut rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
        let connector = MockConnector {
            fail_first: 0,
            attempts: Arc::new(AtomicUsize::new(0)),
            script: Arc::new(std::sync::Mutex::new(vec![vec![Ok(None)], vec![Ok(None)]])),
            sent: Arc::clone(&sent),
        };

        let mut config = config();
        config.subscribe = vec![r#"{"op":"subscribe"}"#.to_owned()];
        let session = Session::new(
            config,
            connector,
            CountingHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let handle = tokio::spawn(session.run(tx, shutdown.clone()));

        for _ in 0..4 {
            let _ = rx.recv().await;
        }
        shutdown.cancel();
        handle.await.expect("joins").expect("runs");

        let sent = sent.lock().expect("lock").clone();
        assert!(
            sent.len() >= 2,
            "resubscribe must happen on every connect, got {sent:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn benign_decode_failures_do_not_drop_the_connection() {
        let (tx, mut rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let connector = MockConnector {
            fail_first: 0,
            attempts: Arc::new(AtomicUsize::new(0)),
            script: Arc::new(std::sync::Mutex::new(vec![vec![
                text("ack"),
                text("not-a-number"),
                text("7"),
                Ok(None),
            ]])),
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        };

        let session = Session::new(
            config(),
            connector,
            CountingHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let handle = tokio::spawn(session.run(tx, shutdown.clone()));

        assert!(matches!(
            rx.recv().await,
            Some(IngestEvent::Connected { .. })
        ));
        assert!(rx.recv().await.expect("event").as_observation().is_some());

        shutdown.cancel();
        let stats = handle.await.expect("joins").expect("runs");
        assert_eq!(stats.observations, 1);
        assert_eq!(stats.decode_skipped, 1, "the ack is routine");
        assert_eq!(
            stats.decode_errors, 1,
            "the garbage payload is worth counting"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_closed_output_channel_stops_the_session() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let connector = MockConnector {
            fail_first: 0,
            attempts: Arc::new(AtomicUsize::new(0)),
            script: Arc::new(std::sync::Mutex::new(vec![vec![text("1"), Ok(None)]])),
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let session = Session::new(
            config(),
            connector,
            CountingHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let result = session.run(tx, CancellationToken::new()).await;
        assert!(matches!(result, Err(IngestError::OutputClosed)));
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_returns_promptly() {
        let (tx, _rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let connector = MockConnector {
            fail_first: 0,
            attempts: Arc::new(AtomicUsize::new(0)),
            script: Arc::new(std::sync::Mutex::new(Vec::new())),
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let session = Session::new(
            config(),
            connector,
            CountingHandler,
            MonotonicClock::anchored_at(1_000),
        );
        let stats = session.run(tx, shutdown).await.expect("runs");
        assert_eq!(
            stats.connects, 0,
            "a cancelled token must not open a connection"
        );
    }
}
