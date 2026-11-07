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
use crate::health::{Counter, VenueHealth};
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

    /// Each instrument the connection subscribes to, with the moving kind it
    /// must send; `None` takes any of them.
    ///
    /// The silence check covers these from the connect, so an instrument that
    /// never sends is noticed too.
    fn subscribed(&self) -> Vec<(InstrumentId, Option<ObsKind>)> {
        Vec::new()
    }
}

/// How often a session reports that its connection is alive.
const ALIVE_EVERY: Duration = Duration::from_millis(200);

/// How often a decode error logs a warning. The errors between two warnings
/// are counted in the next one, so a broken venue cannot flood the log.
const DECODE_WARNING_EVERY: Duration = Duration::from_secs(60);

/// Each instrument and kind that one connection delivered, and when it last
/// reported them alive.
struct Carried {
    seen: HashSet<(InstrumentId, ObsKind)>,
    list: Arc<[(InstrumentId, ObsKind)]>,
    last_sent_ns: Option<u64>,
    /// When each one last delivered a value, for the silence check.
    last_seen: HashMap<(InstrumentId, ObsKind), Instant>,
    /// Subscribed instruments that have sent no moving value yet.
    awaited: HashSet<(InstrumentId, Option<ObsKind>)>,
    connected_at: Instant,
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

/// The kinds that a book with an empty side stops confirming.
const BOOK_KINDS: [ObsKind; 2] = [ObsKind::BookTop, ObsKind::Depth];

impl Carried {
    fn new(subscribed: Vec<(InstrumentId, Option<ObsKind>)>) -> Self {
        Self {
            seen: HashSet::new(),
            list: Arc::from(Vec::new()),
            last_sent_ns: None,
            last_seen: HashMap::new(),
            awaited: subscribed
                .into_iter()
                .filter(|(_, kind)| kind.is_none_or(|kind| ALWAYS_MOVING.contains(&kind)))
                .collect(),
            connected_at: Instant::now(),
        }
    }

    fn learn(&mut self, observation: &Observation) {
        let key = (observation.instrument.clone(), observation.kind);
        if !self.awaited.is_empty() && ALWAYS_MOVING.contains(&observation.kind) {
            self.awaited.remove(&(key.0.clone(), Some(key.1)));
            self.awaited.remove(&(key.0.clone(), None));
        }
        self.last_seen.insert(key.clone(), Instant::now());
        if self.seen.insert(key) {
            self.list = self.seen.iter().cloned().collect();
        }
    }

    /// Stops confirming the kinds of `instrument` that `forgotten` holds.
    fn forget(&mut self, instrument: &InstrumentId, forgotten: impl Fn(ObsKind) -> bool) {
        // The venue answered for these kinds, so their subscription works.
        self.awaited.retain(|(awaited, kind)| {
            awaited != instrument || kind.is_some_and(|kind| !forgotten(kind))
        });
        let gone = |(seen, kind): &(InstrumentId, ObsKind)| seen == instrument && forgotten(*kind);
        let before = self.seen.len();
        self.seen.retain(|key| !gone(key));
        self.last_seen.retain(|key, _| !gone(key));
        if self.seen.len() != before {
            self.list = self.seen.iter().cloned().collect();
        }
    }

    /// Why a value that changes while the market is open has sent nothing for
    /// `after`, if one has not.
    fn silent(&self, now: Instant, after: Duration) -> Option<String> {
        let stale = self
            .last_seen
            .iter()
            .filter(|((_, kind), _)| ALWAYS_MOVING.contains(kind))
            .find(|(_, last)| now.saturating_duration_since(**last) >= after);
        if let Some(((instrument, kind), _)) = stale {
            return Some(format!(
                "{instrument} {} silent for {after:?}",
                kind.as_str()
            ));
        }
        if now.saturating_duration_since(self.connected_at) < after {
            return None;
        }
        self.awaited.iter().next().map(|(instrument, kind)| {
            let kind = kind.map_or("book or mark", ObsKind::as_str);
            format!("{instrument} {kind} silent for {after:?} since the connect")
        })
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

/// Logs decode errors at most once in [`DECODE_WARNING_EVERY`].
#[derive(Default)]
struct DecodeWarnings {
    last: Option<Instant>,
    held: u64,
}

impl DecodeWarnings {
    fn record(&mut self, stream: StreamId, error: &DecodeError) {
        let now = Instant::now();
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < DECODE_WARNING_EVERY)
        {
            self.held = self.held.saturating_add(1);
            debug!(%stream, %error, "decode failed");
            return;
        }
        warn!(%stream, %error, since_last_warning = self.held, "decode failed");
        self.last = Some(now);
        self.held = 0;
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
    health: VenueHealth,
    warnings: DecodeWarnings,
}

impl<C: Connector, H: MessageHandler> Session<C, H> {
    /// Builds a session.
    pub fn new(config: SessionConfig, connector: C, handler: H, clock: MonotonicClock) -> Self {
        let health = VenueHealth::new(config.stream, config.url.clone());
        Self {
            config,
            connector,
            handler,
            clock,
            stats: SessionStats::default(),
            health,
            warnings: DecodeWarnings::default(),
        }
    }

    /// Counts into `health`, a handle that the node reads while the session runs.
    #[must_use]
    pub fn with_health(mut self, health: VenueHealth) -> Self {
        self.health = health;
        self
    }

    /// The handle on this session's counters.
    #[must_use]
    pub fn health(&self) -> VenueHealth {
        self.health.clone()
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
            self.health.count(Counter::Connect);
            info!(%stream, url = %self.config.url, "connected");
            self.handler.on_connect();
            send(&out, IngestEvent::Connected { stream }).await?;

            let started = Instant::now();
            let mut carried = Carried::new(self.handler.subscribed());
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
                    self.health.count(Counter::IdleTimeout);
                    return Ok(format!("idle for {:?}", self.config.idle_timeout));
                }
                () = tick(silence_check.as_mut()) => {
                    let now = Instant::now();
                    if let Some(after) = self.config.resubscribe_after
                        && now.saturating_duration_since(connected_at) >= after
                        && let Some(silent) = carried.silent(now, after)
                    {
                        self.stats.resubscribes = self.stats.resubscribes.saturating_add(1);
                        self.health.count(Counter::Resubscribe);
                        warn!(%stream, %silent, "subscribing again");
                        return Ok(format!("{silent}; subscribing again"));
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
                let halted =
                    match self
                        .handler
                        .on_payload(payload, local_recv_ns, &mut observations)
                    {
                        Ok(()) => {
                            self.stats.messages_decoded =
                                self.stats.messages_decoded.saturating_add(1);
                            Vec::new()
                        }
                        // The values decoded with an emptied book stand; only
                        // the book stops counting.
                        Err(DecodeError::Halted(instruments)) => {
                            self.stats.decode_skipped = self.stats.decode_skipped.saturating_add(1);
                            instruments
                        }
                        Err(DecodeError::Suspended(instrument)) => {
                            carried.forget(&instrument, |_| true);
                            self.stats.decode_skipped = self.stats.decode_skipped.saturating_add(1);
                            observations.clear();
                            Vec::new()
                        }
                        Err(err) if err.is_benign() => {
                            self.stats.decode_skipped = self.stats.decode_skipped.saturating_add(1);
                            observations.clear();
                            Vec::new()
                        }
                        Err(err @ DecodeError::Resync(_)) => {
                            // Observations decoded before the failure are dropped with it.
                            self.health.count(Counter::Resync);
                            warn!(%stream, error = %err, "resyncing");
                            return Ok(err.to_string());
                        }
                        Err(err) => {
                            self.stats.decode_errors = self.stats.decode_errors.saturating_add(1);
                            self.health.count(Counter::DecodeError);
                            self.warnings.record(stream, &err);
                            observations.clear();
                            // A book that cannot be read must not stay confirmed.
                            match err {
                                DecodeError::Lost { instrument, .. } => vec![instrument],
                                _ => Vec::new(),
                            }
                        }
                    };
                for observation in observations.drain(..) {
                    self.stats.observations = self.stats.observations.saturating_add(1);
                    carried.learn(&observation);
                    // Awaiting a full channel is deliberate backpressure: if
                    // the aggregator cannot keep up, stop reading the socket
                    // rather than buffer without bound.
                    send(out, IngestEvent::observation(observation)).await?;
                }
                for instrument in &halted {
                    carried.forget(instrument, |kind| BOOK_KINDS.contains(&kind));
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
    use crate::testing::{
        RECV_NS, Run, Script, ScriptedConnector, run_for, run_until, session_config,
    };
    use oracle_types::{Fixed, InstrumentId, MarketKind, ObsKind, Venue};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SECOND: Duration = Duration::from_secs(1);
    /// The production period of the silence check.
    const RESUBSCRIBE_AFTER: Duration = Duration::from_secs(15 * 60);
    const PROBE_AFTER: Duration = Duration::from_millis(100);
    const QUIET_IDLE_TIMEOUT: Duration = Duration::from_millis(500);

    fn btc() -> InstrumentId {
        InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT")
    }

    /// Decodes test words: `ack` is a reply, `suspend` suspends BTCUSDT, `halt`
    /// empties its book, `empty` empties it after a mark, `lost` is a BTCUSDT
    /// book that does not decode, `resync` asks for a resync, `SYMBOL book` or
    /// `SYMBOL trade` is a value of 100, and a decimal is a BTCUSDT trade.
    #[derive(Default)]
    struct Words {
        connects: Arc<AtomicUsize>,
        subscribed: Vec<(InstrumentId, Option<ObsKind>)>,
    }

    impl MessageHandler for Words {
        fn on_payload(
            &mut self,
            payload: &[u8],
            local_recv_ns: u64,
            out: &mut Vec<Observation>,
        ) -> Result<(), DecodeError> {
            let text =
                core::str::from_utf8(payload).map_err(|e| DecodeError::Malformed(e.to_string()))?;
            let (instrument, kind, price) = match text {
                "ack" => return Err(DecodeError::Control),
                "suspend" => return Err(DecodeError::Suspended(btc())),
                "halt" => return Err(DecodeError::halted(&btc())),
                "empty" => (
                    btc(),
                    ObsKind::MarkPrice,
                    Fixed::from_int(99).map_err(|_| DecodeError::Control)?,
                ),
                "lost" => {
                    return Err(DecodeError::lost(&btc(), DecodeError::MissingField("b")));
                }
                "resync" => return Err(DecodeError::Resync("checksum".to_owned())),
                _ => match text.split_once(' ') {
                    Some((symbol, kind)) => (
                        InstrumentId::new(Venue::Binance, MarketKind::Spot, symbol),
                        if kind == "book" {
                            ObsKind::BookTop
                        } else {
                            ObsKind::Trade
                        },
                        Fixed::from_int(100).map_err(|_| DecodeError::Control)?,
                    ),
                    None => (
                        btc(),
                        ObsKind::Trade,
                        text.parse().map_err(|_| DecodeError::BadDecimal {
                            field: "price",
                            value: text.to_owned(),
                        })?,
                    ),
                },
            };
            let book = kind == ObsKind::BookTop;
            out.push(Observation {
                instrument,
                kind,
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
            if text == "empty" {
                return Err(DecodeError::halted(&btc()));
            }
            Ok(())
        }

        fn on_connect(&mut self) {
            self.connects.fetch_add(1, Ordering::SeqCst);
        }

        fn subscribed(&self) -> Vec<(InstrumentId, Option<ObsKind>)> {
            self.subscribed.clone()
        }
    }

    fn session(
        config: SessionConfig,
        connector: ScriptedConnector,
    ) -> Session<ScriptedConnector, Words> {
        Session::new(
            config,
            connector,
            Words::default(),
            MonotonicClock::anchored_at(RECV_NS),
        )
    }

    /// `B` sends one value of `kind`, then `A` sends one each second.
    async fn ticking(kind: &str, resubscribe_after: Option<Duration>, time: Duration) -> Run {
        let ticks = Script::new()
            .text(format!("B {kind}"))
            .then_repeat(Script::new().delay(SECOND).text(format!("A {kind}")));
        let mut config = session_config();
        config.idle_timeout = 10 * SECOND;
        config.resubscribe_after = resubscribe_after;
        run_for(session(config, ScriptedConnector::repeating(ticks)), time).await
    }

    /// One instrument's book stops while the connection lives: after the
    /// period, the session reconnects, which subscribes again.
    #[tokio::test(start_paused = true)]
    async fn a_silent_book_inside_a_live_connection_reconnects() {
        let run = ticking(
            "book",
            Some(RESUBSCRIBE_AFTER),
            RESUBSCRIBE_AFTER + 60 * SECOND,
        )
        .await;
        assert_eq!(run.stats.resubscribes, 1, "{:?}", run.disconnects());
        let first = run.disconnects().first().copied().unwrap_or_default();
        assert!(
            first.contains("binance:spot:B") && first.contains("silent"),
            "{first}"
        );
    }

    /// A trade can rest for long; its silence is not a stopped stream.
    #[tokio::test(start_paused = true)]
    async fn silent_trades_do_not_reconnect() {
        let run = ticking(
            "trade",
            Some(RESUBSCRIBE_AFTER),
            RESUBSCRIBE_AFTER + 60 * SECOND,
        )
        .await;
        assert_eq!(run.stats.resubscribes, 0);
        assert_eq!(
            run.disconnects(),
            ["shutdown"],
            "one connection, never dropped"
        );
    }

    /// A venue that refuses one symbol sends it nothing from the start; the
    /// check still finds it, because it starts at the connect.
    #[tokio::test(start_paused = true)]
    async fn an_instrument_that_never_sends_reconnects() {
        let ticks = Script::new().then_repeat(Script::new().delay(SECOND).text("A book"));
        let mut config = session_config();
        config.idle_timeout = 10 * SECOND;
        config.resubscribe_after = Some(RESUBSCRIBE_AFTER);
        let handler = Words {
            subscribed: ["A", "B"]
                .map(|symbol| {
                    let id = InstrumentId::new(Venue::Binance, MarketKind::Spot, symbol);
                    (id, None)
                })
                .to_vec(),
            ..Words::default()
        };
        let session = Session::new(
            config,
            ScriptedConnector::repeating(ticks),
            handler,
            MonotonicClock::anchored_at(RECV_NS),
        );
        let run = run_for(session, RESUBSCRIBE_AFTER + 60 * SECOND).await;
        assert_eq!(run.stats.resubscribes, 1, "{:?}", run.disconnects());
        let first = run.disconnects().first().copied().unwrap_or_default();
        assert!(
            first.contains("binance:spot:B") && first.contains("since the connect"),
            "{first}"
        );
    }

    /// An emptied book answers for the book only: a mark that never comes is
    /// still silent.
    #[tokio::test(start_paused = true)]
    async fn a_halted_book_does_not_answer_for_a_silent_mark() {
        let halts = Script::new().then_repeat(Script::new().delay(SECOND).text("halt"));
        let mut config = session_config();
        config.idle_timeout = 10 * SECOND;
        config.resubscribe_after = Some(RESUBSCRIBE_AFTER);
        let handler = Words {
            subscribed: vec![
                (btc(), Some(ObsKind::BookTop)),
                (btc(), Some(ObsKind::MarkPrice)),
            ],
            ..Words::default()
        };
        let session = Session::new(
            config,
            ScriptedConnector::repeating(halts),
            handler,
            MonotonicClock::anchored_at(RECV_NS),
        );
        let run = run_for(session, RESUBSCRIBE_AFTER + 60 * SECOND).await;
        let first = run.disconnects().first().copied().unwrap_or_default();
        assert!(first.contains("BTCUSDT mark_price silent"), "{first}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_silence_check_can_be_off() {
        let run = ticking("book", None, 20 * 60 * SECOND).await;
        assert_eq!(run.stats.resubscribes, 0);
    }

    /// One trade, then silence; the peer answers each ping only when `answers`.
    async fn quiet(answers: bool, time: Duration) -> Run {
        let trade = Script::new().text("100");
        let script = if answers { trade.pong_on_ping() } else { trade };
        let mut config = session_config();
        config.probe_after = PROBE_AFTER;
        config.idle_timeout = QUIET_IDLE_TIMEOUT;
        run_for(session(config, ScriptedConnector::repeating(script)), time).await
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_connection_that_answers_probes_stays_alive() {
        // Six idle timeouts long, held open only by the pongs.
        let quiet_for = 6 * QUIET_IDLE_TIMEOUT;
        let run = quiet(true, quiet_for).await;
        assert_eq!(run.disconnects(), ["shutdown"]);
        assert_eq!(run.stats.idle_timeouts, 0);
        // About one probe each `PROBE_AFTER`; a third off absorbs timer order.
        let each = u64::try_from(quiet_for.as_millis() / PROBE_AFTER.as_millis()).expect("fits");
        assert!(
            run.stats.probes >= each * 2 / 3,
            "{} probes",
            run.stats.probes
        );
        assert!(!run.alive().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_connection_that_ignores_probes_is_dropped() {
        let run = quiet(false, Duration::from_millis(1_200)).await;
        assert!(run.stats.idle_timeouts >= 1, "{:?}", run.events);
        assert!(
            run.disconnects()
                .iter()
                .any(|reason| reason.contains("idle"))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_suspended_instrument_is_no_longer_confirmed() {
        let suspends = Script::new()
            .text("100")
            .then_repeat(Script::new().text("suspend").delay(PROBE_AFTER));
        let mut config = session_config();
        config.idle_timeout = 10 * SECOND;
        let run = run_for(
            session(config, ScriptedConnector::repeating(suspends)),
            SECOND,
        )
        .await;
        assert_eq!(
            run.alive().len(),
            1,
            "only the frame before the suspension confirms the price"
        );
    }

    /// The sources that the connection carried when it closed.
    async fn carried_at_close(script: Script, events: usize) -> Vec<(InstrumentId, ObsKind)> {
        let connector = ScriptedConnector::new([script.close()]);
        let run = run_until(session(session_config(), connector), events).await;
        let disconnect = run.events.iter().find_map(|event| match event {
            IngestEvent::Disconnected { sources, .. } => Some(sources.to_vec()),
            _ => None,
        });
        disconnect.unwrap_or_else(|| panic!("a disconnect: {:?}", run.events))
    }

    /// An emptied book stops counting, but the mark of the same perpetual,
    /// decoded with it, stands.
    #[tokio::test(start_paused = true)]
    async fn an_emptied_book_stops_confirming_only_the_book() {
        let script = Script::new().text("BTCUSDT book").text("empty");
        assert_eq!(
            carried_at_close(script, 4).await,
            [(btc(), ObsKind::MarkPrice)]
        );
    }

    /// A book that never decodes again must not stay confirmed: it goes stale
    /// within the confirmed age, and the error counts.
    #[tokio::test(start_paused = true)]
    async fn a_book_that_stops_decoding_is_no_longer_confirmed() {
        let script = Script::new()
            .text("BTCUSDT book")
            .text("BTCUSDT trade")
            .text("lost")
            .text("lost");
        assert_eq!(carried_at_close(script, 5).await, [(btc(), ObsKind::Trade)]);
    }

    #[tokio::test(start_paused = true)]
    async fn rest_records_do_not_keep_a_silent_socket_alive() {
        let records = Script::new().then_repeat(Script::new().rest("100").delay(PROBE_AFTER));
        let mut config = session_config();
        config.probe_after = PROBE_AFTER;
        config.idle_timeout = QUIET_IDLE_TIMEOUT;
        let connector = ScriptedConnector::repeating(records);
        let run = run_for(session(config, connector), Duration::from_millis(1_200)).await;
        assert!(run.stats.idle_timeouts >= 1, "{:?}", run.stats);
        assert!(
            run.alive().is_empty(),
            "a REST record confirms nothing about the socket"
        );
    }

    /// A keepalive is our own frame, not the venue's. It must not hold a
    /// silent connection open.
    #[tokio::test(start_paused = true)]
    async fn a_keepalive_does_not_hide_a_silent_connection() {
        let connector = ScriptedConnector::new([Script::new()]);
        let mut config = session_config();
        config.keepalive = Some((Duration::from_millis(10), "ping".to_owned()));
        let run = run_until(session(config, connector.clone()), 2).await;
        assert_eq!(run.shape(), ["connected", "disconnected"]);
        assert!(
            run.disconnects()
                .iter()
                .all(|reason| reason.contains("idle"))
        );
        assert!(
            connector.sent().iter().any(|sent| sent == "ping"),
            "the keepalive went out"
        );
    }

    /// Only a fresh snapshot repairs a book, so a resync ends the connection
    /// and the next one starts clean.
    #[tokio::test(start_paused = true)]
    async fn a_resync_drops_the_connection_and_the_next_one_starts_clean() {
        let connector = ScriptedConnector::new([
            Script::new().text("100.5").text("resync").text("999"),
            Script::new().text("101.5"),
        ]);
        let handler = Words::default();
        let connects = Arc::clone(&handler.connects);
        let session = Session::new(
            session_config(),
            connector,
            handler,
            MonotonicClock::anchored_at(1),
        );
        let run = run_until(session, 5).await;

        assert_eq!(
            run.shape(),
            [
                "connected",
                "observation",
                "disconnected",
                "connected",
                "observation"
            ]
        );
        let prices: Vec<String> = run.observations().map(|o| o.price.to_string()).collect();
        assert_eq!(
            prices,
            ["100.5", "101.5"],
            "the frame after the resync is never read"
        );
        assert!(
            matches!(run.disconnects().as_slice(), [reason] if reason.contains("book out of sync")),
            "{:?}",
            run.disconnects()
        );
        assert_eq!(connects.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn decodes_frames_and_emits_observations() {
        let connector = ScriptedConnector::new([Script::new().text("100.5").text("101.5").close()]);
        let run = run_until(session(session_config(), connector), 4).await;
        assert_eq!(
            run.shape(),
            ["connected", "observation", "observation", "disconnected"]
        );
        assert_eq!(
            run.observations().next().map(|o| o.price),
            "100.5".parse().ok()
        );
        assert_eq!(run.stats.observations, 2);
        assert_eq!(run.stats.messages_decoded, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn reconnects_after_connect_failures_and_backs_off() {
        let connector = ScriptedConnector::refusing_first(3, [Script::new().text("42").close()]);
        let run = run_until(session(session_config(), connector.clone()), 1).await;
        assert_eq!(run.shape(), ["connected"]);
        assert_eq!(connector.attempts(), 4, "should have retried three times");
        assert_eq!(run.stats.connect_failures, 3);
        assert_eq!(run.stats.connects, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_connection_is_recycled_by_the_idle_timeout() {
        let connector = ScriptedConnector::new([Script::new()]);
        let run = run_until(session(session_config(), connector), 2).await;
        assert_eq!(run.shape(), ["connected", "disconnected"]);
        assert!(
            matches!(run.disconnects().as_slice(), [reason] if reason.contains("idle")),
            "{:?}",
            run.disconnects()
        );
        assert_eq!(run.stats.idle_timeouts, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_reports_what_it_carries_while_it_lives() {
        // An ack before any data proves nothing about an instrument yet.
        let connector =
            ScriptedConnector::new([Script::new().text("ack").text("1").text("2").text("ack")]);
        let run = run_until(session(session_config(), connector), 4).await;

        // The frames arrive together: one report, after the first observation.
        let alive = run.alive();
        let [IngestEvent::Alive { sources, .. }] = alive.as_slice() else {
            panic!("one alive event: {:?}", run.events);
        };
        assert_eq!(sources.as_ref(), [(btc(), ObsKind::Trade)].as_slice());
        let position = |wanted: fn(&IngestEvent) -> bool| run.events.iter().position(wanted);
        assert!(
            position(|event| matches!(event, IngestEvent::Observation(_)))
                < position(|event| matches!(event, IngestEvent::Alive { .. }))
        );
    }

    /// Ordering is the contract: a consumer must be told to drop its book
    /// before any post-reconnect quote can reach it.
    #[tokio::test(start_paused = true)]
    async fn disconnect_is_announced_before_the_next_connect() {
        let connector = ScriptedConnector::new([
            Script::new().text("1").close(),
            Script::new().text("2").close(),
        ]);
        let run = run_until(session(session_config(), connector), 6).await;
        assert_eq!(
            run.shape(),
            [
                "connected",
                "observation",
                "disconnected",
                "connected",
                "observation",
                "disconnected"
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn subscription_frames_are_sent_on_every_connect() {
        const SUBSCRIBE: &str = r#"{"op":"subscribe"}"#;
        let connector = ScriptedConnector::new([Script::new().close(), Script::new().close()]);
        let mut config = session_config();
        config.subscribe = vec![SUBSCRIBE.to_owned()];
        let _ = run_until(session(config, connector.clone()), 4).await;
        assert_eq!(
            connector.sent(),
            [SUBSCRIBE, SUBSCRIBE],
            "resubscribe must happen on every connect"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn benign_decode_failures_do_not_drop_the_connection() {
        let connector = ScriptedConnector::new([Script::new()
            .text("ack")
            .text("not-a-number")
            .text("7")
            .close()]);
        let run = run_until(session(session_config(), connector), 2).await;
        assert_eq!(run.shape(), ["connected", "observation"]);
        assert_eq!(run.stats.observations, 1);
        assert_eq!(run.stats.decode_skipped, 1, "the ack is routine");
        assert_eq!(
            run.stats.decode_errors, 1,
            "the garbage payload is worth counting"
        );
    }

    /// The node reads the counters while the session runs, not only at its end.
    #[tokio::test(start_paused = true)]
    async fn decode_errors_resyncs_and_idle_timeouts_reach_the_shared_counters() {
        let connector = ScriptedConnector::new([
            Script::new().text("not-a-number").text("resync"),
            Script::new().text("not-a-number"),
        ]);
        let health = VenueHealth::new(session_config().stream, "wss://test");
        let session = session(session_config(), connector).with_health(health.clone());
        let _ = run_until(session, 4).await;
        assert_eq!(
            health.counts(),
            crate::HealthCounts {
                connects: 2,
                decode_errors: 2,
                resyncs: 1,
                resubscribes: 0,
                idle_timeouts: 1,
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_closed_output_channel_stops_the_session() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let connector = ScriptedConnector::new([Script::new().text("1").close()]);
        let result = session(session_config(), connector)
            .run(tx, CancellationToken::new())
            .await;
        assert!(matches!(result, Err(IngestError::OutputClosed)));
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_returns_promptly() {
        let (tx, _rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let stats = session(session_config(), ScriptedConnector::new([]))
            .run(tx, shutdown)
            .await
            .expect("runs");
        assert_eq!(
            stats.connects, 0,
            "a cancelled token must not open a connection"
        );
    }
}
