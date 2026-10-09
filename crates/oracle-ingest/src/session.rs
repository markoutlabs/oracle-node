//! The connect-decode-reconnect loop every adapter runs on.

use std::future::pending;
use std::time::Duration;

use oracle_types::Observation;
use tokio::sync::mpsc;
use tokio::time::{Instant, interval_at, sleep, sleep_until, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::backoff::{Backoff, BackoffConfig};
use crate::clock::MonotonicClock;
use crate::{Connector, DecodeError, IngestError, IngestEvent, StreamId, Transport};

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
    /// Reconnect if nothing at all arrives for this long.
    ///
    /// Set above the venue's own ping period. A silent connection is
    /// indistinguishable from a healthy one on a quiet instrument, and the
    /// failure mode — a half-open socket that never delivers again — is common
    /// enough that waiting for TCP to notice is not good enough.
    pub idle_timeout: Duration,
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
            idle_timeout: Duration::from_secs(60),
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
                result = self.connector.connect(&self.config.url) => result,
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
            let reason = match self.subscribe(&mut conn).await {
                Ok(()) => self.pump(&mut conn, &out, &shutdown).await?,
                Err(err) => format!("subscribe failed: {err}"),
            };
            let uptime = started.elapsed();

            self.stats.disconnects = self.stats.disconnects.saturating_add(1);
            info!(%stream, ?uptime, %reason, "disconnected");
            // Downstream must invalidate this venue's state before anything new
            // arrives, so the notice is in-band and ordered with the data.
            send(&out, IngestEvent::Disconnected { stream, reason }).await?;

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
                result = timeout(self.config.idle_timeout, conn.recv()) => result,
            };

            let frame = match received {
                Err(_elapsed) => {
                    self.stats.idle_timeouts = self.stats.idle_timeouts.saturating_add(1);
                    return Ok(format!("idle for {:?}", self.config.idle_timeout));
                }
                Ok(Err(err)) => return Ok(err.to_string()),
                Ok(Ok(None)) => return Ok("closed by peer".to_owned()),
                Ok(Ok(Some(frame))) => frame,
            };

            // A ping counts as liveness and nothing more; the transport answers it.
            let Some(payload) = frame.payload() else {
                continue;
            };

            let local_recv_ns = self.clock.now_ns();
            observations.clear();
            match self
                .handler
                .on_payload(payload, local_recv_ns, &mut observations)
            {
                Ok(()) => {
                    self.stats.messages_decoded = self.stats.messages_decoded.saturating_add(1)
                }
                Err(err) if err.is_benign() => {
                    self.stats.decode_skipped = self.stats.decode_skipped.saturating_add(1);
                    continue;
                }
                Err(err @ DecodeError::Resync(_)) => {
                    // Observations decoded before the failure are dropped with it.
                    warn!(%stream, error = %err, "resyncing");
                    return Ok(err.to_string());
                }
                Err(err) => {
                    self.stats.decode_errors = self.stats.decode_errors.saturating_add(1);
                    debug!(%stream, error = %err, "decode failed");
                    continue;
                }
            }

            for observation in observations.drain(..) {
                self.stats.observations = self.stats.observations.saturating_add(1);
                // Awaiting a full channel is deliberate backpressure: if the
                // aggregator cannot keep up, stop reading the socket rather than
                // buffer without bound.
                send(out, IngestEvent::observation(observation)).await?;
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
            match rx.recv().await.expect("an event") {
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
            rx.recv().await,
            Some(IngestEvent::Connected { .. })
        ));
        let first = rx.recv().await.expect("observation");
        assert_eq!(
            first.as_observation().map(|o| o.price),
            Some("100.5".parse().expect("valid"))
        );
        assert!(
            rx.recv()
                .await
                .expect("observation")
                .as_observation()
                .is_some()
        );
        assert!(matches!(
            rx.recv().await,
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
        for _ in 0..6 {
            match rx.recv().await {
                Some(IngestEvent::Connected { .. }) => sequence.push("connected"),
                Some(IngestEvent::Disconnected { .. }) => sequence.push("disconnected"),
                Some(IngestEvent::Observation(_)) => sequence.push("observation"),
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
