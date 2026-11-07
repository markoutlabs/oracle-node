//! A scripted connection, and a runner that reads what a session emits.

use std::collections::VecDeque;
use std::future::pending;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use oracle_types::{MarketKind, Observation, Venue};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep, sleep_until};
use tokio_util::sync::CancellationToken;

use crate::session::{MessageHandler, Session, SessionStats};
use crate::{
    BackoffConfig, Connector, ExchangeAdapter, Frame, IngestEvent, SessionConfig, StreamId,
    Transport, TransportError,
};

#[derive(Clone, Debug)]
enum Step {
    Frame(Frame),
    Delay(Duration),
    /// A delay in progress. The deadline stays in the script, so a `recv`
    /// that the session cancels resumes the same wait.
    Until(Instant),
    Fail(TransportError),
    Close,
}

/// What one connection receives, in order.
///
/// After the last step the connection is silent, so the session's own timers
/// decide what happens next, unless [`Script::then_repeat`] gives a cycle.
#[derive(Clone, Debug, Default)]
pub struct Script {
    steps: VecDeque<Step>,
    cycle: Vec<Step>,
    pong_on_ping: bool,
}

impl Script {
    /// An empty script: a connection that opens and then says nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Receives a text frame.
    #[must_use]
    pub fn text(self, payload: impl Into<String>) -> Self {
        self.frame(Frame::Utf8(payload.into().into()))
    }

    /// Receives a binary frame.
    #[must_use]
    pub fn binary(self, payload: impl Into<Vec<u8>>) -> Self {
        self.frame(Frame::Bytes(payload.into().into()))
    }

    /// Receives a record that the connector read over REST.
    #[must_use]
    pub fn rest(self, payload: impl Into<String>) -> Self {
        self.frame(Frame::Rest(payload.into()))
    }

    /// Receives any frame.
    #[must_use]
    pub fn frame(mut self, frame: Frame) -> Self {
        self.steps.push_back(Step::Frame(frame));
        self
    }

    /// Waits before the next step.
    #[must_use]
    pub fn delay(mut self, delay: Duration) -> Self {
        self.steps.push_back(Step::Delay(delay));
        self
    }

    /// The connection fails with an I/O error.
    #[must_use]
    pub fn fail(mut self, reason: &str) -> Self {
        self.steps
            .push_back(Step::Fail(TransportError::Io(reason.to_owned())));
        self
    }

    /// The peer closes the connection.
    #[must_use]
    pub fn close(mut self) -> Self {
        self.steps.push_back(Step::Close);
        self
    }

    /// The peer answers each ping with a pong.
    #[must_use]
    pub const fn pong_on_ping(mut self) -> Self {
        self.pong_on_ping = true;
        self
    }

    /// After the other steps, plays the steps of `cycle` again and again.
    #[must_use]
    pub fn then_repeat(mut self, cycle: Self) -> Self {
        self.cycle = cycle.steps.into();
        self
    }
}

struct Shared {
    scripts: Mutex<VecDeque<Script>>,
    /// The script of each connection after the listed ones, if any.
    every: Option<Script>,
    refuse_first: usize,
    attempts: AtomicUsize,
    urls: Mutex<Vec<String>>,
    sent: Arc<Mutex<Vec<String>>>,
}

/// Opens scripted connections, and keeps what the session asked and sent.
#[derive(Clone)]
pub struct ScriptedConnector {
    shared: Arc<Shared>,
}

impl ScriptedConnector {
    /// Serves one script to each connection, in order. Each later connection
    /// opens and says nothing.
    #[must_use]
    pub fn new(scripts: impl IntoIterator<Item = Script>) -> Self {
        Self::build(scripts.into_iter().collect(), None, 0)
    }

    /// Serves the same script to every connection.
    #[must_use]
    pub fn repeating(script: Script) -> Self {
        Self::build(VecDeque::new(), Some(script), 0)
    }

    /// Refuses the first `count` connects, then serves `scripts` as
    /// [`ScriptedConnector::new`] does.
    #[must_use]
    pub fn refusing_first(count: usize, scripts: impl IntoIterator<Item = Script>) -> Self {
        Self::build(scripts.into_iter().collect(), None, count)
    }

    fn build(scripts: VecDeque<Script>, every: Option<Script>, refuse_first: usize) -> Self {
        Self {
            shared: Arc::new(Shared {
                scripts: Mutex::new(scripts),
                every,
                refuse_first,
                attempts: AtomicUsize::new(0),
                urls: Mutex::new(Vec::new()),
                sent: Arc::new(Mutex::new(Vec::new())),
            }),
        }
    }

    /// Connect attempts so far, the refused ones included.
    #[must_use]
    pub fn attempts(&self) -> usize {
        self.shared.attempts.load(Ordering::SeqCst)
    }

    /// The URL of each connect attempt, in order.
    #[must_use]
    pub fn urls(&self) -> Vec<String> {
        lock(&self.shared.urls).clone()
    }

    /// The text frames that the session sent, on every connection.
    #[must_use]
    pub fn sent(&self) -> Vec<String> {
        lock(&self.shared.sent).clone()
    }
}

impl Connector for ScriptedConnector {
    type Conn = ScriptedConn;

    async fn connect(&self, url: &str) -> Result<Self::Conn, TransportError> {
        let attempt = self.shared.attempts.fetch_add(1, Ordering::SeqCst);
        lock(&self.shared.urls).push(url.to_owned());
        if attempt < self.shared.refuse_first {
            return Err(TransportError::Connect("refused by the script".to_owned()));
        }
        let script = lock(&self.shared.scripts)
            .pop_front()
            .or_else(|| self.shared.every.clone())
            .unwrap_or_default();
        Ok(ScriptedConn {
            script,
            pongs: 0,
            sent: Arc::clone(&self.shared.sent),
        })
    }
}

/// One scripted connection.
pub struct ScriptedConn {
    script: Script,
    pongs: usize,
    sent: Arc<Mutex<Vec<String>>>,
}

impl Transport for ScriptedConn {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        loop {
            if self.pongs > 0 {
                self.pongs -= 1;
                return Ok(Some(Frame::Pong));
            }
            if self.script.steps.is_empty() {
                if self.script.cycle.is_empty() {
                    // The session's timers decide; a ping cancels this wait.
                    pending::<()>().await;
                }
                let cycle = self.script.cycle.clone();
                self.script.steps.extend(cycle);
            }
            let Some(step) = self.script.steps.front_mut() else {
                continue;
            };
            match step {
                Step::Delay(delay) => *step = Step::Until(Instant::now() + *delay),
                Step::Until(deadline) => {
                    sleep_until(*deadline).await;
                    self.script.steps.pop_front();
                }
                Step::Frame(_) | Step::Fail(_) | Step::Close => {
                    return match self.script.steps.pop_front() {
                        Some(Step::Frame(frame)) => Ok(Some(frame)),
                        Some(Step::Fail(error)) => Err(error),
                        _ => Ok(None),
                    };
                }
            }
        }
    }

    async fn send_text(&mut self, text: String) -> Result<(), TransportError> {
        lock(&self.sent).push(text);
        Ok(())
    }

    async fn send_ping(&mut self) -> Result<(), TransportError> {
        if self.script.pong_on_ping {
            self.pongs += 1;
        }
        Ok(())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A Binance spot session to a test URL, with fast timers: a 50 ms idle
/// limit and a 10 ms to 100 ms reconnect backoff with no jitter.
#[must_use]
pub fn session_config() -> SessionConfig {
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

/// Events in flight between a session and a runner. Large enough that no
/// test session waits on the channel.
const CHANNEL: usize = 4_096;

/// What a session emitted, in order, and its counters at shutdown.
#[derive(Debug)]
pub struct Run {
    /// Every event, liveness reports included.
    pub events: Vec<IngestEvent>,
    /// The session's counters.
    pub stats: SessionStats,
}

impl Run {
    /// The observations, in order.
    pub fn observations(&self) -> impl Iterator<Item = &Observation> {
        self.events.iter().filter_map(IngestEvent::as_observation)
    }

    /// The reason of each disconnect, in order.
    #[must_use]
    pub fn disconnects(&self) -> Vec<&str> {
        self.events
            .iter()
            .filter_map(|event| match event {
                IngestEvent::Disconnected { reason, .. } => Some(reason.as_str()),
                _ => None,
            })
            .collect()
    }

    /// The liveness reports.
    #[must_use]
    pub fn alive(&self) -> Vec<&IngestEvent> {
        self.events
            .iter()
            .filter(|event| matches!(event, IngestEvent::Alive { .. }))
            .collect()
    }

    /// Each event other than a liveness report, as one word: `connected`,
    /// `observation` or `disconnected`.
    #[must_use]
    pub fn shape(&self) -> Vec<&'static str> {
        self.events
            .iter()
            .filter_map(|event| match event {
                IngestEvent::Connected { .. } => Some("connected"),
                IngestEvent::Observation(_) => Some("observation"),
                IngestEvent::Disconnected { .. } => Some("disconnected"),
                _ => None,
            })
            .collect()
    }
}

/// Runs `session` for `time`, then shuts it down. Under a paused tokio clock,
/// `time` passes at once.
///
/// # Panics
///
/// Panics if the session fails or its task panics.
pub async fn run_for<C, H>(session: Session<C, H>, time: Duration) -> Run
where
    C: Connector + 'static,
    H: MessageHandler + 'static,
{
    let (out, mut events) = mpsc::channel(CHANNEL);
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(session.run(out, shutdown.clone()));
    let collect = tokio::spawn(async move {
        let mut all = Vec::new();
        while let Some(event) = events.recv().await {
            all.push(event);
        }
        all
    });
    sleep(time).await;
    shutdown.cancel();
    let stats = task
        .await
        .expect("the session joins")
        .expect("the session runs");
    let events = collect.await.expect("the collector joins");
    Run { events, stats }
}

/// Runs `session` until it emits `count` events other than liveness reports,
/// then shuts it down. The run keeps the events up to that point.
///
/// # Panics
///
/// Panics if the session stops first, fails, or its task panics.
pub async fn run_until<C, H>(session: Session<C, H>, count: usize) -> Run
where
    C: Connector + 'static,
    H: MessageHandler + 'static,
{
    let (out, mut events) = mpsc::channel(CHANNEL);
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(session.run(out, shutdown.clone()));
    let mut kept = Vec::new();
    let mut counted = 0;
    while counted < count {
        let event = events.recv().await.expect("the session emits more events");
        counted += usize::from(!matches!(event, IngestEvent::Alive { .. }));
        kept.push(event);
    }
    shutdown.cancel();
    // Drained, so a session that emits at shutdown never waits on the channel.
    tokio::spawn(async move { while events.recv().await.is_some() {} });
    let stats = task
        .await
        .expect("the session joins")
        .expect("the session runs");
    Run {
        events: kept,
        stats,
    }
}

/// Runs `adapter` until `connections` of its sessions have connected, then
/// shuts it down.
///
/// # Panics
///
/// Panics if the adapter stops first, fails, or its task panics.
pub async fn run_adapter_until_connected(adapter: Box<dyn ExchangeAdapter>, connections: usize) {
    let (out, mut events) = mpsc::channel(CHANNEL);
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(adapter.run(out, shutdown.clone()));
    let mut connected = 0;
    while connected < connections {
        let event = events.recv().await.expect("the adapter emits more events");
        connected += usize::from(matches!(event, IngestEvent::Connected { .. }));
    }
    shutdown.cancel();
    tokio::spawn(async move { while events.recv().await.is_some() {} });
    task.await
        .expect("the adapter joins")
        .expect("the adapter runs");
}
