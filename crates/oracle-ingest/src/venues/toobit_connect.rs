//! Toobit has no socket here: its socket `depth` books fell behind its REST
//! books in about 6% of checks on 2026-11-12, for example by 10 s and two ticks.
//!
//! [`ToobitConnector`] takes the depth URL with its books,
//! `https://api.toobit.com/quote/v1/depth?contracts=ICPUSDT,ETHUSDT`, and opens a
//! connection of REST reads alone (see [`super::rest_frames`]). Each book has its
//! own read stream, so a slow reply delays no other book. A good read is a text
//! frame, `{"type":"rest","subject":"depth","topic":"/rest:ICPUSDT","data":{…}}`:
//! it is the venue's own data, so it shows that the connection lives. A failed
//! read is a REST record with `error`, which shows nothing, so the idle timeout
//! ends a connection whose reads all fail. Any other URL passes through.

use std::iter;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_util::FutureExt as _;
use futures_util::future::BoxFuture;
use futures_util::stream::{self, BoxStream, StreamExt as _};
use reqwest::StatusCode;
use serde_json::value::RawValue;
use tokio::time::{Instant, MissedTickBehavior, interval_at, sleep_until};

use super::rest_frames::{self, ReadError, RestTransport};
use crate::book::DEPTH_LEVELS;
use crate::transport::{Connector, Frame, TransportError};

/// The order book endpoint.
pub const URL: &str = "https://api.toobit.com/quote/v1/depth";

/// The subject of each record.
const SUBJECT: &str = "depth";

// Read on 2026-11-12: `rateLimits` in `/api/v1/exchangeInfo` gives 3,000 weight a
// minute. The docs give no weight for `/quote/v1/depth` and 1 for every other read
// of one symbol (api-docs.toobit.com/api/spot-market-data), and no reply carries a count.
const WEIGHT_PER_MINUTE: u32 = 3_000;
const DEPTH_WEIGHT: u32 = 1;
/// The node uses half of the budget. The other half is room for another reader at
/// its address, such as the proxy's depth reads (60 a minute on 2026-11-12).
const NODE_SHARE: u32 = 2;
/// The fastest pace of one book.
const FASTEST: Duration = Duration::from_secs(1);
/// The budget is per address, so a refused read stops the reads of every book.
const PAUSE: Duration = Duration::from_secs(30);
/// The other books' reads confirm a book until its own read fails, so a read gets
/// no more time than the 2 s confirmed age (SPEC §5.2).
const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// The depth URL for a set of books.
#[must_use]
pub fn url<'a>(books: impl Iterator<Item = &'a str>) -> String {
    rest_frames::with_contracts(URL, books)
}

/// Gives the `data` of the reply at a URL. A test reads from a script, with no network.
type Fetch =
    Arc<dyn Fn(&str) -> BoxFuture<'static, Result<Box<RawValue>, ReadError>> + Send + Sync>;

/// Wraps a connector: it answers Toobit's depth URL with a connection of REST
/// reads alone. Any other URL passes through.
#[derive(Clone)]
pub struct ToobitConnector<C> {
    inner: C,
    fetch: Fetch,
    pause: Pause,
}

impl<C> ToobitConnector<C> {
    /// Wraps `inner`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Connect`] if the HTTP client cannot be built,
    /// which means TLS is misconfigured in this binary.
    pub fn new(inner: C) -> Result<Self, TransportError> {
        let client = rest_frames::client()?;
        let fetch: Fetch = Arc::new(move |url| {
            let request = client.get(url).timeout(READ_TIMEOUT);
            rest_frames::read(request, rest_frames::whole_body).boxed()
        });
        Ok(Self {
            inner,
            fetch,
            pause: Pause::default(),
        })
    }
}

impl<C: Connector> Connector for ToobitConnector<C> {
    type Conn = RestTransport<C::Conn>;

    async fn connect(&self, url: &str) -> Result<Self::Conn, TransportError> {
        let (base, query) = url.split_once('?').unwrap_or((url, ""));
        if base != URL {
            return Ok(RestTransport::plain(self.inner.connect(url).await?));
        }
        let symbols = rest_frames::contracts_of(query);
        if symbols.is_empty() {
            return Err(TransportError::Connect(format!("no book in {url}")));
        }
        let every = every(symbols.len());
        // The first reads spread over one period, so the reads do not come in bursts.
        let spread = every / u32::try_from(symbols.len()).unwrap_or(u32::MAX);
        let starts = iter::successors(Some(Instant::now()), |start| Some(*start + spread));
        let books = symbols.into_iter().zip(starts).map(|(symbol, start)| {
            book(
                Arc::clone(&self.fetch),
                self.pause.clone(),
                symbol,
                start,
                every,
            )
        });
        Ok(RestTransport::alone(books))
    }
}

/// The period of each book's reads when `books` books share the node's part of
/// the budget: one second, or longer when they do not fit.
fn every(books: usize) -> Duration {
    let reads_per_minute = WEIGHT_PER_MINUTE / NODE_SHARE / DEPTH_WEIGHT;
    let books = u32::try_from(books).unwrap_or(u32::MAX);
    (Duration::from_secs(60).saturating_mul(books) / reads_per_minute).max(FASTEST)
}

/// One book's reads: the first at `start`, then one each `every`, each after the
/// pause of the address.
fn book(
    fetch: Fetch,
    pause: Pause,
    symbol: String,
    start: Instant,
    every: Duration,
) -> BoxStream<'static, Frame> {
    let url = format!("{URL}?symbol={symbol}&limit={DEPTH_LEVELS}");
    let mut ticks = interval_at(start, every);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    stream::unfold(ticks, move |mut ticks| {
        let (fetch, pause, url, symbol) = (
            Arc::clone(&fetch),
            pause.clone(),
            url.clone(),
            symbol.clone(),
        );
        async move {
            ticks.tick().await;
            while pause.wait().await {
                // The ticks in the pause are lost. This late one comes at once,
                // and the next one keeps the book's place in the spread.
                ticks.tick().await;
            }
            let fetched = fetch(&url).await;
            if let Some(wait) = fetched.as_ref().err().and_then(pause_after) {
                pause.hold(wait);
            }
            Some((frame(&symbol, fetched), ticks))
        }
    })
    .boxed()
}

/// A good read as a text frame, which shows that the connection lives; a failed
/// read as a REST record, which does not.
fn frame(symbol: &str, fetched: Result<Box<RawValue>, ReadError>) -> Frame {
    match fetched {
        Ok(data) => Frame::Utf8(rest_frames::record(SUBJECT, symbol, Ok(data)).into()),
        Err(error) => rest_frames::frame(SUBJECT, symbol, Err(error.to_string())),
    }
}

/// How long a failed read stops every read: 429 and 418 refuse the rate, and 403
/// is Toobit's firewall limit. `Retry-After` counts when it is longer than [`PAUSE`].
fn pause_after(error: &ReadError) -> Option<Duration> {
    let ReadError::Status {
        status,
        retry_after,
        ..
    } = error
    else {
        return None;
    };
    let refused = matches!(
        *status,
        StatusCode::TOO_MANY_REQUESTS | StatusCode::IM_A_TEAPOT | StatusCode::FORBIDDEN
    );
    refused.then(|| retry_after.map_or(PAUSE, |after| after.max(PAUSE)))
}

/// The end of the pause that every read of the address waits out.
#[derive(Clone, Default)]
struct Pause(Arc<Mutex<Option<Instant>>>);

impl Pause {
    fn until(&self) -> Option<Instant> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stops the reads for `wait` from now, unless a longer pause holds.
    fn hold(&self, wait: Duration) {
        let until = Instant::now() + wait;
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *held = Some(held.map_or(until, |held| held.max(until)));
    }

    /// Waits until no pause holds, also one that starts during the wait, and
    /// says whether a pause held.
    async fn wait(&self) -> bool {
        let mut waited = false;
        while let Some(until) = self.until().filter(|until| *until > Instant::now()) {
            sleep_until(until).await;
            waited = true;
        }
        waited
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MonotonicClock;
    use crate::testing::{ScriptedConn, ScriptedConnector, instrument, run_for, session_config};
    use crate::venues::{VenueHandler, toobit};
    use crate::{InstrumentMap, Session, StreamId, Transport as _};
    use oracle_types::{MarketKind, Venue};

    const BOOK: &str = r#"{"t":1794493985514,"b":[["2.526","2008.96"]],"a":[["2.527","2224.77"]]}"#;

    fn refused(status: StatusCode, retry_after: Option<u64>) -> ReadError {
        ReadError::Status {
            status,
            retry_after: retry_after.map(Duration::from_secs),
            url: URL.to_owned(),
        }
    }

    /// Each read, as the time since `start` and the symbol it asked for.
    type Reads = Arc<Mutex<Vec<(Duration, String)>>>;

    /// A connector whose reads log themselves; `answer` gives the reply of each,
    /// from its symbol and the reads of that symbol before it.
    fn scripted(
        answer: fn(&str, usize) -> Result<Box<RawValue>, ReadError>,
    ) -> (ToobitConnector<ScriptedConnector>, Reads) {
        let start = Instant::now();
        let reads = Reads::default();
        let log = Arc::clone(&reads);
        let fetch: Fetch = Arc::new(move |url| {
            let symbol = url
                .split_once("symbol=")
                .and_then(|(_, rest)| rest.split('&').next())
                .unwrap_or_default()
                .to_owned();
            let mut reads = log.lock().unwrap_or_else(PoisonError::into_inner);
            let before = reads.iter().filter(|(_, read)| *read == symbol).count();
            reads.push((start.elapsed(), symbol.clone()));
            let reply = answer(&symbol, before);
            async move { reply }.boxed()
        });
        let connector = ToobitConnector {
            inner: ScriptedConnector::new([]),
            fetch,
            pause: Pause::default(),
        };
        (connector, reads)
    }

    fn book_reply(_: &str, _: usize) -> Result<Box<RawValue>, ReadError> {
        Ok(RawValue::from_string(BOOK.to_owned()).expect("JSON"))
    }

    #[test]
    fn a_book_reads_each_second_until_the_books_pass_half_the_budget() {
        assert_eq!(every(1), FASTEST);
        assert_eq!(every(25), FASTEST);
        assert_eq!(every(30), Duration::from_millis(1_200));
        assert_eq!(every(150), Duration::from_secs(6));
    }

    #[test]
    fn a_refusal_of_the_rate_pauses_for_30_s_or_the_venue_s_wait() {
        let pause = |status, after| pause_after(&refused(status, after));
        assert_eq!(pause(StatusCode::TOO_MANY_REQUESTS, None), Some(PAUSE));
        assert_eq!(pause(StatusCode::IM_A_TEAPOT, Some(5)), Some(PAUSE));
        assert_eq!(
            pause(StatusCode::TOO_MANY_REQUESTS, Some(120)),
            Some(Duration::from_secs(120))
        );
        assert_eq!(pause(StatusCode::FORBIDDEN, None), Some(PAUSE));
        assert_eq!(pause(StatusCode::BAD_REQUEST, None), None);
        assert_eq!(pause(StatusCode::BAD_GATEWAY, None), None);
        assert_eq!(pause_after(&ReadError::Failed("timeout".to_owned())), None);
    }

    #[test]
    fn a_good_read_is_the_connection_s_own_frame_and_a_failed_one_is_not() {
        let good = frame("ICPUSDT", book_reply("ICPUSDT", 0));
        let text = good.socket_text().expect("a text frame");
        assert!(text.contains(r#""topic":"/rest:ICPUSDT""#), "{text}");
        assert!(text.contains(r#""subject":"depth""#), "{text}");
        let failed = frame("ICPUSDT", Err(refused(StatusCode::TOO_MANY_REQUESTS, None)));
        let Frame::Rest(text) = failed else {
            panic!("a REST record: {failed:?}");
        };
        assert!(
            text.contains(r#""error":"HTTP 429 Too Many Requests"#),
            "{text}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn another_url_passes_through() {
        let (connector, reads) = scripted(book_reply);
        let _conn = connector
            .connect("wss://stream.example/ws?contracts=ICPUSDT")
            .await
            .expect("connects");
        assert_eq!(
            connector.inner.urls(),
            ["wss://stream.example/ws?contracts=ICPUSDT"]
        );
        assert!(
            connector.connect(URL).await.is_err(),
            "a depth URL with no book"
        );
        assert!(reads.lock().expect("reads").is_empty());
    }

    /// Reads the connection for `time` and gives its frames.
    async fn frames_for(conn: &mut RestTransport<ScriptedConn>, time: Duration) -> Vec<Frame> {
        let mut frames = Vec::new();
        let deadline = Instant::now() + time;
        while let Ok(Ok(Some(frame))) = tokio::time::timeout_at(deadline, conn.recv()).await {
            frames.push(frame);
        }
        frames
    }

    #[tokio::test(start_paused = true)]
    async fn each_book_reads_once_a_second_in_its_own_place() {
        let (connector, reads) = scripted(book_reply);
        let mut conn = connector
            .connect(&url(["ICPUSDT", "ETHUSDT"].into_iter()))
            .await
            .expect("connects");
        let frames = frames_for(&mut conn, Duration::from_millis(2_900)).await;
        assert_eq!(frames.len(), 6);
        assert!(frames.iter().all(|frame| frame.socket_text().is_some()));
        assert_eq!(read_times(&reads, "ICPUSDT"), [0, 1_000, 2_000]);
        assert_eq!(read_times(&reads, "ETHUSDT"), [500, 1_500, 2_500]);
    }

    /// The time of each read of `symbol`, in milliseconds.
    fn read_times(reads: &Reads, symbol: &str) -> Vec<u128> {
        let reads = reads.lock().expect("reads");
        reads
            .iter()
            .filter(|(_, read)| read == symbol)
            .map(|(time, _)| time.as_millis())
            .collect()
    }

    /// The budget is per address: one book's refusal stops every book for the pause.
    #[tokio::test(start_paused = true)]
    async fn a_refusal_for_the_rate_stops_every_book_for_the_pause() {
        fn first_icp_read_refused(symbol: &str, before: usize) -> Result<Box<RawValue>, ReadError> {
            if symbol == "ICPUSDT" && before == 0 {
                return Err(refused(StatusCode::TOO_MANY_REQUESTS, None));
            }
            book_reply(symbol, before)
        }
        let (connector, reads) = scripted(first_icp_read_refused);
        let mut conn = connector
            .connect(&url(["ICPUSDT", "ETHUSDT"].into_iter()))
            .await
            .expect("connects");
        let frames = frames_for(&mut conn, Duration::from_millis(31_900)).await;
        // Each book reads once when the pause ends, then in its own place again.
        assert_eq!(read_times(&reads, "ICPUSDT"), [0, 30_000, 31_000]);
        assert_eq!(read_times(&reads, "ETHUSDT"), [30_000, 30_500, 31_500]);
        // The refusal is a REST record; each read after the pause is a text frame.
        assert!(matches!(frames.first(), Some(Frame::Rest(_))));
        assert!(
            frames
                .iter()
                .skip(1)
                .all(|frame| frame.socket_text().is_some())
        );
    }

    /// A session of ICPUSDT's reads that ends after 3 s with no frame.
    fn session(
        connector: ToobitConnector<ScriptedConnector>,
    ) -> Session<ToobitConnector<ScriptedConnector>, VenueHandler> {
        let mut config = session_config();
        config.stream = StreamId::new(Venue::Toobit, MarketKind::Spot);
        config.url = url(["ICPUSDT"].into_iter());
        config.idle_timeout = Duration::from_secs(3);
        let icp = [instrument("ICPUSDT", MarketKind::Spot)];
        let map = InstrumentMap::new(Venue::Toobit, MarketKind::Spot, &icp).expect("a map");
        let handler = VenueHandler::new(map, toobit::decode);
        Session::new(config, connector, handler, MonotonicClock::anchored_at(1))
    }

    #[tokio::test(start_paused = true)]
    async fn only_a_good_read_shows_that_the_connection_lives() {
        let (good, _) = scripted(book_reply);
        let run = run_for(session(good), Duration::from_millis(5_500)).await;
        assert!(!run.alive().is_empty());
        assert_eq!(run.disconnects(), ["shutdown"]);

        let (failing, _) = scripted(|_, _| Err(ReadError::Failed("timeout".to_owned())));
        let run = run_for(session(failing), Duration::from_millis(5_500)).await;
        assert!(run.alive().is_empty(), "a failed read confirms nothing");
        assert!(
            run.disconnects()
                .iter()
                .any(|reason| reason.contains("idle"))
        );
        assert!(run.stats.decode_errors >= 3, "{:?}", run.stats);
    }

    #[tokio::test(start_paused = true)]
    async fn a_longer_pause_holds_and_a_shorter_one_does_not_cut_it() {
        let pause = Pause::default();
        pause.hold(Duration::from_secs(60));
        pause.hold(PAUSE);
        let start = Instant::now();
        assert!(pause.wait().await);
        assert_eq!(start.elapsed(), Duration::from_secs(60));
        assert!(!pause.wait().await);
    }
}
