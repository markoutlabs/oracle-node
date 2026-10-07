//! Recording raw venue frames for replay (SPEC §10).
//!
//! The recorder sits at the transport, under every decoder. What it writes is
//! exactly what the venue sent, with the time it arrived, so a replay drives the
//! real decoders, the real session loop, and the real aggregator with the real
//! input. That is what makes an incident reproducible months later and a
//! constant tunable against a real dislocation rather than a guess.
//!
//! One JSON object per line. Text frames are kept as text. Control frames are
//! not recorded: liveness is the transport's business, not the aggregator's.

use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::clock::MonotonicClock;
use crate::{Connector, Frame, Transport, TransportError};

/// One recorded event on one connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Record {
    /// A connection came up.
    Connect {
        /// Receipt time, unix nanoseconds.
        t: u64,
        /// The endpoint, which identifies the connection on replay.
        url: String,
    },
    /// A text frame arrived.
    Text {
        /// Receipt time, unix nanoseconds.
        t: u64,
        /// The endpoint.
        url: String,
        /// The frame, verbatim.
        text: String,
    },
    /// A binary frame arrived.
    Binary {
        /// Receipt time, unix nanoseconds.
        t: u64,
        /// The endpoint.
        url: String,
        /// The frame, verbatim.
        bytes: Vec<u8>,
    },
    /// The connection ended.
    Close {
        /// Time, unix nanoseconds.
        t: u64,
        /// The endpoint.
        url: String,
        /// Why, as the transport reported it.
        reason: String,
    },
}

impl Record {
    /// The endpoint this record belongs to.
    #[must_use]
    pub fn url(&self) -> &str {
        match self {
            Self::Connect { url, .. }
            | Self::Text { url, .. }
            | Self::Binary { url, .. }
            | Self::Close { url, .. } => url,
        }
    }

    /// When it happened, unix nanoseconds.
    #[must_use]
    pub const fn time_ns(&self) -> u64 {
        match self {
            Self::Connect { t, .. }
            | Self::Text { t, .. }
            | Self::Binary { t, .. }
            | Self::Close { t, .. } => *t,
        }
    }
}

/// Writes records as JSON lines. Cheap to clone; clones share the sink.
#[derive(Clone)]
pub struct Recorder {
    sink: Arc<Mutex<Box<dyn Write + Send>>>,
    clock: MonotonicClock,
}

impl Recorder {
    /// Records into any writer.
    pub fn new(writer: impl Write + Send + 'static) -> Self {
        Self {
            sink: Arc::new(Mutex::new(Box::new(BufWriter::new(writer)))),
            clock: MonotonicClock::new(),
        }
    }

    /// Stamps records with `clock`, so a recording shares the node's clock.
    #[must_use]
    pub fn with_clock(mut self, clock: MonotonicClock) -> Self {
        self.clock = clock;
        self
    }

    /// Records into a file, created or truncated.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the file cannot be created.
    pub fn to_file(path: &Path) -> std::io::Result<Self> {
        Ok(Self::new(std::fs::File::create(path)?))
    }

    fn write(&self, record: &Record) {
        // A full disk must not take the feed down with it, so a failed write is
        // dropped here. The recording is a diagnostic; the prices are not.
        if let Ok(mut sink) = self.sink.lock()
            && let Ok(line) = serde_json::to_string(record)
        {
            let _ = writeln!(sink, "{line}");
            let _ = sink.flush();
        }
    }

    fn now_ns(&self) -> u64 {
        self.clock.now_ns()
    }
}

/// Reads a recording back, in order.
///
/// # Errors
///
/// Returns the I/O or parse error with the offending line number.
pub fn read_records(reader: impl std::io::BufRead) -> Result<Vec<Record>, RecordError> {
    let mut records = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| RecordError::Line {
            line: index.saturating_add(1),
            reason: e.to_string(),
        })?;
        if line.trim().is_empty() {
            continue;
        }
        records.push(serde_json::from_str(&line).map_err(|e| RecordError::Line {
            line: index.saturating_add(1),
            reason: e.to_string(),
        })?);
    }
    Ok(records)
}

/// A recording could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecordError {
    /// One line was unreadable or not a record.
    #[error("recording line {line}: {reason}")]
    Line {
        /// 1-based line number.
        line: usize,
        /// Why.
        reason: String,
    },
}

/// Wraps a connector so every frame its connections receive is recorded.
#[derive(Clone)]
pub struct RecordingConnector<C> {
    inner: C,
    recorder: Recorder,
}

impl<C> RecordingConnector<C> {
    /// Records everything `inner` receives into `recorder`.
    pub const fn new(inner: C, recorder: Recorder) -> Self {
        Self { inner, recorder }
    }
}

impl<C: Connector> Connector for RecordingConnector<C> {
    type Conn = RecordingConn<C::Conn>;

    async fn connect(&self, url: &str) -> Result<Self::Conn, TransportError> {
        let inner = self.inner.connect(url).await?;
        self.recorder.write(&Record::Connect {
            t: self.recorder.now_ns(),
            url: url.to_owned(),
        });
        Ok(RecordingConn {
            inner,
            url: url.to_owned(),
            recorder: self.recorder.clone(),
        })
    }
}

/// A connection whose received frames are recorded.
pub struct RecordingConn<T> {
    inner: T,
    url: String,
    recorder: Recorder,
}

impl<T: Transport> Transport for RecordingConn<T> {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        let received = self.inner.recv().await;
        // Stamped here, a few instructions before the session stamps the
        // observation. The node gives both the same clock, so a replay
        // reproduces the staleness decisions the live node made.
        let t = self.recorder.now_ns();
        let url = self.url.clone();
        match &received {
            Ok(Some(Frame::Text(text))) => self.recorder.write(&Record::Text {
                t,
                url,
                text: text.clone(),
            }),
            Ok(Some(Frame::Binary(bytes))) => self.recorder.write(&Record::Binary {
                t,
                url,
                bytes: bytes.clone(),
            }),
            Ok(Some(_)) => {}
            Ok(None) => self.recorder.write(&Record::Close {
                t,
                url,
                reason: "closed by peer".to_owned(),
            }),
            Err(error) => self.recorder.write(&Record::Close {
                t,
                url,
                reason: error.to_string(),
            }),
        }
        received
    }

    async fn send_text(&mut self, text: String) -> Result<(), TransportError> {
        self.inner.send_text(text).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_as_json_lines() {
        let records = vec![
            Record::Connect {
                t: 1,
                url: "wss://a".to_owned(),
            },
            Record::Text {
                t: 2,
                url: "wss://a".to_owned(),
                text: r#"{"x":1}"#.to_owned(),
            },
            Record::Binary {
                t: 3,
                url: "wss://a".to_owned(),
                bytes: vec![0, 255],
            },
            Record::Close {
                t: 4,
                url: "wss://a".to_owned(),
                reason: "closed by peer".to_owned(),
            },
        ];
        let mut text = String::new();
        for record in &records {
            text.push_str(&serde_json::to_string(record).expect("serialises"));
            text.push('\n');
        }
        text.push('\n');
        assert_eq!(read_records(text.as_bytes()).expect("parses"), records);
        assert!(read_records(b"not json\n".as_slice()).is_err());
    }
}
