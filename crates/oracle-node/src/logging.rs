//! Log output: one format for each place the lines end up.
//!
//! Logs go to stderr, the same stream as a fatal error at exit. `auto` picks
//! the format from that stream:
//!
//! | stderr | format |
//! |---|---|
//! | the journal, under systemd | `journald`: `<N>` priority, no time, no colour |
//! | a terminal | `pretty`: local time, colour, compact |
//! | anything else | `plain`: UTC time, no colour |
//!
//! `RUST_LOG` filters as usual.

use std::fmt;

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::{self, FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::{FmtContext, time::OffsetTime};
use tracing_subscriber::registry::LookupSpan;

/// A global subscriber is already installed.
#[derive(Debug, thiserror::Error)]
#[error("cannot set up logging: {0}")]
pub struct LoggingError(Box<dyn std::error::Error + Send + Sync>);

/// How log lines are written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum LogFormat {
    /// Chosen from where stderr goes.
    #[default]
    Auto,
    /// For a person at a terminal.
    Pretty,
    /// For a file or a pipe.
    Plain,
    /// For the systemd journal.
    Journald,
    /// One JSON object per line, for log shippers.
    Json,
}

/// What `auto` looks at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Destination {
    /// stderr is a terminal.
    pub terminal: bool,
    /// stderr is the journal stream systemd connected.
    pub journal: bool,
}

impl Destination {
    /// Inspects this process's stderr.
    #[must_use]
    pub fn stderr() -> Self {
        use std::io::IsTerminal as _;
        Self {
            terminal: std::io::stderr().is_terminal(),
            journal: stderr_is_journal(),
        }
    }
}

impl LogFormat {
    /// Resolves `auto` for `destination`. Other formats stay as they are.
    #[must_use]
    pub const fn resolve(self, destination: Destination) -> Self {
        match self {
            Self::Auto if destination.journal => Self::Journald,
            Self::Auto if destination.terminal => Self::Pretty,
            Self::Auto => Self::Plain,
            other => other,
        }
    }
}

/// Installs the global subscriber, writing to stderr. Returns the format in use.
///
/// Call it before the async runtime starts: the local UTC offset for `pretty`
/// can only be read while the process has one thread.
///
/// # Errors
///
/// Returns [`LoggingError`] if a global subscriber is already installed.
pub fn init(format: LogFormat, default_filter: &str) -> Result<LogFormat, LoggingError> {
    let resolved = format.resolve(Destination::stderr());
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    match resolved {
        LogFormat::Pretty => {
            let offset = time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
            builder
                .compact()
                .with_target(false)
                .with_timer(OffsetTime::new(
                    offset,
                    time::macros::format_description!("[hour]:[minute]:[second]"),
                ))
                .try_init()
        }
        LogFormat::Journald => builder
            .with_ansi(false)
            .event_format(journald_format())
            .try_init(),
        LogFormat::Json => builder.json().try_init(),
        LogFormat::Auto | LogFormat::Plain => builder.with_ansi(false).try_init(),
    }
    .map_err(LoggingError)?;
    Ok(resolved)
}

/// The line format under systemd: the journal adds the time, the unit and the
/// pid, so the line carries only the level, the message and the fields.
fn journald_format() -> Prioritized<format::Format<format::Full, ()>> {
    Prioritized(format().without_time().with_target(false))
}

fn format() -> format::Format {
    format::Format::default()
}

/// Prefixes each line with journald's `<N>` syslog priority, so
/// `journalctl -p warning` filters by level.
///
/// A deliberate exception to using a crate: tracing-journald writes the native
/// journal protocol, which hides the fields from the default `journalctl` view.
pub struct Prioritized<F>(F);

impl<S, N, F> FormatEvent<S, N> for Prioritized<F>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
    F: FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        write!(writer, "<{}>", priority(*event.metadata().level()))?;
        self.0.format_event(ctx, writer, event)
    }
}

fn priority(level: Level) -> u8 {
    if level == Level::ERROR {
        3
    } else if level == Level::WARN {
        4
    } else if level == Level::INFO {
        6
    } else {
        7
    }
}

/// `true` if stderr is the stream systemd connected to the journal.
///
/// `JOURNAL_STREAM` is inherited by children, so a shell started from a
/// journald-logged session has it too. Only a matching device and inode prove
/// that this stream is the journal. A deliberate exception to using a crate:
/// libsystemd is too heavy for one comparison.
#[cfg(unix)]
fn stderr_is_journal() -> bool {
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::MetadataExt as _;

    let Ok(stream) = std::env::var("JOURNAL_STREAM") else {
        return false;
    };
    let Ok(fd) = std::io::stderr().as_fd().try_clone_to_owned() else {
        return false;
    };
    std::fs::File::from(fd)
        .metadata()
        .is_ok_and(|meta| journal_matches(&stream, meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
const fn stderr_is_journal() -> bool {
    false
}

/// `true` if `journal_stream`, `JOURNAL_STREAM`'s `device:inode`, names this stream.
#[must_use]
pub fn journal_matches(journal_stream: &str, device: u64, inode: u64) -> bool {
    journal_stream.split_once(':').is_some_and(|(dev, ino)| {
        dev.parse::<u64>().is_ok_and(|dev| dev == device)
            && ino.parse::<u64>().is_ok_and(|ino| ino == inode)
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn auto_follows_the_destination() {
        let at = |terminal, journal| LogFormat::Auto.resolve(Destination { terminal, journal });
        assert_eq!(at(false, false), LogFormat::Plain);
        assert_eq!(at(true, false), LogFormat::Pretty);
        assert_eq!(at(false, true), LogFormat::Journald);
        assert_eq!(at(true, true), LogFormat::Journald);
        let terminal = Destination {
            terminal: true,
            journal: false,
        };
        assert_eq!(LogFormat::Json.resolve(terminal), LogFormat::Json);
        assert_eq!(LogFormat::Plain.resolve(terminal), LogFormat::Plain);
    }

    #[test]
    fn the_journal_stream_must_name_this_stream() {
        assert!(journal_matches("8:1234", 8, 1234));
        for other in ["8:1235", "9:1234", "8", "", "x:y", "8:1234:5"] {
            assert!(!journal_matches(other, 8, 1234), "{other}");
        }
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("not poisoned")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn journald_lines_carry_the_priority_and_nothing_journald_adds() {
        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .event_format(journald_format())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(stream = "binance:spot", "e");
            tracing::warn!("w");
            tracing::info!(client = "0xc0", reason = "Revoked", "client session closed");
            tracing::debug!("d");
            tracing::trace!("t");
        });

        let text =
            String::from_utf8(capture.0.lock().expect("not poisoned").clone()).expect("utf-8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines,
            [
                "<3>ERROR e stream=\"binance:spot\"",
                "<4> WARN w",
                "<6> INFO client session closed client=\"0xc0\" reason=\"Revoked\"",
                "<7>DEBUG d",
                "<7>TRACE t",
            ]
        );
    }
}
