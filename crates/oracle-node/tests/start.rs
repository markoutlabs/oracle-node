//! `oracle-node start` as a process: how it logs, and how it stops.
//!
//! The node runs from signed files and a plaintext seeded key, so no canister
//! and no passphrase are involved. The venue connections may fail without a
//! network; nothing here depends on them.
#![cfg(unix)]

mod common;

use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use oracle_wire::{ClientEntry, ClientList, NodeEntry, Quorum, Registry, Signer};

use common::{Node, Scratch, WAIT};

/// Signs the registry and the client list.
const GOVERNANCE_SEED: u8 = 0x33;
/// The node under test.
const NODE_SEED: u8 = 0x41;
/// A node that a registry lists in place of the node under test.
const OTHER_NODE_SEED: u8 = 0x42;
/// The one listed client.
const CLIENT_SEED: u8 = 0x51;
/// The client stays listed past the end of every test.
const CLIENT_LIFETIME_SECS: u64 = 3_600;
/// The default broadcast-key epoch of a client list.
const EPOCH_SECS: u64 = 60;
/// The syslog priorities the node logs at: error, warning, info and debug.
const JOURNALD_PRIORITIES: [&str; 4] = ["<3>", "<4>", "<6>", "<7>"];
/// A fast pipeline tick, so a test does not wait on the default one.
const TICK_MS: u64 = 25;
/// The registry version that each fixture starts with.
const FIRST_REGISTRY: u64 = 1;
/// What `systemctl status` shows while the registry does not list the node.
const WAITING: &str = "STATUS=waiting for governance";
/// A short `WatchdogSec=`, so a test sees several pings.
const WATCHDOG: Duration = Duration::from_millis(200);
/// Larger than any notify message that the node sends.
const DATAGRAM_MAX: usize = 4_096;

fn key(seed: u8) -> Signer {
    Signer::from_secret(&[seed; 32].into()).expect("valid key")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

/// A node directory with a signed registry, a client list, a key, and a config.
struct Fixture {
    dir: Scratch,
    port: u16,
}

impl Fixture {
    fn listed(name: &str) -> Self {
        Self::new(name, &key(NODE_SEED))
    }

    /// A node that the registry does not list yet: it lists another node.
    fn unlisted(name: &str) -> Self {
        Self::new(name, &key(OTHER_NODE_SEED))
    }

    fn new(name: &str, listed: &Signer) -> Self {
        let dir = common::scratch(name);
        std::fs::create_dir_all(&dir).expect("creates");
        let port = common::free_port();
        let governance = key(GOVERNANCE_SEED);
        let now = now();
        write_registry(&dir, FIRST_REGISTRY, listed);
        let clients = ClientList::sign(
            &governance,
            1,
            now,
            EPOCH_SECS,
            vec![ClientEntry {
                address: key(CLIENT_SEED).address(),
                expires_at: now + CLIENT_LIFETIME_SECS,
            }],
        )
        .expect("signs");
        let write = |file: &str, text: &str| std::fs::write(dir.join(file), text).expect("writes");
        write(
            "clients.json",
            &serde_json::to_string(&clients).expect("json"),
        );
        write("signing.key", &key(NODE_SEED).to_secret_hex());
        write(
            "config.toml",
            &format!(
                r#"tick_interval_ms = {TICK_MS}

[server]
listen = "127.0.0.1:{port}"

[signing]
key_file = "{dir}/signing.key"

[registry]
path = "{dir}/registry.json"
governance_address = "{governance}"

[clients]
path = "{dir}/clients.json"

[[feeds]]
symbol = "CRYPTO.BTC/USDT"
min_sources = 1
sources = [{{ venue = "binance", market = "spot", symbol = "BTCUSDT" }}]
"#,
                dir = dir.display(),
                governance = governance.address(),
            ),
        );
        Self { dir, port }
    }

    /// Governance lists the node under test in the next registry version.
    fn list_the_node(&self) {
        write_registry(&self.dir, FIRST_REGISTRY + 1, &key(NODE_SEED));
    }

    fn start(&self, format: &str) -> Command {
        common::start(&self.dir.join("config.toml"), format)
    }

    /// The node in plain format, with `systemd` as its notify socket.
    fn under_systemd(&self, systemd: &NotifySocket) -> Command {
        let mut command = self.start("plain");
        command.env("NOTIFY_SOCKET", &systemd.path);
        command
    }

    fn spawn(&self, command: Command) -> Node {
        Node::spawn(command, self.dir.join("node.log"))
    }

    /// Runs the node until it serves, stops it with SIGTERM, and returns its log.
    fn run_until_serving(&self, format: &str) -> String {
        let node = self.spawn(self.start(format));
        node.serving(self.port);
        node.stop()
    }

    /// The first line the node logs in `auto` format, with `JOURNAL_STREAM`
    /// set to what `stream` makes of the log file.
    fn first_auto_line(&self, stream: impl FnOnce(&Path) -> String) -> String {
        let log = self.dir.join("node.log");
        // The stream id is the file's inode; `Node::spawn` truncates in place.
        std::fs::write(&log, "").expect("creates");
        let mut command = self.start("auto");
        command.env("JOURNAL_STREAM", stream(&log));
        let node = self.spawn(command);
        node.serving(self.port);
        node.stop().lines().next().unwrap_or_default().to_owned()
    }
}

/// Writes `dir/registry.json`, signed by governance, listing `listed`.
fn write_registry(dir: &Path, version: u64, listed: &Signer) {
    let registry = Registry::sign(
        &key(GOVERNANCE_SEED),
        version,
        now(),
        vec![NodeEntry {
            address: listed.address(),
            endpoints: vec!["ws://127.0.0.1:1/v2/ws".to_owned()],
            weight: 1,
        }],
        Quorum {
            min_nodes: 1,
            recommended: 1,
        },
    )
    .expect("signs");
    std::fs::write(
        dir.join("registry.json"),
        serde_json::to_string(&registry).expect("json"),
    )
    .expect("writes");
}

/// The socket that systemd reads for `Type=notify`.
struct NotifySocket {
    socket: UnixDatagram,
    path: PathBuf,
    messages: Vec<String>,
}

impl NotifySocket {
    /// A socket for the test called `name`; the tests of this file run at once.
    fn bind(name: &str) -> Self {
        // Unix socket paths are short; the temp dir on macOS is not.
        let path = PathBuf::from(format!(
            "/tmp/oracle-notify-{}-{name}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let socket = UnixDatagram::bind(&path).expect("binds");
        socket.set_read_timeout(Some(WAIT)).expect("sets a timeout");
        Self {
            socket,
            path,
            messages: Vec::new(),
        }
    }

    /// Reads until a message after the first `skip` holds `state`, and returns its index.
    fn until_after(&mut self, skip: usize, state: &str) -> usize {
        let mut buffer = [0_u8; DATAGRAM_MAX];
        loop {
            let found = self
                .messages
                .iter()
                .skip(skip)
                .position(|message| message.contains(state));
            if let Some(found) = found {
                return skip + found;
            }
            let len = self
                .socket
                .recv(&mut buffer)
                .unwrap_or_else(|_| panic!("no {state}; got {:?}", self.messages));
            self.messages
                .push(String::from_utf8_lossy(buffer.get(..len).unwrap_or_default()).into_owned());
        }
    }

    /// Reads until a message holds `state`, and returns its index.
    fn until(&mut self, state: &str) -> usize {
        self.until_after(0, state)
    }

    /// Every message so far, queued ones too: the node has stopped.
    fn all(&mut self) -> &[String] {
        let mut buffer = [0_u8; DATAGRAM_MAX];
        self.socket
            .set_nonblocking(true)
            .expect("sets non-blocking");
        while let Ok(len) = self.socket.recv(&mut buffer) {
            self.messages
                .push(String::from_utf8_lossy(buffer.get(..len).unwrap_or_default()).into_owned());
        }
        &self.messages
    }
}

impl Drop for NotifySocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// `init` starts a node before governance lists it. The node waits, and a
/// signal stops it cleanly while it waits.
#[test]
fn an_unlisted_node_waits_for_governance() {
    let fixture = Fixture::unlisted("unlisted");
    let mut systemd = NotifySocket::bind("unlisted");
    let node = fixture.spawn(fixture.under_systemd(&systemd));
    systemd.until(WAITING);
    assert!(common::health(fixture.port).is_none(), "it serves");
    node.stop();
    let messages = systemd.all();
    assert!(
        !messages.iter().any(|message| message.contains("READY=1")),
        "{messages:?}"
    );
}

/// The node serves at its next check after governance lists it.
#[test]
fn a_waiting_node_serves_once_the_registry_lists_it() {
    let fixture = Fixture::unlisted("listed-later");
    let mut systemd = NotifySocket::bind("listed-later");
    let node = fixture.spawn(fixture.under_systemd(&systemd));
    let waiting = systemd.until(WAITING);
    fixture.list_the_node();
    node.serving(fixture.port);
    systemd.until_after(waiting, "READY=1");
    node.stop();
}

#[test]
fn sigterm_stops_a_node_that_logs_plain_lines_cleanly() {
    let log = Fixture::listed("plain").run_until_serving("plain");
    assert!(!log.contains('\u{1b}'), "colour codes in a pipe:\n{log}");
    assert!(log.contains("signal=\"SIGTERM\""), "{log}");
}

#[test]
fn sigterm_stops_a_node_that_logs_journald_lines_cleanly() {
    let log = Fixture::listed("journald").run_until_serving("journald");
    for line in log.lines() {
        assert!(
            JOURNALD_PRIORITIES
                .iter()
                .any(|prefix| line.starts_with(prefix)),
            "{line}"
        );
    }
}

#[test]
fn sigterm_stops_a_node_that_logs_json_lines_cleanly() {
    let log = Fixture::listed("json").run_until_serving("json");
    for line in log.lines() {
        let value: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}"));
        assert!(value.get("level").is_some(), "{line}");
    }
}

/// systemd names the journal stream in `JOURNAL_STREAM` as `device:inode`.
#[test]
fn auto_picks_journald_for_the_journal_stream() {
    let line = Fixture::listed("auto-journal").first_auto_line(|log| {
        let meta = std::fs::metadata(log).expect("exists");
        format!("{}:{}", meta.dev(), meta.ino())
    });
    assert!(line.starts_with("<6>"), "{line}");
}

/// A child inherits `JOURNAL_STREAM`, so the variable alone does not mean
/// that stderr is the journal.
#[test]
fn auto_picks_plain_lines_for_an_inherited_journal_stream() {
    let line = Fixture::listed("auto-inherited").first_auto_line(|_| "1:1".to_owned());
    assert!(
        line.starts_with(|c: char| c.is_ascii_digit()),
        "a plain line starts with its timestamp: {line}"
    );
}

/// `Type=notify`: systemd hears when the node serves and when it stops.
#[test]
fn systemd_hears_ready_and_stopping() {
    let fixture = Fixture::listed("notify");
    let mut systemd = NotifySocket::bind("notify");
    let node = fixture.spawn(fixture.under_systemd(&systemd));
    let fetching = systemd.until("STATUS=fetching the registry");
    let ready = systemd.until_after(fetching, "READY=1");
    // The datagrams queue on the socket, so the node may stop before they are read.
    node.stop();
    systemd.until_after(ready, "STOPPING=1");
}

/// `WatchdogSec=` in the unit: the pipeline pings systemd while the node serves.
#[test]
fn systemd_hears_the_watchdog_while_the_node_serves() {
    let fixture = Fixture::listed("watchdog");
    let mut systemd = NotifySocket::bind("watchdog");
    let mut command = fixture.under_systemd(&systemd);
    command.env("WATCHDOG_USEC", WATCHDOG.as_micros().to_string());
    let node = fixture.spawn(command);
    let ready = systemd.until("READY=1");
    let first = systemd.until_after(ready, "WATCHDOG=1");
    systemd.until_after(first + 1, "WATCHDOG=1");
    node.stop();
}
