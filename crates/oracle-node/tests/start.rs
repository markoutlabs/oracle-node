//! `oracle-node start` as a process: how it logs, and how it stops.
//!
//! The node runs from signed files and a plaintext seeded key, so no canister
//! and no passphrase are involved. The venue connections may fail without a
//! network; nothing here depends on them.
#![cfg(unix)]

use std::io::{BufRead as _, BufReader};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use oracle_wire::{ClientEntry, ClientList, NodeEntry, Quorum, Registry, Signer};

const BINARY: &str = env!("CARGO_BIN_EXE_oracle-node");
const READY: &str = "serving subscribers";
const WAIT: Duration = Duration::from_secs(20);

fn key(seed: u8) -> Signer {
    Signer::from_secret_bytes([seed; 32]).expect("valid key")
}

/// A node directory with a signed registry, a client list, a key, and a config.
fn fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("oracle-start-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("creates");
    let governance = key(0x33);
    let node = key(0x41);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs();

    let registry = Registry::sign(
        &governance,
        1,
        now,
        vec![NodeEntry {
            address: node.address(),
            operator: "test".to_owned(),
            endpoints: vec!["ws://127.0.0.1:1/v2/ws".to_owned()],
            weight: 1,
        }],
        Quorum {
            min_nodes: 1,
            recommended: 1,
        },
    )
    .expect("signs");
    let clients = ClientList::sign(
        &governance,
        1,
        now,
        60,
        vec![ClientEntry {
            address: key(0x51).address(),
            expires_at: now + 3_600,
        }],
    )
    .expect("signs");
    let write = |file: &str, text: &str| std::fs::write(dir.join(file), text).expect("writes");
    write(
        "registry.json",
        &serde_json::to_string(&registry).expect("json"),
    );
    write(
        "clients.json",
        &serde_json::to_string(&clients).expect("json"),
    );
    write("signing.key", &node.to_secret_hex());
    write(
        "config.toml",
        &format!(
            r#"tick_interval_ms = 25

[server]
listen = "127.0.0.1:0"

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
    dir
}

fn start(dir: &Path, format: &str) -> Command {
    let mut command = Command::new(BINARY);
    command
        .args(["start", "--log-format", format])
        .arg(dir.join("config.toml"))
        .env_remove("JOURNAL_STREAM")
        .env_remove("NOTIFY_SOCKET")
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    command
}

fn terminate(child: &Child) {
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill runs");
    assert!(status.success());
}

/// Runs the node until it serves, stops it with SIGTERM, and returns its log.
fn run_until_ready(mut command: Command) -> String {
    let mut child = command.stderr(Stdio::piped()).spawn().expect("starts");
    let stderr = child.stderr.take().expect("piped");
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let mut lines = Vec::new();
    let deadline = Instant::now() + WAIT;
    while !lines.iter().any(|line: &String| line.contains(READY)) {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(line) => lines.push(line),
            Err(_) => {
                let _ = child.kill();
                panic!("the node never served:\n{}", lines.join("\n"));
            }
        }
    }
    terminate(&child);
    let status = child.wait().expect("exits");
    reader.join().expect("reader ends");
    lines.extend(rx.try_iter());
    let log = lines.join("\n");
    assert!(status.success(), "exit {status}:\n{log}");
    assert!(log.contains("shutting down"), "{log}");
    log
}

#[test]
fn sigterm_stops_the_node_cleanly_in_every_format() {
    let dir = fixture("formats");

    let plain = run_until_ready(start(&dir, "plain"));
    assert!(
        !plain.contains('\u{1b}'),
        "colour codes in a pipe:\n{plain}"
    );
    assert!(plain.contains("signal=\"SIGTERM\""), "{plain}");

    let journald = run_until_ready(start(&dir, "journald"));
    for line in journald.lines() {
        assert!(
            ["<3>", "<4>", "<6>", "<7>"]
                .iter()
                .any(|prefix| line.starts_with(prefix)),
            "{line}"
        );
    }

    let json = run_until_ready(start(&dir, "json"));
    for line in json.lines() {
        let value: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}"));
        assert!(value.get("level").is_some(), "{line}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// systemd names the journal stream in `JOURNAL_STREAM`. Only that exact
/// stream gets journald lines; an inherited variable for another stream does not.
#[test]
fn auto_picks_journald_only_for_the_journal_stream() {
    let dir = fixture("auto");
    let log_path = dir.join("node.log");
    let first_line = |journal_stream: &dyn Fn(&Path) -> String| {
        let log = std::fs::File::create(&log_path).expect("creates");
        let mut command = start(&dir, "auto");
        command
            .env("JOURNAL_STREAM", journal_stream(&log_path))
            .stderr(log);
        let child = command.spawn().expect("starts");
        let deadline = Instant::now() + WAIT;
        while !std::fs::read_to_string(&log_path)
            .unwrap_or_default()
            .contains(READY)
        {
            assert!(Instant::now() < deadline, "the node never served");
            std::thread::sleep(Duration::from_millis(50));
        }
        terminate(&child);
        let mut child = child;
        child.wait().expect("exits");
        std::fs::read_to_string(&log_path)
            .expect("readable")
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned()
    };

    let journal = first_line(&|path| {
        let meta = std::fs::metadata(path).expect("exists");
        format!("{}:{}", meta.dev(), meta.ino())
    });
    assert!(journal.starts_with("<6>"), "{journal}");
    let inherited = first_line(&|_| "1:1".to_owned());
    assert!(
        inherited.starts_with(|c: char| c.is_ascii_digit()),
        "a plain line starts with its timestamp: {inherited}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `Type=notify`: systemd hears when the node serves and when it stops.
#[test]
fn systemd_hears_ready_and_stopping() {
    let dir = fixture("notify");
    // Unix socket paths are short; the temp dir on macOS is not.
    let socket_path = PathBuf::from(format!("/tmp/oracle-notify-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket_path);
    let socket = UnixDatagram::bind(&socket_path).expect("binds");
    socket.set_read_timeout(Some(WAIT)).expect("sets a timeout");

    let mut command = start(&dir, "plain");
    command
        .env("NOTIFY_SOCKET", &socket_path)
        .stderr(Stdio::null());
    let mut child = command.spawn().expect("starts");
    let mut messages = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !messages.iter().any(|m: &String| m.contains("READY=1")) {
        let Ok(len) = socket.recv(&mut buffer) else {
            let _ = child.kill();
            panic!("no READY=1; got {messages:?}");
        };
        messages.push(String::from_utf8_lossy(buffer.get(..len).unwrap_or_default()).into_owned());
    }
    terminate(&child);
    while !messages.iter().any(|m| m.contains("STOPPING=1")) {
        let len = socket.recv(&mut buffer).expect("STOPPING=1 arrives");
        messages.push(String::from_utf8_lossy(buffer.get(..len).unwrap_or_default()).into_owned());
    }
    assert!(child.wait().expect("exits").success());
    assert!(
        messages
            .iter()
            .any(|m| m.contains("STATUS=fetching the registry")),
        "{messages:?}"
    );
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir_all(&dir);
}
