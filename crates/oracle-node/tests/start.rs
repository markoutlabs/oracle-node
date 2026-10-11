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

use oracle_wire::{ClientEntry, ClientList, NodeEntry, Quorum, Registry, Signer};

use common::{Node, READY, WAIT};

fn key(seed: u8) -> Signer {
    Signer::from_secret_bytes([seed; 32]).expect("valid key")
}

/// A node directory with a signed registry, a client list, a key, and a config.
fn fixture(name: &str) -> PathBuf {
    fixture_listing(name, &key(0x41))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

/// Writes `dir/registry.json`, signed by governance, listing `listed`.
fn write_registry(dir: &Path, version: u64, listed: &Signer) {
    let registry = Registry::sign(
        &key(0x33),
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

/// As [`fixture`], with a registry that lists `listed` rather than the node.
fn fixture_listing(name: &str, listed: &Signer) -> PathBuf {
    let dir = common::scratch(name);
    std::fs::create_dir_all(&dir).expect("creates");
    let governance = key(0x33);
    let node = key(0x41);
    let now = now();
    write_registry(&dir, 1, listed);
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
    common::start(&dir.join("config.toml"), format)
}

/// Runs the node until it serves, stops it with SIGTERM, and returns its log.
fn run_until_ready(dir: &Path, format: &str) -> String {
    let node = Node::spawn(start(dir, format), dir.join("node.log"));
    node.wait(READY);
    node.stop()
}

/// `init` starts a node before governance lists it. The node waits, and a
/// signal stops it cleanly while it waits.
#[test]
fn an_unlisted_node_waits_for_governance() {
    let dir = fixture_listing("unlisted", &key(0x42));
    let node = Node::spawn(start(&dir, "plain"), dir.join("node.log"));
    node.wait("waiting for governance to add it");
    let log = node.stop();
    assert!(!log.contains(READY), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The node serves at its next check after governance lists it.
#[test]
fn a_waiting_node_serves_once_the_registry_lists_it() {
    let dir = fixture_listing("listed-later", &key(0x42));
    let node = Node::spawn(start(&dir, "plain"), dir.join("node.log"));
    node.wait("waiting for governance to add it");
    write_registry(&dir, 2, &key(0x41));
    node.wait("the registry lists this node");
    node.wait(READY);
    node.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sigterm_stops_the_node_cleanly_in_every_format() {
    let dir = fixture("formats");

    let plain = run_until_ready(&dir, "plain");
    assert!(
        !plain.contains('\u{1b}'),
        "colour codes in a pipe:\n{plain}"
    );
    assert!(plain.contains("signal=\"SIGTERM\""), "{plain}");

    let journald = run_until_ready(&dir, "journald");
    for line in journald.lines() {
        assert!(
            ["<3>", "<4>", "<6>", "<7>"]
                .iter()
                .any(|prefix| line.starts_with(prefix)),
            "{line}"
        );
    }

    let json = run_until_ready(&dir, "json");
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
        // The stream id is the file's inode; `Node::spawn` truncates in place.
        std::fs::write(&log_path, "").expect("creates");
        let mut command = start(&dir, "auto");
        command.env("JOURNAL_STREAM", journal_stream(&log_path));
        let node = Node::spawn(command, log_path.clone());
        node.wait(READY);
        node.stop().lines().next().unwrap_or_default().to_owned()
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
    command.env("NOTIFY_SOCKET", &socket_path);
    let node = Node::spawn(command, dir.join("node.log"));
    let mut messages = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !messages.iter().any(|m: &String| m.contains("READY=1")) {
        let len = socket
            .recv(&mut buffer)
            .unwrap_or_else(|_| panic!("no READY=1; got {messages:?}"));
        messages.push(String::from_utf8_lossy(buffer.get(..len).unwrap_or_default()).into_owned());
    }
    // The datagrams queue on the socket, so the node may stop before they are read.
    node.stop();
    while !messages.iter().any(|m| m.contains("STOPPING=1")) {
        let len = socket.recv(&mut buffer).expect("STOPPING=1 arrives");
        messages.push(String::from_utf8_lossy(buffer.get(..len).unwrap_or_default()).into_owned());
    }
    assert!(
        messages
            .iter()
            .any(|m| m.contains("STATUS=fetching the registry")),
        "{messages:?}"
    );
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir_all(&dir);
}
