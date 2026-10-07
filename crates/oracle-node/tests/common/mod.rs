//! Shared by the tests that run the `oracle-node` binary: the binary, key and
//! passphrase fixtures, and a running node whose log the test reads.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use age::secrecy::SecretString;
use oracle_wire::Signer;
use serde_json::Value;

pub const BINARY: &str = env!("CARGO_BIN_EXE_oracle-node");
/// The line the node logs once it serves.
pub const READY: &str = "serving subscribers";
/// The longest any one step may take.
pub const WAIT: Duration = Duration::from_secs(60);
pub const PASSPHRASE: &str = "correct horse battery staple";

/// Runs the binary to completion.
pub fn run(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .output()
        .expect("the node binary runs")
}

/// An empty, test-specific directory path. Not created.
pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("oracle-node-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Writes a passphrase file next to, not inside, `dir`, so `init --out` still
/// sees an empty target.
pub fn passphrase_file(dir: &Path) -> String {
    let path = dir.with_extension("passphrase");
    std::fs::write(&path, format!("{PASSPHRASE}\n")).expect("writes");
    path.to_str().expect("utf-8").to_owned()
}

pub fn passphrase() -> SecretString {
    SecretString::from(PASSPHRASE.to_owned())
}

pub fn load_key(path: &Path) -> Signer {
    oracle_node::keyfile::load_signer(path, Some(&passphrase())).expect("a valid encrypted key")
}

/// `oracle-node start` on `config`, outside systemd: no journal stream and no
/// notify socket, whatever the test runner inherited.
pub fn start(config: &Path, format: &str) -> Command {
    let mut command = Command::new(BINARY);
    command
        .args(["start", "--log-format", format])
        .arg(config)
        .env_remove("JOURNAL_STREAM")
        .env_remove("NOTIFY_SOCKET")
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    command
}

/// A running node. Its log goes to a file, which stays for a failed run.
pub struct Node {
    child: Child,
    log: PathBuf,
}

impl Node {
    pub fn spawn(mut command: Command, log: PathBuf) -> Self {
        let file = std::fs::File::create(&log).expect("creates the log");
        let child = command.stderr(file).spawn().expect("the node starts");
        Self { child, log }
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The first log line `find` accepts, within `WAIT`.
    pub fn wait_for<T>(&self, what: &str, find: impl Fn(&str) -> Option<T>) -> T {
        let deadline = Instant::now() + WAIT;
        loop {
            let log = self.log();
            if let Some(found) = log.lines().find_map(&find) {
                return found;
            }
            assert!(
                Instant::now() < deadline,
                "the node never logged {what}:\n{log}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn wait(&self, needle: &str) -> String {
        self.wait_for(needle, |line| {
            line.contains(needle).then(|| line.to_owned())
        })
    }

    /// Stops the node with SIGTERM, as systemd does, and returns its log.
    pub fn stop(mut self) -> String {
        let pid = self.child.id().to_string();
        let kill = Command::new("kill").args(["-TERM", &pid]).status();
        assert!(
            kill.is_ok_and(|status| status.success()),
            "kill -TERM {pid}"
        );
        let exit = self.child.wait().expect("exits");
        let log = self.log();
        assert!(exit.success(), "exit {exit}:\n{log}");
        assert!(log.contains("shutting down"), "{log}");
        log
    }
}

impl Drop for Node {
    /// A failed assertion must not leave the node running.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The fields of one JSON log line.
pub fn fields_of(line: &str) -> Option<Value> {
    serde_json::from_str::<Value>(line)
        .ok()?
        .get_mut("fields")
        .map(Value::take)
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free port")
        .port()
}
