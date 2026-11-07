//! Shared by the tests that run the `oracle-node` binary: the binary, key and
//! passphrase fixtures, scratch directories, and a running node that a test
//! waits on through `/v2/health` or its log.
#![allow(dead_code)]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use age::secrecy::SecretString;
use oracle_wire::Signer;
use serde_json::Value;

pub const BINARY: &str = env!("CARGO_BIN_EXE_oracle-node");
/// The longest any one step may take.
pub const WAIT: Duration = Duration::from_secs(60);
/// How often a wait checks again.
pub const POLL: Duration = Duration::from_millis(50);
pub const PASSPHRASE: &str = "correct horse battery staple";

/// Runs the binary to completion.
pub fn run(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .output()
        .expect("the node binary runs")
}

/// Calls `condition` until it returns `Some`, for at most `timeout`.
pub fn eventually<T>(timeout: Duration, mut condition: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(found) = condition() {
            return Some(found);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(POLL);
    }
}

/// A test-specific directory path in the temp dir, not created. A passing test
/// removes it; a failed one leaves it for a look at the files.
pub struct Scratch(PathBuf);

impl Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// An empty [`Scratch`] directory path for the test called `name`.
pub fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("oracle-node-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    Scratch(dir)
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

/// `oracle-node start` on `config`, outside systemd: no journal stream, no
/// notify socket and no watchdog, whatever the test runner inherited.
pub fn start(config: &Path, format: &str) -> Command {
    let mut command = Command::new(BINARY);
    command
        .args(["start", "--log-format", format])
        .arg(config)
        .env_remove("JOURNAL_STREAM")
        .env_remove("NOTIFY_SOCKET")
        .env_remove("WATCHDOG_USEC")
        .env_remove("WATCHDOG_PID")
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    command
}

/// The JSON body of the node's `GET path` on `port`, or `None` while the node
/// does not serve it.
pub fn get_json(port: u16, path: &str) -> Option<Value> {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    socket.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    socket.read_to_string(&mut response).ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    head.starts_with("HTTP/1.1 200 ")
        .then(|| serde_json::from_str(body).ok())
        .flatten()
}

/// The node's `/v2/health`: its address, feed count and feed set version.
pub fn health(port: u16) -> Option<Value> {
    get_json(port, "/v2/health")
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
        eventually(WAIT, || self.log().lines().find_map(&find))
            .unwrap_or_else(|| panic!("the node never logged {what}:\n{}", self.log()))
    }

    pub fn wait(&self, needle: &str) -> String {
        self.wait_for(needle, |line| {
            line.contains(needle).then(|| line.to_owned())
        })
    }

    /// Waits until the node answers `/v2/health` on `port`, and returns the body.
    pub fn serving(&self, port: u16) -> Value {
        self.health_until(port, "served", |_| true)
    }

    /// Waits until the node's `/v2/health` on `port` passes `done`, and returns the body.
    pub fn health_until(&self, port: u16, what: &str, done: impl Fn(&Value) -> bool) -> Value {
        eventually(WAIT, || health(port).filter(&done))
            .unwrap_or_else(|| panic!("the node never {what} on port {port}:\n{}", self.log()))
    }

    /// Stops the node with SIGTERM, as systemd does, and returns its log. Exit 0
    /// proves the clean shutdown: SIGTERM without a handler kills the process.
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
