//! The `oracle-node` command line.
//!
//! Driven as a subprocess rather than by calling into the library, because the
//! things worth pinning down here are properties of the binary: what it writes
//! to stdout, what it refuses to write to stdout, and what it exits with.

mod common;

use std::path::Path;
use std::process::{Command, Output};

use common::{BINARY, Scratch, load_key, passphrase, passphrase_file, run, scratch};

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A secret seed or key in hex: 32 bytes.
const SECRET_HEX_LEN: usize = 64;
/// What clap exits with for a usage error.
const EXIT_USAGE: i32 = 2;
/// The permission bits of the group and of others.
const NOT_OWNER: u32 = 0o077;

/// A canister and its governance address, standing in for the mainnet
/// deployment until there is one.
const NETWORK: [&str; 4] = [
    "--canister",
    "uxrrr-q7777-77774-qaaaq-cai",
    "--governance",
    "0x5CbDd86a2FA8Dc4bDdd8a8f69dBa48572EeC07FB",
];

fn init_out(dir: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["init", "--out", dir.to_str().expect("utf-8")];
    args.extend(NETWORK);
    args.extend(extra);
    run(&args)
}

/// A node directory that `init --out` wrote, with a passphrase file beside it.
struct Initialised {
    dir: Scratch,
    passphrase_file: String,
    stdout: String,
}

/// Runs `init --out` into a new scratch directory. Panics if `init` fails.
fn initialised(name: &str) -> Initialised {
    let dir = scratch(name);
    let passphrase_file = passphrase_file(&dir);
    let output = init_out(&dir, &["--passphrase-file", &passphrase_file]);
    assert!(output.status.success(), "{}", stderr(&output));
    Initialised {
        dir,
        passphrase_file,
        stdout: stdout(&output),
    }
}

fn rotate(node: &Initialised, extra: &[&str]) -> Output {
    let mut args = vec!["rotate", "--dir", node.dir.to_str().expect("utf-8")];
    args.extend(extra);
    run(&args)
}

/// Counts secret-length hex runs, which is what a leaked secret looks like. The
/// ed25519 line holds a public key of the same shape, so it is left out.
fn secret_like_strings(text: &str) -> usize {
    text.lines()
        .filter(|line| !line.contains("ed25519"))
        .flat_map(|line| line.split(|c: char| !c.is_ascii_hexdigit()))
        .filter(|word| word.len() == SECRET_HEX_LEN)
        .count()
}

/// The ed25519 public key the seed in `path` derives.
fn publisher_of(path: &std::path::Path) -> String {
    let keys = oracle_node::keyfile::load_keys(path, Some(&passphrase())).expect("loads");
    keys.publisher
        .as_ref()
        .map(oracle_node::seed::publisher_hex)
        .expect("a seed derives an ed25519 key")
}

/// `cargo test` gives the child a pipe for stdout, as `| tee`, CI or Ansible do.
#[test]
fn init_refuses_to_print_the_secret_when_stdout_is_not_a_terminal() {
    let output = run(&["init"]);
    assert!(!output.status.success());
    let text = stdout(&output);
    assert_eq!(
        secret_like_strings(&text),
        0,
        "a secret in the pipe:\n{text}"
    );
    let stderr = stderr(&output);
    assert!(stderr.contains("--print-secret"), "{stderr}");
    assert!(stderr.contains("--out DIR"), "{stderr}");
}

#[test]
fn init_prints_the_key_and_the_registry_entry() {
    let output = run(&[
        "init",
        "--print-secret",
        "--endpoint",
        "wss://eu1.example/v2/ws",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);

    assert_eq!(
        secret_like_strings(&text),
        1,
        "expected exactly the node's secret:\n{text}"
    );

    // The registry entry is the thing the operator has to hand onwards.
    let entry = text
        .split_once("Send to governance")
        .map(|(_, rest)| rest)
        .expect("the entry must be printed");
    let start = entry.find('{').expect("json object");
    // Stops at the end of the first value, so the guidance printed after it does
    // not read as trailing garbage.
    let parsed: oracle_wire::NodeEntry = serde_json::Deserializer::from_str(&entry[start..])
        .into_iter()
        .next()
        .expect("an entry follows")
        .expect("a valid registry entry");
    assert_eq!(parsed.endpoints, ["wss://eu1.example/v2/ws"]);
    assert!(
        text.contains(&parsed.address.to_checksummed()),
        "the entry must list the address shown"
    );
}

/// Two runs must never produce the same node. A key-generation path that seeded
/// itself from the clock, or from a constant, would pass every other test here.
#[test]
fn init_generates_a_different_key_every_time() {
    let first = stdout(&run(&["init", "--print-secret"]));
    let second = stdout(&run(&["init", "--print-secret"]));
    assert_ne!(first, second);
}

/// The point of `--out` is that the secrets go to 0600 files instead of into
/// terminal scrollback and shell history.
#[test]
fn init_with_out_writes_files_and_prints_no_secrets() {
    let Initialised {
        dir, stdout: text, ..
    } = initialised("out");
    assert_eq!(
        secret_like_strings(&text),
        0,
        "--out must keep secrets off stdout:\n{text}"
    );

    for name in ["signing.key", "node-entry.json", "config.toml"] {
        assert!(dir.join(name).is_file(), "{name} was not written");
    }
    assert!(!dir.join("identity.key").exists(), "a node has one key");

    // At rest the key is an age file. The hex never touches the disk.
    let on_disk = std::fs::read_to_string(dir.join("signing.key")).expect("readable");
    assert!(oracle_node::keyfile::is_encrypted(&on_disk));
    assert_eq!(secret_like_strings(&on_disk), 0, "plaintext hex on disk");
    // The written key is the one the node will load.
    let signer = load_key(&dir.join("signing.key"));
    let entry: oracle_wire::NodeEntry = serde_json::from_str(
        &std::fs::read_to_string(dir.join("node-entry.json")).expect("readable"),
    )
    .expect("a valid entry");
    assert_eq!(entry.address, signer.address());
    let publisher = publisher_of(&dir.join("signing.key"));
    assert!(
        text.contains(&publisher),
        "init prints the ed25519 key it wrote:\n{text}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(dir.join("signing.key"))
            .expect("exists")
            .permissions()
            .mode();
        assert_eq!(mode & NOT_OWNER, 0, "the key is readable by others");
    }
}

/// A rotation produces a new key beside the live one, never over it, and the
/// printed canister call names the live address and the new one.
#[test]
fn rotate_writes_the_next_key_beside_the_live_one() {
    let node = initialised("rotate");
    let live_before = std::fs::read_to_string(node.dir.join("signing.key")).expect("readable");

    // No --passphrase-file: rotate falls back to the config's passphrase_file.
    let output = rotate(&node, &["--canister", "aaaaa-aa"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert_eq!(
        secret_like_strings(&text),
        0,
        "rotate must keep secrets off stdout:\n{text}"
    );
    let publisher = publisher_of(&node.dir.join("signing.key.next"));
    assert!(
        text.contains(&publisher),
        "rotate prints the new ed25519 key:\n{text}"
    );
    let live = load_key(&node.dir.join("signing.key"));

    let live_after = std::fs::read_to_string(node.dir.join("signing.key")).expect("readable");
    assert_eq!(
        live_before, live_after,
        "the live key must not change until the canister has"
    );
    let on_disk = std::fs::read_to_string(node.dir.join("signing.key.next")).expect("written");
    assert!(
        oracle_node::keyfile::is_encrypted(&on_disk),
        "the next key must be encrypted"
    );
    let next = load_key(&node.dir.join("signing.key.next"));
    let call = format!(
        "icp canister call aaaaa-aa replace_node '(\"{}\", \"{}\")' -n ic",
        live.address().to_checksummed(),
        next.address().to_checksummed()
    );
    assert!(text.contains(&call), "{text}");
}

/// Governance can already have the address of the next key, so a second
/// rotation must not replace that key.
#[test]
fn a_second_rotation_before_the_first_completes_is_refused() {
    let node = initialised("rotate-twice");
    let first = rotate(&node, &["--canister", "aaaaa-aa"]);
    assert!(first.status.success(), "{}", stderr(&first));
    let second = rotate(&node, &[]);
    assert!(!second.status.success());
    assert!(stderr(&second).contains("signing.key.next"));
}

/// Overwriting the key would drop the node out of the registry, and the node
/// would keep running while nobody accepted what it signs.
#[test]
fn init_refuses_to_overwrite_existing_keys() {
    let node = initialised("clobber");
    let second = init_out(&node.dir, &["--passphrase-file", &node.passphrase_file]);
    assert!(!second.status.success(), "the second init must fail");
    assert!(
        stderr(&second).contains("signing.key"),
        "the error should name the file it refused to clobber"
    );
}

#[test]
fn the_emitted_config_is_loadable() {
    let Initialised {
        dir,
        passphrase_file: pass,
        ..
    } = initialised("config");
    // The same call `start` makes. An init that emitted an unloadable config
    // would only fail once someone tried to run the node.
    let config = oracle_node::NodeConfig::load(&dir.join("config.toml")).expect("loads");
    config.resolve().expect("resolves");
    assert_eq!(
        config.signing.key_file.as_deref(),
        Some(Path::new(&dir.join("signing.key"))),
        "the config must point at the key that was just written"
    );
    // And `start` opens it non-interactively through the recorded passphrase file.
    assert_eq!(
        config.signing.passphrase_file.as_deref(),
        Some(Path::new(&pass))
    );
    let signer = config
        .load_signing_key()
        .expect("the node can open its own key");
    assert_eq!(
        signer.address(),
        load_key(&dir.join("signing.key")).address()
    );
}

/// `cargo test` has no terminal. An init that cannot ask for a passphrase must
/// refuse rather than write plaintext keys or hang.
#[test]
fn init_with_out_needs_a_passphrase_source_when_there_is_no_terminal() {
    let dir = scratch("nopass");
    let output = init_out(&dir, &[]);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("passphrase"), "{stderr}");
    assert!(!dir.join("signing.key").exists(), "nothing may be written");
}

#[test]
fn usage_errors_exit_non_zero_without_a_log_prefix() {
    for args in [
        vec![],
        vec!["bogus"],
        vec!["start"],
        vec!["init", "--bogus"],
    ] {
        let output = run(&args);
        assert!(!output.status.success(), "{args:?} should fail");
        let stderr = stderr(&output);
        assert!(
            stderr.to_lowercase().contains("usage"),
            "{args:?}: {stderr}"
        );
        assert!(
            !stderr.contains("ERROR"),
            "{args:?}: usage text should read as an instruction, not a crash: {stderr}"
        );
    }
}

/// The binary used to take a bare config path. Anyone following an older README
/// should be told where it went, not given "unknown command".
#[test]
fn a_bare_config_path_points_at_start() {
    let output = run(&["node.toml"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("start node.toml"),
        "should suggest the start subcommand"
    );
}

/// `--tail` must not be mistaken for the config path, in either order.
#[test]
fn start_finds_the_config_path_around_flags() {
    for args in [
        vec!["start", "missing.toml", "--tail"],
        vec!["start", "--tail", "missing.toml"],
    ] {
        let stderr = stderr(&run(&args));
        assert!(
            stderr.contains("missing.toml"),
            "{args:?} should have tried to load the config: {stderr}"
        );
        assert!(
            !stderr.to_lowercase().contains("usage"),
            "{args:?} parsed as a usage error: {stderr}"
        );
    }

    // ...but a flag on its own is still missing a config.
    let stderr = stderr(&run(&["start", "--tail"]));
    assert!(stderr.to_lowercase().contains("usage"), "{stderr}");
}

#[test]
fn help_succeeds_and_lists_both_commands_and_the_tail_flag() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let text = stdout(&output);
    for word in ["init", "start", "--tail"] {
        assert!(text.contains(word), "{word}: {text}");
    }
}

/// The canister flags fill the config, so a node made this way starts without
/// an edit. Paths are absolute, so the config and the unit do not depend on
/// where the node starts.
#[test]
fn init_flags_fill_the_config_and_the_unit() {
    let dir = scratch("flags");
    std::fs::create_dir_all(&dir).expect("creates");
    let pass = passphrase_file(&dir.join("node"));
    let governance = "0x5CbDd86a2FA8Dc4bDdd8a8f69dBa48572EeC07FB";
    let canister = "uxrrr-q7777-77774-qaaaq-cai";
    let output = Command::new(BINARY)
        .current_dir(&dir)
        .args([
            "init",
            "--out",
            "node",
            "--passphrase-file",
            &pass,
            "--canister",
            canister,
            "--gateway",
            "http://127.0.0.1:8000/",
            "--root-key",
            "3082",
            "--governance",
            governance,
            "--service-user",
            "oracle",
        ])
        .output()
        .expect("runs");
    assert!(output.status.success(), "{}", stderr(&output));

    // The child's working directory, as `getcwd` resolves it.
    let node = dir.canonicalize().expect("exists").join("node");
    let config = oracle_node::NodeConfig::load(&node.join("config.toml")).expect("loads");
    assert_eq!(
        config.registry.url.as_deref(),
        Some(format!("http://127.0.0.1:8000/registry.json?canisterId={canister}").as_str())
    );
    assert_eq!(config.registry.canister_id.as_deref(), Some(canister));
    assert_eq!(config.registry.root_key.as_deref(), Some("3082"));
    assert_eq!(
        config.governance().expect("set").to_checksummed(),
        governance
    );
    assert_eq!(config.signing.key_file, Some(node.join("signing.key")));
    assert!(
        config
            .signing
            .passphrase_file
            .as_deref()
            .is_some_and(Path::is_absolute)
    );

    let unit = std::fs::read_to_string(node.join("oracle-node.service")).expect("a unit");
    assert!(unit.lines().any(|line| line == "User=oracle"), "{unit}");
    assert!(unit.lines().any(|line| line == "Type=notify"), "{unit}");
    assert!(unit.lines().any(|line| line == "WatchdogSec=30s"), "{unit}");
    assert!(
        unit.contains(&format!("start \"{}\"", node.join("config.toml").display())),
        "{unit}"
    );
}

#[test]
fn values_the_registry_would_refuse_are_usage_errors() {
    for args in [
        vec!["init", "--endpoint", "http://node.example"],
        vec!["init", "--canister", "not a principal"],
        vec!["init", "--governance", "0x12"],
        vec!["init", "--out", "x", "--service-user", "oracle"],
        vec!["start", "node.toml", "--log-format", "bogus"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(EXIT_USAGE), "{args:?}");
        let stderr = stderr(&output);
        let flag = args
            .get(args.len().saturating_sub(2))
            .copied()
            .unwrap_or_default();
        assert!(
            stderr.contains(flag),
            "{args:?} should name {flag}: {stderr}"
        );
        assert!(!stderr.contains("ERROR"), "{args:?}: {stderr}");
    }
}

/// The node always fetches from the canister. Until the mainnet one exists,
/// `init --out` needs to be told which.
#[test]
fn init_needs_a_canister_until_mainnet_is_deployed() {
    let dir = scratch("mainnet");
    let pass = passphrase_file(&dir);
    let output = run(&[
        "init",
        "--out",
        dir.to_str().expect("utf-8"),
        "--passphrase-file",
        &pass,
    ]);
    if oracle_client::mainnet::CANISTER_ID.is_none() {
        assert!(!output.status.success());
        let stderr = stderr(&output);
        assert!(stderr.contains("--canister and --governance"), "{stderr}");
        assert!(!dir.exists(), "nothing may be written");
    } else {
        assert!(output.status.success());
    }
}
