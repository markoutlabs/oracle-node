//! The `oracle-node` command line.
//!
//! Driven as a subprocess rather than by calling into the library, because the
//! things worth pinning down here are properties of the binary: what it writes
//! to stdout, what it refuses to write to stdout, and what it exits with.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BINARY: &str = env!("CARGO_BIN_EXE_oracle-node");

fn run(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .output()
        .expect("the node binary runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("oracle-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Counts 64-character hex runs, which is what a leaked secret key looks like.
fn secret_like_strings(text: &str) -> usize {
    text.split(|c: char| !c.is_ascii_hexdigit())
        .filter(|word| word.len() == 64)
        .count()
}

#[test]
fn init_prints_both_keys_and_the_registry_entry() {
    let output = run(&["init", "--node-id", "oracle-eu-1", "--operator", "acme"]);
    assert!(output.status.success());
    let text = stdout(&output);

    // Two keys, because the two-tier split is the design.
    assert_eq!(
        secret_like_strings(&text),
        2,
        "expected exactly the identity and signing secrets:\n{text}"
    );
    assert!(text.contains("identity"), "{text}");
    assert!(text.contains("signing"), "{text}");

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
    assert_eq!(parsed.node_id, "oracle-eu-1");
    assert_eq!(parsed.operator, "acme");
    assert_eq!(parsed.signing_keys.len(), 1);

    // And the certificate in it really was issued by the identity key printed.
    let issuer = parsed
        .signing_keys
        .first()
        .expect("one certificate")
        .recover_issuer()
        .expect("recovers");
    assert!(
        text.contains(&issuer.to_string()),
        "the certificate issuer must be the identity address shown"
    );
}

/// Two runs must never produce the same node. A key-generation path that seeded
/// itself from the clock, or from a constant, would pass every other test here.
#[test]
fn init_generates_a_different_identity_every_time() {
    let first = stdout(&run(&["init"]));
    let second = stdout(&run(&["init"]));
    assert_ne!(first, second);
}

/// The point of `--out` is that the secrets go to 0600 files instead of into
/// terminal scrollback and shell history.
#[test]
fn init_with_out_writes_files_and_prints_no_secrets() {
    let dir = scratch("out");
    let output = run(&["init", "--out", dir.to_str().expect("utf-8")]);
    assert!(output.status.success());
    let text = stdout(&output);

    assert_eq!(
        secret_like_strings(&text),
        0,
        "--out must keep secrets off stdout:\n{text}"
    );

    for name in [
        "identity.key",
        "signing.key",
        "node-entry.json",
        "config.toml",
    ] {
        assert!(dir.join(name).is_file(), "{name} was not written");
    }

    // The written signing key is the one the node will load.
    let signing = std::fs::read_to_string(dir.join("signing.key")).expect("readable");
    let signer = oracle_wire::Signer::from_hex(signing.trim()).expect("a valid key");
    let entry: oracle_wire::NodeEntry = serde_json::from_str(
        &std::fs::read_to_string(dir.join("node-entry.json")).expect("readable"),
    )
    .expect("a valid entry");
    assert_eq!(
        entry.signing_keys.first().expect("one certificate").address,
        signer.address()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for name in ["identity.key", "signing.key"] {
            let mode = std::fs::metadata(dir.join(name))
                .expect("exists")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "{name} is readable by others");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Overwriting an identity key would orphan every certificate it ever issued,
/// and the node would keep running until the registry stopped matching.
#[test]
fn init_refuses_to_overwrite_existing_keys() {
    let dir = scratch("clobber");
    let path = dir.to_str().expect("utf-8");
    assert!(run(&["init", "--out", path]).status.success());

    let second = run(&["init", "--out", path]);
    assert!(!second.status.success(), "the second init must fail");
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("identity.key"),
        "the error should name the file it refused to clobber"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_emitted_config_is_loadable() {
    let dir = scratch("config");
    assert!(
        run(&["init", "--out", dir.to_str().expect("utf-8")])
            .status
            .success()
    );
    // The same call `start` makes. An init that emitted an unloadable config
    // would only fail once someone tried to run the node.
    let config = oracle_node::NodeConfig::load(&dir.join("config.toml")).expect("loads");
    config.resolve().expect("resolves");
    assert_eq!(
        config.signing.key_file.as_deref(),
        Some(Path::new(&dir.join("signing.key"))),
        "the config must point at the key that was just written"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn init_rejects_a_node_id_the_certificate_cannot_carry() {
    let output = run(&["init", "--node-id", &"x".repeat(65)]);
    assert!(!output.status.success());
    assert_eq!(
        secret_like_strings(&stdout(&output)),
        0,
        "a failed init must not print keys it is about to throw away"
    );
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
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("usage"), "{args:?}: {stderr}");
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
        String::from_utf8_lossy(&output.stderr).contains("start node.toml"),
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
        let stderr = String::from_utf8_lossy(&run(&args).stderr).into_owned();
        assert!(
            stderr.contains("missing.toml"),
            "{args:?} should have tried to load the config: {stderr}"
        );
        assert!(
            !stderr.contains("usage"),
            "{args:?} parsed as a usage error: {stderr}"
        );
    }

    // ...but a flag on its own is still missing a config.
    let stderr = String::from_utf8_lossy(&run(&["start", "--tail"]).stderr).into_owned();
    assert!(stderr.contains("usage"), "{stderr}");
}

#[test]
fn help_mentions_the_tail_flag() {
    let text = stdout(&run(&["--help"]));
    assert!(text.contains("--tail"), "{text}");
}

#[test]
fn help_succeeds_and_lists_both_commands() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("init"), "{text}");
    assert!(text.contains("start"), "{text}");
}
