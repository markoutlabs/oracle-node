//! `oracle-node init`: generate a node's keys and everything needed to run it.
//!
//! A node has two keys, and the split is the whole point (SPEC §3.5):
//!
//! ```text
//! identity key ── long-lived. Signs only signing-key certificates, never prices.
//!      │          Encrypted at rest on the operator's machine.
//!      └── signing key ── in process memory, no expiry.
//!                         Signs every PriceUpdate.
//! ```
//!
//! A stolen signing key is revoked by publishing a registry without it. A stolen identity key means
//! governance has to rotate the node entry itself. Generating both here, and
//! writing them to separate files, is what makes that distinction real rather
//! than aspirational.

use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use oracle_wire::{NO_EXPIRY, NodeEntry, Signer, SigningKeyCert};

use crate::keyfile;

/// Something went wrong generating or writing the node's identity.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InitError {
    /// A key could not be generated.
    #[error("cannot generate a key: {0}")]
    Key(#[from] oracle_wire::WireError),

    /// A file could not be written.
    #[error("cannot write {path}: {reason}")]
    Write {
        /// Which file.
        path: PathBuf,
        /// Why.
        reason: String,
    },

    /// The node id was rejected.
    #[error("invalid node id: {0}")]
    NodeId(String),
}

/// What the node should be called and how it will be reached.
#[derive(Clone, Debug)]
pub struct InitOptions {
    /// This node's identifier, which must match its registry entry.
    pub node_id: String,
    /// Who runs it. Operator diversity is what makes the median meaningful.
    pub operator: String,
    /// The WebSocket endpoint subscribers will connect to.
    pub endpoint: String,
}

impl Default for InitOptions {
    fn default() -> Self {
        Self {
            node_id: "oracle-1".to_owned(),
            operator: "unset".to_owned(),
            endpoint: "ws://127.0.0.1:8791/v2/ws".to_owned(),
        }
    }
}

/// A freshly generated node identity.
pub struct NodeKeys {
    /// The long-lived identity key.
    pub identity: Signer,
    /// The hot signing key.
    pub signing: Signer,
    /// The identity key's authorisation of the signing key.
    pub cert: SigningKeyCert,
    /// The options this was generated under.
    pub options: InitOptions,
}

impl NodeKeys {
    /// Generates both keys and issues the signing certificate.
    ///
    /// `now` is unix seconds; the certificate starts there and never expires.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::NodeId`] if the node id is empty or too long for the
    /// certificate encoding, or [`InitError::Key`] if the OS entropy source
    /// cannot be read.
    pub fn generate(options: InitOptions, now: u64) -> Result<Self, InitError> {
        if options.node_id.trim().is_empty() {
            return Err(InitError::NodeId("must not be empty".to_owned()));
        }
        if options.node_id.len() > oracle_wire::MAX_NODE_ID_LEN {
            return Err(InitError::NodeId(format!(
                "`{}` is {} bytes; the limit is {}",
                options.node_id,
                options.node_id.len(),
                oracle_wire::MAX_NODE_ID_LEN
            )));
        }

        let identity = Signer::generate()?;
        let signing = Signer::generate()?;
        let cert = SigningKeyCert::issue(
            &identity,
            &options.node_id,
            signing.address(),
            now,
            NO_EXPIRY,
        )?;

        Ok(Self {
            identity,
            signing,
            cert,
            options,
        })
    }

    /// Builds the registry entry to hand to governance.
    ///
    /// This carries no secret: the identity public key, the endpoints, and a
    /// certificate anyone can check was issued by that identity key. Governance
    /// adds it to the registry and publishes a new version; until that happens
    /// the node's updates verify for nobody.
    #[must_use]
    pub fn registry_entry(&self) -> NodeEntry {
        NodeEntry {
            node_id: self.options.node_id.clone(),
            operator: self.options.operator.clone(),
            identity_pubkey: self.identity.public_key(),
            endpoints: vec![self.options.endpoint.clone()],
            signing_keys: vec![self.cert.clone()],
            weight: 1,
        }
    }

    /// Writes both keys to `dir` as `age` files encrypted with `passphrase`,
    /// readable only by the current user.
    ///
    /// Returns the paths written, identity first.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::Write`] if the directory cannot be created, either
    /// file exists or cannot be written, or encryption fails.
    pub fn write_keys(
        &self,
        dir: &Path,
        passphrase: &SecretString,
    ) -> Result<(PathBuf, PathBuf), InitError> {
        std::fs::create_dir_all(dir).map_err(|e| InitError::Write {
            path: dir.to_path_buf(),
            reason: e.to_string(),
        })?;

        let identity_path = dir.join("identity.key");
        let signing_path = dir.join("signing.key");
        write_encrypted(&identity_path, &self.identity.to_secret_hex(), passphrase)?;
        write_encrypted(&signing_path, &self.signing.to_secret_hex(), passphrase)?;
        Ok((identity_path, signing_path))
    }

    /// Renders a starter config file.
    ///
    /// `signing_key_file` is where the node will read its signing key from,
    /// `registry_path` where it will read the governance-signed registry, and
    /// `passphrase_file`, if given, where it will read the passphrase that opens
    /// the key. Without one the node prompts at startup.
    #[must_use]
    pub fn config_template(
        &self,
        signing_key_file: &Path,
        registry_path: &Path,
        passphrase_file: Option<&Path>,
    ) -> String {
        let listen = self
            .options
            .endpoint
            .parse::<axum::http::Uri>()
            .ok()
            .and_then(|uri| uri.port_u16())
            .map_or_else(
                || "0.0.0.0:8791".to_owned(),
                |port| format!("0.0.0.0:{port}"),
            );
        // Quoted by the TOML serializer, so a quote or a backslash in a node id
        // or a path cannot produce a file the node then refuses to load.
        let quoted = |text: String| toml::Value::String(text).to_string();
        let passphrase_line = passphrase_file.map_or_else(
            || "# passphrase_file = \"/etc/oracle/passphrase\"".to_owned(),
            |path| format!("passphrase_file = {}", quoted(path.display().to_string())),
        );

        format!(
            r#"node_id = {node_id}

# Must be at or below the tightest feed's rate cap, or the cap becomes the tick
# rate and the deviation trigger never fires early.
tick_interval_ms = 25

[server]
listen = {listen}
max_pending_feeds = 512

[signing]
# A file or an environment variable, never a command-line argument: arguments
# are visible in `ps` to every user on the box. The key file is an `age` file;
# the passphrase that opens it comes from a 0600 file, or from a prompt at
# startup when this line is absent.
key_file = {signing_key_file}
{passphrase_line}

[registry]
path = {registry_path}
# A deployed node fetches from the canister instead of `path`:
# url = "https://<canister-id>.raw.icp0.io/registry.json"
# Each fetched document must carry this canister's certificate. Set `root_key`
# (hex) only off mainnet.
canister_id = "<canister-id>"
# Pinned here rather than taken from the registry itself, which would let the
# document vouch for its own author. Ask governance for this address; do not
# copy it out of a registry file you were sent.
governance_address = "0x0000000000000000000000000000000000000000"

# The governance-signed client list (SPEC §6.1). The node serves prices only to
# these clients, encrypted, over /v2/ws, and refuses to start without the list.
[clients]
url = "https://<canister-id>.raw.icp0.io/clients.json"

[[feeds]]
symbol = "CRYPTO.BTC/USDT"
min_sources = 2
sources = [
  {{ venue = "binance", market = "spot", symbol = "BTCUSDT" }},
  {{ venue = "bybit", market = "spot", symbol = "BTCUSDT" }},
  {{ venue = "okx", market = "spot", symbol = "BTC-USDT" }},
]
"#,
            node_id = quoted(self.options.node_id.clone()),
            listen = quoted(listen),
            signing_key_file = quoted(signing_key_file.display().to_string()),
            passphrase_line = passphrase_line,
            registry_path = quoted(registry_path.display().to_string()),
        )
    }
}

/// A new signing key for an existing node, ready for the registry canister.
///
/// The swap is atomic on the canister (SPEC §3.5), so the node must keep
/// signing with its old key until `rotate_key` has been accepted. That is why
/// the new key goes to `signing.key.next` rather than over `signing.key`: the
/// operator moves it into place and restarts the node once the canister has
/// published the new version.
pub struct Rotation {
    /// The new hot signing key.
    pub signing: Signer,
    /// The identity key's authorisation of it.
    pub cert: SigningKeyCert,
}

impl Rotation {
    /// Generates a new signing key and issues its certificate.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::NodeId`] if the node id is too long for the
    /// certificate encoding, or [`InitError::Key`] if the OS entropy source
    /// cannot be read.
    pub fn generate(identity: &Signer, node_id: &str, now: u64) -> Result<Self, InitError> {
        let signing = Signer::generate()?;
        let cert = SigningKeyCert::issue(identity, node_id, signing.address(), now, NO_EXPIRY)
            .map_err(|error| match error {
                oracle_wire::WireError::FieldTooLong { .. } => {
                    InitError::NodeId(format!("`{node_id}` is too long for a certificate"))
                }
                other => InitError::Key(other),
            })?;
        Ok(Self { signing, cert })
    }

    /// Writes the new key to `dir/signing.key.next` as an `age` file encrypted
    /// with `passphrase`, readable only by the current user, and the
    /// certificate to `dir/rotation-cert.json`.
    ///
    /// Returns the two paths, key first.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::Write`] if either file exists or cannot be written.
    /// An existing `signing.key.next` is a rotation that was never completed,
    /// and overwriting it would lose a key the canister may already list.
    pub fn write(
        &self,
        dir: &Path,
        passphrase: &SecretString,
    ) -> Result<(PathBuf, PathBuf), InitError> {
        let key_path = dir.join("signing.key.next");
        let cert_path = dir.join("rotation-cert.json");
        write_encrypted(&key_path, &self.signing.to_secret_hex(), passphrase)?;
        let cert = serde_json::to_string_pretty(&self.cert).map_err(|e| InitError::Write {
            path: cert_path.clone(),
            reason: e.to_string(),
        })?;
        std::fs::write(&cert_path, format!("{cert}\n")).map_err(|e| InitError::Write {
            path: cert_path.clone(),
            reason: e.to_string(),
        })?;
        Ok((key_path, cert_path))
    }

    /// The `dfx canister call` governance runs to swap this key in.
    ///
    /// # Panics
    ///
    /// Cannot panic: a certificate always serialises.
    #[must_use]
    pub fn canister_call(&self, canister: &str) -> String {
        let cert = serde_json::to_string(&self.cert).expect("certificate serialises");
        candid_call(canister, "rotate_key", &[&self.cert.node_id, &cert])
    }
}

/// Renders a `dfx canister call` with Candid text arguments.
///
/// The arguments are JSON documents the canister parses, so they are full of
/// quotes. Candid text literals escape `\\` and `\"` the same way JSON does,
/// plus `\n`, `\r` and `\t`; everything else passes through.
#[must_use]
pub fn candid_call(canister: &str, method: &str, args: &[&str]) -> String {
    let quoted: Vec<String> = args
        .iter()
        .map(|arg| {
            let mut out = String::with_capacity(arg.len() + 2);
            out.push('"');
            for ch in arg.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    other => out.push(other),
                }
            }
            out.push('"');
            out
        })
        .collect();
    format!(
        "dfx canister call {canister} {method} '({})'",
        quoted.join(", ")
    )
}

/// Encrypts a secret and writes it to a file only the current user can read.
fn write_encrypted(path: &Path, secret: &str, passphrase: &SecretString) -> Result<(), InitError> {
    let armored = keyfile::encrypt(secret, passphrase).map_err(|e| InitError::Write {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    write_secret(path, &armored)
}

/// Writes a secret to a file only the current user can read.
fn write_secret(path: &Path, contents: &str) -> Result<(), InitError> {
    let failed = |reason: String| InitError::Write {
        path: path.to_path_buf(),
        reason,
    };

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        // 0600 at creation time, not chmod'd afterwards: a key that is briefly
        // world-readable has been world-readable.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| failed(e.to_string()))?;
        writeln!(file, "{contents}").map_err(|e| failed(e.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, format!("{contents}\n")).map_err(|e| failed(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_754_582_400;

    fn options() -> InitOptions {
        InitOptions {
            node_id: "oracle-eu-1".to_owned(),
            operator: "acme".to_owned(),
            endpoint: "wss://eu1.example/v2/ws".to_owned(),
        }
    }

    #[test]
    fn the_two_keys_are_distinct() {
        let keys = NodeKeys::generate(options(), NOW).expect("generates");
        assert_ne!(
            keys.identity.address(),
            keys.signing.address(),
            "the identity key must never be the signing key — the split is the \
             entire point of the two-tier design"
        );
    }

    #[test]
    fn two_runs_never_produce_the_same_node() {
        let first = NodeKeys::generate(options(), NOW).expect("generates");
        let second = NodeKeys::generate(options(), NOW).expect("generates");
        assert_ne!(first.identity.address(), second.identity.address());
        assert_ne!(first.signing.address(), second.signing.address());
    }

    /// The certificate is the only thing binding the hot key to the node, so it
    /// has to recover to the identity key that issued it.
    #[test]
    fn the_certificate_recovers_to_the_identity_key() {
        let keys = NodeKeys::generate(options(), NOW).expect("generates");
        assert_eq!(
            keys.cert.recover_issuer().expect("recovers"),
            keys.identity.address()
        );
        assert_eq!(keys.cert.address, keys.signing.address());
        assert_eq!(keys.cert.node_id, "oracle-eu-1");
    }

    #[test]
    fn the_certificate_never_expires() {
        let keys = NodeKeys::generate(options(), NOW).expect("generates");
        assert_eq!(keys.cert.not_before, NOW);
        assert_eq!(keys.cert.not_after, NO_EXPIRY);
        assert!(keys.cert.covers(u64::MAX - 1));
        assert!(keys.cert.has_valid_window());
        assert!(keys.cert.covers(NOW * oracle_types::NANOS_PER_SEC));
    }

    /// What init produces has to be what the registry accepts, or the operator
    /// discovers the mismatch only after governance has published.
    #[test]
    fn the_registry_entry_verifies_inside_a_signed_registry() {
        let keys = NodeKeys::generate(options(), NOW).expect("generates");
        let governance = Signer::generate().expect("generates");
        let registry = oracle_wire::Registry::sign(
            &governance,
            1,
            NOW,
            vec![keys.registry_entry()],
            oracle_wire::Quorum {
                min_nodes: 1,
                recommended: 3,
            },
        )
        .expect("signs");

        let verified = registry
            .verify(governance.address(), 0)
            .expect("a registry built from init output must verify");
        assert_eq!(
            verified
                .authorize(keys.signing.address(), NOW * oracle_types::NANOS_PER_SEC)
                .expect("the signing key must be authorised"),
            0
        );
    }

    /// A rotation is a new hot key under the same identity, so its certificate
    /// must recover to that identity and name a different signing address.
    #[test]
    fn a_rotation_keeps_the_identity_and_changes_the_signing_key() {
        let keys = NodeKeys::generate(options(), NOW).expect("generates");
        let rotation =
            Rotation::generate(&keys.identity, "oracle-eu-1", NOW + 10).expect("rotates");
        assert_ne!(rotation.signing.address(), keys.signing.address());
        assert_eq!(
            rotation.cert.recover_issuer().expect("recovers"),
            keys.identity.address()
        );
        assert_eq!(rotation.cert.address, rotation.signing.address());
        assert_eq!(rotation.cert.not_before, NOW + 10);
        assert_eq!(rotation.cert.not_after, NO_EXPIRY);

        // The printed call carries the certificate the canister will parse.
        let call = rotation.canister_call("aaaaa-aa");
        assert!(
            call.starts_with("dfx canister call aaaaa-aa rotate_key '("),
            "{call}"
        );
        assert!(call.contains(r#"\"node_id\":\"oracle-eu-1\""#), "{call}");
    }

    #[test]
    fn candid_calls_escape_json_arguments() {
        let call = candid_call("c", "m", &["plain", r#"{"a":"b\\c"}"#, "line\nbreak"]);
        assert_eq!(
            call,
            r#"dfx canister call c m '("plain", "{\"a\":\"b\\\\c\"}", "line\nbreak")'"#
        );
    }

    #[test]
    fn an_empty_or_over_long_node_id_is_refused() {
        for id in ["", "   ", &"x".repeat(65)] {
            let options = InitOptions {
                node_id: id.to_owned(),
                ..options()
            };
            assert!(
                matches!(
                    NodeKeys::generate(options, NOW),
                    Err(InitError::NodeId(_) | InitError::Key(_))
                ),
                "node id `{id}` should have been refused"
            );
        }
    }

    fn passphrase() -> SecretString {
        SecretString::from("correct horse battery staple".to_owned())
    }

    #[test]
    fn written_keys_are_encrypted_reload_and_are_not_world_readable() {
        let dir = std::env::temp_dir().join(format!("oracle-init-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let keys = NodeKeys::generate(options(), NOW).expect("generates");
        let (identity_path, signing_path) = keys.write_keys(&dir, &passphrase()).expect("writes");

        // At rest the file is an age file; the hex never touches the disk.
        let on_disk = std::fs::read_to_string(&signing_path).expect("readable");
        assert!(keyfile::is_encrypted(&on_disk), "{on_disk}");
        assert!(!on_disk.contains(&*keys.signing.to_secret_hex()));

        // The node loads its key with exactly this call.
        let reloaded = keyfile::load_signer(&signing_path, Some(&passphrase())).expect("valid key");
        assert_eq!(reloaded.address(), keys.signing.address());
        assert!(
            keyfile::load_signer(&signing_path, None).is_err(),
            "an encrypted key must not open without the passphrase"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for path in [&identity_path, &signing_path] {
                let mode = std::fs::metadata(path)
                    .expect("exists")
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o077, 0, "{} is readable by others", path.display());
            }
        }

        // Refusing to clobber matters: silently overwriting an identity key would
        // orphan every certificate it ever issued.
        assert!(
            keys.write_keys(&dir, &passphrase()).is_err(),
            "writing over existing keys must fail"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_config_template_parses_as_a_node_config() {
        let keys = NodeKeys::generate(options(), NOW).expect("generates");
        let config = keys.config_template(
            Path::new("/etc/oracle/signing.key"),
            Path::new("/etc/oracle/registry.json"),
            Some(Path::new("/etc/oracle/passphrase")),
        );
        let parsed: crate::NodeConfig =
            toml::from_str(&config).expect("init must emit a valid config");
        assert_eq!(parsed.node_id, "oracle-eu-1");
        assert_eq!(
            parsed.signing.passphrase_file.as_deref(),
            Some(Path::new("/etc/oracle/passphrase"))
        );
        parsed.resolve().expect("the emitted feeds must resolve");

        // Without a passphrase file the line is a comment, and the node prompts.
        let prompting = keys.config_template(
            Path::new("/etc/oracle/signing.key"),
            Path::new("/etc/oracle/registry.json"),
            None,
        );
        let parsed: crate::NodeConfig = toml::from_str(&prompting).expect("valid config");
        assert!(parsed.signing.passphrase_file.is_none());
    }

    /// A quote in the node id or a backslash in a path used to produce a file
    /// the node then refused to load.
    #[test]
    fn the_config_template_quotes_awkward_values() {
        let options = InitOptions {
            node_id: r#"oracle "eu" \ 1"#.to_owned(),
            ..options()
        };
        let keys = NodeKeys::generate(options, NOW).expect("generates");
        let config = keys.config_template(
            Path::new(r"C:\keys\signing.key"),
            Path::new(r"C:\keys\registry.json"),
            None,
        );
        let parsed: crate::NodeConfig = toml::from_str(&config).expect("valid TOML");
        assert_eq!(parsed.node_id, r#"oracle "eu" \ 1"#);
        assert_eq!(
            parsed.signing.key_file.as_deref(),
            Some(Path::new(r"C:\keys\signing.key"))
        );
    }

    /// A colon later in the URL must not be mistaken for the port.
    #[test]
    fn the_config_listen_port_ignores_colons_in_the_path() {
        let options = InitOptions {
            endpoint: "ws://127.0.0.1:9001/v2/ws?x=a:1".to_owned(),
            ..options()
        };
        let keys = NodeKeys::generate(options, NOW).expect("generates");
        let config =
            keys.config_template(Path::new("signing.key"), Path::new("registry.json"), None);
        assert!(config.contains("listen = \"0.0.0.0:9001\""), "{config}");
    }

    #[test]
    fn the_config_listen_port_follows_the_endpoint() {
        let options = InitOptions {
            endpoint: "ws://127.0.0.1:9001/v2/ws".to_owned(),
            ..options()
        };
        let keys = NodeKeys::generate(options, NOW).expect("generates");
        let config =
            keys.config_template(Path::new("signing.key"), Path::new("registry.json"), None);
        assert!(config.contains("listen = \"0.0.0.0:9001\""), "{config}");
    }
}
