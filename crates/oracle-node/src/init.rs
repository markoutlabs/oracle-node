//! `oracle-node init`: generate a node's key and everything needed to run it.
//!
//! A node has one key (SPEC §3.5). It signs every `PriceUpdate`, its address is
//! the node's id in the registry, and it stays encrypted at rest on the
//! operator's machine. A rotation is a new key that governance puts in place of
//! the old one with `replace_node`.

use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use oracle_wire::{Address, NodeEntry, Signer};

use crate::keyfile;

/// Something went wrong generating or writing the node's key.
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
}

/// Who runs the node and how it will be reached.
#[derive(Clone, Debug)]
pub struct InitOptions {
    /// Who runs it. Operator diversity is what makes the median meaningful.
    pub operator: String,
    /// The WebSocket endpoint subscribers will connect to.
    pub endpoint: String,
}

impl Default for InitOptions {
    fn default() -> Self {
        Self {
            operator: "unset".to_owned(),
            endpoint: "ws://127.0.0.1:8791/v2/ws".to_owned(),
        }
    }
}

/// A freshly generated node key.
pub struct NodeKey {
    /// The key. Its address is the node's id.
    pub signing: Signer,
    /// The options this was generated under.
    pub options: InitOptions,
}

impl NodeKey {
    /// Generates the key.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::Key`] if the OS entropy source cannot be read.
    pub fn generate(options: InitOptions) -> Result<Self, InitError> {
        Ok(Self {
            signing: Signer::generate()?,
            options,
        })
    }

    /// Builds the registry entry to hand to governance.
    ///
    /// This carries no secret. Governance adds it to the registry and
    /// publishes a new version; until that happens the node's updates verify
    /// for nobody.
    #[must_use]
    pub fn registry_entry(&self) -> NodeEntry {
        NodeEntry {
            address: self.signing.address(),
            operator: self.options.operator.clone(),
            endpoints: vec![self.options.endpoint.clone()],
            weight: 1,
        }
    }

    /// Writes the key to `dir/signing.key` as an `age` file encrypted with
    /// `passphrase`, readable only by the current user. Returns the path.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::Write`] if the directory cannot be created, the
    /// file exists or cannot be written, or encryption fails.
    pub fn write_key(&self, dir: &Path, passphrase: &SecretString) -> Result<PathBuf, InitError> {
        std::fs::create_dir_all(dir).map_err(|e| InitError::Write {
            path: dir.to_path_buf(),
            reason: e.to_string(),
        })?;
        let path = dir.join("signing.key");
        write_encrypted(&path, &self.signing.to_secret_hex(), passphrase)?;
        Ok(path)
    }

    /// Renders a starter config file.
    ///
    /// `signing_key_file` is where the node will read its key from,
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
        // Quoted by the TOML serializer, so a quote or a backslash in a path
        // cannot produce a file the node then refuses to load.
        let quoted = |text: String| toml::Value::String(text).to_string();
        let passphrase_line = passphrase_file.map_or_else(
            || "# passphrase_file = \"/etc/oracle/passphrase\"".to_owned(),
            |path| format!("passphrase_file = {}", quoted(path.display().to_string())),
        );

        format!(
            r#"# Must be at or below the tightest feed's rate cap, or the cap becomes the tick
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
            listen = quoted(listen),
            signing_key_file = quoted(signing_key_file.display().to_string()),
            passphrase_line = passphrase_line,
            registry_path = quoted(registry_path.display().to_string()),
        )
    }
}

/// The next key for an existing node, ready for governance's `replace_node`.
///
/// The swap is atomic on the canister (SPEC §3.5), so the node keeps signing
/// with its old key until `replace_node` has been accepted. That is why the
/// new key goes to `signing.key.next` rather than over `signing.key`: the
/// operator moves it into place and restarts the node once the canister has
/// published the new version.
pub struct Rotation {
    /// The live key's address, which the new one replaces.
    pub old: Address,
    /// The new key.
    pub signing: Signer,
}

impl Rotation {
    /// Generates the key that replaces `old`.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::Key`] if the OS entropy source cannot be read.
    pub fn generate(old: Address) -> Result<Self, InitError> {
        Ok(Self {
            old,
            signing: Signer::generate()?,
        })
    }

    /// Writes the new key to `dir/signing.key.next` as an `age` file encrypted
    /// with `passphrase`, readable only by the current user. Returns the path.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::Write`] if the file exists or cannot be written.
    /// An existing `signing.key.next` is a rotation that was never completed,
    /// and overwriting it would lose a key the canister may already list.
    pub fn write(&self, dir: &Path, passphrase: &SecretString) -> Result<PathBuf, InitError> {
        let path = dir.join("signing.key.next");
        write_encrypted(&path, &self.signing.to_secret_hex(), passphrase)?;
        Ok(path)
    }

    /// The `dfx canister call` governance runs to swap this key in.
    #[must_use]
    pub fn canister_call(&self, canister: &str) -> String {
        candid_call(
            canister,
            "replace_node",
            &[
                &self.old.to_checksummed(),
                &self.signing.address().to_checksummed(),
            ],
        )
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
            operator: "acme".to_owned(),
            endpoint: "wss://eu1.example/v2/ws".to_owned(),
        }
    }

    #[test]
    fn two_runs_never_produce_the_same_node() {
        let first = NodeKey::generate(options()).expect("generates");
        let second = NodeKey::generate(options()).expect("generates");
        assert_ne!(first.signing.address(), second.signing.address());
    }

    /// What init produces has to be what the registry accepts, or the operator
    /// discovers the mismatch only after governance has published.
    #[test]
    fn the_registry_entry_verifies_inside_a_signed_registry() {
        let key = NodeKey::generate(options()).expect("generates");
        let governance = Signer::generate().expect("generates");
        let registry = oracle_wire::Registry::sign(
            &governance,
            1,
            NOW,
            vec![key.registry_entry()],
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
                .authorize(key.signing.address())
                .expect("the key must be authorised"),
            0
        );
    }

    /// The printed call names both addresses, checksummed so a typo fails at
    /// the canister rather than burning an address.
    #[test]
    fn a_rotation_names_the_old_and_the_new_address() {
        let key = NodeKey::generate(options()).expect("generates");
        let rotation = Rotation::generate(key.signing.address()).expect("rotates");
        assert_ne!(rotation.signing.address(), key.signing.address());

        let call = rotation.canister_call("aaaaa-aa");
        assert_eq!(
            call,
            format!(
                "dfx canister call aaaaa-aa replace_node '(\"{}\", \"{}\")'",
                key.signing.address().to_checksummed(),
                rotation.signing.address().to_checksummed()
            )
        );
    }

    #[test]
    fn candid_calls_escape_json_arguments() {
        let call = candid_call("c", "m", &["plain", r#"{"a":"b\\c"}"#, "line\nbreak"]);
        assert_eq!(
            call,
            r#"dfx canister call c m '("plain", "{\"a\":\"b\\\\c\"}", "line\nbreak")'"#
        );
    }

    fn passphrase() -> SecretString {
        SecretString::from("correct horse battery staple".to_owned())
    }

    #[test]
    fn a_written_key_is_encrypted_reloads_and_is_not_world_readable() {
        let dir = std::env::temp_dir().join(format!("oracle-init-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key = NodeKey::generate(options()).expect("generates");
        let path = key.write_key(&dir, &passphrase()).expect("writes");

        // At rest the file is an age file; the hex never touches the disk.
        let on_disk = std::fs::read_to_string(&path).expect("readable");
        assert!(keyfile::is_encrypted(&on_disk), "{on_disk}");
        assert!(!on_disk.contains(&*key.signing.to_secret_hex()));

        // The node loads its key with exactly this call.
        let reloaded = keyfile::load_signer(&path, Some(&passphrase())).expect("valid key");
        assert_eq!(reloaded.address(), key.signing.address());
        assert!(
            keyfile::load_signer(&path, None).is_err(),
            "an encrypted key must not open without the passphrase"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("exists")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "{} is readable by others", path.display());
        }

        // Overwriting the key would drop the node out of the registry.
        assert!(
            key.write_key(&dir, &passphrase()).is_err(),
            "writing over an existing key must fail"
        );
        let rotation = Rotation::generate(key.signing.address()).expect("rotates");
        rotation.write(&dir, &passphrase()).expect("writes");
        assert!(
            rotation.write(&dir, &passphrase()).is_err(),
            "an unfinished rotation must not be overwritten"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_config_template_parses_as_a_node_config() {
        let key = NodeKey::generate(options()).expect("generates");
        let config = key.config_template(
            Path::new("/etc/oracle/signing.key"),
            Path::new("/etc/oracle/registry.json"),
            Some(Path::new("/etc/oracle/passphrase")),
        );
        let parsed: crate::NodeConfig =
            toml::from_str(&config).expect("init must emit a valid config");
        assert_eq!(
            parsed.signing.passphrase_file.as_deref(),
            Some(Path::new("/etc/oracle/passphrase"))
        );
        parsed.resolve().expect("the emitted feeds must resolve");

        // Without a passphrase file the line is a comment, and the node prompts.
        let prompting = key.config_template(
            Path::new("/etc/oracle/signing.key"),
            Path::new("/etc/oracle/registry.json"),
            None,
        );
        let parsed: crate::NodeConfig = toml::from_str(&prompting).expect("valid config");
        assert!(parsed.signing.passphrase_file.is_none());
    }

    /// A backslash in a path used to produce a file the node then refused to
    /// load.
    #[test]
    fn the_config_template_quotes_awkward_values() {
        let key = NodeKey::generate(options()).expect("generates");
        let config = key.config_template(
            Path::new(r"C:\keys\signing.key"),
            Path::new(r"C:\keys\registry.json"),
            None,
        );
        let parsed: crate::NodeConfig = toml::from_str(&config).expect("valid TOML");
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
        let key = NodeKey::generate(options).expect("generates");
        let config =
            key.config_template(Path::new("signing.key"), Path::new("registry.json"), None);
        assert!(config.contains("listen = \"0.0.0.0:9001\""), "{config}");
    }

    #[test]
    fn the_config_listen_port_follows_the_endpoint() {
        let options = InitOptions {
            endpoint: "ws://127.0.0.1:9001/v2/ws".to_owned(),
            ..options()
        };
        let key = NodeKey::generate(options).expect("generates");
        let config =
            key.config_template(Path::new("signing.key"), Path::new("registry.json"), None);
        assert!(config.contains("listen = \"0.0.0.0:9001\""), "{config}");
    }
}
