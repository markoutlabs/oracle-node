//! `oracle-node init`: generate a node's key and everything needed to run it.
//!
//! A node has one key (SPEC §3.5). It signs every `PriceUpdate`, its address is
//! the node's id in the registry, and it stays encrypted at rest on the
//! operator's machine. A rotation is a new key that governance puts in place of
//! the old one with `replace_node`.
//!
//! [`NodeSetup`] decides everything `init` writes; [`NodeSetup::write`] is the
//! only path to disk. The wizard and the flags both build one.

use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use oracle_wire::{Address, NodeEntry, Signer};

use crate::keyfile;

mod setup;
mod starter;
mod unit;

pub use setup::{
    CanisterId, Endpoint, Gateway, NodeSetup, Operator, RegistrySource, RootKey, ServiceUnit,
    Unlock, Written,
};

/// Something went wrong generating or writing the node's files.
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

    /// The setup breaks a rule.
    #[error("{0}")]
    Invalid(String),
}

/// Makes a random passphrase for a passphrase file: 32 bytes from the OS, as hex.
///
/// # Errors
///
/// Returns [`InitError::Invalid`] if the OS entropy source cannot be read.
pub fn generate_passphrase() -> Result<SecretString, InitError> {
    let mut bytes = zeroize::Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut())
        .map_err(|error| InitError::Invalid(format!("cannot read OS entropy: {error}")))?;
    Ok(SecretString::from(hex::encode(bytes.as_ref())))
}

/// A freshly generated node key.
pub struct NodeKey {
    /// The key. Its address is the node's id.
    pub signing: Signer,
}

impl NodeKey {
    /// Generates the key.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::Key`] if the OS entropy source cannot be read.
    pub fn generate() -> Result<Self, InitError> {
        Ok(Self {
            signing: Signer::generate()?,
        })
    }

    /// Builds the registry entry to hand to governance.
    ///
    /// This carries no secret. Governance adds it to the registry and
    /// publishes a new version; until that happens the node's updates verify
    /// for nobody.
    #[must_use]
    pub fn entry(&self, operator: &Operator, endpoint: &Endpoint) -> NodeEntry {
        NodeEntry {
            address: self.signing.address(),
            operator: operator.to_string(),
            endpoints: vec![endpoint.to_string()],
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

    /// The `icp canister call` governance runs to swap this key in, on
    /// `network` (`ic` or `local`).
    #[must_use]
    pub fn canister_call(&self, network: &str, canister: &str) -> String {
        candid_call(
            network,
            canister,
            "replace_node",
            &[
                &self.old.to_checksummed(),
                &self.signing.address().to_checksummed(),
            ],
        )
    }
}

/// Renders an `icp canister call` with Candid text arguments, on `network`
/// (`ic` or `local`).
///
/// The arguments are JSON documents the canister parses, so they are full of
/// quotes. Candid text literals escape `\\` and `\"` the same way JSON does,
/// plus `\n`, `\r` and `\t`; everything else passes through.
#[must_use]
pub fn candid_call(network: &str, canister: &str, method: &str, args: &[&str]) -> String {
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
        "icp canister call {canister} {method} '({})' -n {network}",
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
pub(crate) fn write_secret(path: &Path, contents: &str) -> Result<(), InitError> {
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

    fn operator() -> Operator {
        "acme".parse().expect("valid operator")
    }

    fn endpoint() -> Endpoint {
        "wss://eu1.example/v2/ws".parse().expect("valid endpoint")
    }

    #[test]
    fn two_runs_never_produce_the_same_node() {
        let first = NodeKey::generate().expect("generates");
        let second = NodeKey::generate().expect("generates");
        assert_ne!(first.signing.address(), second.signing.address());
    }

    /// What init produces has to be what the registry accepts, or the operator
    /// discovers the mismatch only after governance has published.
    #[test]
    fn the_registry_entry_verifies_inside_a_signed_registry() {
        let key = NodeKey::generate().expect("generates");
        let governance = Signer::generate().expect("generates");
        let registry = oracle_wire::Registry::sign(
            &governance,
            1,
            NOW,
            vec![key.entry(&operator(), &endpoint())],
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
        let key = NodeKey::generate().expect("generates");
        let rotation = Rotation::generate(key.signing.address()).expect("rotates");
        assert_ne!(rotation.signing.address(), key.signing.address());

        let call = rotation.canister_call("ic", "aaaaa-aa");
        assert_eq!(
            call,
            format!(
                "icp canister call aaaaa-aa replace_node '(\"{}\", \"{}\")' -n ic",
                key.signing.address().to_checksummed(),
                rotation.signing.address().to_checksummed()
            )
        );
    }

    #[test]
    fn candid_calls_escape_json_arguments() {
        let call = candid_call(
            "local",
            "c",
            "m",
            &["plain", r#"{"a":"b\\c"}"#, "line\nbreak"],
        );
        assert_eq!(
            call,
            r#"icp canister call c m '("plain", "{\"a\":\"b\\\\c\"}", "line\nbreak")' -n local"#
        );
    }

    fn passphrase() -> SecretString {
        SecretString::from("correct horse battery staple".to_owned())
    }

    #[test]
    fn a_written_key_is_encrypted_reloads_and_is_not_world_readable() {
        let dir = std::env::temp_dir().join(format!("oracle-init-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key = NodeKey::generate().expect("generates");
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
}
