//! Key files encrypted at rest.
//!
//! The node key lives on the operator's machine, never in a KMS or an HSM
//! (SPEC §9.2). At rest it is an `age` file encrypted with a passphrase. In
//! memory it is wiped on drop; nothing here page-locks it.
//!
//! Plaintext hex is still accepted on load, so a local playground can hand a
//! seeded key to the node. A file is told apart by its armor header, never by
//! its name.

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::{ExposeSecret as _, SecretString};
use oracle_wire::Signer;

use crate::seed::NodeKeys;
use zeroize::Zeroizing;

/// The first line of an armored `age` file.
pub const ARMOR_HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

// `age` sizes scrypt by timing the machine it runs on, so a key made by a fast
// build could exceed what a slower build or server accepts. N = 2^18 is 256 MiB.
const WORK_FACTOR: u8 = 18;
// Above WORK_FACTOR, so keys that `age` sized on a fast machine still open.
const MAX_WORK_FACTOR: u8 = 20;

/// A key file could not be read, decrypted, or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyFileError {
    /// The file could not be read.
    #[error("cannot read {path}: {reason}")]
    Read {
        /// Which file.
        path: PathBuf,
        /// Why.
        reason: String,
    },
    /// The file is encrypted and nothing supplied a passphrase.
    #[error(
        "{path} is encrypted and no passphrase was given: set signing.passphrase_file, \
         pass --passphrase-file, or run at a terminal"
    )]
    NeedsPassphrase {
        /// Which file.
        path: PathBuf,
    },
    /// The passphrase does not open the file.
    #[error("cannot decrypt {path}: wrong passphrase")]
    Decrypt {
        /// Which file.
        path: PathBuf,
    },
    /// The file asks for more scrypt work than the node accepts.
    #[error(
        "cannot decrypt {path}: its scrypt work factor 2^{required} is above the limit of \
         2^{MAX_WORK_FACTOR}"
    )]
    WorkFactor {
        /// Which file.
        path: PathBuf,
        /// The work factor in its header.
        required: u8,
    },
    /// The file is not a valid `age` file.
    #[error("cannot decrypt {path}: damaged file: {reason}")]
    Damaged {
        /// Which file.
        path: PathBuf,
        /// What `age` reported.
        reason: String,
    },
    /// Encryption failed.
    #[error("encryption failed: {0}")]
    Encrypt(String),
    /// No terminal to prompt at.
    #[error("no terminal to prompt for a passphrase; use a passphrase file")]
    NonInteractive,
    /// The two prompted passphrases differ.
    #[error("the passphrases did not match")]
    Mismatch,
    /// The passphrase is empty.
    #[error("the passphrase is empty")]
    Empty,
    /// The decrypted bytes are not a key.
    #[error(transparent)]
    Key(#[from] oracle_wire::WireError),
    /// The decrypted text is not a seed or a key.
    #[error(transparent)]
    Seed(#[from] crate::seed::SeedError),
}

/// Returns `true` if `text` is an armored `age` file.
#[must_use]
pub fn is_encrypted(text: &str) -> bool {
    text.trim_start().starts_with(ARMOR_HEADER)
}

/// Returns `true` if the file at `path` is an armored `age` file.
///
/// # Errors
///
/// Returns [`KeyFileError::Read`] if the file cannot be read.
pub fn file_is_encrypted(path: &Path) -> Result<bool, KeyFileError> {
    let text = Zeroizing::new(read(path)?);
    Ok(is_encrypted(&text))
}

/// Encrypts `secret` with `passphrase` into an armored `age` file.
///
/// # Errors
///
/// Returns [`KeyFileError::Encrypt`] if `age` fails, which does not happen for
/// well-formed input.
pub fn encrypt(secret: &str, passphrase: &SecretString) -> Result<String, KeyFileError> {
    let failed = |error: &dyn std::fmt::Display| KeyFileError::Encrypt(error.to_string());
    let mut out = Vec::new();
    let armored =
        ArmoredWriter::wrap_output(&mut out, Format::AsciiArmor).map_err(|e| failed(&e))?;
    let mut recipient = age::scrypt::Recipient::new(passphrase.clone());
    recipient.set_work_factor(WORK_FACTOR);
    let recipients: [&dyn age::Recipient; 1] = [&recipient];
    let mut writer = age::Encryptor::with_recipients(recipients.into_iter())
        .map_err(|e| failed(&e))?
        .wrap_output(armored)
        .map_err(|e| failed(&e))?;
    writer
        .write_all(secret.as_bytes())
        .map_err(|e| failed(&e))?;
    writer
        .finish()
        .and_then(ArmoredWriter::finish)
        .map_err(|e| failed(&e))?;
    String::from_utf8(out).map_err(|e| failed(&e))
}

/// Decrypts an armored `age` file. `path` only names the file in errors.
///
/// # Errors
///
/// Returns [`KeyFileError::Decrypt`] for a wrong passphrase,
/// [`KeyFileError::WorkFactor`] for a file that asks for too much scrypt work,
/// and [`KeyFileError::Damaged`] for anything else.
pub fn decrypt(
    armored: &str,
    passphrase: &SecretString,
    path: &Path,
) -> Result<Zeroizing<String>, KeyFileError> {
    let damaged = |reason: &dyn std::fmt::Display| KeyFileError::Damaged {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    };
    let decryptor =
        age::Decryptor::new(ArmoredReader::new(armored.as_bytes())).map_err(|e| damaged(&e))?;
    let mut identity = age::scrypt::Identity::new(passphrase.clone());
    identity.set_max_work_factor(MAX_WORK_FACTOR);
    let identities: [&dyn age::Identity; 1] = [&identity];
    let mut reader = decryptor
        .decrypt(identities.into_iter())
        .map_err(|error| match error {
            age::DecryptError::DecryptionFailed => KeyFileError::Decrypt {
                path: path.to_path_buf(),
            },
            age::DecryptError::ExcessiveWork { required, .. } => KeyFileError::WorkFactor {
                path: path.to_path_buf(),
                required,
            },
            other => damaged(&other),
        })?;
    let mut plain = Zeroizing::new(String::new());
    reader.read_to_string(&mut plain).map_err(|e| damaged(&e))?;
    Ok(plain)
}

/// Loads a node's keys from a key file, encrypted or plaintext, holding a seed
/// or a bare secp256k1 key in hex.
///
/// # Errors
///
/// Returns [`KeyFileError::NeedsPassphrase`] for an encrypted file with no
/// passphrase, [`KeyFileError::Decrypt`] for a wrong one, and
/// [`KeyFileError::Seed`] if the contents are not a seed or a key.
pub fn load_keys(path: &Path, passphrase: Option<&SecretString>) -> Result<NodeKeys, KeyFileError> {
    let text = Zeroizing::new(read(path)?);
    if !is_encrypted(&text) {
        return Ok(NodeKeys::from_text(&text)?);
    }
    let passphrase = passphrase.ok_or_else(|| KeyFileError::NeedsPassphrase {
        path: path.to_path_buf(),
    })?;
    let plain = decrypt(&text, passphrase, path)?;
    Ok(NodeKeys::from_text(&plain)?)
}

/// Loads the secp256k1 key from a key file, as [`load_keys`] reads it.
///
/// # Errors
///
/// As [`load_keys`].
pub fn load_signer(path: &Path, passphrase: Option<&SecretString>) -> Result<Signer, KeyFileError> {
    load_keys(path, passphrase).map(|keys| keys.signing)
}

/// Where a passphrase comes from.
#[derive(Clone, Debug)]
pub enum PassphraseSource {
    /// A file readable only by the operator. Trailing newlines are ignored.
    File(PathBuf),
    /// A prompt on the terminal. Fails when there is no terminal.
    Prompt,
}

impl PassphraseSource {
    /// A file if one was given, otherwise the terminal.
    #[must_use]
    pub fn from_file(path: Option<PathBuf>) -> Self {
        path.map_or(Self::Prompt, Self::File)
    }

    /// Reads the passphrase. `confirm` asks twice at a prompt, for keys being
    /// created rather than opened.
    ///
    /// # Errors
    ///
    /// Returns [`KeyFileError::Read`] if the file cannot be read,
    /// [`KeyFileError::NonInteractive`] if a prompt is needed and there is no
    /// terminal, [`KeyFileError::Mismatch`] if the confirmation differs, and
    /// [`KeyFileError::Empty`] for an empty passphrase.
    pub fn read(&self, what: &str, confirm: bool) -> Result<SecretString, KeyFileError> {
        let passphrase = match self {
            Self::File(path) => {
                let text = Zeroizing::new(read(path)?);
                SecretString::from(text.trim_end_matches(['\n', '\r']).to_owned())
            }
            Self::Prompt => {
                if !std::io::stdin().is_terminal() {
                    return Err(KeyFileError::NonInteractive);
                }
                let prompt_failed = |e: std::io::Error| KeyFileError::Read {
                    path: PathBuf::from("<terminal>"),
                    reason: e.to_string(),
                };
                let first = SecretString::from(
                    rpassword::prompt_password(format!("passphrase for {what}: "))
                        .map_err(prompt_failed)?,
                );
                if confirm {
                    let second = SecretString::from(
                        rpassword::prompt_password("confirm passphrase: ")
                            .map_err(prompt_failed)?,
                    );
                    if first.expose_secret() != second.expose_secret() {
                        return Err(KeyFileError::Mismatch);
                    }
                }
                first
            }
        };
        if passphrase.expose_secret().is_empty() {
            return Err(KeyFileError::Empty);
        }
        Ok(passphrase)
    }
}

fn read(path: &Path) -> Result<String, KeyFileError> {
    std::fs::read_to_string(path).map_err(|e| KeyFileError::Read {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passphrase(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("oracle-keyfile-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("creates");
        dir
    }

    #[test]
    fn encrypted_keys_round_trip_and_refuse_the_wrong_passphrase() {
        let signer = Signer::from_secret_bytes([5_u8; 32]).expect("valid key");
        let armored =
            encrypt(&signer.to_secret_hex(), &passphrase("correct horse")).expect("encrypts");
        assert!(is_encrypted(&armored));
        assert!(
            !armored.contains(&*signer.to_secret_hex()),
            "the hex must not appear in the file"
        );

        let path = Path::new("signing.key");
        let plain = decrypt(&armored, &passphrase("correct horse"), path).expect("decrypts");
        assert_eq!(plain.trim(), &*signer.to_secret_hex());
        assert!(matches!(
            decrypt(&armored, &passphrase("battery staple"), path),
            Err(KeyFileError::Decrypt { .. })
        ));
    }

    /// A key made on a fast machine must open on a slow one, so the work
    /// factor is fixed, and a file over the limit says so.
    #[test]
    fn keys_use_a_fixed_work_factor_and_too_much_work_is_named() {
        let signer = Signer::from_secret_bytes([7_u8; 32]).expect("valid key");
        let armored = encrypt(&signer.to_secret_hex(), &passphrase("pw")).expect("encrypts");
        let mut bytes = Vec::new();
        ArmoredReader::new(armored.as_bytes())
            .read_to_end(&mut bytes)
            .expect("armored");
        let stanza_end = format!(" {WORK_FACTOR}\n");
        let at = bytes
            .windows(stanza_end.len())
            .position(|window| window == stanza_end.as_bytes())
            .expect("the scrypt stanza names the fixed work factor");

        let over = MAX_WORK_FACTOR + 1;
        bytes.splice(at..at + stanza_end.len(), format!(" {over}\n").into_bytes());
        let mut tampered = Vec::new();
        let mut writer =
            ArmoredWriter::wrap_output(&mut tampered, Format::AsciiArmor).expect("wraps");
        writer.write_all(&bytes).expect("writes");
        writer.finish().expect("finishes");
        let tampered = String::from_utf8(tampered).expect("ascii");
        assert!(matches!(
            decrypt(&tampered, &passphrase("pw"), Path::new("signing.key")),
            Err(KeyFileError::WorkFactor { required, .. }) if required == over
        ));
    }

    #[test]
    fn load_signer_handles_plaintext_and_encrypted_files() {
        let dir = scratch("load");
        let signer = Signer::from_secret_bytes([6_u8; 32]).expect("valid key");

        let plain = dir.join("plain.key");
        std::fs::write(&plain, format!("{}\n", &*signer.to_secret_hex())).expect("writes");
        assert_eq!(
            load_signer(&plain, None).expect("loads").address(),
            signer.address()
        );

        let encrypted = dir.join("encrypted.key");
        let armored = encrypt(&signer.to_secret_hex(), &passphrase("pw")).expect("encrypts");
        std::fs::write(&encrypted, armored).expect("writes");
        assert!(file_is_encrypted(&encrypted).expect("reads"));
        assert!(matches!(
            load_signer(&encrypted, None),
            Err(KeyFileError::NeedsPassphrase { .. })
        ));
        assert_eq!(
            load_signer(&encrypted, Some(&passphrase("pw")))
                .expect("loads")
                .address(),
            signer.address()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_passphrase_file_is_trimmed_and_must_not_be_empty() {
        let dir = scratch("pass");
        let file = dir.join("passphrase");
        std::fs::write(&file, "hunter2\n").expect("writes");
        let read = PassphraseSource::File(file.clone())
            .read("test", false)
            .expect("reads");
        assert_eq!(read.expose_secret(), "hunter2");

        std::fs::write(&file, "\n").expect("writes");
        assert!(matches!(
            PassphraseSource::File(file).read("test", false),
            Err(KeyFileError::Empty)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `cargo test` has no terminal, which is exactly the case a prompt must
    /// refuse rather than hang.
    #[test]
    fn a_prompt_without_a_terminal_is_an_error() {
        if std::io::stdin().is_terminal() {
            return;
        }
        assert!(matches!(
            PassphraseSource::Prompt.read("test", false),
            Err(KeyFileError::NonInteractive)
        ));
    }
}
