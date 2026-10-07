//! What `init` writes, decided before anything is written.
//!
//! Every value is parsed into a type that only holds what the registry and the
//! node accept, so a [`NodeSetup`] that exists is one that can be written.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::{ExposeSecret as _, SecretString};
use oracle_client::Certification;
use oracle_wire::{Address, EntryError, check_endpoint};

use super::{InitError, NodeKey, starter, unit, write_secret};

/// A WebSocket endpoint the registry accepts: what clients dial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint(String);

impl FromStr for Endpoint {
    type Err = EntryError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        check_endpoint(text)?;
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Endpoint {
    /// Returns `true` if the URL names this machine. The registry lists the
    /// endpoint for every client, and no client elsewhere can dial it.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        let Some(uri) = self.0.parse::<axum::http::Uri>().ok() else {
            return false;
        };
        let Some(host) = uri.host() else {
            return false;
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    }

    /// The port the URL names, which the node listens on.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.0
            .parse::<axum::http::Uri>()
            .ok()
            .and_then(|uri| uri.port_u16())
    }
}

/// Expands a leading `~` to the home directory, and makes the path absolute.
///
/// A shell expands `~` in an argument, but not in a wizard answer or after
/// `--out=`. Without this, `~/node` makes a directory named `~`.
///
/// # Errors
///
/// Returns the error of [`std::path::absolute`], such as a missing current
/// directory.
pub fn resolve_path(path: &Path) -> std::io::Result<PathBuf> {
    let expanded = path.to_str().map_or_else(
        || path.to_owned(),
        |text| PathBuf::from(shellexpand::tilde(text).as_ref()),
    );
    std::path::absolute(expanded)
}

/// A registry canister id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanisterId(String);

impl FromStr for CanisterId {
    type Err = oracle_client::FetchError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        Certification::mainnet(text)?;
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for CanisterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A network's root key, DER in hex, as `icp network status --json` prints it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootKey(String);

impl FromStr for RootKey {
    type Err = oracle_client::FetchError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim().trim_start_matches("0x");
        Certification::new("aaaaa-aa", text)?;
        Ok(Self(text.to_owned()))
    }
}

/// An HTTP gateway in front of a network that is not mainnet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gateway(String);

impl FromStr for Gateway {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim().trim_end_matches('/');
        let uri: axum::http::Uri = text
            .parse()
            .map_err(|error| format!("`{text}` is not a URL: {error}"))?;
        match uri.scheme_str() {
            Some("http" | "https") if uri.host().is_some() => Ok(Self(text.to_owned())),
            _ => Err(format!("`{text}` is not an http:// or https:// URL")),
        }
    }
}

impl fmt::Display for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where the node fetches its registry and client list: always the canister.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrySource {
    /// The registry canister on mainnet.
    Mainnet(CanisterId),
    /// The registry canister on the local network.
    Network {
        /// The canister.
        canister: CanisterId,
        /// The HTTP gateway in front of it.
        gateway: Gateway,
        /// The network's root key, which its certificates chain to.
        root_key: RootKey,
    },
}

impl RegistrySource {
    /// The deployed mainnet canister and its governance address, from
    /// [`oracle_client::mainnet`]. `None` until the canister is deployed.
    ///
    /// # Panics
    ///
    /// Panics if a constant does not parse; a test pins them.
    #[must_use]
    pub fn mainnet() -> Option<(Self, Address)> {
        let canister = oracle_client::mainnet::CANISTER_ID?
            .parse()
            .expect("the mainnet canister id parses");
        let governance = oracle_client::mainnet::GOVERNANCE_ADDRESS?
            .parse()
            .expect("the mainnet governance address parses");
        Some((Self::Mainnet(canister), governance))
    }

    /// The icp-cli network name for calls to the canister: `ic` or `local`.
    #[must_use]
    pub const fn network(&self) -> &'static str {
        match self {
            Self::Mainnet(_) => "ic",
            Self::Network { .. } => "local",
        }
    }

    /// The canister.
    #[must_use]
    pub const fn canister(&self) -> &CanisterId {
        match self {
            Self::Mainnet(canister) | Self::Network { canister, .. } => canister,
        }
    }

    /// The URL of one of the canister's documents, such as `registry.json`.
    #[must_use]
    pub fn url(&self, document: &str) -> String {
        match self {
            // The raw domain hands over the canister's response as it is; the
            // node checks the certificate itself.
            Self::Mainnet(canister) => format!("https://{canister}.raw.icp0.io/{document}"),
            Self::Network {
                canister, gateway, ..
            } => format!("{gateway}/{document}?canisterId={canister}"),
        }
    }

    pub(super) fn root_key(&self) -> Option<&str> {
        match self {
            Self::Network { root_key, .. } => Some(root_key.0.as_str()),
            Self::Mainnet(_) => None,
        }
    }
}

/// How the node opens its key at start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unlock {
    /// A new random passphrase, written to this 0600 file. Under systemd
    /// nobody can type, so a service needs a file.
    NewPassphraseFile(PathBuf),
    /// The passphrase in this existing 0600 file.
    PassphraseFile(PathBuf),
    /// A passphrase typed at each start.
    Prompt,
}

impl Unlock {
    /// The file the node reads its passphrase from, if any.
    #[must_use]
    pub fn file(&self) -> Option<&Path> {
        match self {
            Self::NewPassphraseFile(path) | Self::PassphraseFile(path) => Some(path),
            Self::Prompt => None,
        }
    }
}

/// A systemd unit that runs the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceUnit {
    /// The user it runs as. The key file is 0600 and theirs.
    pub user: String,
    /// The `oracle-node` binary it starts.
    pub exe: PathBuf,
}

/// Everything `init` writes, decided up front.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeSetup {
    /// Where the files go.
    pub dir: PathBuf,
    /// What clients dial.
    pub endpoint: Endpoint,
    /// Where the registry and client list come from.
    pub source: RegistrySource,
    /// The governance address: the canister's signing key, which the node pins.
    pub governance: Address,
    /// How the node opens its key.
    pub unlock: Unlock,
    /// A systemd unit to write, if wanted.
    pub service: Option<ServiceUnit>,
}

/// What [`NodeSetup::write`] wrote. Every path is absolute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    /// The encrypted key.
    pub key: PathBuf,
    /// The registry entry for governance.
    pub entry: PathBuf,
    /// The starter config.
    pub config: PathBuf,
    /// The new passphrase file, if one was made.
    pub passphrase: Option<PathBuf>,
    /// The systemd unit, if one was made.
    pub unit: Option<PathBuf>,
}

impl NodeSetup {
    /// The key file this setup writes. It must not exist yet.
    #[must_use]
    pub fn key_path(&self) -> PathBuf {
        self.dir.join("signing.key")
    }

    /// Checks the rules between fields.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::Invalid`] for a service without a passphrase file.
    pub fn check(&self) -> Result<(), InitError> {
        if self.service.is_some() && self.unlock.file().is_none() {
            return Err(InitError::Invalid(
                "a systemd unit needs a passphrase file: nobody can type at a service".to_owned(),
            ));
        }
        Ok(())
    }

    /// Writes the key, the registry entry, the starter config, and the
    /// passphrase file and unit when the setup asks for them. Paths in the
    /// config and the unit are absolute, so neither depends on the directory
    /// the node starts in.
    ///
    /// # Errors
    ///
    /// Returns [`InitError`] if a rule is broken or a file cannot be written.
    /// The key is written first, with `create_new`, so an existing node is
    /// never overwritten.
    pub fn write(&self, key: &NodeKey, passphrase: &SecretString) -> Result<Written, InitError> {
        self.check()?;
        let setup = self.absolute()?;
        let key_path = key.write_key(&setup.dir, passphrase)?;

        let new_passphrase = match &setup.unlock {
            Unlock::NewPassphraseFile(path) => {
                write_secret(path, passphrase.expose_secret())?;
                Some(path.clone())
            }
            Unlock::PassphraseFile(_) | Unlock::Prompt => None,
        };

        let entry_path = setup.dir.join("node-entry.json");
        let entry = serde_json::to_string_pretty(&key.entry(&setup.endpoint))
            .map_err(|e| write_error(&entry_path, &e))?;
        write_file(&entry_path, &format!("{entry}\n"))?;

        let config_path = setup.dir.join("config.toml");
        write_file(&config_path, &starter::render(&setup, &key_path))?;

        let unit_path = match &setup.service {
            Some(service) => {
                let path = setup.dir.join("oracle-node.service");
                let text = unit::render(service, &config_path, key.signing.address())?;
                write_file(&path, &text)?;
                Some(path)
            }
            None => None,
        };

        Ok(Written {
            key: key_path,
            entry: entry_path,
            config: config_path,
            passphrase: new_passphrase,
            unit: unit_path,
        })
    }

    fn absolute(&self) -> Result<Self, InitError> {
        let absolute = |path: &Path| resolve_path(path).map_err(|e| write_error(path, &e));
        let mut setup = self.clone();
        setup.dir = absolute(&self.dir)?;
        setup.unlock = match &self.unlock {
            Unlock::NewPassphraseFile(path) => Unlock::NewPassphraseFile(absolute(path)?),
            Unlock::PassphraseFile(path) => Unlock::PassphraseFile(absolute(path)?),
            Unlock::Prompt => Unlock::Prompt,
        };
        if let Some(service) = &mut setup.service {
            service.exe = absolute(&service.exe)?;
        }
        Ok(setup)
    }
}

fn write_file(path: &Path, contents: &str) -> Result<(), InitError> {
    std::fs::write(path, contents).map_err(|e| write_error(path, &e))
}

fn write_error(path: &Path, error: &dyn std::error::Error) -> InitError {
    InitError::Write {
        path: path.to_path_buf(),
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_endpoints_are_recognised() {
        for local in [
            "ws://127.0.0.1:8791/v2/ws",
            "ws://localhost:8791/v2/ws",
            "ws://LOCALHOST/v2/ws",
            "ws://[::1]:8791/v2/ws",
            "ws://127.9.9.9/v2/ws",
        ] {
            let endpoint: Endpoint = local.parse().expect("valid");
            assert!(endpoint.is_loopback(), "{local}");
        }
        for public in ["wss://node.example.com/v2/ws", "ws://10.0.0.5:8791/v2/ws"] {
            let endpoint: Endpoint = public.parse().expect("valid");
            assert!(!endpoint.is_loopback(), "{public}");
        }
    }

    #[test]
    fn a_path_is_absolute_and_a_tilde_is_the_home_directory() {
        let relative = resolve_path(Path::new("oracle-node")).expect("absolute");
        assert_eq!(
            relative,
            std::env::current_dir().expect("a cwd").join("oracle-node")
        );
        if let Ok(home) = std::env::var("HOME") {
            let tilde = resolve_path(Path::new("~/oracle-node")).expect("absolute");
            assert_eq!(tilde, Path::new(&home).join("oracle-node"));
        }
        let elsewhere = resolve_path(Path::new("/srv/~node")).expect("absolute");
        assert_eq!(elsewhere, Path::new("/srv/~node"), "only a leading tilde");
    }

    #[test]
    fn values_parse_into_what_the_registry_accepts() {
        assert!("wss://eu1.example/v2/ws".parse::<Endpoint>().is_ok());
        for bad in ["http://eu1.example", &format!("wss://{}", "x".repeat(251))] {
            assert!(bad.parse::<Endpoint>().is_err(), "{bad}");
        }
        assert!("uxrrr-q7777-77774-qaaaq-cai".parse::<CanisterId>().is_ok());
        assert!("not a principal".parse::<CanisterId>().is_err());
        assert!("3082".parse::<RootKey>().is_ok());
        assert!("xyz".parse::<RootKey>().is_err());
        assert_eq!(
            "http://127.0.0.1:8000/"
                .parse::<Gateway>()
                .map(|g| g.to_string()),
            Ok("http://127.0.0.1:8000".to_owned())
        );
        for bad in ["127.0.0.1:8000", "ftp://x", "http://"] {
            assert!(bad.parse::<Gateway>().is_err(), "{bad}");
        }
    }

    #[test]
    fn the_endpoint_names_the_listen_port() {
        let port = |text: &str| text.parse::<Endpoint>().ok().and_then(|e| e.port());
        assert_eq!(port("ws://127.0.0.1:9001/v2/ws"), Some(9001));
        // A colon later in the URL must not be mistaken for the port.
        assert_eq!(port("ws://127.0.0.1:9001/v2/ws?x=a:1"), Some(9001));
        assert_eq!(port("wss://eu1.example/v2/ws"), None);
    }

    #[test]
    fn canister_urls_follow_the_network() {
        let canister: CanisterId = "uxrrr-q7777-77774-qaaaq-cai".parse().expect("valid");
        assert_eq!(
            RegistrySource::Mainnet(canister.clone()).url("registry.json"),
            "https://uxrrr-q7777-77774-qaaaq-cai.raw.icp0.io/registry.json"
        );
        let local = RegistrySource::Network {
            canister,
            gateway: "http://127.0.0.1:8000".parse().expect("valid"),
            root_key: "3082".parse().expect("valid"),
        };
        assert_eq!(
            local.url("clients.json"),
            "http://127.0.0.1:8000/clients.json?canisterId=uxrrr-q7777-77774-qaaaq-cai"
        );
    }

    /// When deployment sets the constants, they must parse.
    #[test]
    fn the_mainnet_constants_parse_once_set() {
        assert_eq!(
            RegistrySource::mainnet().is_some(),
            oracle_client::mainnet::CANISTER_ID.is_some()
                && oracle_client::mainnet::GOVERNANCE_ADDRESS.is_some()
        );
    }
}
