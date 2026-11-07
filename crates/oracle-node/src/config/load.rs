//! The config's key and signed documents: the registry, the client list and
//! the network's feed set, each from a file or from the canister.

use std::path::Path;

use super::{ConfigError, NodeConfig};

impl NodeConfig {
    /// Loads a config file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] or [`ConfigError::Parse`].
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })
    }

    /// Loads the secp256k1 signing key from the configured source.
    ///
    /// # Errors
    ///
    /// As [`Self::load_node_keys`].
    pub fn load_signing_key(&self) -> Result<oracle_wire::Signer, ConfigError> {
        self.load_node_keys().map(|keys| keys.signing)
    }

    /// Loads the node's keys from the configured source.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::SigningKey`] if no source is configured, the source
    /// cannot be read, or the value is not a seed or a key. A default build
    /// also refuses `key_env`.
    pub fn load_node_keys(&self) -> Result<crate::NodeKeys, ConfigError> {
        let failed = |e: &dyn std::fmt::Display| ConfigError::SigningKey(e.to_string());
        match (&self.signing.key_file, &self.signing.key_env) {
            (Some(path), _) => {
                // The passphrase is read only for an encrypted file, so a
                // plaintext playground key never prompts.
                let passphrase =
                    if crate::keyfile::file_is_encrypted(path).map_err(|e| failed(&e))? {
                        let source = crate::keyfile::PassphraseSource::from_file(
                            self.signing.passphrase_file.clone(),
                        );
                        Some(
                            source
                                .read(&path.display().to_string(), false)
                                .map_err(|e| failed(&e))?,
                        )
                    } else {
                        None
                    };
                crate::keyfile::load_keys(path, passphrase.as_ref()).map_err(|e| failed(&e))
            }
            (None, Some(var)) => key_from_env(var),
            (None, None) => Err(ConfigError::SigningKey("set signing.key_file".to_owned())),
        }
    }

    /// Fetches the registry from its configured source and verifies it against
    /// the pinned governance address.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Registry`] if not exactly one of `registry.path`
    /// and `registry.url` is set, if the document cannot be read or fetched, or
    /// if it is not signed by the pinned key.
    pub async fn fetch_registry(&self) -> Result<oracle_wire::Registry, ConfigError> {
        let registry: oracle_wire::Registry = self
            .load_document(
                "registry",
                self.registry.path.as_deref(),
                self.registry.url.as_deref(),
            )
            .await
            .map_err(ConfigError::Registry)?;
        registry
            .verify(self.governance()?, 0)
            .map_err(|e| ConfigError::Registry(e.to_string()))?;
        Ok(registry)
    }

    /// Returns the pinned governance address.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if it does not parse or is the zero
    /// placeholder.
    pub fn governance(&self) -> Result<oracle_wire::Address, ConfigError> {
        let address: oracle_wire::Address = self
            .registry
            .governance_address
            .parse()
            .map_err(|e| ConfigError::Invalid(format!("registry.governance_address: {e}")))?;
        if address == oracle_wire::Address::default() {
            return Err(ConfigError::Invalid(
                "registry.governance_address is the placeholder init wrote; set it to the \
                 address governance gave you"
                    .to_owned(),
            ));
        }
        Ok(address)
    }

    /// Fetches the client list, unverified, or `None` without a `[clients]`
    /// section. Verifying it against the governance address is the caller's job.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Clients`] if not exactly one of `path` and `url`
    /// is set, or the document cannot be read or fetched.
    pub async fn fetch_client_list(&self) -> Result<Option<oracle_wire::ClientList>, ConfigError> {
        let Some(clients) = &self.clients else {
            return Ok(None);
        };
        self.load_document("clients", clients.path.as_deref(), clients.url.as_deref())
            .await
            .map(Some)
            .map_err(ConfigError::Clients)
    }

    /// Fetches the network's feed set with its certificate checked, but not its signature.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::FeedSet`] when the fetch or the certificate fails.
    pub async fn fetch_feed_set(&self) -> Result<Option<oracle_wire::FeedSet>, ConfigError> {
        let Some(settings) = &self.network_feeds else {
            return Ok(None);
        };
        self.load_document("network_feeds", None, Some(settings.url.as_str()))
            .await
            .map(Some)
            .map_err(ConfigError::FeedSet)
    }

    /// Reads a signed document from a file, or fetches it from the canister
    /// with its certificate checked. The governance signature is unchecked.
    async fn load_document<T: serde::de::DeserializeOwned>(
        &self,
        section: &str,
        path: Option<&std::path::Path>,
        url: Option<&str>,
    ) -> Result<T, String> {
        match (path, url) {
            (Some(path), None) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
            }
            (None, Some(url)) => {
                let canister_id = self.registry.canister_id.as_deref().ok_or(
                    "set registry.canister_id: a fetched document must carry its certificate",
                )?;
                let certification = match &self.registry.root_key {
                    Some(root_key) => oracle_client::Certification::new(canister_id, root_key),
                    None => oracle_client::Certification::mainnet(canister_id),
                }
                .map_err(|e| e.to_string())?;
                oracle_client::HttpDocumentSource::new(url, certification)
                    .map_err(|e| e.to_string())?
                    .fetch()
                    .await
                    .map_err(|e| format!("{url}: {e}"))
            }
            _ => Err(format!(
                "set exactly one of {section}.path and {section}.url"
            )),
        }
    }
}

/// The environment keeps a copy of the key for the life of the process, and
/// the workspace forbids the unsafe `remove_var`. So only a playground build reads it.
#[cfg(feature = "dev-key-env")]
fn key_from_env(var: &str) -> Result<crate::NodeKeys, ConfigError> {
    // Wiped on drop. The value is a seed or a bare key.
    let text = zeroize::Zeroizing::new(
        std::env::var(var).map_err(|_| ConfigError::SigningKey(format!("${var} is not set")))?,
    );
    crate::NodeKeys::from_text(&text).map_err(|e| ConfigError::SigningKey(e.to_string()))
}

#[cfg(not(feature = "dev-key-env"))]
fn key_from_env(var: &str) -> Result<crate::NodeKeys, ConfigError> {
    Err(ConfigError::SigningKey(format!(
        "signing.key_env = \"{var}\" works only in a build with `--features dev-key-env`, \
         for a local playground: the process environment keeps the key while the node runs. \
         Set signing.key_file instead"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::fixture::config;

    #[tokio::test]
    async fn the_clients_section_is_optional_and_exactly_one_source() {
        /// The default `clients.poll_secs`.
        const POLL_SECS: u64 = 30;
        let none = config().parse();
        assert!(none.clients.is_none());
        assert!(
            none.fetch_client_list()
                .await
                .expect("no section")
                .is_none()
        );

        let clients = |body: &str| config().section(&format!("[clients]\n{body}")).parse();
        let url = r#"url = "http://127.0.0.1:1/clients.json""#;
        assert_eq!(
            clients(url).clients.as_ref().map(|c| c.poll_secs),
            Some(POLL_SECS)
        );
        for bad in [
            clients("poll_secs = 5"),
            clients(&format!("path = \"c.json\"\n{url}")),
        ] {
            let error = bad.fetch_client_list().await.expect_err("must refuse");
            assert!(error.to_string().contains("exactly one"), "{error}");
        }
    }

    #[tokio::test]
    async fn the_registry_source_is_exactly_one_of_path_and_url() {
        for source in [
            "",
            "path = \"r.json\"\nurl = \"http://127.0.0.1:1/registry.json\"",
        ] {
            let error = config()
                .registry(source)
                .parse()
                .fetch_registry()
                .await
                .expect_err("must refuse");
            assert!(error.to_string().contains("exactly one"), "{error}");
        }
    }

    /// A validly signed registry from a plain server is refused: only the
    /// canister's certificate proves that it is the latest version.
    #[tokio::test]
    async fn a_registry_url_needs_the_canister_certificate() {
        use oracle_client::testing::{governance, signed_registry};

        let registry = signed_registry(3, Vec::new());
        let json = serde_json::to_string(&registry).expect("serialises");
        let app = axum::Router::new().route(
            "/registry.json",
            axum::routing::get(move || std::future::ready(json.clone())),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serves");
        });

        let fetched = |extra: &str| {
            config()
                .registry(&format!(
                    "url = \"http://{address}/registry.json\"\n{extra}"
                ))
                .governance(governance().address())
                .parse()
        };
        let error = fetched("").fetch_registry().await.expect_err("no canister");
        assert!(error.to_string().contains("canister_id"), "{error}");
        let error = fetched("canister_id = \"aaaaa-aa\"")
            .fetch_registry()
            .await
            .expect_err("uncertified");
        assert!(error.to_string().contains("not certified"), "{error}");
    }

    #[test]
    fn a_missing_signing_key_source_is_an_error_not_a_default() {
        assert!(matches!(
            config().signing("").parse().load_signing_key(),
            Err(ConfigError::SigningKey(_))
        ));
    }

    /// `PATH` is set in every test run, so only the build refuses it.
    #[cfg(not(feature = "dev-key-env"))]
    #[test]
    fn a_default_build_refuses_a_key_from_the_environment() {
        let error = config()
            .signing(r#"key_env = "PATH""#)
            .parse()
            .load_signing_key()
            .expect_err("refused");
        assert!(
            matches!(&error, ConfigError::SigningKey(m) if m.contains("dev-key-env")),
            "{error}"
        );
    }

    #[cfg(feature = "dev-key-env")]
    #[test]
    fn a_playground_build_reads_the_key_from_the_environment() {
        let error = config()
            .signing(r#"key_env = "ORACLE_TEST_UNSET_KEY""#)
            .parse()
            .load_signing_key()
            .expect_err("unset");
        assert!(error.to_string().contains("is not set"), "{error}");
    }
}
