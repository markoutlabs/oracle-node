//! Where the registry document comes from.
//!
//! A source hands back an unverified [`Registry`]. Verifying it against the
//! pinned governance address is the client's job, every time, so a source can
//! be a canister, a CDN, a file, or a test double without changing what is
//! trusted. See SPEC §3.6.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use oracle_wire::Registry;

/// A pending fetch.
pub type RegistryFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Registry, FetchError>> + Send + 'a>>;

/// A fetch failed before verification could even start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FetchError {
    /// The transport failed, or the server answered with an error status.
    #[error("registry fetch failed: {0}")]
    Transport(String),
    /// The body was not a registry document.
    #[error("registry document is not valid JSON: {0}")]
    Malformed(String),
}

/// Somewhere the latest registry document can be fetched from.
pub trait RegistrySource: Send + Sync {
    /// Fetches the latest document. Unverified.
    fn fetch(&self) -> RegistryFuture<'_>;
}

/// Fetches a governance-signed JSON document over HTTP: the registry or the
/// client list. The response is not checked beyond parsing; the document's own
/// governance signature is the check, so a tampering gateway can only serve
/// what governance signed.
pub struct HttpDocumentSource {
    url: String,
    client: reqwest::Client,
}

impl HttpDocumentSource {
    /// How long one fetch may take.
    pub const TIMEOUT: Duration = Duration::from_secs(10);

    /// A source at an explicit URL.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::Transport`] if the HTTP client cannot be built,
    /// which means TLS is misconfigured in this binary.
    pub fn new(url: impl Into<String>) -> Result<Self, FetchError> {
        // reqwest is built with `rustls-no-provider`, which leaves the choice of
        // crypto provider to the binary. The workspace already uses `ring`
        // through tokio-tungstenite; make it the process default unless the
        // embedding application installed one first.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .timeout(Self::TIMEOUT)
            .build()
            .map_err(|error| FetchError::Transport(error.to_string()))?;
        Ok(Self {
            url: url.into(),
            client,
        })
    }

    /// The URL fetched.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Fetches and parses the document. Unverified.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::Transport`] for a transport failure or an error
    /// status, and [`FetchError::Malformed`] for a body that does not parse.
    pub async fn fetch<T: serde::de::DeserializeOwned>(&self) -> Result<T, FetchError> {
        let text = self
            .client
            .get(&self.url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| FetchError::Transport(error.to_string()))?
            .text()
            .await
            .map_err(|error| FetchError::Transport(error.to_string()))?;
        serde_json::from_str(&text).map_err(|error| FetchError::Malformed(error.to_string()))
    }
}

/// Fetches the registry document over HTTP. Freshness is the client's
/// `max_registry_age`.
pub struct HttpRegistrySource {
    document: HttpDocumentSource,
}

impl HttpRegistrySource {
    /// How long one fetch may take.
    pub const TIMEOUT: Duration = HttpDocumentSource::TIMEOUT;

    /// A source at an explicit URL.
    ///
    /// # Errors
    ///
    /// See [`HttpDocumentSource::new`].
    pub fn new(url: impl Into<String>) -> Result<Self, FetchError> {
        Ok(Self {
            document: HttpDocumentSource::new(url)?,
        })
    }

    /// The registry canister's `/registry.json` on the Internet Computer.
    ///
    /// The canister certifies the response, so no `raw` domain is needed. The
    /// document's own governance signature remains the check that matters.
    ///
    /// # Errors
    ///
    /// See [`HttpRegistrySource::new`].
    pub fn canister(canister_id: &str) -> Result<Self, FetchError> {
        Self::new(format!("https://{canister_id}.icp0.io/registry.json"))
    }

    /// The URL fetched.
    #[must_use]
    pub fn url(&self) -> &str {
        self.document.url()
    }
}

impl RegistrySource for HttpRegistrySource {
    fn fetch(&self) -> RegistryFuture<'_> {
        Box::pin(self.document.fetch::<Registry>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Building the client is where TLS providers get resolved. With `ring`
    /// from tungstenite and no second provider from reqwest, this must work.
    #[test]
    fn the_http_client_builds_with_the_workspace_tls_provider() {
        let source = HttpRegistrySource::canister("aaaaa-aa").expect("builds");
        assert_eq!(source.url(), "https://aaaaa-aa.icp0.io/registry.json");
    }
}
