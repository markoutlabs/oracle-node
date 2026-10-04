//! Where the registry document comes from.
//!
//! A source proves that the document it returns is current. The client then
//! verifies who signed it, against the pinned governance address, every time.
//! The two checks answer different questions: the governance signature says
//! the document is genuine, and the IC certificate says it is the canister's
//! latest. The canister publishes only on change (SPEC §3.6), so the
//! document's own `effective_from` says nothing about freshness.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use candid::Principal;
use ic_http_certification::{HttpRequest, HttpResponse, StatusCode};
use oracle_wire::Registry;

use crate::client::now_unix_nanos;

/// The Internet Computer mainnet root key, DER in hex. Every mainnet
/// certificate chains to it.
pub const IC_MAINNET_ROOT_KEY: &str = "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae";

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
    /// The response has no valid, recent certificate from the canister.
    #[error("response is not certified by the canister: {0}")]
    Uncertified(String),
    /// The canister id or the root key is not valid.
    #[error("invalid certification settings: {0}")]
    Settings(String),
}

/// Somewhere the latest registry document can be fetched from.
pub trait RegistrySource: Send + Sync {
    /// Fetches the latest document. The governance signature is unchecked.
    ///
    /// A success must prove the document is the latest one, as the IC
    /// certificate does. The client counts it as a freshness confirmation.
    fn fetch(&self) -> RegistryFuture<'_>;
}

/// The check that a canister served a response recently: its IC certificate.
#[derive(Clone, Debug)]
pub struct Certification {
    canister_id: Principal,
    root_key: Vec<u8>,
}

impl Certification {
    /// Oldest certificate accepted, the HTTP gateway's own limit. An older one
    /// is a replay of what the canister used to serve.
    pub const MAX_CERT_AGE: Duration = Duration::from_secs(300);

    /// A canister on mainnet.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::Settings`] if `canister_id` is not a principal.
    pub fn mainnet(canister_id: &str) -> Result<Self, FetchError> {
        Self::new(canister_id, IC_MAINNET_ROOT_KEY)
    }

    /// A canister on another network, such as a local replica. `root_key` is
    /// that network's DER root key in hex, from `dfx ping` or `icp network status`.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::Settings`] if `canister_id` is not a principal or
    /// `root_key` is not hex.
    pub fn new(canister_id: &str, root_key: &str) -> Result<Self, FetchError> {
        let canister_id = Principal::from_text(canister_id)
            .map_err(|error| FetchError::Settings(format!("canister id: {error}")))?;
        let root_key = hex::decode(root_key.trim().trim_start_matches("0x"))
            .map_err(|error| FetchError::Settings(format!("root key: {error}")))?;
        Ok(Self {
            canister_id,
            root_key,
        })
    }

    /// Checks the response to `GET path` against the canister's certificate at
    /// `now_ns`. Returns the certified body.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::Uncertified`] if the certificate is missing, is
    /// not the canister's, does not cover this response, or is older than
    /// [`Certification::MAX_CERT_AGE`].
    pub fn verify(
        &self,
        path: &str,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        now_ns: u64,
    ) -> Result<Vec<u8>, FetchError> {
        let status = StatusCode::from_u16(status)
            .map_err(|error| FetchError::Uncertified(error.to_string()))?;
        let response = HttpResponse::builder()
            .with_status_code(status)
            .with_headers(headers)
            .with_body(body)
            .build();
        // Version 2 at least: version 1 certifies only the body.
        let info = ic_response_verification::verify_request_response_pair(
            HttpRequest::get(path).build(),
            response,
            self.canister_id.as_slice(),
            u128::from(now_ns),
            Self::MAX_CERT_AGE.as_nanos(),
            &self.root_key,
            2,
        )
        .map_err(|error| FetchError::Uncertified(error.to_string()))?;
        info.response
            .map(|response| response.body)
            .ok_or_else(|| FetchError::Uncertified("the canister skipped certification".to_owned()))
    }
}

/// Fetches a governance-signed JSON document over HTTP: the registry or the
/// client list. The response must carry the canister's certificate.
pub struct HttpDocumentSource {
    url: reqwest::Url,
    certification: Certification,
    client: reqwest::Client,
}

impl HttpDocumentSource {
    /// How long one fetch may take.
    pub const TIMEOUT: Duration = Duration::from_secs(10);

    /// A source at an explicit URL, certified by `certification`'s canister.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::Settings`] for a URL that does not parse, or
    /// [`FetchError::Transport`] if the HTTP client cannot be built, which
    /// means TLS is misconfigured in this binary.
    pub fn new(url: &str, certification: Certification) -> Result<Self, FetchError> {
        let url = reqwest::Url::parse(url)
            .map_err(|error| FetchError::Settings(format!("url `{url}`: {error}")))?;
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
            url,
            certification,
            client,
        })
    }

    /// The URL fetched.
    #[must_use]
    pub fn url(&self) -> &str {
        self.url.as_str()
    }

    /// Fetches the document, checks its certificate, and parses it. The
    /// governance signature is unchecked.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::Transport`] for a transport failure or an error
    /// status, [`FetchError::Uncertified`] for a response the canister did not
    /// certify recently, and [`FetchError::Malformed`] for a body that does
    /// not parse.
    pub async fn fetch<T: serde::de::DeserializeOwned>(&self) -> Result<T, FetchError> {
        let response = self
            .client
            .get(self.url.clone())
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| FetchError::Transport(error.to_string()))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect();
        let body = response
            .bytes()
            .await
            .map_err(|error| FetchError::Transport(error.to_string()))?;
        let certified = self.certification.verify(
            self.url.path(),
            status,
            headers,
            body.to_vec(),
            now_unix_nanos(),
        )?;
        serde_json::from_slice(&certified).map_err(|error| FetchError::Malformed(error.to_string()))
    }
}

/// Fetches the registry document from the canister over HTTP.
pub struct HttpRegistrySource {
    document: HttpDocumentSource,
}

impl HttpRegistrySource {
    /// How long one fetch may take.
    pub const TIMEOUT: Duration = HttpDocumentSource::TIMEOUT;

    /// A source at an explicit URL, certified by `certification`'s canister.
    ///
    /// # Errors
    ///
    /// See [`HttpDocumentSource::new`].
    pub fn new(url: &str, certification: Certification) -> Result<Self, FetchError> {
        Ok(Self {
            document: HttpDocumentSource::new(url, certification)?,
        })
    }

    /// The registry canister's `/registry.json` on mainnet.
    ///
    /// The `raw` domain hands over the canister's response as it is, and this
    /// client checks the certificate itself.
    ///
    /// # Errors
    ///
    /// See [`HttpRegistrySource::new`].
    pub fn canister(canister_id: &str) -> Result<Self, FetchError> {
        Self::new(
            &format!("https://{canister_id}.raw.icp0.io/registry.json"),
            Certification::mainnet(canister_id)?,
        )
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
        assert_eq!(source.url(), "https://aaaaa-aa.raw.icp0.io/registry.json");
    }

    #[test]
    fn bad_certification_settings_are_refused() {
        assert!(matches!(
            Certification::mainnet("not a principal"),
            Err(FetchError::Settings(_))
        ));
        assert!(matches!(
            Certification::new("aaaaa-aa", "zz"),
            Err(FetchError::Settings(_))
        ));
        assert_eq!(
            Certification::mainnet("aaaaa-aa")
                .expect("valid")
                .root_key
                .len(),
            133
        );
    }
}
