//! The proxy's one SDK client, and the loop that feeds the hub from it.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use oracle_client::{
    Certification, Event, HttpRegistrySource, OracleClient, mainnet, now_unix_nanos,
};
use oracle_types::Symbol;
use oracle_wire::{Address, Signer};
use tokio::time::Instant;
use tracing::info;

use crate::config::{FeedsConfig, UpstreamConfig};
use crate::hub::{Hub, UpstreamStatus};

/// How often each price feed is resolved again without a new frame. A node
/// that goes silent then shows as a halted feed, not as the last good price.
const RESOLVE_EVERY: Duration = Duration::from_secs(1);

/// Builds the SDK client, verifies the registry, and subscribes.
///
/// # Errors
///
/// Returns an error if the key file is unreadable or open to others, the
/// registry does not verify against the governance address, or no node lists
/// an endpoint.
pub async fn connect(
    upstream: &UpstreamConfig,
    feeds: &FeedsConfig,
) -> anyhow::Result<OracleClient> {
    let key = read_client_key(&upstream.client_key_file)?;
    let canister = upstream
        .canister_id
        .as_deref()
        .or(mainnet::CANISTER_ID)
        .context("no canister_id, and this build has no mainnet canister")?;
    let governance: Address = match upstream.governance {
        Some(address) => address,
        None => mainnet::GOVERNANCE_ADDRESS
            .context("no governance address, and this build has no mainnet one")?
            .parse()
            .context("the mainnet governance address")?,
    };
    let source = match (&upstream.registry_url, &upstream.root_key) {
        (Some(url), Some(root_key)) => {
            HttpRegistrySource::new(url, Certification::new(canister, root_key)?)?
        }
        _ => HttpRegistrySource::canister(canister)?,
    };
    let mut builder = OracleClient::builder_from_source(Arc::new(source), governance)
        .await
        .context("the registry")?
        .client_key(key)
        .quorum(upstream.quorum);
    if upstream.allow_low_quorum {
        builder = builder.i_understand_this_provides_no_protection_against_a_bad_node();
    }
    let mut client = builder.build()?;
    info!(
        registry = client.registry_version(),
        %governance,
        "registry verified"
    );
    // Each call reconnects every node with the full set, so the last one counts.
    let names =
        |symbols: &[Symbol]| -> Vec<String> { symbols.iter().map(ToString::to_string).collect() };
    let (prices, venues, books) = (
        names(&feeds.prices),
        names(&feeds.venues),
        names(&feeds.books),
    );
    fn refs(names: &[String]) -> Vec<&str> {
        names.iter().map(String::as_str).collect()
    }
    if !venues.is_empty() {
        client.subscribe_venues(&refs(&venues)).await?;
    }
    if !books.is_empty() {
        client.subscribe_books(&refs(&books)).await?;
    }
    client.subscribe(&refs(&prices)).await?;
    Ok(client)
}

/// Reads the client key: hex in a file that only its owner can read.
fn read_client_key(path: &Path) -> anyhow::Result<Signer> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("cannot read {}", path.display()))?
            .permissions()
            .mode();
        anyhow::ensure!(
            mode & 0o077 == 0,
            "{} is readable by others (mode {:o}); run chmod 600 on it",
            path.display(),
            mode & 0o777
        );
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    Signer::from_hex(text.trim()).with_context(|| format!("{} holds no valid key", path.display()))
}

/// Feeds the hub until every node connection ends.
///
/// # Errors
///
/// Returns an error when the SDK reports that every connection ended.
pub async fn run(
    mut client: OracleClient,
    hub: Arc<Hub>,
    prices: Vec<Symbol>,
    book_interval: Duration,
) -> anyhow::Result<()> {
    let mut next_books = Instant::now() + book_interval;
    let mut next_resolve = Instant::now() + RESOLVE_EVERY;
    loop {
        // A deadline rather than `select!`: the event future keeps its borrow,
        // and the timers run between events however busy the stream is.
        let deadline = next_books.min(next_resolve);
        match tokio::time::timeout_at(deadline, client.next_event()).await {
            Ok(Some(Event::Price(resolved))) => hub.publish_price(&resolved),
            Ok(Some(Event::Venues(accepted))) => hub.publish_venues(&accepted),
            Ok(Some(Event::Book(_))) | Err(_) => {}
            Ok(None) => anyhow::bail!("every node connection ended"),
        }
        let now = Instant::now();
        if now >= next_books {
            next_books = now + book_interval;
            let at = now_unix_nanos();
            let instruments: Vec<_> = client.book_instruments().cloned().collect();
            for instrument in &instruments {
                hub.update_book(instrument, client.book(instrument, at));
            }
        }
        if now >= next_resolve {
            next_resolve = now + RESOLVE_EVERY;
            let at = now_unix_nanos();
            for symbol in &prices {
                if let Some(resolved) = client.resolve(symbol, at) {
                    hub.publish_price(&resolved);
                }
            }
            let status = UpstreamStatus {
                registry_version: client.registry_version(),
                stats: client.stats(),
            };
            hub.set_upstream(status);
        }
    }
}
