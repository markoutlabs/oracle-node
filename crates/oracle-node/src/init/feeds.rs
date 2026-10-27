//! The network's feeds, built into the binary. Every node that `init` makes
//! serves the same feeds, so a quorum can form on each one.

use std::collections::BTreeMap;

use toml_edit::DocumentMut;

use super::InitError;
use crate::config::max_pending;

/// The hand-written feeds, below the settings of a local test node.
const CORE: &str = include_str!("../../../../node/all-feeds.toml");
/// The most traded assets, from `scripts/asset-feeds.py`.
const ASSETS: &str = include_str!("../../../../node/assets.toml");

/// The `[[feeds]]` tables of the built-in files.
pub(super) struct NetworkFeeds {
    /// The tables as TOML, with their comments.
    pub(super) text: String,
    /// How many feeds the text holds.
    pub(super) count: usize,
}

/// Takes the feeds out of the built-in files, and drops everything else.
///
/// # Panics
///
/// Panics if a built-in file is not valid TOML. A test parses both.
pub(super) fn network() -> NetworkFeeds {
    let mut text = String::new();
    let mut count = 0_usize;
    for file in [CORE, ASSETS] {
        let mut document: DocumentMut = file.parse().expect("the built-in feed files parse");
        // The test node's key, registry and listen address must not reach a real node.
        document.retain(|key, _| key == "feeds");
        count = count.saturating_add(
            document
                .get("feeds")
                .and_then(toml_edit::Item::as_array_of_tables)
                .map_or(0, toml_edit::ArrayOfTables::len),
        );
        if !text.is_empty() {
            text.push_str("\n\n");
        }
        text.push_str(document.to_string().trim());
    }
    text.push('\n');
    NetworkFeeds { text, count }
}

/// The header above the feeds in a config.
pub(super) fn header(count: usize) -> String {
    format!(
        "# The network's {count} feeds, from oracle-node {}. Every node serves the\n\
         # same feeds, so that a quorum can form on each one.",
        env!("CARGO_PKG_VERSION")
    )
}

/// A config with the network's feeds of this binary, and what changed.
#[derive(Debug)]
pub struct FeedUpdate {
    /// The new config text.
    pub text: String,
    /// Feeds that this binary adds.
    pub added: Vec<String>,
    /// Feeds that the old config has and this binary does not.
    pub removed: Vec<String>,
    /// Feeds in both whose settings changed.
    pub changed: Vec<String>,
    /// Feeds in the new config.
    pub count: usize,
    /// The config had no `[network_feeds]` section, and now has one.
    pub network_feeds_added: bool,
}

/// The `[network_feeds]` section for a config whose registry comes from a URL:
/// the same canister's `/feeds.json`. `None` for a registry read from a file.
fn network_feeds_section(document: &DocumentMut) -> Option<toml_edit::Item> {
    let registry_url = document
        .get("registry")
        .and_then(|registry| registry.get("url"))
        .and_then(toml_edit::Item::as_str)?;
    if !registry_url.contains("registry.json") {
        return None;
    }
    let url = oracle_client::document_url_beside(registry_url, "feeds.json")?;
    let poll_secs = crate::config::NetworkFeedsSettings::POLL_SECS;
    let mut section = toml_edit::Table::new();
    section.insert("url", toml_edit::value(url));
    section.insert(
        "poll_secs",
        toml_edit::value(i64::try_from(poll_secs).unwrap_or(i64::MAX)),
    );
    section.decor_mut().set_prefix(
        "\n# The network's feed set from the canister (SPEC §3.8). Once it verifies, it\n\
         # takes the place of the feeds below, and the node takes each new version\n\
         # while it runs, in its own slot. Every node must see a new set within\n\
         # two minutes, so keep poll_secs low.\n",
    );
    Some(toml_edit::Item::Table(section))
}

/// Replaces a config's `[[feeds]]` with this binary's, and adds `[network_feeds]` for a fetched registry.
///
/// # Errors
///
/// Returns [`InitError::Invalid`] when the config is not TOML, or when the new
/// config does not resolve.
pub fn update_feeds(config: &str) -> Result<FeedUpdate, InitError> {
    let mut document: DocumentMut = config
        .parse()
        .map_err(|e| InitError::Invalid(format!("the config is not TOML: {e}")))?;
    document.remove("feeds");
    let network_feeds_added = !document.contains_key("network_feeds")
        && network_feeds_section(&document).is_some_and(|section| {
            document.insert("network_feeds", section);
            true
        });
    let feeds = network();
    let wanted = i64::try_from(max_pending(feeds.count)).unwrap_or(i64::MAX);
    if let Some(server) = document
        .get_mut("server")
        .and_then(toml_edit::Item::as_table_like_mut)
        && server
            .get("max_pending_feeds")
            .and_then(toml_edit::Item::as_integer)
            .is_some_and(|current| current < wanted)
    {
        server.insert("max_pending_feeds", toml_edit::value(wanted));
    }
    let text = format!(
        "{}\n\n{}\n\n{}",
        document.to_string().trim_end(),
        header(feeds.count),
        feeds.text
    );

    let parsed: crate::NodeConfig = toml::from_str(&text)
        .map_err(|e| InitError::Invalid(format!("the new config does not parse: {e}")))?;
    // The checks of the node's start, so that a bad peg fails here, not in a
    // restart loop.
    crate::feed_set::check_feeds(&parsed, &parsed.feeds)
        .map_err(|e| InitError::Invalid(format!("the new config fails a check: {e}")))?;

    let (old, new) = (by_symbol(config)?, by_symbol(&text)?);
    let changed = new
        .iter()
        .filter(|(symbol, feed)| old.get(*symbol).is_some_and(|before| before != *feed))
        .map(|(symbol, _)| symbol.clone())
        .collect();
    Ok(FeedUpdate {
        added: new
            .keys()
            .filter(|s| !old.contains_key(*s))
            .cloned()
            .collect(),
        removed: old
            .keys()
            .filter(|s| !new.contains_key(*s))
            .cloned()
            .collect(),
        changed,
        count: feeds.count,
        network_feeds_added,
        text,
    })
}

/// Each `[[feeds]]` table of a config by its symbol, as values, so that a comment
/// or a layout change does not count as a change.
fn by_symbol(config: &str) -> Result<BTreeMap<String, toml::Value>, InitError> {
    let table: toml::Table = toml::from_str(config)
        .map_err(|e| InitError::Invalid(format!("the config is not TOML: {e}")))?;
    let feeds = table
        .get("feeds")
        .and_then(toml::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    Ok(feeds
        .iter()
        .filter_map(|feed| {
            let symbol = feed.get("symbol")?.as_str()?.to_owned();
            Some((symbol, feed.clone()))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_feeds_and_their_comments_remain() {
        let feeds = network();
        assert!(feeds.count > 200, "{} feeds", feeds.count);
        assert_eq!(feeds.text.matches("[[feeds]]").count(), feeds.count);
        for leftover in [
            "[server]",
            "[signing]",
            "[registry]",
            "[clients]",
            "key_env",
            "registry.json",
            "tick_interval_ms",
            "gen_local_registry",
        ] {
            assert!(!feeds.text.contains(leftover), "{leftover} remains");
        }
        assert!(feeds.text.contains("# ---"), "the section comments stay");
    }

    const SETTINGS: &str = r#"tick_interval_ms = 25

[server]
listen = "0.0.0.0:8791"
max_pending_feeds = 8

[signing]
# The operator's note.
key_env = "K"

[registry]
path = "r.json"
governance_address = "0x0000000000000000000000000000000000000001"
"#;

    /// A config from an older binary: one feed that this binary dropped, one that
    /// it does not have yet, and one OKX swap without its contract size.
    fn older_config() -> String {
        let current = network().text;
        let okx = r#"symbol = "BTC-USDT-SWAP", kinds = ["mark_price"], contract_size = "0.01""#;
        assert!(current.contains(okx));
        let feeds = current
            .replacen(
                okx,
                r#"symbol = "BTC-USDT-SWAP", kinds = ["mark_price"]"#,
                1,
            )
            .replacen("CRYPTO.AAVE/USD\"", "CRYPTO.OLD/USD\"", 1);
        format!("{SETTINGS}\n{}\n\n{feeds}", header(1))
    }

    #[test]
    fn an_older_config_gets_the_network_feeds_and_keeps_its_settings() {
        let update = update_feeds(&older_config()).expect("updates");
        assert_eq!(update.added, ["CRYPTO.AAVE/USD"]);
        assert_eq!(update.removed, ["CRYPTO.OLD/USD"]);
        assert_eq!(update.changed, ["CRYPTO.BTC/USDT.PERP_MARK"]);
        assert_eq!(update.count, network().count);
        assert!(update.text.contains("# The operator's note."));
        assert!(update.text.contains(&header(network().count)));
        assert!(!update.text.contains(&header(1)), "the old header goes");
        let config: crate::NodeConfig = toml::from_str(&update.text).expect("parses");
        assert_eq!(
            config.resolve().expect("resolves").feeds.len(),
            network().count
        );
        assert_eq!(
            config.server.max_pending_feeds,
            max_pending(network().count)
        );
        assert_eq!(config.tick_interval_ms, 25);
    }

    #[test]
    fn a_config_that_fetches_its_registry_gets_the_network_feed_set_once() {
        let fetched = older_config().replace(
            r#"path = "r.json""#,
            "url = \"https://xb5gv-diaaa-aaaaf-qg5qa-cai.raw.icp0.io/registry.json\"\ncanister_id = \"xb5gv-diaaa-aaaaf-qg5qa-cai\"",
        );
        let first = update_feeds(&fetched).expect("updates");
        assert!(first.network_feeds_added);
        let config: crate::NodeConfig = toml::from_str(&first.text).expect("parses");
        let section = config.network_feeds.expect("the section");
        assert_eq!(
            section.url,
            "https://xb5gv-diaaa-aaaaf-qg5qa-cai.raw.icp0.io/feeds.json"
        );
        assert_eq!(section.poll_secs, 30);
        let second = update_feeds(&first.text).expect("updates");
        assert!(!second.network_feeds_added);
        assert_eq!(second.text, first.text);
        assert!(
            !update_feeds(&older_config())
                .expect("updates")
                .network_feeds_added,
            "a registry file has no canister to ask"
        );
    }

    #[test]
    fn a_second_update_changes_nothing() {
        let first = update_feeds(&older_config()).expect("updates");
        let second = update_feeds(&first.text).expect("updates");
        assert_eq!(second.text, first.text);
        assert!(second.added.is_empty() && second.removed.is_empty() && second.changed.is_empty());
    }

    #[test]
    fn a_config_that_does_not_parse_is_refused() {
        assert!(matches!(
            update_feeds("[server"),
            Err(InitError::Invalid(reason)) if reason.contains("not TOML")
        ));
    }
}
