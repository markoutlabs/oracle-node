//! The network's feeds, built into the binary. Every node that `init` makes
//! serves the same feeds, so a quorum can form on each one.

use std::collections::BTreeMap;

use toml_edit::DocumentMut;

use super::InitError;

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

/// The bound below which `max_pending_feeds` never goes.
const MIN_PENDING: usize = 512;

/// The `server.max_pending_feeds` that `init` writes for `count` feeds.
pub(super) fn max_pending(count: usize) -> usize {
    // A slow subscriber can owe a price and a venue report for each feed.
    count.saturating_mul(2).next_power_of_two().max(MIN_PENDING)
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
}

/// Replaces the `[[feeds]]` of a node's config with the network's feeds of this
/// binary, so that a node keeps serving the same feeds as the others.
///
/// Every other key and comment stays. `server.max_pending_feeds` rises to what
/// `init` would write, when it is lower.
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
    parsed
        .resolve()
        .map_err(|e| InitError::Invalid(format!("the new config does not resolve: {e}")))?;

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
