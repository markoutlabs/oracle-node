//! The network's feeds, built into the binary. Every node that `init` makes
//! serves the same feeds, so a quorum can form on each one.

use toml_edit::DocumentMut;

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
}
