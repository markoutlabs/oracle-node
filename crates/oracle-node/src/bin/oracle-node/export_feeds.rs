//! `oracle-node export-feeds`: a feed set from feed files, checked as a node
//! checks it, as the JSON that the canister's `set_feed_set` takes.

use std::path::PathBuf;

use anyhow::Context as _;
use clap::Args;
use oracle_wire::{FeedContent, FeedSettings, PushPolicy};
use serde::Deserialize;

use oracle_node::feed_set::NODE_VERSION;

#[derive(Args)]
pub(crate) struct ExportFeedsArgs {
    /// Files with `[[feeds]]` tables, such as `node/all-feeds.toml` and
    /// `node/assets.toml`. Their other keys are ignored.
    #[arg(value_name = "FILE", required = true)]
    files: Vec<PathBuf>,
    /// The oldest node version that can serve the set. Default: this binary's.
    #[arg(long, value_name = "VERSION")]
    min_node_version: Option<String>,
    /// Also writes the `set_feed_set` argument to this file, as binary Candid
    /// for `icp canister call --args-format bin`.
    #[arg(long, value_name = "FILE")]
    candid: Option<PathBuf>,
    /// Seconds after which every node pushes a feed whose price did not move.
    /// With the two flags below; without all three, each node keeps its own.
    #[arg(long, value_name = "SECS", requires_all = ["push_deviation_bps", "push_min_interval_secs"])]
    push_heartbeat_secs: Option<u64>,
    /// A move this large, in basis points, pushes a feed at once.
    #[arg(long, value_name = "BPS", requires_all = ["push_heartbeat_secs", "push_min_interval_secs"])]
    push_deviation_bps: Option<u32>,
    /// Seconds between two pushes of a node, at least.
    #[arg(long, value_name = "SECS", requires_all = ["push_heartbeat_secs", "push_deviation_bps"])]
    push_min_interval_secs: Option<u64>,
}

/// The feed tables of a file; everything else in it is ignored.
#[derive(Deserialize)]
struct FeedTables {
    #[serde(default)]
    feeds: Vec<FeedSettings>,
}

pub(crate) fn run(args: ExportFeedsArgs) -> anyhow::Result<()> {
    let mut feeds = Vec::new();
    for file in &args.files {
        let text = std::fs::read_to_string(file)
            .with_context(|| format!("cannot read {}", file.display()))?;
        let tables: FeedTables =
            toml::from_str(&text).with_context(|| format!("cannot parse {}", file.display()))?;
        feeds.extend(tables.feeds);
    }
    let push = match (
        args.push_heartbeat_secs,
        args.push_deviation_bps,
        args.push_min_interval_secs,
    ) {
        (Some(heartbeat_secs), Some(deviation_bps), Some(min_interval_secs)) => Some(PushPolicy {
            heartbeat_secs,
            deviation_bps,
            min_interval_secs,
        }),
        _ => None,
    };
    let content = FeedContent {
        min_node_version: args
            .min_node_version
            .unwrap_or_else(|| NODE_VERSION.to_owned()),
        push,
        feeds,
    }
    .canonical()
    .map_err(|error| anyhow::anyhow!("the feed set fails the canister's checks: {error}"))?;
    oracle_node::feed_set::check_feed_list(&content.feeds)
        .context("the feed set fails a node's checks")?;
    let json = serde_json::to_string(&content)?;
    if let Some(path) = &args.candid {
        std::fs::write(path, candid_argument(&json)?)
            .with_context(|| format!("cannot write {}", path.display()))?;
    }
    println!("{json}");
    eprintln!(
        "{} feeds pass every check. Publish them with `set_feed_set`.",
        content.feeds.len()
    );
    Ok(())
}

fn candid_argument(json: &str) -> anyhow::Result<Vec<u8>> {
    Ok(candid::encode_one(json)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_candid_argument_holds_the_json_text() {
        let json = r#"{"feeds":[{"symbol":"CRYPTO.ETH/BTC","note":"a \"quoted\" \\ text"}]}"#;
        let bytes = candid_argument(json).expect("encodes");
        let text: String = candid::decode_one(&bytes).expect("decodes");
        assert_eq!(text, json);
    }
}
