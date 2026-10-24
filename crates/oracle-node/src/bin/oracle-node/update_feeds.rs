//! `oracle-node update-feeds`: the network's feeds of this binary in an existing config.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, chown};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::Args;

/// Feed names printed for each kind of change; a deploy log needs no more.
const SHOWN: usize = 8;

#[derive(Args)]
pub(crate) struct UpdateFeedsArgs {
    /// The node's config, such as the one in the systemd unit's `start` line.
    #[arg(value_name = "CONFIG")]
    config: PathBuf,
}

/// Writes the network's feeds into the config, and keeps the old file as
/// `<CONFIG>.prev`. A current config is left as it is.
pub(crate) fn run(args: UpdateFeedsArgs) -> anyhow::Result<()> {
    let path = args.config;
    let old =
        fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
    let update = oracle_node::update_feeds(&old)?;
    if update.text == old {
        println!("{}: the {} feeds are current", path.display(), update.count);
        return Ok(());
    }
    let prev = with_suffix(&path, "prev");
    fs::copy(&path, &prev).with_context(|| format!("cannot write {}", prev.display()))?;
    replace(&path, &update.text)?;
    println!(
        "{}: {} feeds, {} added, {} removed, {} changed. The old config is {}.",
        path.display(),
        update.count,
        update.added.len(),
        update.removed.len(),
        update.changed.len(),
        prev.display()
    );
    for (what, symbols) in [
        ("added", &update.added),
        ("removed", &update.removed),
        ("changed", &update.changed),
    ] {
        if symbols.is_empty() {
            continue;
        }
        let shown: Vec<&str> = symbols.iter().take(SHOWN).map(String::as_str).collect();
        let more = symbols.len().saturating_sub(SHOWN);
        let tail = if more > 0 {
            format!(", and {more} more")
        } else {
            String::new()
        };
        println!("  {what}: {}{tail}", shown.join(", "));
    }
    Ok(())
}

/// Writes `text` over `path` in one rename, with the old file's owner and mode,
/// so that the service user can still read it.
fn replace(path: &Path, text: &str) -> anyhow::Result<()> {
    let meta = fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    let next = with_suffix(path, "next");
    let written = || -> std::io::Result<()> {
        fs::write(&next, text)?;
        fs::set_permissions(&next, meta.permissions())?;
        chown(&next, Some(meta.uid()), Some(meta.gid()))?;
        fs::rename(&next, path)
    };
    written().with_context(|| format!("cannot write {}", path.display()))
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}
