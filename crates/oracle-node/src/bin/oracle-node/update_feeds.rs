//! `oracle-node update-feeds`: the network's feeds of this binary in an existing config.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, fchown};
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
    // Root runs this in a directory that the service user can write, so the
    // config opens only if it is not a link, and each write is a new file.
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("cannot open {}, or it is a link", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("cannot read {}", path.display()))?;
    let mut old = String::new();
    file.read_to_string(&mut old)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let update = oracle_node::update_feeds(&old)?;
    if update.text == old {
        println!("{}: the {} feeds are current", path.display(), update.count);
        return Ok(());
    }
    let prev = with_suffix(&path, "prev");
    write_as(&prev, &old, &meta)?;
    write_as(&path, &update.text, &meta)?;
    println!(
        "{}: {} feeds, {} added, {} removed, {} changed. The old config is {}.",
        path.display(),
        update.count,
        update.added.len(),
        update.removed.len(),
        update.changed.len(),
        prev.display()
    );
    if update.network_feeds_added {
        println!(
            "  added [network_feeds]: the node follows the network's feed set from the canister"
        );
    }
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

/// Writes `text` to `path` in one rename, with the config's owner and mode, so
/// that the service user can still read it. A link at `path` is replaced, never
/// followed.
fn write_as(path: &Path, text: &str, meta: &fs::Metadata) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let written = || -> std::io::Result<()> {
        let mut next = tempfile::NamedTempFile::new_in(dir)?;
        next.write_all(text.as_bytes())?;
        next.as_file().set_permissions(meta.permissions())?;
        fchown(next.as_file(), Some(meta.uid()), Some(meta.gid()))?;
        next.as_file().sync_all()?;
        next.persist(path).map_err(|error| error.error)?;
        Ok(())
    };
    written().with_context(|| format!("cannot write {}", path.display()))
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_planted_link_is_replaced_not_followed() {
        let dir = std::env::temp_dir().join(format!("update-feeds-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a scratch dir");
        let config = dir.join("config.toml");
        let target = dir.join("target");
        fs::write(&config, "old").expect("writes");
        fs::write(&target, "untouched").expect("writes");
        let prev = with_suffix(&config, "prev");
        std::os::unix::fs::symlink(&target, &prev).expect("links");
        let meta = fs::metadata(&config).expect("stat");

        write_as(&prev, "old", &meta).expect("writes through no link");
        assert_eq!(fs::read_to_string(&target).expect("reads"), "untouched");
        assert!(fs::symlink_metadata(&prev).expect("stat").is_file());
        assert_eq!(fs::read_to_string(&prev).expect("reads"), "old");

        let linked = dir.join("linked.toml");
        std::os::unix::fs::symlink(&target, &linked).expect("links");
        let refused = run(UpdateFeedsArgs { config: linked });
        assert!(refused.is_err(), "a config that is a link is refused");
        fs::remove_dir_all(&dir).expect("cleans up");
    }
}
