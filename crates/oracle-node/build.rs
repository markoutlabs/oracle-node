//! Puts the commit the installer built into `--version`, so an operator can
//! state what runs. A build without `ORACLE_COMMIT` reports the version alone.

fn main() {
    println!("cargo:rerun-if-env-changed=ORACLE_COMMIT");
    let version = std::env::var("CARGO_PKG_VERSION").expect("cargo sets the package version");
    let full = match std::env::var("ORACLE_COMMIT") {
        Ok(commit) if !commit.trim().is_empty() => {
            let commit = commit.trim();
            format!("{version} ({})", commit.get(..12).unwrap_or(commit))
        }
        _ => version,
    };
    println!("cargo:rustc-env=ORACLE_VERSION={full}");
}
