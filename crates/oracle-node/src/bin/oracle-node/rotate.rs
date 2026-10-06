//! `oracle-node rotate`: the next key for an existing node.

use std::path::PathBuf;

use clap::Args;
use oracle_node::{NodeConfig, PassphraseSource, Rotation, keyfile};

use crate::ui;

#[derive(Args)]
pub(crate) struct RotateArgs {
    /// The directory `init --out` wrote: signing.key, config.toml.
    #[arg(long, value_name = "DIR")]
    dir: PathBuf,
    /// The registry canister id for the printed call. Defaults to the
    /// config's `registry.canister_id`.
    #[arg(long, value_name = "CANISTER_ID")]
    canister: Option<String>,
    /// A 0600 file holding the passphrase that opens the live key and
    /// encrypts the next one. Defaults to the config's
    /// `signing.passphrase_file`, then to a prompt.
    #[arg(long, value_name = "FILE")]
    passphrase_file: Option<PathBuf>,
}

/// Generates the next key for an existing node.
///
/// Nothing on the node changes yet. The canister swaps addresses atomically,
/// so the node keeps signing with its old key until the registry lists the
/// new one.
pub(crate) fn run(args: RotateArgs) -> anyhow::Result<()> {
    let config = NodeConfig::load(&args.dir.join("config.toml"))?;
    // One passphrase opens the live key and seals the next one, so the node's
    // `signing.passphrase_file` keeps working after the swap.
    let passphrase = PassphraseSource::from_file(
        args.passphrase_file
            .clone()
            .or_else(|| config.signing.passphrase_file.clone()),
    )
    .read("signing.key", false)?;
    let live_path = args.dir.join("signing.key");
    let live = keyfile::load_signer(&live_path, Some(&passphrase))?;

    let rotation = Rotation::generate(live.address())?;
    let next_path = rotation.write(&args.dir, &passphrase)?;

    println!("{}\n", ui::heading("Generated the next key for this node."));
    println!("  old address  {}", rotation.old.to_checksummed());
    println!(
        "  new address  {}",
        ui::strong(rotation.next.signing.address().to_checksummed())
    );
    println!("  new ed25519  {}", rotation.next.publisher_hex());
    println!("\n{}", ui::heading("Written"));
    println!("  {}  (age, 0600 — not loaded yet)", next_path.display());

    let canister = args
        .canister
        .or_else(|| config.registry.canister_id.clone())
        .unwrap_or_else(|| "<CANISTER_ID>".to_owned());
    // Only a local network needs a root key in the config; mainnet's is built in.
    let network = if config.registry.root_key.is_some() {
        "local"
    } else {
        "ic"
    };
    let call = rotation.canister_call(network, &canister);
    println!(
        "\n{}\n\n  1. Send both addresses to governance. They swap the new one in with:\n\n     \
         {call}\n\n  \
         2. Once the call succeeds the registry lists only the new address. Move the \
         key into place and restart:\n\n     mv {next} {live}\n\n  \
         3. Consumers follow on the first frame the new key signs. The old address \
         is retired on the canister and can never be listed again.\n\n  \
         A venue that verifies ed25519, such as tapray-perps, may delay a new \
         publisher key by a day. Register the new ed25519 key there before step 2.",
        ui::heading("Next"),
        next = next_path.display(),
        live = live_path.display(),
    );
    Ok(())
}
