//! `oracle-node init`: generate a node key and everything needed to run it.
//!
//! At a terminal without `--out`, the wizard asks for each value. Otherwise the
//! flags give them, and the output is plain text a script can read. The node
//! always fetches from the registry canister: the mainnet one unless
//! `--canister` and `--governance` name another.

use std::path::PathBuf;

use anyhow::Context as _;
use clap::Args;
use oracle_node::{
    CanisterId, Endpoint, Gateway, NodeKey, NodeSetup, PassphraseSource, RegistrySource, RootKey,
    ServiceUnit, Unlock, Written, candid_call,
};
use oracle_wire::Address;

use crate::{ui, wizard};

#[derive(Args)]
pub(crate) struct InitArgs {
    /// The WebSocket endpoint subscribers will connect to.
    #[arg(long, default_value = "ws://127.0.0.1:8791/v2/ws")]
    pub(crate) endpoint: Endpoint,
    /// Write the key, registry entry, and a starter config to DIR instead of
    /// printing the secret to the terminal. The key is encrypted at rest.
    #[arg(long, value_name = "DIR")]
    pub(crate) out: Option<PathBuf>,
    /// A 0600 file holding the passphrase that encrypts the key. Without it,
    /// `--out` prompts at the terminal. Recorded in the starter config.
    #[arg(long, value_name = "FILE", requires = "out")]
    pub(crate) passphrase_file: Option<PathBuf>,
    /// Another registry canister than the mainnet one, such as one on the
    /// local network. Needs the governance address that goes with it.
    #[arg(long, value_name = "CANISTER_ID", requires = "governance")]
    pub(crate) canister: Option<CanisterId>,
    /// The local network's HTTP gateway, such as `http://127.0.0.1:8000`.
    #[arg(long, value_name = "URL", requires_all = ["canister", "root_key"])]
    pub(crate) gateway: Option<Gateway>,
    /// The local network's root key in hex, from `icp network status --json`.
    #[arg(long, value_name = "HEX", requires = "gateway")]
    pub(crate) root_key: Option<RootKey>,
    /// The governance address of `--canister`: its signing key's address.
    #[arg(long, value_name = "ADDRESS", requires = "canister")]
    pub(crate) governance: Option<Address>,
    /// Also write a systemd unit that runs the node as USER.
    #[arg(long, value_name = "USER", requires_all = ["out", "passphrase_file"])]
    pub(crate) service_user: Option<String>,
}

/// Generates a node key and prints everything needed to run it.
pub(crate) fn run(args: InitArgs) -> anyhow::Result<()> {
    if args.out.is_none() && ui::interactive() {
        return wizard::run(&args);
    }
    let key = NodeKey::generate()?;
    let entry = key.entry(&args.endpoint);
    let add_call = network(&args).ok().map(|(source, _)| {
        let compact = serde_json::to_string(&entry).expect("entry serialises");
        candid_call(
            source.network(),
            &source.canister().to_string(),
            "add_node",
            &[&compact],
        )
    });

    println!("{}\n", ui::heading("Generated a new node key."));
    println!(
        "  address  {}",
        ui::strong(key.signing.address().to_checksummed())
    );
    println!(
        "{}",
        ui::dim(
            "           The node's id in the registry, and what its price updates\n\
             \x20          recover to. It never expires; rotate it if you think it leaked."
        )
    );
    println!("  ed25519  {}", key.publisher_hex());
    println!(
        "{}",
        ui::dim(
            "           The publisher key for venues that verify ed25519, such as\n\
             \x20          tapray-perps. The same secret seed derives both keys."
        )
    );

    let Some(dir) = args.out.clone() else {
        println!(
            "\n{}\n  {}",
            ui::heading("Secret seed"),
            &*key.secret_text()
        );
        println!(
            "\n  This is now in your terminal scrollback and shell history. Re-run\n  \
             with `--out DIR` to write it to a 0600 file instead."
        );
        let entry = serde_json::to_string_pretty(&entry)?;
        println!("\n{}\n\n{entry}", ui::heading("Send to governance"));
        if let Some(call) = add_call {
            println!("\nGovernance adds the node to the registry canister with:\n\n{call}");
        }
        return Ok(());
    };

    let setup = setup(args, dir)?;
    setup.check()?;
    // Asked for before anything is written, so a refused prompt leaves no
    // half-initialised directory behind.
    let passphrase = PassphraseSource::from_file(setup.unlock.file().map(Into::into))
        .read("the new key file", true)?;
    let written = setup.write(&key, &passphrase)?;
    report(&setup, &written, add_call.as_deref());
    Ok(())
}

/// The registry canister and its governance address: the flags' if given,
/// otherwise the mainnet deployment's.
pub(crate) fn network(args: &InitArgs) -> anyhow::Result<(RegistrySource, Address)> {
    if let (Some(canister), Some(governance)) = (&args.canister, args.governance) {
        let source = match (&args.gateway, &args.root_key) {
            (Some(gateway), Some(root_key)) => RegistrySource::Network {
                canister: canister.clone(),
                gateway: gateway.clone(),
                root_key: root_key.clone(),
            },
            _ => RegistrySource::Mainnet(canister.clone()),
        };
        return Ok((source, governance));
    }
    RegistrySource::mainnet().context(
        "the registry canister is not on mainnet yet: pass --canister and --governance, \
         and --gateway and --root-key for the local network",
    )
}

fn setup(args: InitArgs, dir: PathBuf) -> anyhow::Result<NodeSetup> {
    let (source, governance) = network(&args)?;
    let service = match args.service_user {
        Some(user) => Some(ServiceUnit {
            user,
            exe: std::env::current_exe().context("cannot find this binary for the unit")?,
        }),
        None => None,
    };
    Ok(NodeSetup {
        dir,
        endpoint: args.endpoint,
        source,
        governance,
        unlock: args
            .passphrase_file
            .map_or(Unlock::Prompt, Unlock::PassphraseFile),
        service,
    })
}

fn report(setup: &NodeSetup, written: &Written, add_call: Option<&str>) {
    println!("\n{}", ui::heading("Written"));
    println!(
        "  {}  (age, 0600 — the node reads this)",
        written.key.display()
    );
    if let Some(passphrase) = &written.passphrase {
        println!("  {}  (0600 — opens the key)", passphrase.display());
    }
    println!("  {}  (send to governance)", written.entry.display());
    println!("  {}  (starter config)", written.config.display());
    if let Some(unit) = &written.unit {
        println!("  {}  (systemd unit)", unit.display());
    }
    // At column 0, so a script can take the line as it is.
    if let Some(call) = add_call {
        println!("\nGovernance adds the node to the registry canister with:\n\n{call}");
    }
    println!(
        "\n{}\n{}",
        ui::heading("Next"),
        ui::numbered(&ui::next_steps(written))
    );
    for warning in ui::warnings(setup) {
        println!("\n{} {warning}", ui::heading("Note:"));
    }
}
