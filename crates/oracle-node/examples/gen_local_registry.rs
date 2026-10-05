//! Generates a governance-signed local registry with deterministic keys.
//!
//! The keys are derived from small integers. **Never use them anywhere real.**
//!
//! ```text
//! # A five-node deployment: the shape SPEC §9.2 asks for, plus the client
//! # list every node needs and one local client to subscribe with.
//! cargo run -p oracle-node --example gen_local_registry -- \
//!     --nodes 5 --clients clients.json > registry.json
//!
//! # Sign in a node generated with `oracle-node init`, which has real keys but
//! # no governance key of its own.
//! cargo run -p oracle-node --example gen_local_registry -- \
//!     --nodes 0 --entry node1/node-entry.json > node1/registry.json
//! ```
//!
//! This stands in for the registry canister on a laptop. Rotation is not
//! modelled here: it is the canister's `replace_node`, which
//! `oracle-node rotate` prints, and the canister retires old addresses
//! (SPEC §3.6).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use oracle_wire::{ClientEntry, ClientList, NodeEntry, Quorum, Registry, Signer, WireError};

/// Far-future expiry for the local client.
const FOREVER: u64 = 4_102_444_800;

/// Governance key seed. Signs the registry; pinned by every consumer.
const GOVERNANCE_SEED: u8 = 0x33;

/// The local client's API key seed.
const CLIENT_SEED: u8 = 0x60;

/// Generates a governance-signed local registry with deterministic keys.
///
/// `--entry` signs in an entry produced by `oracle-node init`, which generates
/// real keys but has no governance key of its own.
#[derive(clap::Parser)]
struct Options {
    /// Number of generated nodes, 0 to 32.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(0..=32))]
    nodes: u8,
    /// Registry version.
    #[arg(long, default_value_t = 1)]
    version: u64,
    /// Port of the first node; each further node takes the next one.
    #[arg(long, default_value_t = 8791)]
    base_port: u16,
    /// A node entry from `oracle-node init` to sign in. Repeatable.
    #[arg(long = "entry", value_name = "node-entry.json")]
    entries: Vec<PathBuf>,
    /// Also write a signed client list naming one local client, which every
    /// node needs to start (SPEC §6.1).
    #[arg(long, value_name = "clients.json")]
    clients: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = <Options as clap::Parser>::parse();
    if options.nodes == 0 && options.entries.is_empty() {
        return Err("--nodes 0 needs at least one --entry".into());
    }
    if options
        .base_port
        .checked_add(u16::from(options.nodes))
        .is_none()
    {
        return Err("--base-port is too high for that many nodes".into());
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let governance = Signer::from_secret_bytes([GOVERNANCE_SEED; 32])?;

    let mut entries = Vec::with_capacity(usize::from(options.nodes) + options.entries.len());
    for index in 1..=options.nodes {
        entries.push(entry(index, &options)?);
    }
    // Entries produced by `oracle-node init`, which generates real keys and has
    // no governance key of its own. Signing them in is the step a real
    // deployment does on the canister, and the reason a node's own output cannot
    // make it trusted.
    for path in &options.entries {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let entry: NodeEntry = serde_json::from_str(&text)
            .map_err(|e| format!("{} is not a node entry: {e}", path.display()))?;
        eprintln!("# including {} from {}", entry.address, path.display());
        entries.push(entry);
    }

    // A quorum of three is the smallest that defends against a single bad node,
    // so it is the floor whenever the deployment can support it.
    let quorum = Quorum {
        min_nodes: u16::from(options.nodes).min(3),
        recommended: u16::from(options.nodes).min(5),
    };
    let registry = Registry::sign(&governance, options.version, now, entries, quorum)?;
    println!("{}", serde_json::to_string_pretty(&registry)?);

    if let Some(path) = &options.clients {
        let client = Signer::from_secret_bytes([CLIENT_SEED; 32])?;
        let list = ClientList::sign(
            &governance,
            options.version,
            now,
            60,
            vec![ClientEntry {
                address: client.address(),
                expires_at: FOREVER,
            }],
        )?;
        std::fs::write(path, serde_json::to_string_pretty(&list)?)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        eprintln!("# client list written to {}", path.display());
        eprintln!("LOCAL_CLIENT_KEY={}", hex32(CLIENT_SEED));
    }

    eprintln!("GOVERNANCE={}", governance.address());
    eprintln!("# Pin this address in every node and consumer config.");
    for index in 1..=options.nodes {
        eprintln!(
            "ORACLE_LOCAL_{index}_SIGNING_KEY={}",
            hex32(signing_seed(index))
        );
    }
    Ok(())
}

fn entry(index: u8, options: &Options) -> Result<NodeEntry, WireError> {
    let signing = Signer::from_secret_bytes([signing_seed(index); 32])?;
    Ok(NodeEntry {
        address: signing.address(),
        // Distinct operator names by default: five nodes under one operator is
        // one node wearing a costume (SPEC §9.2). Local runs cannot make that
        // true, but they should not encode the opposite either.
        operator: format!("local-{index}"),
        endpoints: vec![format!(
            "ws://127.0.0.1:{}/v2/ws",
            options.base_port + u16::from(index) - 1
        )],
        weight: 1,
    })
}

const fn signing_seed(index: u8) -> u8 {
    0x40 + index
}

fn hex32(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}
