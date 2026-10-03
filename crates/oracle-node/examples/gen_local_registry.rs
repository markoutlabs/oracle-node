//! Generates a signed local registry, and models a signing-key rotation.
//!
//! The keys are derived from small integers. **Never use them anywhere real.**
//!
//! ```text
//! # A five-node deployment: the shape SPEC §9.2 asks for.
//! cargo run -p oracle-node --example gen_local_registry -- --nodes 5 > registry.json
//!
//! # Version 2, with oracle-local-1 mid-rotation: both its keys are listed and
//! # both verify, so it can move to the new one without a gap in which every
//! # subscriber refuses it.
//! cargo run -p oracle-node --example gen_local_registry -- \
//!     --nodes 5 --version 2 --rotate oracle-local-1 > registry.v2.json
//!
//! # Version 3, once the overlap closes. This is what actually revokes the old
//! # key, and it is a separate, later publication — not part of the rotation.
//! cargo run -p oracle-node --example gen_local_registry -- \
//!     --nodes 5 --version 3 --rotate oracle-local-1 --close-overlap > registry.v3.json
//! ```
//!
//! Consumers adopt each version with `OracleClient::refresh_registry`, which
//! enforces that versions only move forward — so publishing v3 is what makes the
//! outgoing key unusable, and replaying v2 afterwards cannot bring it back.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use oracle_wire::{NodeEntry, Quorum, Registry, Signer, SigningKeyCert, WireError};

/// Far-future expiry for keys that are not being rotated.
const FOREVER: u64 = 4_102_444_800;

/// The overlap window from SPEC §3.5.
const OVERLAP: u64 = 24 * 3_600;

/// Governance key seed. Signs the registry; pinned by every consumer.
const GOVERNANCE_SEED: u8 = 0x33;

struct Options {
    nodes: u8,
    version: u64,
    base_port: u16,
    rotate: Option<String>,
    close_overlap: bool,
    entries: Vec<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            nodes: 1,
            version: 1,
            base_port: 8791,
            rotate: None,
            close_overlap: false,
            entries: Vec::new(),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_args()?;
    if options.nodes > 32 {
        return Err("--nodes must be 32 or fewer".into());
    }
    if options.nodes == 0 && options.entries.is_empty() {
        return Err("--nodes 0 needs at least one --entry".into());
    }
    if let Some(target) = &options.rotate
        && !(1..=options.nodes).any(|index| node_id(index) == *target)
    {
        return Err(format!("--rotate {target} names no node in this registry").into());
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let governance = Signer::from_secret_bytes([GOVERNANCE_SEED; 32])?;

    let mut entries = Vec::with_capacity(usize::from(options.nodes) + options.entries.len());
    for index in 1..=options.nodes {
        entries.push(entry(index, &options, now)?);
    }
    // Entries produced by `oracle-node init`, which generates real keys and has
    // no governance key of its own. Signing them in is the step a real
    // deployment does out of band, and the reason a node's own output cannot
    // make it trusted.
    for path in &options.entries {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let entry: NodeEntry = serde_json::from_str(&text)
            .map_err(|e| format!("{} is not a node entry: {e}", path.display()))?;
        eprintln!("# including {} from {}", entry.node_id, path.display());
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

    eprintln!("GOVERNANCE={}", governance.address());
    eprintln!("# Pin this address in every node and consumer config.");
    for index in 1..=options.nodes {
        // A rotating node should be started on its incoming key; that is what the
        // rotation is for. Its outgoing key stays valid until the overlap closes
        // only so the move needs no coordination.
        let rotated = options.rotate.as_deref() == Some(node_id(index).as_str());
        let seed = if rotated {
            incoming_seed(index)
        } else {
            signing_seed(index)
        };
        eprintln!(
            "{}_SIGNING_KEY={}{}",
            node_id(index).to_uppercase().replace('-', "_"),
            hex32(seed),
            if rotated { "  # incoming key" } else { "" }
        );
    }
    Ok(())
}

fn entry(index: u8, options: &Options, now: u64) -> Result<NodeEntry, WireError> {
    let id = node_id(index);
    let identity = Signer::from_secret_bytes([identity_seed(index); 32])?;
    let outgoing = Signer::from_secret_bytes([signing_seed(index); 32])?;
    let incoming = Signer::from_secret_bytes([incoming_seed(index); 32])?;

    let signing_keys = match (
        options.rotate.as_deref() == Some(id.as_str()),
        options.close_overlap,
    ) {
        // Not rotating: one key, valid indefinitely.
        (false, _) => vec![SigningKeyCert::issue(
            &identity,
            &id,
            outgoing.address(),
            0,
            FOREVER,
        )?],
        // Mid-rotation: both keys authorised, the outgoing one until the overlap
        // closes. A consumer counting *keys* rather than nodes would seat this
        // one machine twice for the next 24 hours.
        (true, false) => vec![
            SigningKeyCert::issue(&identity, &id, outgoing.address(), 0, now + OVERLAP)?,
            SigningKeyCert::issue(&identity, &id, incoming.address(), now, FOREVER)?,
        ],
        // Overlap closed: the outgoing key is gone, which is what revokes it.
        (true, true) => vec![SigningKeyCert::issue(
            &identity,
            &id,
            incoming.address(),
            now,
            FOREVER,
        )?],
    };

    Ok(NodeEntry {
        node_id: id.clone(),
        // Distinct operator names by default: five nodes under one operator is
        // one node wearing a costume (SPEC §9.2). Local runs cannot make that
        // true, but they should not encode the opposite either.
        operator: format!("local-{index}"),
        identity_pubkey: identity.public_key(),
        endpoints: vec![format!(
            "ws://127.0.0.1:{}/v1/ws",
            options.base_port + u16::from(index) - 1
        )],
        signing_keys,
        weight: 1,
    })
}

fn node_id(index: u8) -> String {
    format!("oracle-local-{index}")
}

const fn identity_seed(index: u8) -> u8 {
    0x10 + index
}

const fn signing_seed(index: u8) -> u8 {
    0x40 + index
}

const fn incoming_seed(index: u8) -> u8 {
    0x70 + index
}

fn hex32(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

fn parse_args() -> Result<Options, Box<dyn std::error::Error>> {
    let mut options = Options::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--nodes" => options.nodes = next(&mut args, "--nodes")?.parse()?,
            "--version" => options.version = next(&mut args, "--version")?.parse()?,
            "--base-port" => options.base_port = next(&mut args, "--base-port")?.parse()?,
            "--rotate" => options.rotate = Some(next(&mut args, "--rotate")?),
            "--close-overlap" => options.close_overlap = true,
            "--entry" => options.entries.push(next(&mut args, "--entry")?.into()),
            "--help" | "-h" => {
                eprintln!(
                    "usage: gen_local_registry [--nodes N] [--version V] [--base-port P] \
                     [--rotate NODE_ID [--close-overlap]] [--entry node-entry.json]...\n\n\
                     --entry signs in an entry produced by `oracle-node init`, which \
                     generates real keys but has no governance key of its own."
                );
                std::process::exit(0);
            }
            other => return Err(format!("unrecognised argument `{other}`").into()),
        }
    }
    if options.close_overlap && options.rotate.is_none() {
        return Err("--close-overlap only means anything alongside --rotate".into());
    }
    Ok(options)
}

fn next(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} needs a value").into())
}
