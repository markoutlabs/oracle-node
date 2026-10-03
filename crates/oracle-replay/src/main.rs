//! `oracle-replay`: play a recording back through the node's pipeline.
//!
//! ```sh
//! oracle-node start node.toml --record capture.jsonl     # on the node
//! oracle-replay node.toml capture.jsonl                   # anywhere, later
//! oracle-replay node.toml capture.jsonl --json > updates.jsonl
//! ```
//!
//! The final line is a digest of every published update. Two nodes replaying
//! one recording with one config must print the same digest (SPEC §10,
//! cross-node conformance).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use oracle_node::NodeConfig;
use oracle_wire::Signer;

/// Replay recorded venue frames through the real pipeline.
#[derive(Parser)]
#[command(name = "oracle-replay", version)]
struct Cli {
    /// The node config the recording was made with.
    config: PathBuf,
    /// The recording, as `oracle-node start --record` wrote it.
    recording: PathBuf,
    /// Sleep the recorded gaps between frames instead of running flat out.
    #[arg(long)]
    realtime: bool,
    /// Print each published update as a JSON line instead of a summary line.
    #[arg(long)]
    json: bool,
}

/// Signatures are not part of a replay's outcome, so any key will do. Seeded,
/// so the frames themselves are also reproducible.
const REPLAY_SIGNER_SEED: u8 = 0x5E;

// Single-threaded on purpose: the driven clock is only coherent when nothing
// runs between a transport returning a frame and the session stamping it.
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match replay().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn replay() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let resolved = NodeConfig::load(&cli.config)?.resolve()?;
    let file = std::fs::File::open(&cli.recording)
        .map_err(|e| format!("{}: {e}", cli.recording.display()))?;
    let records = oracle_ingest::record::read_records(std::io::BufReader::new(file))?;
    let signer = Signer::from_secret_bytes([REPLAY_SIGNER_SEED; 32])?;

    let outcome = oracle_replay::run(resolved, records, signer, cli.realtime).await?;
    for update in &outcome.updates {
        if cli.json {
            println!("{}", serde_json::to_string(update)?);
        } else {
            println!(
                "t={} feed={} price={} conf={} seq={} sources={} flags={:?}",
                update.publish_time_ns,
                update.feed_id,
                update
                    .price_fixed()
                    .map(|p| p.to_string())
                    .unwrap_or_default(),
                update
                    .conf_fixed()
                    .map(|c| c.to_string())
                    .unwrap_or_default(),
                update.seq,
                update.num_sources,
                update.flags,
            );
        }
    }
    for error in &outcome.errors {
        eprintln!("aggregation error: {error}");
    }
    eprintln!(
        "published={} observations={} disconnects={} digest=0x{}",
        outcome.updates.len(),
        outcome.stats.observations,
        outcome.stats.disconnects,
        hex_lower(&outcome.digest),
    );
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
