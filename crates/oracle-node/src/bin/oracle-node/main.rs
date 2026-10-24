//! The node binary. Each command lives in its own module, with its arguments;
//! the library holds everything that does not touch the terminal.

use std::process::ExitCode;

use clap::{CommandFactory as _, Parser, Subcommand};
use oracle_node::{ConfigError, KeyFileError};

mod init;
mod notify;
mod rotate;
mod start;
mod status;
#[cfg(unix)]
mod system;
mod tail;
mod ui;
mod update_feeds;
mod wizard;

/// `EX_CONFIG` from sysexits.h. The unit file tells systemd not to restart on
/// it, because only an edit fixes the cause.
const EXIT_CONFIG: u8 = 78;

/// What a shell reports for Ctrl-C.
const EXIT_CANCELLED: u8 = 130;

/// Price oracle node: ingest, aggregate, sign, serve.
#[derive(Parser)]
#[command(
    name = "oracle-node",
    version,
    after_help = "`oracle-node start <CONFIG> --tail` logs every decoded observation going into \
                  the aggregator and every signed update coming out, which is how you see what \
                  a venue is actually sending."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate this node's key and print what to do with it. As root, also
    /// install the node as a systemd service and start it.
    Init(init::InitArgs),
    /// Generate the next key for an existing node and print the registry call
    /// that swaps it in.
    Rotate(rotate::RotateArgs),
    /// Run the node: ingest, aggregate, sign, serve.
    Start(start::StartArgs),
    /// Write the network's feeds of this binary into an existing config, so
    /// that the node serves the same feeds as the others.
    UpdateFeeds(update_feeds::UpdateFeedsArgs),
}

fn main() -> ExitCode {
    match dispatch() {
        Ok(()) => ExitCode::SUCCESS,
        // The wizard already said so on screen.
        Err(error) if error.is::<wizard::Cancelled>() => ExitCode::from(EXIT_CANCELLED),
        Err(error) => {
            // Plainly, not through `tracing`. Usage text wearing a timestamp and
            // an ERROR level reads as a crash rather than as an instruction, and
            // for `init` the subscriber is not even running.
            eprintln!("{error:#}");
            exit_code(&error)
        }
    }
}

fn dispatch() -> anyhow::Result<()> {
    // The bare-path form this binary used to take. Say so, rather than failing
    // with "unrecognized subcommand" at someone following an older README.
    if let Some(first) = std::env::args().nth(1)
        && first.ends_with(".toml")
    {
        anyhow::bail!(
            "did you mean `oracle-node start {first}`?\n\n{}",
            Cli::command().render_usage()
        );
    }
    match Cli::parse().command {
        Command::Init(args) => init::run(args),
        Command::Rotate(args) => rotate::run(args),
        Command::Start(args) => start::run(args),
        Command::UpdateFeeds(args) => update_feeds::run(args),
    }
}

fn exit_code(error: &anyhow::Error) -> ExitCode {
    let permanent = error.chain().any(|cause| {
        cause
            .downcast_ref::<ConfigError>()
            .is_some_and(ConfigError::is_permanent)
            || cause.is::<KeyFileError>()
    });
    if permanent {
        ExitCode::from(EXIT_CONFIG)
    } else {
        ExitCode::FAILURE
    }
}
