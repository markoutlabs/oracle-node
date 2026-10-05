//! Generates a client API key (SPEC §6.1) and prints its address, which
//! governance lists with `add_client`.
//!
//! ```sh
//! cargo run -p oracle-client --example client_key -- --out client.key
//! ```
//!
//! The key is written as plaintext hex, readable only by you. Keep it on the
//! consumer's machine or in its KMS; it only ever signs.

use std::io::Write as _;
use std::path::PathBuf;

use clap::Parser;

/// Generate a client API key.
#[derive(Parser)]
struct Args {
    /// Where to write the secret key. Never overwritten.
    #[arg(long)]
    out: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let key = oracle_wire::Signer::generate()?;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(&args.out)?
        .write_all(key.to_secret_hex().as_bytes())?;

    let address = key.address().to_checksummed();
    println!("address {address}");
    println!("written {}", args.out.display());
    println!(
        "\nGovernance lists the client with:\n  \
         dfx canister call <CANISTER_ID> add_client '(\"{address}\", <expires_at> : nat64)'"
    );
    Ok(())
}
