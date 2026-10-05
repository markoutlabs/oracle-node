//! The `init` wizard: one question at a time, then a summary to confirm.
//!
//! It only asks. Every answer parses into the same types the flags use, and
//! the files come from the same `NodeSetup::write`, so the wizard cannot write
//! anything the flags could not.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use anyhow::Context as _;
use cliclack::{confirm, input, intro, log, note, outro, outro_cancel, password, select};
use oracle_node::{
    Endpoint, NodeKey, NodeSetup, Operator, RegistrySource, ServiceUnit, Unlock, Written,
    candid_call, generate_passphrase,
};
use oracle_wire::Address;

use crate::init::{self, InitArgs};
use crate::ui;

/// The person cancelled the wizard. Nothing was written.
#[derive(Debug)]
pub(crate) struct Cancelled;

impl fmt::Display for Cancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cancelled; nothing was written")
    }
}

impl std::error::Error for Cancelled {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UnlockKind {
    GeneratedFile,
    Typed,
}

pub(crate) fn run(args: &InitArgs) -> anyhow::Result<()> {
    // Known before the first question, so the wizard never asks what it
    // cannot use.
    let (source, governance) = init::network(args)?;
    // In raw mode Ctrl-C reaches cliclack as a key and cancels the prompt.
    // Between prompts it would kill the process, so it does nothing there.
    let _ = ctrlc::set_handler(|| {});
    match ask(args, source, governance) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {
            let _ = outro_cancel("Nothing was written.");
            Err(Cancelled.into())
        }
        Err(error) => Err(error).context("the wizard failed"),
    }
}

fn ask(args: &InitArgs, source: RegistrySource, governance: Address) -> io::Result<()> {
    intro(ui::heading(" oracle-node init "))?;
    note(
        "A new node",
        "This makes the node's key, its registry entry for governance, and a\n\
         starter config, and a systemd unit if you want one.\n\
         Nothing is written until you confirm at the end.",
    )?;

    let dir: PathBuf = input("Where should the node's files go?")
        .default_input("./oracle-node")
        .validate(|text: &String| {
            if Path::new(text).join("signing.key").exists() {
                Err("this directory already holds a node key")
            } else {
                Ok(())
            }
        })
        .interact()?;
    let operator: Operator = input("Who runs this node?")
        .placeholder("your organisation, as governance knows it")
        .validate(|text: &String| parses::<Operator>(text))
        .interact()?;
    let endpoint: Endpoint = input("Which WebSocket URL will clients dial?")
        .default_input(&args.endpoint.to_string())
        .validate(|text: &String| parses::<Endpoint>(text))
        .interact()?;

    let (unlock, passphrase) = unlock(&dir)?;
    let service = service(&unlock)?;

    let setup = NodeSetup {
        dir,
        operator,
        endpoint,
        source,
        governance,
        unlock,
        service,
    };
    note("Ready to write", summary(&setup))?;
    if !confirm("Create the node?").initial_value(true).interact()? {
        return Err(io::ErrorKind::Interrupted.into());
    }

    let spinner = cliclack::spinner();
    spinner.start("Generating and encrypting the key…");
    let written = NodeKey::generate()
        .and_then(|key| {
            let written = setup.write(&key, &passphrase)?;
            Ok((key, written))
        })
        .map_err(io::Error::other);
    let (key, written) = match written {
        Ok(done) => {
            spinner.stop("Key encrypted");
            done
        }
        Err(error) => {
            spinner.error(&error);
            return Err(error);
        }
    };
    finish(&setup, &key, &written)
}

fn unlock(dir: &Path) -> io::Result<(Unlock, SecretString)> {
    let kind = select("How does the node open its key when it starts?")
        .item(
            UnlockKind::GeneratedFile,
            "A generated passphrase in a 0600 file",
            "for systemd: nobody types at a service",
        )
        .item(
            UnlockKind::Typed,
            "A passphrase I type at each start",
            "nothing to steal next to the key",
        )
        .interact()?;
    match kind {
        UnlockKind::GeneratedFile => Ok((
            Unlock::NewPassphraseFile(dir.join("passphrase")),
            generate_passphrase().map_err(io::Error::other)?,
        )),
        UnlockKind::Typed => loop {
            let first = password("Passphrase for the key").mask('▪').interact()?;
            let again = password("The same passphrase again").mask('▪').interact()?;
            if first == again {
                break Ok((Unlock::Prompt, SecretString::from(first)));
            }
            log::warning("The two passphrases differ. Try again.")?;
        },
    }
}

fn service(unlock: &Unlock) -> io::Result<Option<ServiceUnit>> {
    if unlock.file().is_none() {
        return Ok(None);
    }
    if !confirm("Write a systemd unit for it?")
        .initial_value(cfg!(target_os = "linux"))
        .interact()?
    {
        return Ok(None);
    }
    let user: String = input("Which user does the service run as?")
        .default_input(&std::env::var("USER").unwrap_or_default())
        .validate(|text: &String| {
            if !text.is_empty()
                && text
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            {
                Ok(())
            } else {
                Err("a user name of letters, digits, `_`, `-` or `.`")
            }
        })
        .interact()?;
    let exe = std::env::current_exe()?;
    Ok(Some(ServiceUnit { user, exe }))
}

fn summary(setup: &NodeSetup) -> String {
    let source = match &setup.source {
        RegistrySource::Mainnet(canister) => format!("canister {canister} on mainnet"),
        RegistrySource::Network {
            canister, gateway, ..
        } => format!("canister {canister} through {gateway}"),
    };
    let unlock = setup.unlock.file().map_or_else(
        || "a passphrase typed at each start".to_owned(),
        |file| format!("a passphrase in {}", file.display()),
    );
    let lines = [
        ("directory", setup.dir.display().to_string()),
        ("operator", setup.operator.to_string()),
        ("endpoint", setup.endpoint.to_string()),
        ("registry", source),
        ("governance", setup.governance.to_checksummed()),
        ("unlock", unlock),
        (
            "service",
            setup.service.as_ref().map_or_else(
                || "none".to_owned(),
                |service| format!("oracle-node.service, as {}", service.user),
            ),
        ),
    ];
    lines
        .iter()
        .map(|(name, value)| format!("{} {value}", ui::dim(format!("{name:<11}"))))
        .collect::<Vec<_>>()
        .join("\n")
}

fn finish(setup: &NodeSetup, key: &NodeKey, written: &Written) -> io::Result<()> {
    let mut files = vec![
        (&written.key, "the key, encrypted"),
        (&written.entry, "the registry entry, for governance"),
        (&written.config, "the config"),
    ];
    if let Some(path) = &written.passphrase {
        files.push((path, "opens the key"));
    }
    if let Some(path) = &written.unit {
        files.push((path, "the systemd unit"));
    }
    let dir = written.key.parent().unwrap_or(&setup.dir);
    let lines: Vec<String> = files
        .iter()
        .map(|(path, what)| {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            format!("{name:<21}{}", ui::dim(what))
        })
        .collect();
    log::success(format!(
        "Written to {}\n{}",
        dir.display(),
        lines.join("\n")
    ))?;

    let entry = key.entry(&setup.operator, &setup.endpoint);
    let entry = serde_json::to_string(&entry).map_err(io::Error::other)?;
    // Log lines, not notes: a note box wraps a long command into pieces that
    // no longer paste.
    log::info(format!(
        "Governance adds the node with:\n{}",
        candid_call(&setup.source.canister().to_string(), "add_node", &[&entry])
    ))?;
    for warning in ui::warnings(setup) {
        log::warning(warning)?;
    }
    log::step(format!("Next\n{}", ui::numbered(&ui::next_steps(written))))?;
    outro(format!(
        "Node {} is ready for governance.",
        ui::strong(key.signing.address().to_checksummed())
    ))
}

/// A validator for cliclack: the text must parse as `T`.
fn parses<T>(text: &str) -> Result<(), String>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    text.trim()
        .parse::<T>()
        .map(|_| ())
        .map_err(|error| error.to_string())
}
