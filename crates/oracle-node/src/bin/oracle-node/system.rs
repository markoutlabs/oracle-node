//! `sudo oracle-node init`: the node as a system service.
//!
//! One question, the endpoint, and then everything else: the service user,
//! the key and the config in /var/lib/oracle-node, the systemd unit, and the
//! port. The node starts at once, and waits until governance lists it.

use std::io;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use cliclack::{confirm, input, intro, log, note, outro, outro_cancel};
use oracle_node::init::system::{self, SERVICE_USER, SYSTEM_DIR, UNIT_NAME, UNIT_PATH};
use oracle_node::{
    Endpoint, NodeKey, NodeSetup, ServiceUnit, Unlock, candid_call, generate_passphrase,
};

use crate::init::{self, InitArgs};
use crate::{ui, wizard};

pub(crate) fn run(args: &InitArgs) -> anyhow::Result<()> {
    let (source, governance) = init::network(args)?;
    let exe = std::env::current_exe().context("cannot find this binary for the unit")?;
    system::preflight(&exe)?;
    let setup = |endpoint: Endpoint| NodeSetup {
        dir: PathBuf::from(SYSTEM_DIR),
        endpoint,
        source,
        governance,
        unlock: Unlock::NewPassphraseFile(Path::new(SYSTEM_DIR).join("passphrase")),
        service: Some(ServiceUnit {
            user: SERVICE_USER.to_owned(),
            exe,
        }),
    };

    let setup = if ui::interactive() {
        // In raw mode Ctrl-C reaches cliclack as a key and cancels the prompt.
        let _ = ctrlc::set_handler(|| {});
        match ask(args, setup) {
            Ok(setup) => setup,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                let _ = outro_cancel("Nothing was written.");
                return Err(wizard::Cancelled.into());
            }
            Err(error) => return Err(error).context("the wizard failed"),
        }
    } else {
        setup(args.endpoint.clone().context(
            "a system install needs --endpoint: the WebSocket URL that clients dial, \
             such as ws://203.0.113.7:8791/v2/ws",
        )?)
    };
    setup.check()?;
    install(&setup)
}

/// Asks for the endpoint unless `--endpoint` gave it, then for a yes.
fn ask(args: &InitArgs, setup: impl FnOnce(Endpoint) -> NodeSetup) -> io::Result<NodeSetup> {
    intro(ui::heading(" oracle-node init "))?;
    let endpoint = match &args.endpoint {
        Some(endpoint) => endpoint.clone(),
        None => input("Which WebSocket URL will clients dial?")
            .placeholder("ws://203.0.113.7:8791/v2/ws")
            .validate(|text: &String| wizard::parses::<Endpoint>(text))
            .interact()?,
    };
    let setup = setup(endpoint);
    if let Some(warning) = ui::loopback_warning(&setup.source, &setup.endpoint) {
        log::warning(warning)?;
    }
    note("A system install", summary(&setup))?;
    if !confirm("Install and start the node?")
        .initial_value(true)
        .interact()?
    {
        return Err(io::ErrorKind::Interrupted.into());
    }
    outro("Installing")?;
    Ok(setup)
}

fn summary(setup: &NodeSetup) -> String {
    let lines = [
        ("user", SERVICE_USER.to_owned()),
        ("directory", SYSTEM_DIR.to_owned()),
        ("endpoint", setup.endpoint.to_string()),
        ("listen", format!("0.0.0.0:{}", setup.listen_port())),
        ("registry", wizard::registry(&setup.source)),
        ("service", format!("{UNIT_PATH}, started now and at boot")),
    ];
    let mut text: Vec<String> = lines
        .iter()
        .map(|(name, value)| format!("{} {value}", ui::dim(format!("{name:<10}"))))
        .collect();
    text.push(String::new());
    text.push("The node waits until governance adds it to the registry.".to_owned());
    text.join("\n")
}

fn install(setup: &NodeSetup) -> anyhow::Result<()> {
    let user = system::ensure_user()?;
    done(&if user.created {
        format!("Created the user {SERVICE_USER}")
    } else {
        format!("The user {SERVICE_USER} exists")
    });
    system::make_dir(&user)?;

    // Up to here, a retry needs no cleanup. From here, it needs one, but the
    // registry does not list the key yet, so nothing is lost.
    let cleanup = || {
        format!(
            "the install stopped part way. Fix the cause, then remove what it made and run \
             init again:\n  sudo systemctl disable --now {UNIT_NAME}\n  \
             sudo rm -rf {SYSTEM_DIR} {UNIT_PATH}"
        )
    };
    let key = NodeKey::generate()?;
    let passphrase = generate_passphrase()?;
    let mut written = setup.write(&key, &passphrase).with_context(cleanup)?;
    system::install(&mut written, &user).with_context(cleanup)?;
    done(&format!(
        "Wrote the key, its passphrase and the config to {SYSTEM_DIR}"
    ));

    let port = setup.listen_port();
    match system::open_port(port).with_context(cleanup)? {
        Some(firewall) => done(&format!("Opened port {port}/tcp in {firewall}")),
        None => println!(
            "  No active ufw or firewalld. Open TCP port {port} in any other firewall, \
             such as the cloud provider's."
        ),
    }
    system::start_service().with_context(cleanup)?;
    done(&format!("Started {UNIT_NAME}, which also starts at boot"));
    report(setup, &key)
}

fn done(text: &str) {
    println!("{} {text}", ui::strong("✓"));
}

fn report(setup: &NodeSetup, key: &NodeKey) -> anyhow::Result<()> {
    let address = key.signing.address().to_checksummed();
    println!(
        "\n{} {}\n  It waits until governance adds it to the registry, then serves.",
        ui::heading("Node"),
        ui::strong(&address)
    );
    let entry = serde_json::to_string(&key.entry(&setup.endpoint))?;
    // At column 0, so the command pastes as it is.
    println!(
        "\n{}\n{}",
        ui::heading("Governance adds the node with:"),
        candid_call(
            setup.source.network(),
            &setup.source.canister().to_string(),
            "add_node",
            &[&entry]
        )
    );
    println!(
        "\n{}\n  {}",
        ui::heading("The ed25519 publisher key, for venues that verify ed25519:"),
        key.publisher_hex()
    );
    println!(
        "\n{}\n  journalctl -u {UNIT_NAME} -f\n  systemctl status {UNIT_NAME}",
        ui::heading("Follow the node:")
    );
    for warning in ui::warnings(setup) {
        println!("\n{} {warning}", ui::heading("Note:"));
    }
    Ok(())
}
