//! `sudo oracle-node init`: the node as a system service.
//!
//! One question, the endpoint, and then everything else: the service user,
//! the key and the config in /var/lib/oracle-node, the systemd unit, and the
//! firewall. A second question comes only when init would turn a firewall
//! on. The node starts at once, and waits until governance lists it.

use std::io;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use cliclack::{confirm, input, intro, log, note, outro, outro_cancel};
use oracle_node::init::system::{
    self, FirewallPlan, FirewallStep, SERVICE_USER, SYSTEM_DIR, UNIT_NAME, UNIT_PATH,
};
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

    let (setup, firewall) = if ui::interactive() {
        // In raw mode Ctrl-C reaches cliclack as a key and cancels the prompt.
        let _ = ctrlc::set_handler(|| {});
        match ask(args, setup) {
            Ok(answer) => answer,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                let _ = outro_cancel("Nothing was written.");
                return Err(wizard::Cancelled.into());
            }
            Err(error) => return Err(error).context("the wizard failed"),
        }
    } else {
        let setup = setup(args.endpoint.clone().context(
            "a system install needs --endpoint: the WebSocket URL that clients dial, \
             such as ws://<this machine's public IP>:8791/v2/ws",
        )?);
        let firewall = firewall_step(args, &setup);
        (setup, firewall)
    };
    setup.check()?;
    install(&setup, firewall.as_ref())
}

/// The firewall step, unless `--no-firewall` leaves the firewall alone.
fn firewall_step(args: &InitArgs, setup: &NodeSetup) -> Option<FirewallStep> {
    (!args.no_firewall).then(|| FirewallStep::detect(setup.listen_port()))
}

/// Asks for the endpoint unless `--endpoint` gave it, for a yes before a
/// firewall is turned on, then for a yes to the whole install.
fn ask(
    args: &InitArgs,
    setup: impl FnOnce(Endpoint) -> NodeSetup,
) -> io::Result<(NodeSetup, Option<FirewallStep>)> {
    intro(ui::heading(" oracle-node init "))?;
    let endpoint = match &args.endpoint {
        Some(endpoint) => endpoint.clone(),
        // TODO: suggest this machine's public address as the default. A typed
        // address is the one part of the entry that can never change later.
        None => input("Which WebSocket URL will clients dial?")
            .placeholder("ws://<this machine's public IP>:8791/v2/ws")
            .validate(|text: &String| wizard::parses::<Endpoint>(text))
            .interact()?,
    };
    let setup = setup(endpoint);
    if let Some(warning) = ui::loopback_warning(&setup.source, &setup.endpoint) {
        log::warning(warning)?;
    }
    let mut firewall = firewall_step(args, &setup);
    if let Some(step) = &firewall {
        let question = match step.plan {
            FirewallPlan::Install(name) => Some(format!(
                "No firewall is active. Install {name} and turn it on? It allows {} and \
                 closes every other port.",
                step.allowed()
            )),
            FirewallPlan::Enable(name) => Some(format!(
                "{name} is installed but off. Turn it on? It allows {} and closes every \
                 other port.",
                step.allowed()
            )),
            FirewallPlan::Open(_) | FirewallPlan::Unavailable => None,
        };
        if let Some(question) = question
            && !confirm(question).initial_value(true).interact()?
        {
            firewall = None;
        }
    }
    note("A system install", summary(&setup, firewall.as_ref()))?;
    if !confirm("Install and start the node?")
        .initial_value(true)
        .interact()?
    {
        return Err(io::ErrorKind::Interrupted.into());
    }
    outro("Installing")?;
    Ok((setup, firewall))
}

fn summary(setup: &NodeSetup, firewall: Option<&FirewallStep>) -> String {
    let firewall = firewall.map_or_else(
        || format!("left alone; open {}/tcp yourself", setup.listen_port()),
        ToString::to_string,
    );
    let lines = [
        ("user", SERVICE_USER.to_owned()),
        ("directory", SYSTEM_DIR.to_owned()),
        ("endpoint", setup.endpoint.to_string()),
        ("listen", format!("0.0.0.0:{}", setup.listen_port())),
        ("registry", wizard::registry(&setup.source)),
        ("service", format!("{UNIT_PATH}, started now and at boot")),
        ("firewall", firewall),
    ];
    let mut text: Vec<String> = lines
        .iter()
        .map(|(name, value)| format!("{} {value}", ui::dim(format!("{name:<10}"))))
        .collect();
    text.push(String::new());
    text.push("The node waits until governance adds it to the registry.".to_owned());
    text.join("\n")
}

fn install(setup: &NodeSetup, firewall: Option<&FirewallStep>) -> anyhow::Result<()> {
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
    match firewall {
        Some(step) => match (step.plan, step.apply().with_context(cleanup)?) {
            (FirewallPlan::Open(_), Some(name)) => {
                done(&format!("Opened port {port}/tcp in {name}"));
            }
            (FirewallPlan::Install(_), Some(name)) => done(&format!(
                "Installed and turned on {name}: {} allowed, every other port closed",
                step.allowed()
            )),
            (_, Some(name)) => done(&format!(
                "Turned on {name}: {} allowed, every other port closed",
                step.allowed()
            )),
            (_, None) => println!(
                "  No firewall found, and no apt-get or dnf to install one. Open TCP port \
                 {port} in the firewall you use, or the cloud provider's."
            ),
        },
        None => println!("  Firewall left alone. Open TCP port {port} in it."),
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
