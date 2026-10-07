//! Output for people: styled when the stream is a terminal, plain otherwise,
//! with the same words either way so scripts and tests can read it.

use std::fmt::Display;
use std::io::IsTerminal as _;

use console::{StyledObject, style};
use oracle_node::{Endpoint, NodeSetup, RegistrySource, Written};

/// `true` when a person can answer prompts. cliclack draws on stderr, and a
/// redirected stdout means a script is reading.
pub(crate) fn interactive() -> bool {
    std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal()
}

pub(crate) fn heading<D: Display>(text: D) -> StyledObject<D> {
    style(text).bold()
}

pub(crate) fn strong<D: Display>(text: D) -> StyledObject<D> {
    style(text).bold().green()
}

pub(crate) fn dim<D: Display>(text: D) -> StyledObject<D> {
    style(text).dim()
}

/// One thing to do after `init`: what and why, then commands to run as they are.
pub(crate) struct Step {
    pub(crate) text: String,
    pub(crate) commands: Vec<String>,
}

impl Step {
    fn new(text: String) -> Self {
        Self {
            text,
            commands: Vec::new(),
        }
    }

    fn run(mut self, command: String) -> Self {
        self.commands.push(command);
        self
    }
}

/// What to do after `init`.
pub(crate) fn next_steps(written: &Written) -> Vec<Step> {
    let mut steps = vec![Step::new(format!(
        "Send {} to governance. Until governance adds the node, nothing it signs \
         verifies for anyone.",
        written.entry.display()
    ))];
    steps.push(match &written.unit {
        Some(unit) => Step::new("Install the service and start it:".to_owned())
            .run(format!(
                "sudo install -m 0644 {} /etc/systemd/system/",
                unit.display()
            ))
            .run("sudo systemctl daemon-reload".to_owned())
            .run("sudo systemctl enable --now oracle-node".to_owned())
            .run("journalctl -u oracle-node -f".to_owned()),
        None => Step::new("Start the node:".to_owned())
            .run(format!("oracle-node start {}", written.config.display())),
    });
    steps
}

/// Things in the setup that work but need a hand before production.
/// A mainnet node that registers a loopback endpoint cannot serve anyone.
pub(crate) fn loopback_warning(source: &RegistrySource, endpoint: &Endpoint) -> Option<String> {
    (matches!(source, RegistrySource::Mainnet(_)) && endpoint.is_loopback()).then(|| {
        format!(
            "{endpoint} names this machine, but mainnet lists it for every client. \
             Clients elsewhere cannot dial it; use the node's public wss:// URL."
        )
    })
}

pub(crate) fn warnings(setup: &NodeSetup) -> Vec<String> {
    let mut warnings: Vec<String> = loopback_warning(&setup.source, &setup.endpoint)
        .into_iter()
        .collect();
    if let Some(service) = &setup.service {
        if service
            .exe
            .components()
            .any(|part| part.as_os_str() == "target")
        {
            warnings.push(format!(
                "The unit starts {}, a build output. Install the binary, for example in \
                 /usr/local/bin, and edit ExecStart.",
                service.exe.display()
            ));
        }
        if let Some(port) = setup.endpoint.port().filter(|port| *port < 1024) {
            warnings.push(format!(
                "Port {port} is below 1024: uncomment the two capability lines in the unit."
            ));
        }
    }
    warnings
}

/// Numbers the steps, with each command on its own indented line.
pub(crate) fn numbered(steps: &[Step]) -> String {
    let mut out = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        out.push(format!("  {}. {}", index.saturating_add(1), step.text));
        for command in &step.commands {
            for line in command.lines() {
                out.push(format!("       {line}"));
            }
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use oracle_node::{RegistrySource, ServiceUnit, Unlock};

    use super::*;

    fn setup(service: Option<ServiceUnit>) -> NodeSetup {
        NodeSetup {
            dir: PathBuf::from("/srv/oracle"),
            endpoint: "ws://127.0.0.1:443/v2/ws".parse().expect("valid"),
            source: RegistrySource::Mainnet("uxrrr-q7777-77774-qaaaq-cai".parse().expect("valid")),
            governance: oracle_wire::Address::from_bytes([0x11; 20]),
            unlock: Unlock::NewPassphraseFile(PathBuf::from("/srv/oracle/passphrase")),
            service,
        }
    }

    fn written(unit: bool) -> Written {
        Written {
            key: PathBuf::from("/srv/oracle/signing.key"),
            entry: PathBuf::from("/srv/oracle/node-entry.json"),
            config: PathBuf::from("/srv/oracle/config.toml"),
            passphrase: Some(PathBuf::from("/srv/oracle/passphrase")),
            unit: unit.then(|| PathBuf::from("/srv/oracle/oracle-node.service")),
        }
    }

    #[test]
    fn systemctl_appears_only_with_a_unit() {
        let without = numbered(&next_steps(&written(false)));
        assert!(!without.contains("systemctl"), "{without}");
        assert!(without.contains("oracle-node start /srv/oracle/config.toml"));

        let service = ServiceUnit {
            user: "oracle".to_owned(),
            exe: PathBuf::from("/repo/target/debug/oracle-node"),
        };
        let with = numbered(&next_steps(&written(true)));
        assert!(
            with.contains("systemctl enable --now oracle-node"),
            "{with}"
        );
        let warned = warnings(&setup(Some(service)));
        assert_eq!(warned.len(), 3, "{warned:?}");
        assert!(
            warned.iter().any(|w| w.contains("names this machine")),
            "{warned:?}"
        );
    }

    #[test]
    fn a_loopback_endpoint_warns_only_on_mainnet() {
        let mainnet = setup(None);
        assert_eq!(warnings(&mainnet).len(), 1, "the loopback endpoint");
        let public = NodeSetup {
            endpoint: "wss://node.example.com/v2/ws".parse().expect("valid"),
            ..setup(None)
        };
        assert!(warnings(&public).is_empty());
    }
}
