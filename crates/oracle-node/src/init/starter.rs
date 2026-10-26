//! The starter `config.toml`. `init` knows every value in it, so the node
//! starts from it without an edit.

use std::path::Path;

use super::{NodeSetup, feeds};

/// Renders the config. Paths are written as given; `NodeSetup::write` passes
/// absolute ones.
pub(super) fn render(setup: &NodeSetup, key_file: &Path) -> String {
    // Quoted by the TOML serializer, so a quote or a backslash in a path cannot
    // produce a file the node then refuses to load.
    let quoted = |text: &str| toml::Value::String(text.to_owned()).to_string();
    let path = |path: &Path| quoted(&path.display().to_string());

    let listen = format!("0.0.0.0:{}", setup.listen_port());
    let passphrase_line = setup.unlock.file().map_or_else(
        || "# passphrase_file = \"/etc/oracle/passphrase\"".to_owned(),
        |file| format!("passphrase_file = {}", path(file)),
    );

    let source = &setup.source;
    let mut registry_source = format!(
        "url = {}\n# Each fetched document must carry this canister's certificate.\n\
         canister_id = {}",
        quoted(&source.url("registry.json")),
        quoted(&source.canister().to_string()),
    );
    if let Some(root_key) = source.root_key() {
        registry_source.push_str(&format!(
            "\n# The root key of the network the canister runs on. Mainnet's is built in.\n\
             root_key = {}",
            quoted(root_key)
        ));
    }
    let clients_source = format!(
        "url = {}\n# Seconds between fetches. Bounds how long a revocation takes to land.\n\
         poll_secs = 30",
        quoted(&source.url("clients.json"))
    );
    let publish_gateway = source.gateway().map_or_else(String::new, |gateway| {
        format!("gateway = {}\n", quoted(&gateway.to_string()))
    });
    let governance = format!(
        "governance_address = {}",
        quoted(&setup.governance.to_checksummed())
    );
    let feeds = feeds::network();
    let max_pending = feeds::max_pending(feeds.count);

    format!(
        r#"# Heartbeats and stale venues are checked on this timer. A price move publishes
# when it arrives.
tick_interval_ms = 25

[server]
listen = {listen}
max_pending_feeds = {max_pending}

[signing]
# A file or an environment variable, never a command-line argument: arguments
# are visible in `ps` to every user on the box. The key file is an `age` file;
# the passphrase that opens it comes from a 0600 file, or from a prompt at
# startup when this line is absent.
key_file = {key_file}
{passphrase_line}

[registry]
{registry_source}
# Pinned here rather than taken from the registry itself, which would let the
# document vouch for its own author.
{governance}

# The governance-signed client list (SPEC §6.1). The node serves prices only to
# these clients, encrypted, over /v2/ws, and refuses to start without the list.
[clients]
{clients_source}

# Pushes this node's frames to the registry canister, which serves each listed
# feed's median to other canisters and as the certified /prices.json. Each push
# costs the canister cycles. Remove the section to stop the pushes.
[publish]
{publish_gateway}heartbeat_secs = 30
deviation_bps = 10
min_interval_secs = 5

{header}

{feeds}"#,
        listen = quoted(&listen),
        key_file = path(key_file),
        header = feeds::header(feeds.count),
        feeds = feeds.text,
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::super::{CanisterId, RegistrySource, Unlock};
    use super::*;
    use crate::NodeConfig;

    const CANISTER: &str = "uxrrr-q7777-77774-qaaaq-cai";

    fn governance() -> oracle_wire::Address {
        oracle_wire::Address::from_bytes([0x11; 20])
    }

    fn setup(source: RegistrySource) -> NodeSetup {
        NodeSetup {
            dir: PathBuf::from("/etc/oracle"),
            endpoint: "ws://127.0.0.1:9001/v2/ws".parse().expect("valid"),
            source,
            governance: governance(),
            unlock: Unlock::PassphraseFile(PathBuf::from("/etc/oracle/passphrase")),
            service: None,
        }
    }

    fn canister() -> CanisterId {
        CANISTER.parse().expect("valid")
    }

    fn sources() -> [RegistrySource; 2] {
        [
            RegistrySource::Mainnet(canister()),
            RegistrySource::Network {
                canister: canister(),
                gateway: "http://127.0.0.1:8000".parse().expect("valid"),
                root_key: "3082".parse().expect("valid"),
            },
        ]
    }

    fn parse(setup: &NodeSetup) -> NodeConfig {
        let text = render(setup, Path::new("/etc/oracle/signing.key"));
        toml::from_str(&text)
            .unwrap_or_else(|e| panic!("init must emit a valid config: {e}\n{text}"))
    }

    #[test]
    fn every_network_renders_a_config_the_node_starts_from() {
        for source in sources() {
            let config = parse(&setup(source.clone()));
            let resolved = config.resolve().expect("the emitted feeds must resolve");
            assert_eq!(resolved.feeds.len(), feeds::network().count);
            assert!(config.server.max_pending_feeds >= 2 * resolved.feeds.len());
            assert_eq!(
                config.signing.key_file.as_deref(),
                Some(Path::new("/etc/oracle/signing.key"))
            );
            assert_eq!(config.server.listen, "0.0.0.0:9001");
            assert_eq!(config.governance().ok(), Some(governance()));
            assert_eq!(config.registry.url, Some(source.url("registry.json")));
            assert_eq!(config.registry.canister_id.as_deref(), Some(CANISTER));
            assert_eq!(
                config.registry.root_key.is_some(),
                matches!(source, RegistrySource::Network { .. })
            );
            let clients = config.clients.as_ref().expect("a [clients] section");
            assert_eq!(clients.url, Some(source.url("clients.json")));
            assert_eq!(clients.poll_secs, 30);
            let push = crate::publish::PushTarget::from_config(&config)
                .expect("a valid [publish] section")
                .expect("a [publish] section");
            let local = matches!(source, RegistrySource::Network { .. });
            assert_eq!(push.gateway == "http://127.0.0.1:8000", local);
            assert_eq!(push.root_key.is_some(), local);
        }
    }

    #[test]
    fn without_a_passphrase_file_the_node_prompts() {
        let mut setup = setup(RegistrySource::Mainnet(canister()));
        setup.unlock = Unlock::Prompt;
        assert!(parse(&setup).signing.passphrase_file.is_none());
    }

    /// A backslash in a path used to produce a file the node then refused to
    /// load.
    #[test]
    fn awkward_paths_are_quoted() {
        let mut setup = setup(RegistrySource::Mainnet(canister()));
        setup.unlock = Unlock::PassphraseFile(PathBuf::from(r#"C:\keys\"pass""#));
        let text = render(&setup, Path::new(r"C:\keys\signing.key"));
        let config: NodeConfig = toml::from_str(&text).expect("valid TOML");
        assert_eq!(
            config.signing.key_file.as_deref(),
            Some(Path::new(r"C:\keys\signing.key"))
        );
        assert_eq!(
            config.signing.passphrase_file.as_deref(),
            Some(Path::new(r#"C:\keys\"pass""#))
        );
    }
}
