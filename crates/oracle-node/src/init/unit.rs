//! The systemd unit `init` writes beside the config.
//!
//! `Type=notify`: the node tells systemd when it serves and what it is doing.
//! The sandboxing leaves the node what it uses: reading its directory,
//! binding its port, and outbound TCP to the venues and the canister.

use std::path::Path;

use oracle_wire::Address;

use super::{InitError, ServiceUnit};

/// Renders the unit.
///
/// # Errors
///
/// Returns [`InitError::Invalid`] for a user name or a path that systemd would
/// read as something else: unit files expand `%` and `$`, and quote with `"`.
pub(super) fn render(
    service: &ServiceUnit,
    config: &Path,
    address: Address,
) -> Result<String, InitError> {
    let user = &service.user;
    let valid_user = !user.is_empty()
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if !valid_user {
        return Err(InitError::Invalid(format!(
            "`{user}` is not a user name systemd accepts"
        )));
    }
    let exe = quoted(&service.exe)?;
    // The node caches the network's feed set beside its config.
    let dir = quoted(config.parent().unwrap_or_else(|| Path::new("/")))?;
    let config = quoted(config)?;
    Ok(format!(
        r#"# Written by `oracle-node init`. After an edit:
#   sudo systemctl daemon-reload && sudo systemctl restart oracle-node
[Unit]
Description=Price oracle node {address}
# The node fetches the registry at start.
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
NotifyAccess=main
User={user}
ExecStart={exe} start {config}
Restart=on-failure
RestartSec=10s
# Exit 78 is a config error: only an edit fixes it.
RestartPreventExitStatus=78
TimeoutStopSec=20s

# Each client socket and venue connection is a file: room for server.limits.max_sockets.
LimitNOFILE=65536

# The key is in memory: no core dumps, no swap (SPEC §9.2).
LimitCORE=0
MemorySwapMax=0
UMask=0077

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
# A listen port below 1024 needs:
# AmbientCapabilities=CAP_NET_BIND_SERVICE
# CapabilityBoundingSet=CAP_NET_BIND_SERVICE
# The node caches the network's feed set next to its config, and
# `start --record FILE` writes there too.
ReadWritePaths={dir}

[Install]
WantedBy=multi-user.target
"#,
        address = address.to_checksummed(),
    ))
}

fn quoted(path: &Path) -> Result<String, InitError> {
    let text = path.display().to_string();
    if text
        .chars()
        .any(|c| matches!(c, '%' | '$' | '"' | '\\') || c.is_control())
    {
        return Err(InitError::Invalid(format!(
            "systemd cannot quote the path `{text}`: it holds % $ \" \\ or a control character"
        )));
    }
    Ok(format!("\"{text}\""))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn service(user: &str, exe: &str) -> ServiceUnit {
        ServiceUnit {
            user: user.to_owned(),
            exe: PathBuf::from(exe),
        }
    }

    #[test]
    fn the_unit_runs_the_node_as_a_notify_service() {
        let unit = render(
            &service("oracle", "/usr/local/bin/oracle-node"),
            Path::new("/home/oracle/node 1/config.toml"),
            Address::from_bytes([0x11; 20]),
        )
        .expect("renders");
        for line in [
            "Type=notify",
            "User=oracle",
            r#"ExecStart="/usr/local/bin/oracle-node" start "/home/oracle/node 1/config.toml""#,
            "RestartPreventExitStatus=78",
            "LimitNOFILE=65536",
            "LimitCORE=0",
            "MemorySwapMax=0",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            r#"ReadWritePaths="/home/oracle/node 1""#,
        ] {
            assert!(unit.lines().any(|l| l == line), "missing `{line}`:\n{unit}");
        }
    }

    #[test]
    fn what_systemd_would_expand_is_refused() {
        let address = Address::from_bytes([0x11; 20]);
        let config = Path::new("/etc/oracle/config.toml");
        for exe in [
            "/opt/%i/oracle-node",
            "/opt/$HOME/oracle-node",
            "/opt/\"x\"",
        ] {
            assert!(
                render(&service("oracle", exe), config, address).is_err(),
                "{exe}"
            );
        }
        for user in ["", "root user", "x;y"] {
            assert!(
                render(&service(user, "/usr/bin/oracle-node"), config, address).is_err(),
                "{user:?}"
            );
        }
    }
}
