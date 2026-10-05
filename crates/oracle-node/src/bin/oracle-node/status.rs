//! What the node reports about itself: once when it starts serving, then every
//! minute.
//!
//! No field name contains "error": `scripts/e2e-dfx.sh` reads any startup line
//! with that word as a failure.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use console::style;
use oracle_wire::Address;
use tracing::info;

/// How often the status line is written.
pub(crate) const STATUS_EVERY: Duration = Duration::from_secs(60);

/// The node as it starts serving.
pub(crate) struct Summary {
    pub(crate) listen: SocketAddr,
    pub(crate) address: Address,
    pub(crate) governance: Address,
    pub(crate) registry_version: u64,
    pub(crate) client_list_version: u64,
    pub(crate) clients: usize,
    pub(crate) feeds: usize,
    pub(crate) connections: usize,
}

impl Summary {
    pub(crate) fn log(&self) {
        info!(
            listen = %self.listen,
            address = %self.address,
            registry = self.registry_version,
            client_list = self.client_list_version,
            clients = self.clients,
            feeds = self.feeds,
            connections = self.connections,
            "serving subscribers"
        );
    }

    /// A block for a person at a terminal, written to stderr like the logs.
    pub(crate) fn banner(&self) -> String {
        let label = |text: &str| style(format!("{text:<12}")).for_stderr().dim();
        let lines = [
            (
                "node",
                style(self.address.to_checksummed())
                    .for_stderr()
                    .bold()
                    .to_string(),
            ),
            ("governance", self.governance.to_checksummed()),
            ("registry", format!("v{}", self.registry_version)),
            (
                "clients",
                format!(
                    "{} listed, client list v{}",
                    self.clients, self.client_list_version
                ),
            ),
            (
                "feeds",
                format!("{} over {} venue connections", self.feeds, self.connections),
            ),
        ];
        let mut out = format!(
            "\n  {} {}  serving on {}\n\n",
            style("oracle-node").for_stderr().bold().green(),
            env!("CARGO_PKG_VERSION"),
            style(self.listen).for_stderr().bold(),
        );
        for (name, value) in lines {
            out.push_str(&format!("  {} {value}\n", label(name)));
        }
        out
    }
}

/// The node over the last status interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NodeStatus {
    pub(crate) feeds_published: usize,
    pub(crate) feeds: usize,
    pub(crate) clients: usize,
    pub(crate) connections_up: u64,
    pub(crate) connections: usize,
    pub(crate) updates: u64,
    pub(crate) client_list_version: u64,
}

impl NodeStatus {
    pub(crate) fn log(&self) {
        info!(
            feeds = %format_args!("{}/{}", self.feeds_published, self.feeds),
            clients = self.clients,
            connections = %format_args!("{}/{}", self.connections_up, self.connections),
            updates = self.updates,
            client_list = self.client_list_version,
            "status"
        );
    }
}

/// One line, because systemd shows `STATUS=` as one line.
impl fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{} feeds published, {} clients, {}/{} venue connections up, \
             {} updates in the last minute, client list v{}",
            self.feeds_published,
            self.feeds,
            self.clients,
            self.connections_up,
            self.connections,
            self.updates,
            self.client_list_version,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_is_one_line() {
        let status = NodeStatus {
            feeds_published: 11,
            feeds: 12,
            clients: 3,
            connections_up: 7,
            connections: 8,
            updates: 2_400,
            client_list_version: 4,
        };
        let text = status.to_string();
        assert!(!text.contains('\n'), "{text}");
        assert!(text.starts_with("11/12 feeds published"), "{text}");
        assert!(text.contains("7/8 venue connections up"), "{text}");
    }
}
