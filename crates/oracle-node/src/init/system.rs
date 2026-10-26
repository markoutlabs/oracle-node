//! A system install: what `sudo oracle-node init` adds to the files that
//! [`NodeSetup::write`](super::NodeSetup::write) writes.
//!
//! A service user owns the node's directory, systemd runs the unit, and a
//! firewall allows SSH and the port: an active one gets the rule, an absent
//! one is installed and turned on. Users, units and firewall rules change
//! only through the distribution's own commands.

use std::fmt;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use nix::unistd::{Gid, Uid, User};

use super::{InitError, Written};

/// The user the service runs as.
pub const SERVICE_USER: &str = "oracle-node";
/// The node's files.
pub const SYSTEM_DIR: &str = "/var/lib/oracle-node";
/// Where systemd reads the unit.
pub const UNIT_PATH: &str = "/etc/systemd/system/oracle-node.service";
/// The unit, as `systemctl` names it.
pub const UNIT_NAME: &str = "oracle-node";

/// Returns `true` when this process runs as root.
#[must_use]
pub fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Checks that a system install can finish, before anything is written.
///
/// # Errors
///
/// Returns [`InitError::Invalid`] when systemd does not run this machine, when
/// a node is already installed, or when the service user cannot run `exe`.
pub fn preflight(exe: &Path) -> Result<(), InitError> {
    // A home folder is closed to other users on most systems.
    if exe.starts_with("/root") || exe.starts_with("/home") {
        return Err(InitError::Invalid(format!(
            "the service user cannot run {}. Install the binary outside home folders first:\n  \
             sudo install -m 0755 {} /usr/local/bin/",
            exe.display(),
            exe.display()
        )));
    }
    // The same test as sd_booted(3).
    if !Path::new("/run/systemd/system").is_dir() {
        return Err(InitError::Invalid(
            "a system install needs systemd. To write the files only, run init with --out DIR."
                .to_owned(),
        ));
    }
    let dir = Path::new(SYSTEM_DIR);
    let used = std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some());
    if used || Path::new(UNIT_PATH).exists() {
        return Err(InitError::Invalid(format!(
            "this machine already has a node: {SYSTEM_DIR} is not empty, or {UNIT_PATH} \
             exists. To replace that node, governance removes it from the registry first. \
             Then delete both paths. The key in {SYSTEM_DIR} is the only copy."
        )));
    }
    Ok(())
}

/// The service user.
#[derive(Clone, Copy, Debug)]
pub struct ServiceUser {
    uid: Uid,
    gid: Gid,
    /// `true` if this install created it.
    pub created: bool,
}

/// Finds the service user, or creates it as a system user with no login.
///
/// # Errors
///
/// Returns [`InitError::Command`] if `useradd` fails, and
/// [`InitError::Invalid`] if the user database cannot be read.
pub fn ensure_user() -> Result<ServiceUser, InitError> {
    if let Some(user) = lookup()? {
        return Ok(ServiceUser {
            uid: user.uid,
            gid: user.gid,
            created: false,
        });
    }
    run(Command::new("useradd").args(useradd_args()))?;
    let user = lookup()?.ok_or_else(|| {
        InitError::Invalid(format!("useradd ran, but there is no user {SERVICE_USER}"))
    })?;
    Ok(ServiceUser {
        uid: user.uid,
        gid: user.gid,
        created: true,
    })
}

fn lookup() -> Result<Option<User>, InitError> {
    User::from_name(SERVICE_USER).map_err(|error| {
        InitError::Invalid(format!("cannot read the user {SERVICE_USER}: {error}"))
    })
}

const fn useradd_args() -> [&'static str; 8] {
    [
        "--system",
        "--user-group",
        "--home-dir",
        SYSTEM_DIR,
        "--no-create-home",
        "--shell",
        "/usr/sbin/nologin",
        SERVICE_USER,
    ]
}

/// Makes the node's directory, which only the service user can open.
///
/// # Errors
///
/// Returns [`InitError::Write`] if the directory cannot be made or given away.
pub fn make_dir(user: &ServiceUser) -> Result<PathBuf, InitError> {
    let dir = PathBuf::from(SYSTEM_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| write_error(&dir, &e))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| write_error(&dir, &e))?;
    give(&dir, user)?;
    Ok(dir)
}

/// Gives the written files to the service user, and moves the unit to where
/// systemd reads it.
///
/// # Errors
///
/// Returns [`InitError::Write`] if a file cannot be given away or moved.
pub fn install(written: &mut Written, user: &ServiceUser) -> Result<(), InitError> {
    for path in [&written.key, &written.entry, &written.config]
        .into_iter()
        .chain(written.passphrase.as_ref())
    {
        give(path, user)?;
    }
    if let Some(unit) = written.unit.take() {
        let target = PathBuf::from(UNIT_PATH);
        std::fs::copy(&unit, &target).map_err(|e| write_error(&target, &e))?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| write_error(&target, &e))?;
        std::fs::remove_file(&unit).map_err(|e| write_error(&unit, &e))?;
        written.unit = Some(target);
    }
    Ok(())
}

/// Loads the unit, enables it at boot, and starts it.
///
/// `--no-block`, because the node tells systemd it is ready only when it
/// serves, and it serves only after governance lists it.
///
/// # Errors
///
/// Returns [`InitError::Command`] if `systemctl` fails.
pub fn start_service() -> Result<(), InitError> {
    run(Command::new("systemctl").arg("daemon-reload"))?;
    run(Command::new("systemctl").args(["enable", "--now", "--no-block", UNIT_NAME]))
}

/// A firewall that init changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Firewall {
    /// Ubuntu's and Debian's.
    Ufw,
    /// Fedora's and RHEL's.
    Firewalld,
}

impl fmt::Display for Firewall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ufw => "ufw",
            Self::Firewalld => "firewalld",
        })
    }
}

/// What init does about the firewall, decided before it asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallPlan {
    /// The firewall is active: allow the port in it.
    Open(Firewall),
    /// The firewall is installed but off: allow SSH and the port, then turn it on.
    Enable(Firewall),
    /// No firewall is installed: install this one, allow SSH and the port, and turn it on.
    Install(Firewall),
    /// No firewall, and no `apt-get` or `dnf` to install one.
    Unavailable,
}

impl FirewallPlan {
    /// Looks for an active firewall, then an installed one, then a package manager.
    #[must_use]
    pub fn detect() -> Self {
        if stdout_of("ufw", &["status"]).is_some_and(|status| ufw_active(&status)) {
            return Self::Open(Firewall::Ufw);
        }
        if stdout_of("firewall-cmd", &["--state"]).is_some_and(|state| state.trim() == "running") {
            return Self::Open(Firewall::Firewalld);
        }
        if installed("ufw") {
            return Self::Enable(Firewall::Ufw);
        }
        if installed("firewall-cmd") {
            return Self::Enable(Firewall::Firewalld);
        }
        if installed("apt-get") {
            return Self::Install(Firewall::Ufw);
        }
        if installed("dnf") {
            return Self::Install(Firewall::Firewalld);
        }
        Self::Unavailable
    }

    /// `true` when the plan turns a firewall on, which closes every other port.
    #[must_use]
    pub const fn closes_ports(self) -> bool {
        matches!(self, Self::Enable(_) | Self::Install(_))
    }
}

/// The firewall step of a system install: the plan, and the ports it allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallStep {
    /// What to do.
    pub plan: FirewallPlan,
    /// The ports sshd listens on, from `sshd -T`. Empty without an SSH server.
    pub ssh_ports: Vec<u16>,
    /// The node's listen port.
    pub port: u16,
}

impl FirewallStep {
    /// Detects the plan and reads sshd's ports, so that turning the firewall
    /// on does not lock the operator out.
    #[must_use]
    pub fn detect(port: u16) -> Self {
        Self {
            plan: FirewallPlan::detect(),
            ssh_ports: ssh_ports(),
            port,
        }
    }

    /// The ports the step allows, as "SSH (22) and 8791/tcp".
    #[must_use]
    pub fn allowed(&self) -> String {
        if self.ssh_ports.is_empty() {
            return format!("{}/tcp only, as there is no SSH server", self.port);
        }
        let ssh: Vec<String> = self.ssh_ports.iter().map(u16::to_string).collect();
        format!("SSH ({}) and {}/tcp", ssh.join(", "), self.port)
    }

    /// Carries out the plan. Returns the firewall that now allows the port.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::Command`] if the package manager or the firewall refuses.
    pub fn apply(&self) -> Result<Option<Firewall>, InitError> {
        match self.plan {
            FirewallPlan::Open(firewall) => {
                allow(firewall, &[self.port])?;
                Ok(Some(firewall))
            }
            FirewallPlan::Enable(firewall) => {
                self.enable(firewall)?;
                Ok(Some(firewall))
            }
            FirewallPlan::Install(firewall) => {
                install_package(firewall)?;
                self.enable(firewall)?;
                Ok(Some(firewall))
            }
            FirewallPlan::Unavailable => Ok(None),
        }
    }

    fn enable(&self, firewall: Firewall) -> Result<(), InitError> {
        let mut ports = self.ssh_ports.clone();
        ports.push(self.port);
        match firewall {
            Firewall::Ufw => {
                run(Command::new("ufw").args(["default", "deny", "incoming"]))?;
                run(Command::new("ufw").args(["default", "allow", "outgoing"]))?;
                allow(firewall, &ports)?;
                run(Command::new("ufw").args(["--force", "enable"]))
            }
            Firewall::Firewalld => {
                run(Command::new("systemctl").args(["enable", "--now", "firewalld"]))?;
                allow(firewall, &ports)
            }
        }
    }
}

impl fmt::Display for FirewallStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.plan {
            FirewallPlan::Open(firewall) => {
                write!(f, "allow {}/tcp in {firewall}, which is active", self.port)
            }
            FirewallPlan::Enable(firewall) => write!(
                f,
                "turn on {firewall}: allow {}, close every other port",
                self.allowed()
            ),
            FirewallPlan::Install(firewall) => write!(
                f,
                "install {firewall} and turn it on: allow {}, close every other port",
                self.allowed()
            ),
            FirewallPlan::Unavailable => {
                write!(f, "none found; open {}/tcp yourself", self.port)
            }
        }
    }
}

fn install_package(firewall: Firewall) -> Result<(), InitError> {
    match firewall {
        Firewall::Ufw => {
            let mut update = Command::new("apt-get");
            update
                .args(["update", "-q"])
                .env("DEBIAN_FRONTEND", "noninteractive");
            run(&mut update)?;
            let mut install = Command::new("apt-get");
            install
                .args(["install", "-y", "-q", "ufw"])
                .env("DEBIAN_FRONTEND", "noninteractive");
            run(&mut install)
        }
        Firewall::Firewalld => run(Command::new("dnf").args(["install", "-y", "-q", "firewalld"])),
    }
}

fn allow(firewall: Firewall, ports: &[u16]) -> Result<(), InitError> {
    for port in ports {
        let rule = format!("{port}/tcp");
        match firewall {
            Firewall::Ufw => run(Command::new("ufw").args(["allow", &rule]))?,
            Firewall::Firewalld => {
                run(Command::new("firewall-cmd")
                    .args(["--permanent", &format!("--add-port={rule}")]))?;
            }
        }
    }
    if firewall == Firewall::Firewalld {
        run(Command::new("firewall-cmd").arg("--reload"))?;
    }
    Ok(())
}

/// The ports sshd listens on. Without an SSH server, none; when `sshd -T`
/// gives no answer, the default port, so the operator is never locked out.
fn ssh_ports() -> Vec<u16> {
    let Ok(output) = Command::new("sshd").arg("-T").env("LC_ALL", "C").output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return vec![22];
    }
    let ports = ports_in(&String::from_utf8_lossy(&output.stdout));
    if ports.is_empty() { vec![22] } else { ports }
}

/// The `port N` lines of `sshd -T`.
fn ports_in(config: &str) -> Vec<u16> {
    config
        .lines()
        .filter_map(|line| line.strip_prefix("port "))
        .filter_map(|port| port.trim().parse().ok())
        .collect()
}

/// `true` when the program can run, whatever it answers to `--version`.
fn installed(program: &str) -> bool {
    Command::new(program).arg("--version").output().is_ok()
}

fn ufw_active(status: &str) -> bool {
    status
        .lines()
        .next()
        .is_some_and(|line| line.trim() == "Status: active")
}

/// The output of a command that succeeded, or `None`.
fn stdout_of(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run(command: &mut Command) -> Result<(), InitError> {
    let line = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|part| part.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let output = command
        .env("LC_ALL", "C")
        .output()
        .map_err(|error| InitError::Command {
            command: line.clone(),
            reason: error.to_string(),
        })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(InitError::Command {
        command: line,
        reason: format!("{}: {}", output.status, stderr.trim()),
    })
}

fn give(path: &Path, user: &ServiceUser) -> Result<(), InitError> {
    std::os::unix::fs::chown(path, Some(user.uid.as_raw()), Some(user.gid.as_raw()))
        .map_err(|e| write_error(path, &e))
}

fn write_error(path: &Path, error: &std::io::Error) -> InitError {
    InitError::Write {
        path: path.to_path_buf(),
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_active_ufw_counts() {
        assert!(ufw_active("Status: active\n\nTo Action From\n"));
        assert!(!ufw_active("Status: inactive\n"));
        assert!(!ufw_active(""));
    }

    #[test]
    fn sshd_ports_come_from_its_port_lines() {
        assert_eq!(
            ports_in("port 22\nport 2222\nlistenaddress [::]:22\n"),
            [22, 2222]
        );
        assert!(ports_in("addressfamily any\n").is_empty());
    }

    #[test]
    fn the_step_says_what_it_allows() {
        let step = FirewallStep {
            plan: FirewallPlan::Install(Firewall::Ufw),
            ssh_ports: vec![22, 2222],
            port: 8791,
        };
        assert_eq!(step.allowed(), "SSH (22, 2222) and 8791/tcp");
        assert!(step.plan.closes_ports());
        let open = FirewallStep {
            plan: FirewallPlan::Open(Firewall::Ufw),
            ssh_ports: Vec::new(),
            port: 8791,
        };
        assert!(!open.plan.closes_ports());
        assert_eq!(open.to_string(), "allow 8791/tcp in ufw, which is active");
    }

    #[test]
    fn the_service_user_has_no_login_and_no_home_of_its_own() {
        let args = useradd_args();
        for flag in ["--system", "--no-create-home", "/usr/sbin/nologin"] {
            assert!(args.contains(&flag), "{flag}");
        }
        assert_eq!(args.last(), Some(&SERVICE_USER));
    }

    #[test]
    fn a_binary_in_a_home_folder_is_refused() {
        for exe in [
            "/root/.cargo/bin/oracle-node",
            "/home/me/.local/bin/oracle-node",
        ] {
            assert!(preflight(Path::new(exe)).is_err(), "{exe}");
        }
    }

    #[test]
    fn a_failed_command_names_itself_and_its_error() {
        let error = run(Command::new("sh").args(["-c", "echo nope >&2; exit 3"]))
            .expect_err("exit 3 fails");
        let text = error.to_string();
        assert!(text.contains("sh -c"), "{text}");
        assert!(text.contains("nope"), "{text}");
        assert!(
            run(&mut Command::new("oracle-node-no-such-program")).is_err(),
            "a missing program fails"
        );
    }
}
