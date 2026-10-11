//! A system install: what `sudo oracle-node init` adds to the files that
//! [`NodeSetup::write`](super::NodeSetup::write) writes.
//!
//! A service user owns the node's directory, systemd runs the unit, and an
//! active firewall opens the port. Users, units and firewall rules change only
//! through the distribution's own commands.

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

/// A firewall that [`open_port`] changed.
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

/// Opens a TCP port in ufw or firewalld, if one of them is active. Returns
/// the firewall it changed.
///
/// # Errors
///
/// Returns [`InitError::Command`] if the firewall refuses the rule.
pub fn open_port(port: u16) -> Result<Option<Firewall>, InitError> {
    let rule = format!("{port}/tcp");
    if stdout_of("ufw", &["status"]).is_some_and(|status| ufw_active(&status)) {
        run(Command::new("ufw").args(["allow", &rule]))?;
        return Ok(Some(Firewall::Ufw));
    }
    if stdout_of("firewall-cmd", &["--state"]).is_some_and(|state| state.trim() == "running") {
        run(Command::new("firewall-cmd").args(["--permanent", &format!("--add-port={rule}")]))?;
        run(Command::new("firewall-cmd").arg("--reload"))?;
        return Ok(Some(Firewall::Firewalld));
    }
    Ok(None)
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
