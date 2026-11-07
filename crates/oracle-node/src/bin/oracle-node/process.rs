//! The process around the node: its signals, and its open-file limit.

#[cfg(unix)]
use tracing::warn;

/// SIGTERM and SIGINT, registered once at start. A signal that arrives
/// between two waits then stays queued, and is not lost.
pub(crate) struct Signals {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
}

impl Signals {
    pub(crate) fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                terminate: signal(SignalKind::terminate())?,
                interrupt: signal(SignalKind::interrupt())?,
            })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }

    /// Waits for the next signal, and names it.
    pub(crate) async fn recv(&mut self) -> std::io::Result<&'static str> {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.terminate.recv() => Ok("SIGTERM"),
                _ = self.interrupt.recv() => Ok("SIGINT"),
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await?;
            Ok("ctrl-c")
        }
    }
}

/// Raises the open-file limit to its ceiling, and warns when it is still below
/// `needed`: past it, the node cannot accept clients or reach venues.
#[cfg(unix)]
pub(crate) fn raise_open_files(needed: usize) {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};
    let Ok((soft, hard)) = getrlimit(Resource::RLIMIT_NOFILE) else {
        return;
    };
    let needed = nix::libc::rlim_t::try_from(needed).unwrap_or(nix::libc::rlim_t::MAX);
    // macOS refuses an unlimited soft limit, so the second try asks only for `needed`.
    let limit = [hard, needed]
        .into_iter()
        .find(|&target| {
            target > soft
                && target <= hard
                && setrlimit(Resource::RLIMIT_NOFILE, target, hard).is_ok()
        })
        .unwrap_or(soft);
    if limit < needed {
        warn!(
            limit,
            needed,
            "the open-file limit is below what server.limits.max_sockets and the venues need; \
             raise LimitNOFILE or lower max_sockets"
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use nix::sys::resource::{Resource, getrlimit};

    #[test]
    fn the_open_file_limit_rises_to_what_the_node_needs() {
        let (_, hard) = getrlimit(Resource::RLIMIT_NOFILE).expect("readable");
        raise_open_files(2_048);
        let (soft, _) = getrlimit(Resource::RLIMIT_NOFILE).expect("readable");
        assert!(soft >= hard.min(2_048), "soft {soft}, hard {hard}");
    }
}
