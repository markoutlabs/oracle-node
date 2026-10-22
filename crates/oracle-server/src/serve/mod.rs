//! The accept loop. It refuses a socket before it reads a byte, and closes a
//! socket that does not send a whole request head in time.
//!
//! `axum::serve` sets no timer, so hyper's header timeout is off there: a
//! socket that sends nothing would stay open for ever.

mod held;

use std::io;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::http::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower::Service as _;
use tracing::warn;

use crate::limit::{Admission, Limits};
use held::Held;

/// The largest request head in bytes; hyper answers 431 past it. A client
/// sends one GET with a few headers.
const MAX_HEAD: usize = 16 * 1024;
/// After an accept error such as too many open files, so the loop does not spin.
const ACCEPT_PAUSE: Duration = Duration::from_secs(1);

/// Serves `router` on `listener` within the socket limits, until `shutdown`.
/// Then it stops accepting and lets each plain request finish. Each request
/// carries [`ConnectInfo`] with the peer's address.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    limits: Limits,
    shutdown: CancellationToken,
) {
    let sockets = Arc::new(Admission::new(
        limits.max_sockets,
        limits.sockets_per_ip,
        limits.sockets_per_minute,
    ));
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout())
        .max_buf_size(MAX_HEAD);
    let tracker = TaskTracker::new();
    loop {
        let accepted = tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let (socket, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                if !is_connection_error(&error) {
                    warn!(%error, "cannot accept a socket");
                    tokio::time::sleep(ACCEPT_PAUSE).await;
                }
                continue;
            }
        };
        // A refused socket closes here, before hyper reads from it.
        let Ok(place) = Admission::admit(&sockets, limits.key(peer.ip())) else {
            continue;
        };
        let router = router.clone();
        let service = service_fn(move |mut request: Request<Incoming>| {
            request.extensions_mut().insert(ConnectInfo(peer));
            router.clone().call(request)
        });
        let connection = http
            .serve_connection(TokioIo::new(Held { socket, place }), service)
            .with_upgrades();
        let shutdown = shutdown.clone();
        tracker.spawn(async move {
            let mut connection = pin!(connection);
            tokio::select! {
                _ = connection.as_mut() => return,
                () = shutdown.cancelled() => connection.as_mut().graceful_shutdown(),
            }
            let _ = connection.await;
        });
    }
    tracker.close();
    tracker.wait().await;
}

fn is_connection_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}
