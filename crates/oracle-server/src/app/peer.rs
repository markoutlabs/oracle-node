//! The address that the per-address limits count, from the accept loop.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

/// The peer's limit key, from the accept loop. A server that does not set
/// [`ConnectInfo`], such as a test's `axum::serve`, gets only the totals.
pub(super) struct Peer(pub(super) Option<IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Infallible> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(peer)| peer.ip()),
        ))
    }
}
