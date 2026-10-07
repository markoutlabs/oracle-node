//! A proxy that serves verified oracle data to web clients.
//!
//! A browser cannot run the node transport (SPEC §6.1): the handshake needs a
//! client API key, which a web page cannot keep secret. This proxy is one listed
//! client. It runs the SDK, with its signature checks and its quorum, and serves
//! the result as JSON over one plain WebSocket, `/v1/ws`. A reverse proxy in
//! front of it terminates TLS.
//!
//! The web socket is open to anyone. The limits in [`config::Limits`] are what
//! bound one client's cost.

pub mod config;
pub mod hub;
pub mod protocol;
pub mod upstream;
pub mod web;
