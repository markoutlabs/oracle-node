//! The test harness of this crate: a scripted connection, a session runner, and
//! recorded frames through one decoder.
//!
//! Only tests build it, with the `testing` feature. Nothing here is fit for
//! production use.

mod feed;
mod script;

pub use feed::{Feed, RECV_NS, Replayed, contracts_of, fixed, instrument, kinds, of};
pub use script::{
    Run, Script, ScriptedConn, ScriptedConnector, run_adapter_until_connected, run_for, run_until,
    session_config,
};
