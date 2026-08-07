//! Consumer SDK: verify signed updates from many nodes, resolve one price.
//!
//! # Read this before using the crate
//!
//! **A signature proves authorship, not truth.** It says a particular node
//! asserted a particular price. It says nothing about whether that price is
//! right, or even whether the node ever connected to an exchange. There is no
//! verifiable computation here.
//!
//! The defence against a lying or malfunctioning node is the **median across N
//! independently-keyed nodes**, plus divergence monitoring. Verifying signatures
//! from a single node confirms who is talking and nothing else — which is why
//! [`OracleClientBuilder::build`] refuses a quorum below three unless you go out
//! of your way to say otherwise.
//!
//! # The two halves
//!
//! [`Verifier`] handles one update at a time: signature, registry membership,
//! certificate validity at publish time, replay, staleness, coherence. It is the
//! piece that catches a relay withholding new updates and rebroadcasting old
//! ones — an attack under which every signature still verifies perfectly.
//!
//! [`FeedView`] handles the cross-node step: median price, and a confidence
//! interval floored at half the inter-node spread. That floor is the crux — a
//! disagreeing node cannot move the median, and its disagreement automatically
//! widens the band, so a consumer that keys off `conf` reacts correctly with no
//! additional logic.
//!
//! Both are pure and synchronous. [`OracleClient`] is the thin async layer that
//! connects to nodes and drives them.
//!
//! # Example
//!
//! ```no_run
//! use std::time::Duration;
//! use oracle_client::{OracleClient, Status};
//!
//! # async fn run(registry: oracle_wire::VerifiedRegistry) -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = OracleClient::builder(registry)
//!     .quorum(3)
//!     .max_age(Duration::from_secs(2))
//!     .build()?;
//!
//! client.subscribe(&["CRYPTO.BTC/USD"]).await?;
//! while let Some(price) = client.next().await {
//!     match price.status {
//!         Status::Ok | Status::Degraded => {
//!             // Act on `price.conf`. Degraded means the band is doing real work.
//!         }
//!         Status::Halted => { /* stop */ }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

mod client;
pub mod quorum;
pub mod testing;
pub mod verify;

pub use client::{ClientError, OracleClient, OracleClientBuilder};
pub use quorum::{Concern, FeedView, QuorumConfig, Resolved, Status};
pub use verify::{Accepted, RejectReason, Verifier, VerifyConfig};
