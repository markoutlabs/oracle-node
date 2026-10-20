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
//! # Rotation
//!
//! A node has one key, and its address is the node's id (SPEC §3.5). A rotation
//! is governance's `replace_node`: the registry lists the new address in place
//! of the old one, at the same endpoint. This client learns about it the first
//! time it sees a frame from the new key, or a challenge from the new address:
//! either triggers one fetch from the [`RegistrySource`], at most once per
//! `refresh_interval`. [`OracleClient::refresh_registry`] adopts the newer
//! governance-signed document in place, with no lost feed state. The quorum
//! seat moves to the new address, and the old key is reported as
//! [`RejectReason::RetiredKey`] from then on, without a fetch.
//!
//! Stored frames are a separate path: [`verify_historical`] checks a frame
//! against when its signer was listed.
//!
//! # Example
//!
//! ```no_run
//! use std::time::Duration;
//! use oracle_client::{OracleClient, Status};
//!
//! # async fn run(
//! #     registry: oracle_wire::VerifiedRegistry,
//! #     api_key: oracle_wire::Signer,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = OracleClient::builder(registry)
//!     .quorum(3)
//!     .max_age(Duration::from_secs(2))
//!     .client_key(api_key) // its address is listed by governance (SPEC §6.1)
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

mod book;
mod client;
pub mod latency;
pub mod mainnet;
pub mod nodes;
pub mod quorum;
pub mod source;
pub mod tap;
pub mod testing;
pub mod verify;

pub use book::Book;
pub use client::{
    ClientError, ClientStats, Event, OracleClient, OracleClientBuilder, Subscription,
    now_unix_nanos,
};
pub use latency::{LatencyHistogram, LatencyReport, Percentiles};
pub use nodes::{ConnectionState, DeliveryWindow, NodeFeed, NodeFrames, NodeReport};
pub use quorum::{Concern, FeedView, NodeFeedState, QuorumConfig, Resolved, Status};
pub use source::{
    Certification, FetchError, HttpDocumentSource, HttpRegistrySource, IC_MAINNET_ROOT_KEY,
    RegistrySource,
};
pub use tap::{FrameKind, TappedFrame, Verdict};
pub use verify::{
    Accepted, AcceptedBook, AcceptedFunding, AcceptedVenues, RejectReason, Verifier, VerifyConfig,
    verify_historical,
};
