//! The subscriber-facing server: WebSocket fanout and REST.
//!
//! # What this serves, and what it does not promise
//!
//! Every update leaves here signed by this node and nothing more. The server
//! does not aggregate across nodes, does not vouch for its own registry, and
//! cannot make a price true. A subscriber that trusts one node's output has
//! confirmed who is talking and learned nothing about whether to believe them —
//! `oracle-client` exists to do the rest.
//!
//! # Fanout is conflating
//!
//! Each subscriber holds one slot per feed. A newer update replaces a pending
//! older one rather than queueing behind it, because a stale price delivered
//! from behind a backlog is worse than no price: the consumer acts on it as
//! though it were current.
//!
//! The consequence is that subscribers observe **state, not transitions**. Every
//! frame carries complete state and the heartbeat makes any sustained halt
//! unmissable, but a consumer that accumulates transitions rather than reading
//! state will eventually be wrong.

pub mod app;
pub mod hub;
pub mod protocol;
pub mod testing;
pub mod transport;

pub use app::{FeedEntry, ServerState, router};
pub use hub::{Channel, Hub, Outgoing, PreparedUpdate, PreparedVenues, Subscriber};
pub use protocol::{ClientMessage, ServerMessage};
pub use transport::{NodeTransport, TransportConfig, unix_now};
