//! Server state, HTTP routes, and the WebSocket handler (SPEC §6.1).
//!
//! - `rest`: the open routes, which carry no price data, and their rate.
//! - `session`: the upgrade, the handshake and the sealed session.
//! - `control`: what a session asks for: subscribe, unsubscribe, ping.
//! - `peer`: the address that the per-address limits count.

mod control;
mod peer;
mod rest;
mod session;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::Router;
use axum::middleware;
use axum::routing::get;
use oracle_types::{FeedId, InstrumentId, Symbol};
use oracle_wire::{
    Registry, SignedBookUpdate, SignedFundingUpdate, SignedUpdate, SignedVenueReport, feed_id,
};
use serde::Serialize;

use crate::hub::{Hub, PreparedBook, PreparedFunding, PreparedUpdate, PreparedVenues};
use crate::limit::{Admission, Limits, PerIp};
use crate::transport::NodeTransport;
use rest::{feeds, health, limit_requests, registry};
use session::ws_upgrade;

/// A feed this node serves.
#[derive(Clone, Debug, Serialize)]
pub struct FeedEntry {
    /// Canonical symbol.
    pub symbol: String,
    /// Derived feed id, `0x`-hex.
    pub feed_id: String,
    /// Publication exponent.
    pub expo: i32,
}

/// The feeds a node serves, the books of each one's sources, and the version
/// of the network's feed set that holds them.
struct Catalog {
    symbols: HashMap<FeedId, Symbol>,
    by_symbol: HashMap<String, FeedId>,
    books: HashMap<FeedId, Vec<InstrumentId>>,
    version: u64,
}

impl Catalog {
    fn new(feeds: &[Symbol], books: HashMap<FeedId, Vec<InstrumentId>>, version: u64) -> Self {
        let mut symbols = HashMap::with_capacity(feeds.len());
        let mut by_symbol = HashMap::with_capacity(feeds.len());
        for symbol in feeds {
            let id = feed_id(symbol);
            symbols.insert(id, *symbol);
            by_symbol.insert(symbol.to_string(), id);
        }
        Self {
            symbols,
            by_symbol,
            books,
            version,
        }
    }
}

/// Shared server state.
pub struct ServerState {
    hub: Arc<Hub>,
    /// Swapped whole when the network's feed set changes. A publish takes the
    /// current one, so it never sees half of a change.
    catalog: ArcSwap<Catalog>,
    registry: Registry,
    transport: Arc<NodeTransport>,
}

impl ServerState {
    /// Builds server state for a fixed feed catalogue. The hub is the
    /// transport's, so every update is sealed once before fan-out.
    #[must_use]
    pub fn new(feeds: &[Symbol], registry: Registry, transport: Arc<NodeTransport>) -> Arc<Self> {
        Self::with_books(feeds, HashMap::new(), 0, registry, transport)
    }

    /// Builds server state that also serves the books of each feed's sources, from feed set `version`.
    #[must_use]
    pub fn with_books(
        feeds: &[Symbol],
        books: HashMap<FeedId, Vec<InstrumentId>>,
        version: u64,
        registry: Registry,
        transport: Arc<NodeTransport>,
    ) -> Arc<Self> {
        let hub = Arc::clone(transport.hub());
        Arc::new(Self {
            hub,
            catalog: ArcSwap::from_pointee(Catalog::new(feeds, books, version)),
            registry,
            transport,
        })
    }

    /// Serves feed set `version` with `max_pending` per subscriber, and drops the latest update of each feed that left.
    pub fn set_feeds(
        &self,
        feeds: &[Symbol],
        books: HashMap<FeedId, Vec<InstrumentId>>,
        version: u64,
        max_pending: usize,
    ) {
        let next = Catalog::new(feeds, books, version);
        let kept: HashSet<FeedId> = next.symbols.keys().copied().collect();
        self.hub.set_max_pending(max_pending);
        self.catalog.store(Arc::new(next));
        self.hub.forget_feeds(&kept);
    }

    /// The version of the network's feed set this node serves; zero for its config's feeds.
    #[must_use]
    pub fn feed_set_version(&self) -> u64 {
        self.catalog.load().version
    }

    /// Returns the transport: admission, key rotation, revocation.
    #[must_use]
    pub const fn transport(&self) -> &Arc<NodeTransport> {
        &self.transport
    }

    /// Returns the fanout hub.
    #[must_use]
    pub fn hub(&self) -> &Arc<Hub> {
        &self.hub
    }

    /// Publishes a signed update to subscribers.
    ///
    /// Updates for feeds outside the catalogue are ignored rather than served
    /// under an unknown symbol.
    #[must_use]
    pub fn publish(&self, signed: SignedUpdate) -> Option<Arc<PreparedUpdate>> {
        let symbol = *self.catalog.load().symbols.get(&signed.update().feed_id)?;
        Some(self.hub.publish(symbol, signed))
    }

    /// Publishes a signed book frame to the subscribers of that book.
    #[must_use]
    pub fn publish_book(&self, signed: SignedBookUpdate) -> Arc<PreparedBook> {
        self.hub.publish_book(signed)
    }

    /// Publishes a signed funding frame to the subscribers of that perpetual.
    #[must_use]
    pub fn publish_funding(&self, signed: SignedFundingUpdate) -> Arc<PreparedFunding> {
        self.hub.publish_funding(signed)
    }

    /// Publishes a signed venue report to the subscribers that asked for it.
    #[must_use]
    pub fn publish_venues(&self, signed: SignedVenueReport) -> Option<Arc<PreparedVenues>> {
        let symbol = *self.catalog.load().symbols.get(&signed.report().feed_id)?;
        Some(self.hub.publish_venues(symbol, signed))
    }

    /// The books of these feeds' sources, each once.
    #[must_use]
    pub fn books_of(&self, feeds: &[FeedId]) -> Vec<InstrumentId> {
        let catalog = self.catalog.load();
        let mut books: Vec<InstrumentId> = Vec::new();
        for book in feeds
            .iter()
            .filter_map(|feed| catalog.books.get(feed))
            .flatten()
        {
            if !books.contains(book) {
                books.push(book.clone());
            }
        }
        books
    }

    /// The perpetual sources of these feeds, each once.
    #[must_use]
    pub fn perps_of(&self, feeds: &[FeedId]) -> Vec<InstrumentId> {
        let mut perps = self.books_of(feeds);
        perps.retain(|instrument| instrument.market.is_perp());
        perps
    }

    /// Resolves a symbol to a feed id.
    #[must_use]
    pub fn lookup(&self, symbol: &str) -> Option<FeedId> {
        self.catalog.load().by_symbol.get(symbol).copied()
    }

    /// Returns the feed catalogue.
    #[must_use]
    pub fn feeds(&self) -> Vec<FeedEntry> {
        let mut feeds: Vec<FeedEntry> = self
            .catalog
            .load()
            .symbols
            .iter()
            .map(|(id, symbol)| FeedEntry {
                symbol: symbol.to_string(),
                feed_id: id.to_string(),
                expo: symbol.expo(),
            })
            .collect();
        feeds.sort_by(|a, b| a.symbol.cmp(&b.symbol));
        feeds
    }
}

struct Web {
    state: Arc<ServerState>,
    handshakes: Arc<Admission>,
    requests: PerIp,
    limits: Limits,
}

/// Builds the HTTP and WebSocket router. Prices go only to authenticated
/// clients over `/v2/ws`; the open routes carry no price data. Serve it with
/// [`crate::serve()`], which gives the per-address limits each peer.
pub fn router(state: Arc<ServerState>, limits: &Limits) -> Router {
    let web = Arc::new(Web {
        state,
        handshakes: Arc::new(Admission::new(
            limits.max_handshakes,
            limits.handshakes_per_ip,
            limits.handshakes_per_minute,
        )),
        requests: PerIp::per_minute(limits.requests_per_minute),
        limits: limits.clone(),
    });
    let rest = Router::new()
        .route("/v2/feeds", get(feeds))
        .route("/v2/registry", get(registry))
        .route("/v2/health", get(health))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&web),
            limit_requests,
        ));
    Router::new()
        .route("/v2/ws", get(ws_upgrade))
        .merge(rest)
        .with_state(web)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{test_registry, test_transport};

    fn symbols() -> Vec<Symbol> {
        ["CRYPTO.BTC/USD", "CRYPTO.ETH/USD"]
            .into_iter()
            .map(|text| text.parse().expect("valid symbol"))
            .collect()
    }

    pub(super) fn state() -> Arc<ServerState> {
        ServerState::new(&symbols(), test_registry(), test_transport())
    }

    #[test]
    fn the_catalogue_is_sorted_and_carries_derived_ids() {
        let feeds = state().feeds();
        let symbols: Vec<&str> = feeds.iter().map(|feed| feed.symbol.as_str()).collect();
        assert_eq!(symbols, ["CRYPTO.BTC/USD", "CRYPTO.ETH/USD"]);

        let btc = feeds.first().expect("a feed");
        let expected = feed_id(&"CRYPTO.BTC/USD".parse::<Symbol>().expect("valid"));
        assert_eq!(btc.feed_id, expected.to_string());
        assert_eq!(btc.expo, -8);
    }

    #[test]
    fn a_new_feed_set_serves_its_feeds_and_drops_the_others() {
        let state = state();
        let signer = oracle_wire::Signer::from_secret_bytes([5; 32]).expect("valid key");
        let btc = feed_id(&"CRYPTO.BTC/USD".parse::<Symbol>().expect("valid"));
        let sol: Symbol = "CRYPTO.SOL/USD".parse().expect("valid");
        let update = |id| signer.sign_update(&crate::testing::sample_update(id));
        assert!(state.publish(update(btc)).is_some());
        state.set_feeds(&[sol], HashMap::new(), 4, 512);
        assert!(state.publish(update(btc)).is_none(), "BTC left the set");
        assert!(state.publish(update(feed_id(&sol))).is_some());
        assert_eq!(state.lookup("CRYPTO.BTC/USD"), None);
        assert_eq!(state.feeds().len(), 1);
        assert_eq!(
            state.hub().latest_all().len(),
            1,
            "BTC's latest update left"
        );
        assert_eq!(state.feed_set_version(), 4);
    }

    #[test]
    fn updates_for_uncatalogued_feeds_are_not_published() {
        let state = state();
        let signer = oracle_wire::Signer::from_secret_bytes([5; 32]).expect("valid key");
        let mut update = crate::testing::sample_update(feed_id(
            &"CRYPTO.BTC/USD".parse::<Symbol>().expect("valid"),
        ));
        update.feed_id = FeedId::from_bytes([0xAB; 32]);
        assert!(state.publish(signer.sign_update(&update)).is_none());
    }
}
