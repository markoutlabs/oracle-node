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

use std::collections::HashMap;
use std::sync::Arc;

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

/// Shared server state.
pub struct ServerState {
    hub: Arc<Hub>,
    catalog: HashMap<FeedId, Symbol>,
    by_symbol: HashMap<String, FeedId>,
    /// The books of each feed's sources.
    books: HashMap<FeedId, Vec<InstrumentId>>,
    registry: Registry,
    transport: Arc<NodeTransport>,
}

impl ServerState {
    /// Builds server state for a fixed feed catalogue. The hub is the
    /// transport's, so every update is sealed once before fan-out.
    #[must_use]
    pub fn new(feeds: &[Symbol], registry: Registry, transport: Arc<NodeTransport>) -> Arc<Self> {
        Self::with_books(feeds, HashMap::new(), registry, transport)
    }

    /// Builds server state that also serves the books of each feed's sources.
    #[must_use]
    pub fn with_books(
        feeds: &[Symbol],
        books: HashMap<FeedId, Vec<InstrumentId>>,
        registry: Registry,
        transport: Arc<NodeTransport>,
    ) -> Arc<Self> {
        let hub = Arc::clone(transport.hub());
        let mut catalog = HashMap::with_capacity(feeds.len());
        let mut by_symbol = HashMap::with_capacity(feeds.len());
        for symbol in feeds {
            let id = feed_id(symbol);
            catalog.insert(id, *symbol);
            by_symbol.insert(symbol.to_string(), id);
        }
        Arc::new(Self {
            hub,
            catalog,
            by_symbol,
            books,
            registry,
            transport,
        })
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
        let symbol = *self.catalog.get(&signed.update().feed_id)?;
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
        let symbol = *self.catalog.get(&signed.report().feed_id)?;
        Some(self.hub.publish_venues(symbol, signed))
    }

    /// The books of these feeds' sources, each once.
    #[must_use]
    pub fn books_of(&self, feeds: &[FeedId]) -> Vec<InstrumentId> {
        let mut books: Vec<InstrumentId> = Vec::new();
        for book in feeds
            .iter()
            .filter_map(|feed| self.books.get(feed))
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
        self.by_symbol.get(symbol).copied()
    }

    /// Returns the feed catalogue.
    #[must_use]
    pub fn feeds(&self) -> Vec<FeedEntry> {
        let mut feeds: Vec<FeedEntry> = self
            .catalog
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
