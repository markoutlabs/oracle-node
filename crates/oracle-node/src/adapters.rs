//! Builds the venue adapters a node runs, from a resolved config.
//!
//! Shared by the node binary and the replay harness, so a replay drives exactly
//! the adapters the node would have run, over a different transport and clock.

use oracle_ingest::binance::{BinanceAdapter, BinanceConfig};
use oracle_ingest::clock::MonotonicClock;
use oracle_ingest::venues::VenueAdapter;
use oracle_ingest::{Connector, ExchangeAdapter, IngestError};
use oracle_types::Venue;
use tracing::info;

use crate::config::VenueConnection;

/// One venue's adapter, as a node runs it.
pub struct Adapter {
    /// The venue.
    pub venue: Venue,
    /// The adapter.
    pub adapter: Box<dyn ExchangeAdapter>,
    /// The WebSocket connections it holds when it is up.
    pub connections: usize,
}

/// Builds one adapter per venue, each with its connections.
///
/// `connector` opens the sockets and `clock` stamps receipt times. The node
/// passes a real WebSocket connector and a real clock; a replay passes a
/// recording and a clock driven by it.
///
/// # Errors
///
/// Returns [`IngestError`] if an adapter rejects its instruments, or
/// [`IngestError::NoInstruments`] if nothing at all is configured.
pub fn build_adapters<C: Connector + Clone + 'static>(
    binance: BinanceConfig,
    venues: Vec<(Venue, Vec<VenueConnection>)>,
    connector: C,
    clock: MonotonicClock,
) -> Result<Vec<Adapter>, IngestError> {
    let adapters = build_venue_adapters(binance, venues, connector, clock)?;
    if adapters.is_empty() {
        return Err(IngestError::NoInstruments {
            venue: Venue::Binance,
        });
    }
    Ok(adapters)
}

/// Builds the adapters of `venues` only, for a live change; no instrument is no error.
///
/// # Errors
///
/// Returns [`IngestError`] if an adapter rejects its instruments.
pub fn build_venue_adapters<C: Connector + Clone + 'static>(
    binance: BinanceConfig,
    venues: Vec<(Venue, Vec<VenueConnection>)>,
    connector: C,
    clock: MonotonicClock,
) -> Result<Vec<Adapter>, IngestError> {
    let mut adapters = Vec::new();
    if !binance.spot.is_empty() || !binance.perp.is_empty() {
        let adapter = BinanceAdapter::new(binance, connector.clone())?.with_clock(clock.clone());
        let plan = adapter.plan()?;
        for (session, market, _) in &plan {
            info!(venue = "binance", %market, url = %session.url, "ingest endpoint");
        }
        adapters.push(Adapter {
            venue: Venue::Binance,
            adapter: Box::new(adapter),
            connections: plan.len(),
        });
    }
    for (venue, venue_connections) in venues {
        // Each connection carries its own decoder: a venue can speak different
        // protocols on different markets, and config resolution has already
        // refused any market this build cannot serve.
        let specs: Vec<_> = venue_connections
            .into_iter()
            .map(|connection| {
                info!(%venue, market = %connection.spec.market, url = %connection.spec.url,
                      "ingest endpoint");
                (connection.spec, connection.instruments)
            })
            .collect();
        adapters.push(Adapter {
            venue,
            connections: specs.len(),
            adapter: Box::new(
                VenueAdapter::new(venue, specs, connector.clone())?.with_clock(clock.clone()),
            ),
        });
    }
    Ok(adapters)
}
