//! `start --tail`: every observation in and every signed update out.

use oracle_ingest::IngestEvent;
use oracle_types::Symbol;
use tracing::{info, warn};

/// Logs one decoded observation on its way into the aggregator.
///
/// This is the venue's own view, after normalisation and before anything is
/// weighted, filtered or aggregated — which is what makes it the right place to
/// see whether an adapter is actually reading a feed correctly.
pub(crate) fn log_observation(event: &IngestEvent) {
    match event {
        IngestEvent::Observation(observation) => {
            let instrument = &observation.instrument;
            info!(
                target: "tail",
                venue = %instrument.venue,
                market = %instrument.market,
                symbol = %instrument.symbol,
                kind = observation.kind.as_str(),
                // The venue's own update id, where it sends one. Two lines with
                // the same price and a different seq are two real book updates
                // — `bookTicker` pushes on size-only changes too — which is
                // otherwise indistinguishable from a duplicate at a glance.
                seq = observation.seq.map(|s| s.to_string()).unwrap_or_default(),
                price = %observation.price,
                bid = observation.bid.map(|b| b.to_string()).unwrap_or_default(),
                ask = observation.ask.map(|a| a.to_string()).unwrap_or_default(),
                bid_qty = observation.bid_qty.map(|q| q.to_string()).unwrap_or_default(),
                ask_qty = observation.ask_qty.map(|q| q.to_string()).unwrap_or_default(),
                // `None` on venues that send no timestamp, and never used for
                // staleness — that is measured with our own clock.
                lag_ms = observation
                    .exchange_time_ns
                    .map(|venue_ns| {
                        (i128::from(observation.local_recv_ns) - i128::from(venue_ns)) / 1_000_000
                    })
                    .map(|ms| ms.to_string())
                    .unwrap_or_default(),
                "observation"
            );
        }
        IngestEvent::Connected { stream } => {
            info!(target: "tail", %stream, "stream up");
        }
        IngestEvent::Disconnected { stream, reason } => {
            warn!(target: "tail", %stream, %reason, "stream down — venue state invalidated");
        }
        // Five a second for each connection, and no new value in any of them.
        IngestEvent::Alive { .. } => {}
        // `IngestEvent` is non-exhaustive. A tail that silently skipped a new
        // variant would be least useful exactly when something new appeared.
        other => info!(target: "tail", ?other, "event"),
    }
}

/// Logs one signed update on its way out to subscribers, named by its feed.
pub(crate) fn log_update(update: &oracle_wire::SignedUpdate, symbol: Option<&Symbol>) {
    let payload = update.update();
    let status = if payload.flags.is_halted() {
        "HALTED"
    } else if payload.flags.is_degraded() {
        "degraded"
    } else {
        "ok"
    };
    info!(
        target: "tail",
        feed = symbol.map(ToString::to_string).unwrap_or_default(),
        status,
        price = payload.price_fixed().map(|p| p.to_string()).unwrap_or_default(),
        conf = payload.conf_fixed().map(|c| c.to_string()).unwrap_or_default(),
        seq = payload.seq,
        sources = payload.num_sources,
        venues = ?payload.sources,
        "published"
    );
}
