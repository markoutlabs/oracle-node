//! Depth snapshots into observations, for every venue that sends them.

use std::sync::Arc;

use oracle_types::{BookDepth, Fixed, InstrumentId, Level, ObsKind, Observation};

use crate::DecodeError;

/// Parses one level from the strings a venue sends.
pub(crate) fn level(price: &str, qty: &str) -> Result<Level, DecodeError> {
    let parse = |field: &'static str, value: &str| {
        value.parse::<Fixed>().map_err(|_| DecodeError::BadDecimal {
            field,
            value: value.to_owned(),
        })
    };
    Ok(Level {
        price: parse("depth price", price)?,
        qty: parse("depth size", qty)?,
    })
}

/// A depth observation, with the best level of each side as its top of book.
/// `None` for a one-sided snapshot, which prices nothing.
///
/// Sorted best first here, whatever order the venue used, because the impact
/// walk trusts that order.
pub(crate) fn observation(
    instrument: InstrumentId,
    mut bids: Vec<Level>,
    mut asks: Vec<Level>,
    exchange_time_ns: Option<u64>,
    local_recv_ns: u64,
    seq: Option<u64>,
) -> Option<Observation> {
    bids.retain(|level| level.qty.is_positive());
    asks.retain(|level| level.qty.is_positive());
    bids.sort_by(|a, b| b.price.cmp(&a.price));
    asks.sort_by(|a, b| a.price.cmp(&b.price));
    let (best_bid, best_ask) = (*bids.first()?, *asks.first()?);
    let mid = best_bid
        .price
        .checked_add(best_ask.price)?
        .checked_div(Fixed::from_int(2).ok()?)?;
    Some(Observation {
        instrument,
        kind: ObsKind::Depth,
        price: mid,
        bid: Some(best_bid.price),
        ask: Some(best_ask.price),
        bid_qty: Some(best_bid.qty),
        ask_qty: Some(best_ask.qty),
        depth_notional_1bp: None,
        exchange_time_ns,
        local_recv_ns,
        seq,
        book: Some(Arc::new(BookDepth { bids, asks })),
    })
}
