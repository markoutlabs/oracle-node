//! The JSON a web client sends and receives.
//!
//! ```jsonc
//! // client → proxy
//! {"op":"subscribe","prices":["CRYPTO.BTC/USD"],"venues":[...],"books":["binance:spot:BTCUSDT"]}
//! {"op":"unsubscribe","prices":[...],"venues":[...],"books":[...]}
//! {"op":"ping","id":1}
//!
//! // proxy → client
//! {"type":"subscribed","prices":[...],"venues":[...],"books":[...],"unknown":[...]}
//! {"type":"price","symbol":"CRYPTO.BTC/USD","status":"ok","price":"86599.95",...}
//! {"type":"venues","symbol":"CRYPTO.BTC/USDT","node":"0x…","report":{...}}
//! {"type":"book","book":"binance:spot:BTCUSDT","seq":12,"snapshot":false,...}
//! {"type":"pong","id":1}
//! {"type":"error","code":"rate_limited","message":"..."}
//! ```
//!
//! Every 64-bit time and every decimal is a string: a JavaScript number would
//! lose precision on a nanosecond timestamp.

use std::sync::Arc;

use oracle_client::{AcceptedVenues, Book, Resolved};
use oracle_types::{BookLevel, InstrumentId, MarketKind, Symbol, Venue, VenueReport};
use serde::{Deserialize, Serialize};

/// A message from a web client.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientOp {
    /// Start receiving the listed topics.
    Subscribe(Topics),
    /// Stop receiving the listed topics.
    Unsubscribe(Topics),
    /// Liveness check.
    Ping {
        /// Echoed back.
        #[serde(default)]
        id: Option<u64>,
    },
}

/// Topics by name: feed symbols for prices and venue reports, and
/// `venue:market:symbol` for books.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Topics {
    /// Feed symbols whose prices to send.
    #[serde(default)]
    pub prices: Vec<String>,
    /// Feed symbols whose venue reports to send.
    #[serde(default)]
    pub venues: Vec<String>,
    /// Books, as `venue:market:symbol`.
    #[serde(default)]
    pub books: Vec<String>,
}

impl Topics {
    /// How many topics are listed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.prices.len() + self.venues.len() + self.books.len()
    }

    /// Returns `true` if nothing is listed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Parses a book name, `venue:market:symbol`, as [`InstrumentId`] prints it.
#[must_use]
pub fn parse_book(text: &str) -> Option<InstrumentId> {
    let mut parts = text.splitn(3, ':');
    let venue: Venue = parts.next()?.parse().ok()?;
    let market: MarketKind = parts.next()?.parse().ok()?;
    let symbol = parts.next().filter(|symbol| !symbol.is_empty())?;
    Some(InstrumentId::new(venue, market, symbol))
}

fn json(value: &impl Serialize) -> Arc<str> {
    // Every message type here serializes; a failure would be a bug in this file.
    serde_json::to_string(value)
        .unwrap_or_else(|error| {
            format!(r#"{{"type":"error","code":"internal","message":"{error}"}}"#)
        })
        .into()
}

#[derive(Serialize)]
struct PriceMessage {
    r#type: &'static str,
    symbol: String,
    feed_id: String,
    status: &'static str,
    price: Option<String>,
    conf: Option<String>,
    nodes: usize,
    halted_nodes: usize,
    concerns: Vec<&'static str>,
    publish_time_ns: String,
    spread_bps: Option<String>,
}

/// A resolved price.
#[must_use]
pub fn price_message(symbol: &Symbol, resolved: &Resolved) -> Arc<str> {
    json(&PriceMessage {
        r#type: "price",
        symbol: symbol.to_string(),
        feed_id: resolved.feed_id.to_string(),
        status: resolved.status.as_str(),
        price: resolved.price.map(|price| price.to_string()),
        conf: resolved.conf.map(|conf| conf.to_string()),
        nodes: resolved.nodes,
        halted_nodes: resolved.halted_nodes,
        concerns: resolved
            .concerns
            .iter()
            .map(|concern| concern.as_str())
            .collect(),
        publish_time_ns: resolved.publish_time_ns.to_string(),
        spread_bps: resolved.spread_bps.map(|bps| bps.to_string()),
    })
}

#[derive(Serialize)]
struct VenuesMessage<'a> {
    r#type: &'static str,
    symbol: String,
    node: String,
    report: &'a VenueReport,
}

/// One node's venue report.
#[must_use]
pub fn venues_message(symbol: &Symbol, accepted: &AcceptedVenues) -> Arc<str> {
    json(&VenuesMessage {
        r#type: "venues",
        symbol: symbol.to_string(),
        node: accepted.signer.to_string(),
        report: &accepted.report,
    })
}

#[derive(Serialize)]
struct BookMessage {
    r#type: &'static str,
    book: String,
    seq: u64,
    snapshot: bool,
    available: bool,
    node: Option<String>,
    publish_time_ns: String,
    local_recv_ns: String,
    bids: Vec<[String; 2]>,
    asks: Vec<[String; 2]>,
}

/// What one book message says, before it is serialized.
pub struct BookFrame<'a> {
    /// The book.
    pub instrument: &'a InstrumentId,
    /// The proxy's own sequence for this book.
    pub seq: u64,
    /// `true` for the whole book, `false` for the changed levels.
    pub snapshot: bool,
    /// `false` when no node has a valid book: the levels are empty.
    pub available: bool,
    /// The node whose book this is.
    pub source: Option<&'a Book>,
    /// Bids, best first. A size of zero removes the level.
    pub bids: Vec<BookLevel>,
    /// Asks, best first. A size of zero removes the level.
    pub asks: Vec<BookLevel>,
}

/// A book snapshot or delta. Prices and sizes are decimals.
#[must_use]
pub fn book_message(frame: &BookFrame<'_>) -> Arc<str> {
    let levels = |levels: &[BookLevel]| -> Vec<[String; 2]> {
        levels
            .iter()
            .filter_map(|level| Book::level_fixed(*level).ok())
            .map(|(price, qty)| [price.to_string(), qty.to_string()])
            .collect()
    };
    json(&BookMessage {
        r#type: "book",
        book: frame.instrument.to_string(),
        seq: frame.seq,
        snapshot: frame.snapshot,
        available: frame.available,
        node: frame.source.map(|book| book.node.to_string()),
        publish_time_ns: frame
            .source
            .map_or(0, |book| book.publish_time_ns)
            .to_string(),
        local_recv_ns: frame
            .source
            .map_or(0, |book| book.local_recv_ns)
            .to_string(),
        bids: levels(&frame.bids),
        asks: levels(&frame.asks),
    })
}

#[derive(Serialize)]
struct Subscribed<'a> {
    r#type: &'static str,
    prices: &'a [String],
    venues: &'a [String],
    books: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    unknown: &'a [String],
}

/// The reply to a subscribe or an unsubscribe.
#[must_use]
pub fn subscribed(kind: &'static str, accepted: &Topics, unknown: &[String]) -> Arc<str> {
    json(&Subscribed {
        r#type: kind,
        prices: &accepted.prices,
        venues: &accepted.venues,
        books: &accepted.books,
        unknown,
    })
}

/// The reply to a ping.
#[must_use]
pub fn pong(id: Option<u64>) -> Arc<str> {
    json(&serde_json::json!({ "type": "pong", "id": id }))
}

/// A refused request.
#[must_use]
pub fn error(code: &str, message: &str) -> Arc<str> {
    json(&serde_json::json!({ "type": "error", "code": code, "message": message }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ops_parse_and_refuse_unknown_fields() {
        let op: ClientOp = serde_json::from_str(
            r#"{"op":"subscribe","prices":["CRYPTO.BTC/USD"],"books":["binance:spot:BTCUSDT"]}"#,
        )
        .expect("parses");
        let ClientOp::Subscribe(topics) = op else {
            panic!("a subscribe: {op:?}");
        };
        assert_eq!(topics.len(), 2);
        assert!(serde_json::from_str::<ClientOp>(r#"{"op":"subscribe","feeds":[]}"#).is_err());
        assert!(serde_json::from_str::<ClientOp>(r#"{"op":"drop"}"#).is_err());
        assert_eq!(
            serde_json::from_str::<ClientOp>(r#"{"op":"ping"}"#).expect("parses"),
            ClientOp::Ping { id: None }
        );
    }

    #[test]
    fn book_names_round_trip_with_instrument_ids() {
        let instrument = InstrumentId::new(Venue::Okx, MarketKind::LinearPerp, "BTC-USDT-SWAP");
        assert_eq!(parse_book(&instrument.to_string()), Some(instrument));
        assert_eq!(parse_book("binance:spot:"), None);
        assert_eq!(parse_book("nowhere:spot:BTC"), None);
        assert_eq!(parse_book("binance:BTC"), None);
    }
}
