//! Toobit spot books, read over REST each second: Toobit is the one venue here
//! with no socket (see [`super::toobit_connect::ToobitConnector`]).
//!
//! - **One record a read.** `{"type":"rest","subject":"depth","topic":"/rest:ICPUSDT",
//!   "data":{"t":…,"b":[…],"a":[…]}}`; the symbol is the part of the topic after
//!   its prefix. A failed read has `error` in place of `data`.
//! - **Books.** `/quote/v1/depth` gives the best levels as a whole book, prices
//!   and sizes as text, best first, so the node keeps no deltas. `t` is the time
//!   of the venue's last match, in milliseconds.
//! - **Refusals.** A reply such as `{"code":-1121,"msg":"Invalid symbol."}` has
//!   no book.
//!
//! Checked against the live REST on 2026-11-12. Spot only.

use oracle_types::Observation;
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::book::{BookMsg, BookRule, Books, Change, Continuity};
use crate::clock::millis_to_nanos;
use crate::{DecodeError, InstrumentMap};

use super::{decimal, parse};

pub use super::toobit_connect::{URL, url};

/// Markets on one connection: all of them, so that the connector paces the
/// reads of the whole address.
pub const MARKETS_PER_CONNECTION: usize = usize::MAX;

/// Each reply is a whole book.
const BOOK_RULE: BookRule = BookRule::new(Continuity::WholeBook);

const TOPIC: &str = "/rest:";

#[derive(Deserialize)]
struct Record<'a> {
    #[serde(borrow, default)]
    topic: Option<&'a str>,
    #[serde(borrow, default)]
    data: Option<&'a RawValue>,
    #[serde(borrow, default)]
    error: Option<&'a RawValue>,
}

/// A book, or Toobit's refusal in its place.
#[derive(Deserialize)]
struct Reply<'a> {
    #[serde(default)]
    t: Option<u64>,
    #[serde(borrow, default)]
    b: Option<Vec<(&'a str, &'a str)>>,
    #[serde(borrow, default)]
    a: Option<Vec<(&'a str, &'a str)>>,
    #[serde(default)]
    code: Option<i64>,
    #[serde(borrow, default)]
    msg: Option<&'a str>,
}

/// Decodes one record of the connector's.
///
/// # Errors
///
/// Returns [`DecodeError`]. A failed read, a refusal and a book that does not
/// parse lose the book; a crossed book is a resync, and an empty side a halt.
pub fn decode(
    payload: &[u8],
    map: &InstrumentMap,
    books: &mut Books,
    local_recv_ns: u64,
    out: &mut Vec<Observation>,
) -> Result<(), DecodeError> {
    let record: Record<'_> = serde_json::from_slice(payload)?;
    let symbol = record
        .topic
        .and_then(|topic| topic.strip_prefix(TOPIC))
        .ok_or(DecodeError::MissingField("topic"))?;
    let entry = map
        .lookup(symbol)
        .ok_or_else(|| DecodeError::UnknownInstrument(symbol.to_owned()))?;
    let parsed = match (record.data, record.error) {
        (_, Some(error)) => Err(DecodeError::Malformed(format!(
            "the read failed: {}",
            error.get()
        ))),
        (Some(data), None) => parse::<Reply<'_>>(data).and_then(whole),
        (None, None) => Err(DecodeError::MissingField("data")),
    };
    books
        .keeper
        .apply(BOOK_RULE, entry, parsed, local_recv_ns, out)
}

/// The whole book of a reply.
fn whole(reply: Reply<'_>) -> Result<BookMsg<'static>, DecodeError> {
    if let Some(code) = reply.code {
        return Err(DecodeError::Malformed(format!(
            "Toobit refused the read: code {code}: {}",
            reply.msg.unwrap_or_default()
        )));
    }
    let bids = reply.b.ok_or(DecodeError::MissingField("b"))?;
    let asks = reply.a.ok_or(DecodeError::MissingField("a"))?;
    let book = BookMsg::whole(&bids, &asks, |(price, size)| {
        Ok(Change::new(
            decimal("price", price)?,
            decimal("size", size)?,
        ))
    })?;
    Ok(book.at(reply.t.map(millis_to_nanos)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::book::DEPTH_LEVELS;
    use crate::testing::{Feed, fixed, instrument, of};
    use oracle_types::{MarketKind, ObsKind, Venue};

    /// Recorded from Toobit on 2026-11-12: three reads each of ICPUSDT and
    /// ETHUSDT, 50 levels a side, as the connector frames them.
    const RECORDED: &str = include_str!("../../tests/fixtures/toobit.jsonl");

    /// ICP with its book, and ETH with its top only.
    fn toobit() -> Feed {
        let books = [
            instrument("ICPUSDT", MarketKind::Spot).with_depth(),
            instrument("ETHUSDT", MarketKind::Spot),
        ];
        Feed::venue(decode, Venue::Toobit, MarketKind::Spot, &books)
    }

    fn record(data: &str) -> String {
        format!(r#"{{"data":{data},"subject":"depth","topic":"/rest:ICPUSDT","type":"rest"}}"#)
    }

    #[test]
    fn each_read_gives_its_book_and_a_top_only_market_its_top() {
        let all = toobit().replay(RECORDED.lines());
        let icp = of(&all, "ICPUSDT", ObsKind::Depth);
        assert_eq!(icp.len(), 3);
        let last = icp.last().expect("a book");
        let book = last.book.as_deref().expect("levels");
        assert_eq!(
            (book.bids.len(), book.asks.len()),
            (DEPTH_LEVELS, DEPTH_LEVELS)
        );
        assert_eq!(
            (last.bid, last.ask),
            (Some(fixed("2.527")), Some(fixed("2.528")))
        );
        assert_eq!(
            last.exchange_time_ns,
            Some(millis_to_nanos(1_794_493_990_997))
        );

        let eth = of(&all, "ETHUSDT", ObsKind::BookTop);
        assert_eq!(eth.len(), 3);
        assert!(of(&all, "ETHUSDT", ObsKind::Depth).is_empty());
        assert!(
            eth.iter()
                .all(|top| top.bid < top.ask && top.book.is_none())
        );
    }

    #[test]
    fn a_failed_read_or_a_refusal_loses_the_book() {
        let mut feed = toobit();
        let _ = feed.decoded(record(r#"{"t":1,"b":[["2.5","1"]],"a":[["2.6","1"]]}"#));
        let failed = r#"{"error":"HTTP 429 Too Many Requests from https://api.toobit.com","subject":"depth","topic":"/rest:ICPUSDT","type":"rest"}"#;
        for payload in [
            failed.to_owned(),
            record(r#"{"code":-1121,"msg":"Invalid symbol."}"#),
            record(r#"{"t":1,"b":[["2.5","1"]]}"#),
            record(r#"{"t":1,"b":[["x","1"]],"a":[["2.6","1"]]}"#),
        ] {
            let error = feed.refused(&payload);
            assert!(
                matches!(&error, DecodeError::Lost { instrument, .. } if &*instrument.symbol == "ICPUSDT"),
                "{payload}: {error:?}"
            );
        }
        let error = feed.refused(failed);
        assert!(error.to_string().contains("429"), "{error}");
    }

    #[test]
    fn a_crossed_book_resyncs_and_an_empty_side_halts() {
        let mut feed = toobit();
        let crossed = record(r#"{"t":1,"b":[["2.7","1"]],"a":[["2.6","1"]]}"#);
        assert!(matches!(feed.refused(crossed), DecodeError::Resync(_)));
        let one_sided = record(r#"{"t":1,"b":[["2.5","1"]],"a":[]}"#);
        let (out, halted) = feed.halted(one_sided);
        assert!(out.is_empty());
        assert_eq!(halted, ["ICPUSDT"]);
    }

    #[test]
    fn an_untracked_book_is_benign() {
        let untracked = r#"{"data":{"t":1,"b":[],"a":[]},"topic":"/rest:BTCUSDT","type":"rest"}"#;
        assert!(toobit().refused(untracked).is_benign());
        assert!(matches!(
            toobit().refused(r#"{"data":{},"type":"rest"}"#),
            DecodeError::MissingField("topic")
        ));
    }
}
