//! Two tables: venue books with the rules that every book keeps, and top-of-book
//! quotes with the rules that every quote keeps.
//!
//! A book row replays a recorded session through the venue's own handler. Each
//! rule is a function, and [`conformance!`] makes one test of it for each row.
#![expect(
    clippy::indexing_slicing,
    reason = "fixed recordings; an out-of-range index is a failing test"
)]

use oracle_types::{MarketKind, ObsKind, Observation, Venue};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::DecodeError;
use crate::binance::BinanceHandler;
use crate::book::{LocalBook, Side};
use crate::testing::{Feed, contracts_of, fixed, instrument};
use crate::{InstrumentMap, InstrumentSpec};

/// How a venue proves that no update was lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proof {
    /// Each update names the one before it.
    Chain,
    /// Each update carries a checksum of the top levels.
    Checksum,
    /// A checksum message comes now and then, between the updates.
    PeriodicChecksum,
    /// Each message is a whole book, so no update can be lost.
    WholeBook,
    /// Nothing: the changes carry no sequence.
    Unproved,
}

/// One venue's recorded book.
struct Book {
    /// A new connection's handler, over the book's instrument.
    feed: fn() -> Feed,
    /// The recorded session, one message to a line.
    recorded: &'static str,
    /// The venue symbol of the book.
    symbol: &'static str,
    proof: Proof,
    /// The number of messages that emit the book.
    messages: usize,
    /// The requests that the venue refused in the recording, each an error.
    refusals: usize,
    /// The best bid and ask after the whole replay. A separate replay of each
    /// recording, outside this crate, gives the same quotes.
    best: (&'static str, &'static str),
    /// The book message that the gap case leaves out; none for a whole-book venue.
    dropped: Option<usize>,
    /// The book message that the corrupt case breaks, and the decimal in it.
    corrupt: (usize, &'static str),
    /// The first book message without its asks, to send after `last`, the
    /// recording's last line.
    without_asks: fn(first: &str, last: &str) -> String,
}

/// A book of one instrument through a venue decoder.
fn venue_feed(
    decode: super::DecodeFn,
    venue: Venue,
    market: MarketKind,
    spec: InstrumentSpec,
) -> Feed {
    Feed::venue(decode, venue, market, &[spec.with_depth()])
}

const BINANCE: Book = Book {
    feed: || {
        let spec = instrument("BTCUSDT", MarketKind::Spot).with_depth();
        let map = InstrumentMap::new(Venue::Binance, MarketKind::Spot, &[spec]).expect("valid");
        Feed::new(BinanceHandler::new(map))
    },
    // Recorded from Binance spot on 2026-10-06: five diffs, the REST
    // snapshot, then 25 more diffs.
    recorded: include_str!("../../tests/fixtures/binance-depth.jsonl"),
    symbol: "BTCUSDT",
    proof: Proof::Chain,
    messages: 26,
    refusals: 0,
    best: ("86563.2", "86563.21"),
    dropped: Some(1),
    corrupt: (1, "86699.06000000"),
    without_asks: |first, _| without(first, r#""asks":"#),
};

const BYBIT: Book = Book {
    feed: || {
        let spot = instrument("BTCUSDT", MarketKind::Spot);
        venue_feed(super::bybit::decode, Venue::Bybit, MarketKind::Spot, spot)
    },
    // Recorded from Bybit spot on 2026-10-06.
    recorded: include_str!("../../tests/fixtures/bybit-book.jsonl"),
    symbol: "BTCUSDT",
    proof: Proof::Chain,
    messages: 13,
    refusals: 0,
    best: ("86210.4", "86210.5"),
    dropped: Some(1),
    corrupt: (1, "86236.4"),
    without_asks: |first, _| without(first, r#""a":"#),
};

const OKX: Book = Book {
    feed: || {
        let spot = instrument("BTC-USDT", MarketKind::Spot);
        venue_feed(super::okx::decode, Venue::Okx, MarketKind::Spot, spot)
    },
    // Recorded from OKX on 2026-10-06: a 400-level snapshot and its updates.
    recorded: include_str!("../../tests/fixtures/okx-books.jsonl"),
    symbol: "BTC-USDT",
    proof: Proof::Chain,
    messages: 15,
    refusals: 0,
    best: ("86149.9", "86150"),
    dropped: Some(1),
    corrupt: (1, "85932.9"),
    without_asks: |first, _| without(first, r#""asks":"#),
};

const COINBASE: Book = Book {
    feed: || {
        let spot = instrument("BTC-USD", MarketKind::Spot);
        venue_feed(
            super::coinbase::decode_book,
            Venue::Coinbase,
            MarketKind::Spot,
            spot,
        )
    },
    // Recorded from Coinbase Advanced Trade on 2026-10-06; the snapshot is cut
    // to its best 200 levels a side.
    recorded: include_str!("../../tests/fixtures/coinbase-level2.jsonl"),
    symbol: "BTC-USD",
    proof: Proof::Chain,
    messages: 29,
    refusals: 0,
    best: ("86285.9", "86285.91"),
    dropped: Some(1),
    corrupt: (1, "86310"),
    without_asks: coinbase_without_asks,
};

const KRAKEN: Book = Book {
    feed: || {
        let spot = instrument("BTC/USD", MarketKind::Spot);
        venue_feed(super::kraken::decode, Venue::Kraken, MarketKind::Spot, spot)
    },
    // Recorded from Kraken on 2026-10-06 at depth 100.
    recorded: include_str!("../../tests/fixtures/kraken-book.jsonl"),
    symbol: "BTC/USD",
    proof: Proof::Checksum,
    messages: 29,
    refusals: 0,
    best: ("86061", "86061.1"),
    dropped: Some(1),
    corrupt: (1, "86049.3"),
    without_asks: kraken_without_asks,
};

const DERIBIT: Book = Book {
    feed: || {
        let perp = instrument("BTC-PERPETUAL", MarketKind::InversePerp);
        venue_feed(
            super::deribit::decode,
            Venue::Deribit,
            MarketKind::InversePerp,
            perp,
        )
    },
    // Recorded from Deribit on 2026-10-06.
    recorded: include_str!("../../tests/fixtures/deribit-book.jsonl"),
    symbol: "BTC-PERPETUAL",
    proof: Proof::Chain,
    messages: 7,
    refusals: 0,
    best: ("86192", "86192.5"),
    dropped: Some(1),
    corrupt: (1, "129289.0"),
    without_asks: |first, _| without(first, r#""asks":"#),
};

const BITFINEX: Book = Book {
    feed: || {
        let perp = instrument("tETHF0:USTF0", MarketKind::LinearPerp);
        venue_feed(
            super::bitfinex::decode,
            Venue::Bitfinex,
            MarketKind::LinearPerp,
            perp,
        )
    },
    // Recorded from Bitfinex on 2026-10-29 with checksums on: a snapshot, 57
    // updates and two checksums.
    recorded: include_str!("../../tests/fixtures/bitfinex-checksum.jsonl"),
    symbol: "tETHF0:USTF0",
    proof: Proof::PeriodicChecksum,
    messages: 56,
    refusals: 0,
    best: ("2322.8", "2323.2"),
    dropped: Some(8),
    corrupt: (1, "2318.4"),
    without_asks: bitfinex_without_asks,
};

const BITGET: Book = Book {
    feed: || {
        let spot = instrument("ETHUSDT", MarketKind::Spot);
        venue_feed(super::bitget::decode, Venue::Bitget, MarketKind::Spot, spot)
    },
    // Recorded from Bitget on 2026-10-28; the snapshot is cut to 30 levels.
    recorded: include_str!("../../tests/fixtures/bitget-spot.jsonl"),
    symbol: "ETHUSDT",
    proof: Proof::Chain,
    messages: 7,
    refusals: 1,
    best: ("2356.57", "2356.58"),
    dropped: Some(1),
    corrupt: (1, "2315.01"),
    without_asks: |first, _| without(first, r#""a":"#),
};

const LIGHTER: Book = Book {
    feed: || {
        let perp = instrument("1", MarketKind::LinearPerp);
        venue_feed(
            super::lighter::decode,
            Venue::Lighter,
            MarketKind::LinearPerp,
            perp,
        )
    },
    // Recorded from Lighter on 2026-10-28; the book is cut to 30 levels a side.
    recorded: include_str!("../../tests/fixtures/lighter.jsonl"),
    symbol: "1",
    proof: Proof::Chain,
    messages: 7,
    refusals: 1,
    best: ("81098.7", "81099.5"),
    dropped: Some(1),
    corrupt: (1, "81083.2"),
    without_asks: |first, _| without(first, r#""asks":"#),
};

const DYDX: Book = Book {
    feed: || {
        let perp = instrument("ETH-USD", MarketKind::LinearPerp);
        venue_feed(
            super::dydx::decode,
            Venue::Dydx,
            MarketKind::LinearPerp,
            perp,
        )
    },
    // Recorded from dYdX on 2026-10-28; the book is cut to 30 levels a side.
    recorded: include_str!("../../tests/fixtures/dydx.jsonl"),
    symbol: "ETH-USD",
    proof: Proof::Unproved,
    messages: 7,
    refusals: 1,
    best: ("2356", "2356.4"),
    dropped: Some(1),
    corrupt: (1, "2368.7"),
    without_asks: |first, _| without(first, r#""asks":"#),
};

const GATE: Book = Book {
    feed: || {
        let spot = instrument("ETH_USDT", MarketKind::Spot);
        venue_feed(super::gate::decode, Venue::Gate, MarketKind::Spot, spot)
    },
    // Recorded from Gate on 2026-10-28.
    recorded: include_str!("../../tests/fixtures/gate-spot.jsonl"),
    symbol: "ETH_USDT",
    proof: Proof::WholeBook,
    messages: 2,
    refusals: 0,
    best: ("2355.26", "2355.27"),
    dropped: None,
    corrupt: (0, "2358.85"),
    without_asks: |first, _| without(first, r#""asks":"#),
};

const KUCOIN: Book = Book {
    feed: || {
        let spot = instrument("BTC-USDT", MarketKind::Spot);
        venue_feed(
            super::kucoin::decode_spot,
            Venue::Kucoin,
            MarketKind::Spot,
            spot,
        )
    },
    // Recorded from KuCoin on 2026-10-25.
    recorded: include_str!("../../tests/fixtures/kucoin-spot.jsonl"),
    symbol: "BTC-USDT",
    proof: Proof::WholeBook,
    messages: 2,
    refusals: 0,
    best: ("80377.8", "80377.9"),
    dropped: None,
    corrupt: (0, "80343.5"),
    without_asks: |first, _| without(first, r#""asks":"#),
};

const MEXC: Book = Book {
    feed: || {
        let perp = contracts_of(instrument("BTC_USDT", MarketKind::LinearPerp), "0.0001");
        venue_feed(
            super::mexc::decode_futures,
            Venue::Mexc,
            MarketKind::LinearPerp,
            perp,
        )
    },
    // Recorded from MEXC futures on 2026-10-25.
    recorded: include_str!("../../tests/fixtures/mexc-futures.jsonl"),
    symbol: "BTC_USDT",
    proof: Proof::WholeBook,
    messages: 2,
    refusals: 0,
    best: ("80689.1", "80689.2"),
    dropped: None,
    corrupt: (0, "80686.9"),
    without_asks: |first, _| without(first, r#""asks":"#),
};

const BITSTAMP: Book = Book {
    feed: || {
        let spot = instrument("btcusd", MarketKind::Spot);
        venue_feed(
            super::bitstamp::decode,
            Venue::Bitstamp,
            MarketKind::Spot,
            spot,
        )
    },
    // Recorded from Bitstamp on 2026-10-28.
    recorded: include_str!("../../tests/fixtures/bitstamp-spot.jsonl"),
    symbol: "btcusd",
    proof: Proof::WholeBook,
    messages: 3,
    refusals: 1,
    best: ("80783.02", "80783.03"),
    dropped: None,
    corrupt: (0, "81020.45"),
    without_asks: |first, _| without(first, r#""asks":"#),
};

const TOOBIT: Book = Book {
    feed: || {
        let spot = instrument("ICPUSDT", MarketKind::Spot);
        venue_feed(super::toobit::decode, Venue::Toobit, MarketKind::Spot, spot)
    },
    // Recorded from Toobit's REST on 2026-11-12: three reads each of ICPUSDT and
    // ETHUSDT, as the connector frames them.
    recorded: include_str!("../../tests/fixtures/toobit.jsonl"),
    symbol: "ICPUSDT",
    proof: Proof::WholeBook,
    messages: 3,
    refusals: 0,
    best: ("2.527", "2.528"),
    dropped: None,
    corrupt: (1, "1671.33"),
    without_asks: |first, _| without(first, r#""a":"#),
};

const HYPERLIQUID: Book = Book {
    feed: || {
        let perp = instrument("BTC", MarketKind::LinearPerp);
        venue_feed(
            super::hyperliquid::decode,
            Venue::Hyperliquid,
            MarketKind::LinearPerp,
            perp,
        )
    },
    // Recorded from Hyperliquid on 2026-10-25: one whole book.
    recorded: include_str!("../../tests/fixtures/hyperliquid-book.json"),
    symbol: "BTC",
    proof: Proof::WholeBook,
    messages: 1,
    refusals: 0,
    best: ("80560", "80561"),
    dropped: None,
    corrupt: (0, "80580.0"),
    // `levels` is `[bids, asks]`.
    without_asks: |first, _| {
        let levels = first.find(r#""levels":["#).expect("levels") + r#""levels":["#.len();
        let asks = array_end(first, levels) + 2;
        empty_array(first, asks)
    },
};

/// What a clean replay of `book` emits: the book observations of each line,
/// and each error that is not benign.
fn clean_replay(book: &Book) -> (Vec<Vec<Observation>>, Vec<DecodeError>) {
    let mut feed = (book.feed)();
    let mut errors = Vec::new();
    let emitted = book
        .recorded
        .lines()
        .map(|line| match feed.push(line) {
            Ok(out) => out
                .into_iter()
                .filter(|o| is_book_of(o, book.symbol))
                .collect(),
            Err(error) => {
                if !error.is_benign() {
                    errors.push(error);
                }
                Vec::new()
            }
        })
        .collect();
    (emitted, errors)
}

fn is_book_of(observation: &Observation, symbol: &str) -> bool {
    &*observation.instrument.symbol == symbol && observation.kind == ObsKind::Depth
}

/// The line index of each book message: each line that emits the book.
fn book_messages(book: &Book) -> Vec<usize> {
    clean_replay(book)
        .0
        .iter()
        .enumerate()
        .filter(|(_, emitted)| !emitted.is_empty())
        .map(|(index, _)| index)
        .collect()
}

/// What came first after a fault: a resync, or a book that priced.
#[derive(Debug, PartialEq, Eq)]
enum After {
    Resync,
    Priced { line: usize },
    Neither,
}

/// Feeds `lines`, numbered from `first`, until a resync or a book observation of `symbol`.
fn after<'a>(
    feed: &mut Feed,
    first: usize,
    lines: impl Iterator<Item = &'a str>,
    symbol: &str,
) -> After {
    for (index, line) in (first..).zip(lines) {
        match feed.push(line) {
            Err(DecodeError::Resync(_)) => return After::Resync,
            Ok(out) if out.iter().any(|o| is_book_of(o, symbol)) => {
                return After::Priced { line: index };
            }
            _ => {}
        }
    }
    After::Neither
}

/// One digit more than the 48 that `Fixed` reads.
const TOO_MANY_DIGITS: usize = 49;

/// `decimal` in `line` with zeros to [`TOO_MANY_DIGITS`]. It stays a valid
/// JSON number, so only the decimal parser can refuse it.
fn with_too_many_digits(line: &str, decimal: &str) -> String {
    let at = tokens(line, decimal);
    let [at] = at.as_slice() else {
        panic!("`{decimal}` is in the line once: found {at:?}");
    };
    let point = if decimal.contains('.') { "" } else { "." };
    let end = at + decimal.len();
    format!(
        "{}{point}{}{}",
        &line[..end],
        "0".repeat(TOO_MANY_DIGITS),
        &line[end..]
    )
}

/// Where `decimal` stands alone in `line`, not inside a longer number.
fn tokens(line: &str, decimal: &str) -> Vec<usize> {
    let part = |c: char| c.is_ascii_digit() || c == '.';
    line.match_indices(decimal)
        .map(|(at, _)| at)
        .filter(|at| {
            let before = line[..*at].chars().next_back();
            let after = line[at + decimal.len()..].chars().next();
            !before.is_some_and(part) && !after.is_some_and(part)
        })
        .collect()
}

/// The index of the bracket that closes the one at `open`.
fn array_end(line: &str, open: usize) -> usize {
    let mut depth = 0_usize;
    let mut quoted = false;
    for (index, c) in line.char_indices().skip(open) {
        match c {
            '"' => quoted = !quoted,
            '[' if !quoted => depth += 1,
            ']' if !quoted => {
                depth -= 1;
                if depth == 0 {
                    return index;
                }
            }
            _ => {}
        }
    }
    panic!("the array at {open} does not close");
}

/// `line` with the array that opens at `open` emptied.
fn empty_array(line: &str, open: usize) -> String {
    assert_eq!(line.as_bytes().get(open), Some(&b'['), "an array at {open}");
    format!("{}{}", &line[..=open], &line[array_end(line, open)..])
}

/// `line` with the array after `key` emptied.
fn without(line: &str, key: &str) -> String {
    let open = line
        .find(key)
        .unwrap_or_else(|| panic!("{key} in the line"))
        + key.len();
    empty_array(line, open)
}

/// Coinbase numbers every message on a connection, so the emptied snapshot
/// takes the number after the last one.
fn coinbase_without_asks(first: &str, last: &str) -> String {
    let mut message: serde_json::Value = serde_json::from_str(first).expect("JSON");
    let sequence = |line: &str| {
        serde_json::from_str::<serde_json::Value>(line).expect("JSON")["sequence_num"]
            .as_u64()
            .expect("a message number")
    };
    message["sequence_num"] = (sequence(last) + 1).into();
    let updates = message["events"][0]["updates"]
        .as_array_mut()
        .expect("updates");
    updates.retain(|update| update["side"] == "bid");
    message.to_string()
}

/// Kraken checks a checksum on each message, so the emptied snapshot carries
/// the checksum of its bids alone.
fn kraken_without_asks(first: &str, _: &str) -> String {
    #[derive(Deserialize)]
    struct Message<'a> {
        #[serde(borrow)]
        data: Vec<Data<'a>>,
    }
    #[derive(Deserialize)]
    struct Data<'a> {
        #[serde(borrow)]
        bids: Vec<Level<'a>>,
    }
    #[derive(Deserialize)]
    struct Level<'a> {
        #[serde(borrow)]
        price: &'a RawValue,
        #[serde(borrow)]
        qty: &'a RawValue,
    }
    let message: Message<'_> = serde_json::from_str(first).expect("a Kraken book");
    let mut bids = LocalBook::default();
    for level in message.data.iter().flat_map(|data| &data.bids) {
        let (price, qty) = (level.price.get(), level.qty.get());
        let parsed = crate::depth::level(price, qty).expect("a recorded level");
        bids.set_with_text(Side::Bid, parsed.price, parsed.qty, Some((price, qty)));
    }
    bids.truncate(super::kraken::BOOK_DEPTH);
    let checksum = super::kraken::checksum(&bids).expect("every level has its text");
    let emptied = without(first, r#""asks":"#);
    let at = emptied.find(r#""checksum":"#).expect("a checksum") + r#""checksum":"#.len();
    let end = at
        + emptied[at..]
            .find(|c: char| !c.is_ascii_digit())
            .expect("digits end");
    format!("{}{checksum}{}", &emptied[..at], &emptied[end..])
}

/// A Bitfinex snapshot is `[channel, [[price, count, amount], …]]`; an ask has
/// a negative amount.
fn bitfinex_without_asks(first: &str, _: &str) -> String {
    let (channel, levels): (u64, Vec<Vec<&RawValue>>) =
        serde_json::from_str(first).expect("a Bitfinex snapshot");
    let bids: Vec<String> = levels
        .iter()
        .filter(|level| {
            level
                .get(2)
                .is_some_and(|amount| !amount.get().starts_with('-'))
        })
        .map(|level| {
            let fields: Vec<&str> = level.iter().map(|field| field.get()).collect();
            format!("[{}]", fields.join(","))
        })
        .collect();
    format!("[{channel},[{}]]", bids.join(","))
}

/// The recording replays with no error but its refusals: each book message
/// emits the book once, the book never crosses, and it ends at the recorded quote.
fn a_clean_replay_ends_at_the_recorded_quote(book: &Book) {
    let (emitted, errors) = clean_replay(book);
    assert_eq!(
        errors.len(),
        book.refusals,
        "errors that are not benign: {errors:?}"
    );
    let messages = emitted.iter().filter(|out| !out.is_empty()).count();
    assert_eq!(messages, book.messages, "book messages");
    assert!(
        emitted.iter().all(|out| out.len() <= 1),
        "one book observation a message"
    );
    let tops: Vec<&Observation> = emitted.iter().flatten().collect();
    assert!(tops.iter().all(|o| o.bid < o.ask), "the book never crosses");
    let last = tops.last().expect("a book observation");
    let (bid, ask) = book.best;
    assert_eq!((last.bid, last.ask), (Some(fixed(bid)), Some(fixed(ask))));
}

/// A lost update shows only when the venue's proof fails, so the rule is that
/// the proof fails: at once for a chain, and at the next checksum message for
/// a periodic checksum. A checksum on each update covers only the levels an
/// observation shows, so until it fails, each book shows what the clean replay shows.
fn a_dropped_update_forces_a_resync(book: &Book) {
    let dropped = book_messages(book)[book.dropped.expect("a venue that can lose an update")];
    let mut feed = (book.feed)();
    let lines: Vec<&str> = book.recorded.lines().collect();
    let _ = feed.replay_all(&lines[..dropped]);
    let rest = lines[dropped + 1..].iter().copied();
    match book.proof {
        Proof::PeriodicChecksum => {
            let resynced = rest
                .map(|line| feed.push(line))
                .any(|outcome| matches!(outcome, Err(DecodeError::Resync(_))));
            assert!(resynced, "no checksum failed after the gap");
        }
        Proof::Checksum => {
            let clean = clean_replay(book).0;
            for (index, line) in (dropped + 1..).zip(rest) {
                match feed.push(line) {
                    Err(DecodeError::Resync(_)) => return,
                    Ok(out) => {
                        let shown: Vec<Observation> = out
                            .into_iter()
                            .filter(|o| is_book_of(o, book.symbol))
                            .collect();
                        assert_eq!(shown, clean[index], "line {index} showed a wrong book");
                    }
                    Err(_) => {}
                }
            }
        }
        _ => assert_eq!(
            after(&mut feed, dropped + 1, rest, book.symbol),
            After::Resync,
            "the book priced across the gap"
        ),
    }
}

/// A corrupt decimal is visible at once, so the book does not price again
/// before a resync. A whole-book venue may go on: the next book replaces it.
fn a_corrupt_decimal_never_prices_a_half_applied_book(book: &Book) {
    let (message, decimal) = book.corrupt;
    let at = book_messages(book)[message];
    let lines: Vec<&str> = book.recorded.lines().collect();
    let mut feed = (book.feed)();
    let _ = feed.replay_all(&lines[..at]);

    let error = feed
        .push(with_too_many_digits(lines[at], decimal))
        .expect_err("a corrupt decimal does not decode");
    assert!(!error.is_benign(), "{error}");
    if matches!(error, DecodeError::Resync(_)) {
        return;
    }
    if book.proof == Proof::WholeBook {
        let next: Vec<Observation> = feed.decoded(lines[at]);
        assert_eq!(
            next,
            clean_replay(book).0[at],
            "the next whole book replaces it"
        );
    } else {
        let rest = lines[at + 1..].iter().copied();
        assert_eq!(
            after(&mut feed, at + 1, rest, book.symbol),
            After::Resync,
            "after `{error}`"
        );
    }
}

/// A book with one side gone has no quote, so its last two-sided quote must
/// stop counting: the book is halted.
fn an_emptied_side_drops_the_old_quote(book: &Book) {
    let lines: Vec<&str> = book.recorded.lines().collect();
    let mut feed = (book.feed)();
    let _ = feed.replay_all(&lines);
    let first = lines[book_messages(book)[0]];
    let last = lines.last().expect("a recorded line");
    let (_, halted) = feed.halted((book.without_asks)(first, last));
    assert_eq!(halted, [book.symbol]);
}

/// One venue's top of book: a two-sided quote, and the same quote with its
/// bid gone, as the venue sends an empty side.
struct Top {
    feed: fn() -> Feed,
    symbol: &'static str,
    quote: &'static str,
    without_bid: fn(&str) -> String,
    /// The bid price in `quote`, for the corrupt case.
    bid: &'static str,
}

fn top_feed(decode: super::DecodeFn, venue: Venue, market: MarketKind, symbol: &str) -> Feed {
    Feed::venue(decode, venue, market, &[instrument(symbol, market)])
}

const OKX_TOP: Top = Top {
    feed: || top_feed(super::okx::decode, Venue::Okx, MarketKind::Spot, "BTC-USDT"),
    symbol: "BTC-USDT",
    quote: r#"{"arg":{"channel":"bbo-tbt","instId":"BTC-USDT"},"data":[{"asks":[["64313.0","0.25","0","3"]],"bids":[["64312.0","0.50","0","5"]],"ts":"1754582400123"}]}"#,
    without_bid: |quote| without(quote, r#""bids":"#),
    bid: "64312.0",
};

const BYBIT_TOP: Top = Top {
    feed: || {
        top_feed(
            super::bybit::decode,
            Venue::Bybit,
            MarketKind::Spot,
            "BTCUSDT",
        )
    },
    symbol: "BTCUSDT",
    quote: r#"{"topic":"orderbook.1.BTCUSDT","type":"snapshot","ts":1754582400123,"data":{"s":"BTCUSDT","b":[["64312.00","0.500"]],"a":[["64313.00","0.250"]],"u":18521288}}"#,
    without_bid: |quote| without(quote, r#""b":"#),
    bid: "64312.00",
};

const HYPERLIQUID_TOP: Top = Top {
    feed: || {
        let perp = MarketKind::LinearPerp;
        top_feed(super::hyperliquid::decode, Venue::Hyperliquid, perp, "BTC")
    },
    symbol: "BTC",
    quote: r#"{"channel":"bbo","data":{"coin":"BTC","time":1754582400123,"bbo":[{"px":"64312.0","sz":"0.5","n":3},{"px":"64313.0","sz":"0.25","n":2}]}}"#,
    without_bid: |quote| quote.replace(r#"{"px":"64312.0","sz":"0.5","n":3}"#, "null"),
    bid: "64312.0",
};

const BITGET_TOP: Top = Top {
    feed: || {
        top_feed(
            super::bitget::decode,
            Venue::Bitget,
            MarketKind::Spot,
            "BTCUSDT",
        )
    },
    symbol: "BTCUSDT",
    quote: r#"{"action":"snapshot","arg":{"instType":"spot","topic":"books1","symbol":"BTCUSDT"},"data":[{"a":[["64313.0","0.25"]],"b":[["64312.0","0.5"]],"seq":1,"pseq":0,"ts":"1754582400123"}]}"#,
    without_bid: |quote| without(quote, r#""b":"#),
    bid: "64312.0",
};

const LIGHTER_TOP: Top = Top {
    feed: || {
        let perp = MarketKind::LinearPerp;
        top_feed(super::lighter::decode, Venue::Lighter, perp, "0")
    },
    symbol: "0",
    quote: r#"{"channel":"ticker:0","type":"update/ticker","ticker":{"s":"ETH","a":{"price":"2356.98","size":"1.4647"},"b":{"price":"2356.89","size":"2.7113"},"last_updated_at":1793214904836755}}"#,
    without_bid: |quote| quote.replace(r#"{"price":"2356.89","size":"2.7113"}"#, "null"),
    bid: "2356.89",
};

const KRAKEN_TOP: Top = Top {
    feed: || {
        top_feed(
            super::kraken::decode,
            Venue::Kraken,
            MarketKind::Spot,
            "BTCUSD",
        )
    },
    symbol: "BTCUSD",
    quote: r#"{"channel":"ticker","type":"update","data":[{"symbol":"BTCUSD","bid":64312.0,"bid_qty":0.5,"ask":64313.0,"ask_qty":0.25,"last":64312.1}]}"#,
    without_bid: |quote| quote.replace(r#""bid":64312.0"#, r#""bid":null"#),
    bid: "64312.0",
};

const KRAKEN_FUTURES_TOP: Top = Top {
    feed: || {
        let perp = MarketKind::LinearPerp;
        top_feed(
            super::kraken_futures::decode,
            Venue::Kraken,
            perp,
            "PF_XBTUSD",
        )
    },
    symbol: "PF_XBTUSD",
    quote: r#"{"feed":"ticker","product_id":"PF_XBTUSD","time":1676393235406,"bid":21978.5,"bid_size":2536.0,"ask":21987.0,"ask_size":13948.0,"markPrice":21979.68,"suspended":false}"#,
    without_bid: |quote| quote.replace(r#""bid":21978.5,"#, ""),
    bid: "21978.5",
};

const DERIBIT_TOP: Top = Top {
    feed: || {
        let perp = MarketKind::InversePerp;
        top_feed(
            super::deribit::decode,
            Venue::Deribit,
            perp,
            "BTC-PERPETUAL",
        )
    },
    symbol: "BTC-PERPETUAL",
    quote: r#"{"jsonrpc":"2.0","method":"subscription","params":{"channel":"ticker.BTC-PERPETUAL.100ms","data":{"instrument_name":"BTC-PERPETUAL","timestamp":1623060194301,"state":"open","best_bid_price":36442.5,"best_bid_amount":5000,"best_ask_price":36443,"best_ask_amount":100,"mark_price":36446.51}}}"#,
    without_bid: |quote| quote.replace(r#""best_bid_price":36442.5"#, r#""best_bid_price":null"#),
    bid: "36442.5",
};

const GATE_TOP: Top = Top {
    feed: || {
        top_feed(
            super::gate::decode,
            Venue::Gate,
            MarketKind::Spot,
            "BTC_USDT",
        )
    },
    symbol: "BTC_USDT",
    quote: r#"{"time":1,"channel":"spot.book_ticker","event":"update","result":{"t":1754582400123,"s":"BTC_USDT","b":"64312.0","B":"0.5","a":"64313.0","A":"0.25"}}"#,
    without_bid: |quote| quote.replace(r#""b":"64312.0""#, r#""b":"""#),
    bid: "64312.0",
};

const KUCOIN_TOP: Top = Top {
    feed: || {
        top_feed(
            super::kucoin::decode_spot,
            Venue::Kucoin,
            MarketKind::Spot,
            "BTC-USDT",
        )
    },
    symbol: "BTC-USDT",
    quote: r#"{"type":"message","topic":"/market/ticker:BTC-USDT","subject":"trade.ticker","data":{"bestBid":"64312.0","bestBidSize":"0.5","bestAsk":"64313.0","bestAskSize":"0.25","time":1754582400123}}"#,
    without_bid: |quote| quote.replace(r#""bestBid":"64312.0""#, r#""bestBid":"0""#),
    bid: "64312.0",
};

/// A two-sided quote gives one top of book.
fn a_quote_gives_one_book_top(top: &Top) {
    let out = (top.feed)().decoded(top.quote);
    let tops: Vec<&Observation> = out
        .iter()
        .filter(|o| &*o.instrument.symbol == top.symbol && o.kind == ObsKind::BookTop)
        .collect();
    let [quote] = tops.as_slice() else {
        panic!("one top of book: {out:?}");
    };
    assert!(quote.bid < quote.ask, "{quote:?}");
}

/// An empty side has no quote, so the last one must stop counting.
fn an_emptied_side_halts_the_quote(top: &Top) {
    let mut feed = (top.feed)();
    let _ = feed.decoded(top.quote);
    let (_, halted) = feed.halted((top.without_bid)(top.quote));
    assert_eq!(halted, [top.symbol]);
}

/// A quote that does not decode must stop the last one too: it is lost, or a
/// kept top of book resyncs.
fn a_corrupt_quote_stops_the_last_one(top: &Top) {
    let mut feed = (top.feed)();
    let _ = feed.decoded(top.quote);
    let error = feed.refused(with_too_many_digits(top.quote, top.bid));
    let stops = match &error {
        DecodeError::Lost { instrument, .. } => &*instrument.symbol == top.symbol,
        DecodeError::Resync(_) => true,
        _ => false,
    };
    assert!(stops, "the last quote stays live: {error:?}");
}

/// One module for each row, with one test for each rule. A rule may carry
/// attributes, such as `#[ignore]` for a known failure.
macro_rules! conformance {
    ($($venue:ident: $book:expr => { $($(#[$attr:meta])* $rule:ident),* $(,)? })*) => {
        $(
            mod $venue {
                $(
                    #[test]
                    $(#[$attr])*
                    fn $rule() {
                        super::$rule(&$book);
                    }
                )*
            }
        )*
    };
}

// A whole-book venue has no gap case: each message replaces the whole book.
conformance! {
    binance: super::BINANCE => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_dropped_update_forces_a_resync,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    bybit: super::BYBIT => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_dropped_update_forces_a_resync,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    okx: super::OKX => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_dropped_update_forces_a_resync,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    coinbase: super::COINBASE => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_dropped_update_forces_a_resync,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    kraken: super::KRAKEN => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_dropped_update_forces_a_resync,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    deribit: super::DERIBIT => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_dropped_update_forces_a_resync,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    bitfinex: super::BITFINEX => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_dropped_update_forces_a_resync,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    bitget: super::BITGET => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_dropped_update_forces_a_resync,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    lighter: super::LIGHTER => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_dropped_update_forces_a_resync,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    dydx: super::DYDX => {
        a_clean_replay_ends_at_the_recorded_quote,
        #[ignore = "known: dYdX changes carry no sequence, so its feed is off (finding 22), see plans/review-price-oracle-sdk-feeds-2026-11-06.md"]
        a_dropped_update_forces_a_resync,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    gate: super::GATE => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    kucoin: super::KUCOIN => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    mexc: super::MEXC => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    bitstamp: super::BITSTAMP => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    hyperliquid: super::HYPERLIQUID => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
    toobit: super::TOOBIT => {
        a_clean_replay_ends_at_the_recorded_quote,
        a_corrupt_decimal_never_prices_a_half_applied_book,
        an_emptied_side_drops_the_old_quote,
    }
}

conformance! {
    okx_top: super::OKX_TOP => {
        a_quote_gives_one_book_top,
        an_emptied_side_halts_the_quote,
        a_corrupt_quote_stops_the_last_one,
    }
    bybit_top: super::BYBIT_TOP => {
        a_quote_gives_one_book_top,
        an_emptied_side_halts_the_quote,
        a_corrupt_quote_stops_the_last_one,
    }
    hyperliquid_top: super::HYPERLIQUID_TOP => {
        a_quote_gives_one_book_top,
        an_emptied_side_halts_the_quote,
        a_corrupt_quote_stops_the_last_one,
    }
    bitget_top: super::BITGET_TOP => {
        a_quote_gives_one_book_top,
        an_emptied_side_halts_the_quote,
        a_corrupt_quote_stops_the_last_one,
    }
    lighter_top: super::LIGHTER_TOP => {
        a_quote_gives_one_book_top,
        an_emptied_side_halts_the_quote,
        a_corrupt_quote_stops_the_last_one,
    }
    kraken_top: super::KRAKEN_TOP => {
        a_quote_gives_one_book_top,
        an_emptied_side_halts_the_quote,
        a_corrupt_quote_stops_the_last_one,
    }
    kraken_futures_top: super::KRAKEN_FUTURES_TOP => {
        a_quote_gives_one_book_top,
        an_emptied_side_halts_the_quote,
        a_corrupt_quote_stops_the_last_one,
    }
    deribit_top: super::DERIBIT_TOP => {
        a_quote_gives_one_book_top,
        an_emptied_side_halts_the_quote,
        a_corrupt_quote_stops_the_last_one,
    }
    gate_top: super::GATE_TOP => {
        a_quote_gives_one_book_top,
        an_emptied_side_halts_the_quote,
        a_corrupt_quote_stops_the_last_one,
    }
    kucoin_top: super::KUCOIN_TOP => {
        a_quote_gives_one_book_top,
        an_emptied_side_halts_the_quote,
        a_corrupt_quote_stops_the_last_one,
    }
}
