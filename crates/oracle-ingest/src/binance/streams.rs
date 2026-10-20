//! Binance stream naming and endpoint construction.

use oracle_types::MarketKind;

/// Spot combined-stream endpoint.
pub const SPOT_BASE: &str = "wss://stream.binance.com:9443/stream";

/// USD-margined futures endpoint for the book ticker and depth.
///
/// Binance serves futures streams on two routes. The old `/stream` path serves
/// only these, and gives no error for the others.
pub const FUTURES_BASE: &str = "wss://fstream.binance.com/public/stream";

/// USD-margined futures endpoint for trades and the mark price.
pub const FUTURES_MARKET_BASE: &str = "wss://fstream.binance.com/market/stream";

/// Streams per connection.
///
/// Binance permits far more, but a combined-stream URL is a GET request line and
/// long ones are refused by intermediaries in ways that look like an outage. A
/// few extra connections cost nothing and fail independently, which is the more
/// useful property anyway.
pub const MAX_STREAMS_PER_CONNECTION: usize = 200;

/// Book ticker streams per futures connection. A connection from Europe to
/// Binance in Tokyo falls behind above about 150 KB/s, and Binance then closes it.
pub const PERP_BOOK_TICKERS_PER_CONNECTION: usize = 5;

/// Which streams to subscribe to for one instrument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamKind {
    /// Best bid and offer, pushed on every change.
    BookTicker,
    /// Aggregated trade prints.
    AggTrade,
    /// Mark price, index price, and funding rate, once per second.
    MarkPrice,
    /// Book changes every 100ms, for instruments that ask for depth. They apply
    /// to a REST snapshot; see `super::snapshot`.
    Depth,
    /// The REST snapshot, delivered as a frame. Not a stream Binance serves.
    DepthSnapshot,
}

impl StreamKind {
    /// Returns the streams this adapter subscribes to for a market.
    ///
    /// Spot has no mark price; perpetuals carry all three. `bookTicker` is the
    /// primary input — it is pushed on every top-of-book change rather than
    /// throttled, so it is both fresher and cheaper than a depth stream.
    #[must_use]
    pub const fn for_market(market: MarketKind) -> Option<&'static [Self]> {
        match market {
            MarketKind::Spot => Some(&[Self::BookTicker, Self::AggTrade]),
            MarketKind::LinearPerp => Some(&[Self::BookTicker, Self::AggTrade, Self::MarkPrice]),
            // Binance's coin-margined futures live on a different host with
            // their own contract catalogue. `None` rather than a silent fall
            // back to the USD-margined host, which would stream the wrong
            // contract under the right-looking name.
            MarketKind::InversePerp => None,
        }
    }

    /// Returns `true` for a stream that Binance futures serve on the market
    /// route, [`FUTURES_MARKET_BASE`].
    #[must_use]
    pub const fn on_market_route(self) -> bool {
        matches!(self, Self::AggTrade | Self::MarkPrice)
    }

    /// Returns the suffix Binance uses in stream names.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::BookTicker => "@bookTicker",
            Self::AggTrade => "@aggTrade",
            // The `@1s` variant; the default pushes every three seconds.
            Self::MarkPrice => "@markPrice@1s",
            Self::Depth => "@depth@100ms",
            Self::DepthSnapshot => "@depthSnapshot",
        }
    }

    /// Matches a stream name's suffix.
    #[must_use]
    pub fn from_stream_name(stream: &str) -> Option<Self> {
        // Checked longest-first: "@markPrice@1s" also ends with nothing else,
        // but an unqualified "@markPrice" must still match.
        if stream.ends_with("@bookTicker") {
            Some(Self::BookTicker)
        } else if stream.ends_with("@aggTrade") {
            Some(Self::AggTrade)
        } else if stream.contains("@markPrice") {
            Some(Self::MarkPrice)
        } else if stream.ends_with("@depthSnapshot") {
            Some(Self::DepthSnapshot)
        } else if stream.contains("@depth") {
            Some(Self::Depth)
        } else {
            None
        }
    }
}

/// Returns the base endpoint for a market.
#[must_use]
pub const fn base_url(market: MarketKind) -> Option<&'static str> {
    match market {
        MarketKind::Spot => Some(SPOT_BASE),
        MarketKind::LinearPerp => Some(FUTURES_BASE),
        // See `for_market`: coin-margined futures are `dstream`, not this host.
        MarketKind::InversePerp => None,
    }
}

/// Builds the stream names for a set of venue symbols.
#[must_use]
pub fn stream_names<'a>(
    venue_symbols: impl Iterator<Item = &'a str>,
    market: MarketKind,
) -> Vec<String> {
    // A market this adapter does not serve yields no streams, so it opens no
    // connection rather than one subscribed to nothing.
    let Some(kinds) = StreamKind::for_market(market) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for symbol in venue_symbols {
        // Binance names streams in lowercase and stamps payloads in uppercase.
        let lower = symbol.to_ascii_lowercase();
        for kind in kinds {
            names.push(format!("{lower}{}", kind.suffix()));
        }
    }
    names.sort_unstable();
    names
}

/// Splits stream names into per-connection URLs.
///
/// Sorted input in, deterministic URLs out, so a config change produces a diff a
/// human can read.
#[must_use]
pub fn combined_urls(base: &str, streams: &[String], chunk: usize) -> Vec<String> {
    let chunk = chunk.max(1);
    streams
        .chunks(chunk)
        .map(|group| format!("{base}?streams={}", group.join("/")))
        .collect()
}

/// Splits futures stream names into per-connection URLs, by route and by load.
///
/// Trades and mark prices go to `market_base`, `chunk` to a connection. On
/// `public_base`, each depth stream gets its own connection and the book
/// tickers go `book_chunk` to a connection.
#[must_use]
pub fn perp_urls(
    public_base: &str,
    market_base: &str,
    streams: Vec<String>,
    chunk: usize,
    book_chunk: usize,
) -> Vec<String> {
    let kind = |name: &String| StreamKind::from_stream_name(name);
    let (market, public): (Vec<String>, Vec<String>) = streams
        .into_iter()
        .partition(|name| kind(name).is_some_and(StreamKind::on_market_route));
    let (depth, books): (Vec<String>, Vec<String>) = public
        .into_iter()
        .partition(|name| kind(name) == Some(StreamKind::Depth));
    let mut urls = combined_urls(public_base, &depth, 1);
    urls.extend(combined_urls(public_base, &books, book_chunk));
    urls.extend(combined_urls(market_base, &market, chunk));
    urls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_streams_are_recognised() {
        assert_eq!(
            StreamKind::from_stream_name("btcusdt@depth@100ms"),
            Some(StreamKind::Depth)
        );
        assert_eq!(
            StreamKind::from_stream_name("btcusdt@depthSnapshot"),
            Some(StreamKind::DepthSnapshot)
        );
    }

    #[test]
    fn spot_and_perp_subscribe_to_different_streams() {
        assert_eq!(
            StreamKind::for_market(MarketKind::Spot),
            Some([StreamKind::BookTicker, StreamKind::AggTrade].as_slice())
        );
        assert!(
            StreamKind::for_market(MarketKind::LinearPerp)
                .expect("linear perps are served")
                .contains(&StreamKind::MarkPrice)
        );
    }

    /// Coin-margined futures live on `dstream`, which this adapter does not
    /// serve. Falling back to the USD-margined host would stream a different
    /// contract under a name that looks right.
    #[test]
    fn coin_margined_futures_are_refused_rather_than_mis_hosted() {
        assert_eq!(StreamKind::for_market(MarketKind::InversePerp), None);
        assert_eq!(base_url(MarketKind::InversePerp), None);
        assert!(
            stream_names(["BTCUSD_PERP"].into_iter(), MarketKind::InversePerp).is_empty(),
            "no streams means no connection, rather than one subscribed to nothing"
        );
    }

    #[test]
    fn stream_names_are_lowercase_and_sorted() {
        let names = stream_names(["BTCUSDT", "ETHUSDT"].into_iter(), MarketKind::Spot);
        assert_eq!(
            names,
            [
                "btcusdt@aggTrade",
                "btcusdt@bookTicker",
                "ethusdt@aggTrade",
                "ethusdt@bookTicker",
            ]
        );
    }

    #[test]
    fn perp_names_include_the_one_second_mark_price() {
        let names = stream_names(["BTCUSDT"].into_iter(), MarketKind::LinearPerp);
        assert!(names.contains(&"btcusdt@markPrice@1s".to_owned()));
    }

    #[test]
    fn stream_kinds_round_trip_from_names() {
        assert_eq!(
            StreamKind::from_stream_name("btcusdt@bookTicker"),
            Some(StreamKind::BookTicker)
        );
        assert_eq!(
            StreamKind::from_stream_name("btcusdt@aggTrade"),
            Some(StreamKind::AggTrade)
        );
        assert_eq!(
            StreamKind::from_stream_name("btcusdt@markPrice@1s"),
            Some(StreamKind::MarkPrice)
        );
        // The unqualified three-second variant must still match.
        assert_eq!(
            StreamKind::from_stream_name("btcusdt@markPrice"),
            Some(StreamKind::MarkPrice)
        );
        assert_eq!(StreamKind::from_stream_name("btcusdt@kline_1m"), None);
        assert_eq!(StreamKind::from_stream_name(""), None);
    }

    #[test]
    fn urls_are_chunked() {
        let streams: Vec<String> = (0..5).map(|i| format!("s{i}@bookTicker")).collect();
        let urls = combined_urls("wss://example/stream", &streams, 2);
        assert_eq!(
            urls,
            [
                "wss://example/stream?streams=s0@bookTicker/s1@bookTicker",
                "wss://example/stream?streams=s2@bookTicker/s3@bookTicker",
                "wss://example/stream?streams=s4@bookTicker",
            ]
        );
    }

    #[test]
    fn chunk_size_zero_does_not_hang_or_panic() {
        let streams = vec!["a@bookTicker".to_owned()];
        assert_eq!(combined_urls("wss://x/stream", &streams, 0).len(), 1);
    }

    #[test]
    fn empty_input_yields_no_urls() {
        assert!(combined_urls("wss://x/stream", &[], 10).is_empty());
    }

    #[test]
    fn perp_streams_split_by_route_and_load() {
        let symbols: Vec<String> = (0..120).map(|i| format!("SYM{i}USDT")).collect();
        let mut names = stream_names(symbols.iter().map(String::as_str), MarketKind::LinearPerp);
        names.extend(["btcusdt@depth@100ms", "ethusdt@depth@100ms"].map(str::to_owned));
        let urls = perp_urls(
            FUTURES_BASE,
            FUTURES_MARKET_BASE,
            names,
            MAX_STREAMS_PER_CONNECTION,
            PERP_BOOK_TICKERS_PER_CONNECTION,
        );

        // Two depth, 120 / 5 book ticker, and 240 / 200 market connections.
        assert_eq!(urls.len(), 2 + 24 + 2);
        assert_eq!(
            urls.get(..2),
            Some(
                [
                    format!("{FUTURES_BASE}?streams=btcusdt@depth@100ms"),
                    format!("{FUTURES_BASE}?streams=ethusdt@depth@100ms"),
                ]
                .as_slice()
            )
        );
        for url in &urls {
            let (base, streams) = url.split_once("?streams=").expect("combined");
            let kinds: Vec<_> = streams
                .split('/')
                .map(|name| StreamKind::from_stream_name(name).expect("known"))
                .collect();
            if base == FUTURES_MARKET_BASE {
                assert!(kinds.iter().all(|kind| kind.on_market_route()), "{url}");
            } else if kinds != [StreamKind::Depth] {
                assert!(kinds.len() <= PERP_BOOK_TICKERS_PER_CONNECTION, "{url}");
                assert!(
                    kinds.iter().all(|kind| *kind == StreamKind::BookTicker),
                    "{url}"
                );
            }
            assert!(
                url.len() < 8_000,
                "URL is long enough to worry an intermediary"
            );
        }
    }
}
