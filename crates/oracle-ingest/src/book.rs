//! Local order books, kept from a venue's snapshot and the changes after it.
//!
//! [`BookKeeper::apply`] proves, applies and emits each [`BookMsg`] by the
//! venue's [`BookRule`]; a book that the node cannot prove never prices.

use std::collections::{BTreeMap, HashMap, btree_map};
use std::iter::Rev;
use std::sync::Arc;

use oracle_types::{BookDepth, Fixed, InstrumentId, Level, ObsKind, Observation};

use crate::DecodeError;
use crate::instrument::InstrumentEntry;
use crate::venues::{mid, observation};

/// Levels per side carried in each depth observation.
pub const DEPTH_LEVELS: usize = 50;

/// Which side of the book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Bids.
    Bid,
    /// Asks.
    Ask,
}

/// One resting level. The venue's own text is kept where a checksum is
/// computed over it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Resting {
    qty: Fixed,
    text: Option<(Box<str>, Box<str>)>,
}

/// One instrument's book.
#[derive(Clone, Debug, Default)]
pub struct LocalBook {
    bids: BTreeMap<Fixed, Resting>,
    asks: BTreeMap<Fixed, Resting>,
    /// The venue's last update id or sequence number, for continuity checks.
    pub last_id: Option<u64>,
    /// A snapshot started this book, so a change can apply to it.
    synced: bool,
}

/// The levels of one side, best first.
enum Levels<'a> {
    Bids(Rev<btree_map::Iter<'a, Fixed, Resting>>),
    Asks(btree_map::Iter<'a, Fixed, Resting>),
}

impl Iterator for Levels<'_> {
    type Item = Level;

    fn next(&mut self) -> Option<Level> {
        let (price, resting) = match self {
            Self::Bids(levels) => levels.next()?,
            Self::Asks(levels) => levels.next()?,
        };
        Some(Level {
            price: *price,
            qty: resting.qty,
        })
    }
}

impl LocalBook {
    /// Empties the book, ahead of a snapshot.
    pub fn clear(&mut self) {
        self.bids.clear();
        self.asks.clear();
        self.last_id = None;
        self.synced = false;
    }

    /// Sets a level. A zero size removes it.
    pub fn set(&mut self, side: Side, price: Fixed, qty: Fixed) {
        self.set_with_text(side, price, qty, None);
    }

    /// Sets a level and keeps the venue's text for it.
    pub fn set_with_text(
        &mut self,
        side: Side,
        price: Fixed,
        qty: Fixed,
        text: Option<(&str, &str)>,
    ) {
        let levels = self.side_mut(side);
        if qty.is_positive() {
            let text = text.map(|(price, qty)| (price.into(), qty.into()));
            levels.insert(price, Resting { qty, text });
        } else {
            levels.remove(&price);
        }
    }

    /// Applies a message whose levels all parsed. A snapshot replaces the book.
    pub fn apply(&mut self, message: &BookMsg<'_>) {
        if message.snapshot {
            self.clear();
            self.synced = true;
        }
        for (side, changes) in [(Side::Bid, &message.bids), (Side::Ask, &message.asks)] {
            for change in changes {
                self.set_with_text(side, change.price, change.qty, change.text);
            }
        }
        if message.next_id.is_some() {
            self.last_id = message.next_id;
        }
    }

    /// Keeps only the best `depth` levels on each side. Venues that publish a
    /// fixed depth stop sending levels that fall out of it.
    pub fn truncate(&mut self, depth: usize) {
        while self.bids.len() > depth {
            self.bids.pop_first();
        }
        while self.asks.len() > depth {
            self.asks.pop_last();
        }
    }

    /// The best `n` levels of one side, best first.
    #[must_use]
    pub fn top(&self, side: Side, n: usize) -> Vec<Level> {
        self.levels(side).take(n).collect()
    }

    /// The venue's text for the best `n` levels of one side, best first.
    /// `None` if any of them was set without text.
    #[must_use]
    pub fn top_text(&self, side: Side, n: usize) -> Option<Vec<(&str, &str)>> {
        fn text(resting: &Resting) -> Option<(&str, &str)> {
            resting
                .text
                .as_ref()
                .map(|(price, qty)| (price.as_ref(), qty.as_ref()))
        }
        match side {
            Side::Bid => self.bids.values().rev().take(n).map(text).collect(),
            Side::Ask => self.asks.values().take(n).map(text).collect(),
        }
    }

    /// `true` if the best bid is at or above the best ask. A locked book
    /// proves a wrong book as well as a crossed one.
    #[must_use]
    pub fn is_crossed(&self) -> bool {
        matches!(
            (self.bids.last_key_value(), self.asks.first_key_value()),
            (Some((bid, _)), Some((ask, _))) if bid >= ask
        )
    }

    fn levels(&self, side: Side) -> Levels<'_> {
        match side {
            Side::Bid => Levels::Bids(self.bids.iter().rev()),
            Side::Ask => Levels::Asks(self.asks.iter()),
        }
    }

    fn top_is(&self, depth: &BookDepth, levels: usize) -> bool {
        let same = |side, shown: &[Level]| {
            let count = self.side(side).len().min(levels);
            count == shown.len() && self.levels(side).zip(shown).all(|(a, b)| a == *b)
        };
        same(Side::Bid, &depth.bids) && same(Side::Ask, &depth.asks)
    }

    const fn side(&self, side: Side) -> &BTreeMap<Fixed, Resting> {
        match side {
            Side::Bid => &self.bids,
            Side::Ask => &self.asks,
        }
    }

    const fn side_mut(&mut self, side: Side) -> &mut BTreeMap<Fixed, Resting> {
        match side {
            Side::Bid => &mut self.bids,
            Side::Ask => &mut self.asks,
        }
    }
}

/// One level as a message sets it. A zero size removes the level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Change<'a> {
    /// The price.
    pub price: Fixed,
    /// The new size, in base units.
    pub qty: Fixed,
    /// The venue's text of the price and the size, where a checksum covers it.
    pub text: Option<(&'a str, &'a str)>,
}

impl Change<'_> {
    /// A change of a venue that sends no checksum over its text.
    #[must_use]
    pub const fn new(price: Fixed, qty: Fixed) -> Self {
        Self {
            price,
            qty,
            text: None,
        }
    }
}

impl From<Level> for Change<'_> {
    fn from(level: Level) -> Self {
        Self::new(level.price, level.qty)
    }
}

/// One book message, parsed whole before anything applies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BookMsg<'a> {
    /// The message is the whole book, not a change to it.
    pub snapshot: bool,
    /// The id of the update before this one, for [`Continuity::UpdateId`].
    pub prev_id: Option<u64>,
    /// This message's own id or sequence number.
    pub next_id: Option<u64>,
    /// The bid levels that changed.
    pub bids: Vec<Change<'a>>,
    /// The ask levels that changed.
    pub asks: Vec<Change<'a>>,
    /// The checksum that the venue sent with the message, if any.
    pub checksum: Option<u32>,
    /// The venue's time of the message, in unix nanoseconds.
    pub time: Option<u64>,
}

impl<'a> BookMsg<'a> {
    /// A whole book, each level of each side parsed by `change`.
    ///
    /// # Errors
    ///
    /// Returns the first error of `change`.
    pub fn whole<L>(
        bids: &[L],
        asks: &[L],
        change: impl Fn(&L) -> Result<Change<'a>, DecodeError>,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            snapshot: true,
            ..Self::changes(bids, asks, change)?
        })
    }

    /// The changes of each side, each level parsed by `change`.
    ///
    /// # Errors
    ///
    /// Returns the first error of `change`.
    pub fn changes<L>(
        bids: &[L],
        asks: &[L],
        change: impl Fn(&L) -> Result<Change<'a>, DecodeError>,
    ) -> Result<Self, DecodeError> {
        let side = |levels: &[L]| levels.iter().map(&change).collect::<Result<Vec<_>, _>>();
        Ok(Self {
            bids: side(bids)?,
            asks: side(asks)?,
            ..Self::default()
        })
    }

    /// Sets the time, for a venue that sends it apart from the levels.
    #[must_use]
    pub fn at(self, time: Option<u64>) -> Self {
        Self { time, ..self }
    }
}

/// How a venue proves that a book holds every change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Continuity {
    /// Each update names the id of the update before it (`prev_id`) and its own
    /// (`next_id`).
    UpdateId,
    /// Each message carries a number one above the last (`next_id`).
    NextSequence,
    /// The connection numbers every message, so the proof is
    /// [`BookKeeper::next_message`] and a book needs no id of its own.
    Connection,
    /// Only the checksum of [`BookRule::checksum`] proves the book: it comes
    /// with each update, or now and then apart from them.
    Checksum,
    /// Each message is the whole book, so no change can be lost.
    WholeBook,
    /// Nothing proves the book: the changes carry no sequence. Such a feed is
    /// off by default.
    Unproved,
}

impl Continuity {
    fn check(self, book: &LocalBook, message: &BookMsg<'_>) -> Result<(), String> {
        let chained = matches!(self, Self::UpdateId | Self::NextSequence);
        if message.snapshot {
            if chained && message.next_id.is_none() {
                return Err("a snapshot without its id".to_owned());
            }
            return Ok(());
        }
        if self == Self::WholeBook {
            return Err("a change on a venue that sends whole books".to_owned());
        }
        if !book.synced {
            return Err("a change before the snapshot".to_owned());
        }
        match self {
            Self::UpdateId => {
                let previous = message
                    .prev_id
                    .ok_or("an update without the id of the one before it")?;
                if message.next_id.is_none() {
                    return Err("an update without its id".to_owned());
                }
                if Some(previous) != book.last_id {
                    return Err(format!(
                        "update follows {previous} but the book is at {:?}",
                        book.last_id
                    ));
                }
            }
            Self::NextSequence => {
                let next = message.next_id.ok_or("an update without its number")?;
                if book.last_id.and_then(|last| last.checked_add(1)) != Some(next) {
                    return Err(format!("update {next} does not follow {:?}", book.last_id));
                }
            }
            Self::Connection | Self::Checksum | Self::WholeBook | Self::Unproved => {}
        }
        Ok(())
    }

    /// A message that did not parse lost a change, so the book resyncs. On a
    /// whole-book venue the next message replaces it, so the book is only lost.
    fn lost(self, book: Option<&InstrumentId>, error: DecodeError) -> DecodeError {
        if error.is_benign() || matches!(error, DecodeError::Resync(_)) {
            return error;
        }
        match (self, book) {
            (Self::WholeBook, Some(instrument)) => DecodeError::lost(instrument, error),
            (Self::WholeBook, None) => error,
            (_, Some(instrument)) => {
                DecodeError::Resync(format!("{instrument}: a change did not parse: {error}"))
            }
            (_, None) => DecodeError::Resync(format!("a book message did not parse: {error}")),
        }
    }
}

/// A venue's checksum of its book: CRC32 of the venue's own text.
pub type ChecksumFn = fn(&LocalBook) -> Option<u32>;

/// How one venue keeps its books: the proof, the depth and the checksum.
#[derive(Clone, Copy, Debug)]
pub struct BookRule {
    /// How a change proves that it follows the last one.
    pub continuity: Continuity,
    /// The levels per side that the venue keeps. The book is cut to it after
    /// each message, because the venue says nothing of a level that falls out.
    pub depth: Option<usize>,
    /// The checksum the venue sends, if any. A message that carries one must
    /// match the book after it applies.
    pub checksum: Option<ChecksumFn>,
    /// The levels per side that an observation shows: no more than the proof
    /// covers. With 1, the book gives only its best bid and ask.
    pub shown: usize,
}

impl BookRule {
    /// A rule with no depth limit and no checksum.
    #[must_use]
    pub const fn new(continuity: Continuity) -> Self {
        Self {
            continuity,
            depth: None,
            checksum: None,
            shown: DEPTH_LEVELS,
        }
    }

    /// Cuts the book to `levels` a side.
    #[must_use]
    pub const fn depth(mut self, levels: usize) -> Self {
        self.depth = Some(levels);
        self
    }

    /// Checks the venue's checksum.
    #[must_use]
    pub const fn checksum(mut self, checksum: ChecksumFn) -> Self {
        self.checksum = Some(checksum);
        self
    }

    /// Shows at most `levels` a side, because only they are proved.
    #[must_use]
    pub const fn shown(mut self, levels: usize) -> Self {
        self.shown = levels;
        self
    }

    /// What a book message means that did not parse far enough to name its
    /// book: a lost change, as in [`BookKeeper::apply`].
    #[must_use]
    pub fn unparsed(self, error: DecodeError) -> DecodeError {
        self.continuity.lost(None, error)
    }
}

#[derive(Clone, Debug, Default)]
struct Kept {
    book: LocalBook,
    depth: Option<Arc<BookDepth>>,
}

impl Kept {
    /// Unchanged levels give the last depth again, so a change below the top
    /// allocates nothing.
    fn depth(&mut self, levels: usize) -> Arc<BookDepth> {
        let levels = levels.min(DEPTH_LEVELS);
        if let Some(last) = &self.depth
            && self.book.top_is(last, levels)
        {
            return Arc::clone(last);
        }
        let depth = Arc::new(BookDepth {
            bids: self.book.top(Side::Bid, levels),
            asks: self.book.top(Side::Ask, levels),
        });
        self.depth = Some(Arc::clone(&depth));
        depth
    }
}

/// Every book on one connection, keyed by the instrument's venue symbol.
#[derive(Clone, Debug, Default)]
pub struct BookKeeper {
    books: HashMap<Arc<str>, Kept>,
    /// The number of the last message, on a venue that numbers every message.
    sequence: Option<u64>,
}

impl BookKeeper {
    /// Drops every book, so nothing from before a gap survives it.
    pub fn clear(&mut self) {
        self.books.clear();
        self.sequence = None;
    }

    /// Checks the number of a message, on a venue that numbers every message
    /// on the connection ([`Continuity::Connection`]).
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Resync`] when the number skips.
    pub fn next_message(&mut self, sequence: u64) -> Result<(), DecodeError> {
        if let Some(last) = self.sequence
            && last.checked_add(1) != Some(sequence)
        {
            return Err(DecodeError::Resync(format!(
                "message {sequence} does not follow {last}"
            )));
        }
        self.sequence = Some(sequence);
        Ok(())
    }

    /// Proves and applies one book message as the venue's parser gave it, then
    /// emits the book.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Resync`] when the proof fails, a change did not parse, or
    /// the book is crossed; [`DecodeError::Halted`] when a side is empty.
    pub fn apply(
        &mut self,
        rule: BookRule,
        entry: &InstrumentEntry,
        parsed: Result<BookMsg<'_>, DecodeError>,
        local_recv_ns: u64,
        out: &mut Vec<Observation>,
    ) -> Result<(), DecodeError> {
        let message =
            parsed.map_err(|error| rule.continuity.lost(Some(&entry.instrument), error))?;
        self.update(rule, &entry.instrument.symbol, &message)?;
        self.emit(rule, entry, message.time, local_recv_ns, out)
    }

    /// Proves and applies one book message, with no emit.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Resync`] when the proof or the checksum fails.
    pub fn update(
        &mut self,
        rule: BookRule,
        key: &Arc<str>,
        message: &BookMsg<'_>,
    ) -> Result<(), DecodeError> {
        let book = self.book_mut(key);
        rule.continuity
            .check(book, message)
            .map_err(|why| DecodeError::Resync(format!("{key}: {why}")))?;
        book.apply(message);
        if let Some(depth) = rule.depth {
            book.truncate(depth);
        }
        if let (Some(checksum), Some(sent)) = (rule.checksum, message.checksum)
            && checksum(book) != Some(sent)
        {
            return Err(DecodeError::Resync(format!("{key}: checksum mismatch")));
        }
        Ok(())
    }

    /// Checks a checksum that the venue sends apart from the changes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Resync`] if the book is missing or does not match.
    pub fn check(&self, rule: BookRule, key: &str, sent: u32) -> Result<(), DecodeError> {
        let Some(checksum) = rule.checksum else {
            return Ok(());
        };
        match self.books.get(key) {
            Some(kept) if checksum(&kept.book) == Some(sent) => Ok(()),
            _ => Err(DecodeError::Resync(format!("{key}: checksum mismatch"))),
        }
    }

    /// Emits the book as depth where the instrument wants depth and the rule
    /// shows it, or else as its best bid and ask.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Resync`] for a crossed book, which nothing can trust;
    /// [`DecodeError::Halted`] when a side is empty, so the old quote stops counting.
    pub fn emit(
        &mut self,
        rule: BookRule,
        entry: &InstrumentEntry,
        exchange_time_ns: Option<u64>,
        local_recv_ns: u64,
        out: &mut Vec<Observation>,
    ) -> Result<(), DecodeError> {
        let key = &entry.instrument.symbol;
        let Some(kept) = self.books.get_mut(key.as_ref()) else {
            return Ok(());
        };
        if kept.book.is_crossed() {
            return Err(DecodeError::Resync(format!("{key}: the book is crossed")));
        }
        let best = |side| kept.book.levels(side).next();
        let (Some(bid), Some(ask)) = (best(Side::Bid), best(Side::Ask)) else {
            return Err(DecodeError::halted(&entry.instrument));
        };
        let seq = kept.book.last_id;
        let (kind, book) = if entry.depth && rule.shown > 1 {
            (ObsKind::Depth, Some(kept.depth(rule.shown)))
        } else {
            (ObsKind::BookTop, None)
        };
        out.push(Observation {
            bid: Some(bid.price),
            ask: Some(ask.price),
            bid_qty: Some(bid.qty),
            ask_qty: Some(ask.qty),
            exchange_time_ns,
            seq,
            book,
            ..observation(entry, kind, mid(bid.price, ask.price), local_recv_ns)
        });
        Ok(())
    }

    /// Only a miss allocates, and the key is the instrument's own shared symbol.
    pub(crate) fn book_mut(&mut self, key: &Arc<str>) -> &mut LocalBook {
        &mut self.books.entry(Arc::clone(key)).or_default().book
    }
}

/// The halts of one message with several books. Each book applies, and the
/// halts come out after the last one.
#[derive(Debug, Default)]
pub(crate) struct Halts(Vec<InstrumentId>);

impl Halts {
    /// Keeps a halt of `instrument` for [`Halts::finish`]; a later quote of it in
    /// the same message clears the halt.
    pub(crate) fn absorb(
        &mut self,
        instrument: &InstrumentId,
        result: Result<(), DecodeError>,
    ) -> Result<(), DecodeError> {
        match result {
            Ok(()) => {
                self.0.retain(|halted| halted != instrument);
                Ok(())
            }
            Err(DecodeError::Halted(halted)) => {
                for instrument in halted {
                    if !self.0.contains(&instrument) {
                        self.0.push(instrument);
                    }
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// The halts of the message, or `otherwise` when there are none.
    pub(crate) fn finish(self, otherwise: Result<(), DecodeError>) -> Result<(), DecodeError> {
        if self.0.is_empty() {
            otherwise
        } else {
            Err(DecodeError::Halted(self.0))
        }
    }
}

/// The last funding fields of one instrument, for a venue whose messages
/// carry only the fields that changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LastFunding {
    /// The funding rate.
    pub rate: Option<Fixed>,
    /// The funding period, in nanoseconds.
    pub interval_ns: Option<u64>,
    /// The next funding time, in unix nanoseconds.
    pub next_funding_time_ns: Option<u64>,
    /// The venue's prediction of the next rate.
    pub predicted: Option<Fixed>,
    /// The last rate that the venue settled, and when.
    pub settled: Option<(Fixed, u64)>,
    /// The open interest, in the venue's unit.
    pub open_interest: Option<Fixed>,
}

impl LastFunding {
    /// Stores a repeated venue's rate and open interest, and says whether either
    /// changed, so that a message that repeats each second goes out only on a change.
    pub fn update(&mut self, rate: Option<Fixed>, open_interest: Option<Fixed>) -> bool {
        let changed = rate != self.rate || open_interest != self.open_interest;
        self.rate = rate;
        self.open_interest = open_interest;
        changed
    }
}

/// What one connection keeps between messages. Emptied on each connect, so
/// nothing from before a gap survives it.
#[derive(Clone, Debug, Default)]
pub struct Books {
    /// The order books.
    pub keeper: BookKeeper,
    /// A second book of each instrument, for a venue that streams the top of
    /// book apart from the depth (Bybit).
    pub tops: BookKeeper,
    /// The channel and the venue symbol of each channel id, for venues that
    /// name a subscription by a number the server picks (Bitfinex).
    pub channels: HashMap<u64, (&'static str, String)>,
    funding: HashMap<Arc<str>, LastFunding>,
}

impl Books {
    /// Drops every book and every funding state.
    pub fn clear(&mut self) {
        self.keeper.clear();
        self.tops.clear();
        self.channels.clear();
        self.funding.clear();
    }

    /// The last funding fields of an instrument, created empty.
    pub fn funding(&mut self, instrument: &InstrumentId) -> &mut LastFunding {
        self.funding
            .entry(Arc::clone(&instrument.symbol))
            .or_default()
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "fixed-shape books; an out-of-range index is a failing test"
)]
mod tests {
    use super::*;
    use crate::testing::{fixed, instrument};
    use crate::{InstrumentMap, InstrumentSpec};
    use oracle_types::{MarketKind, Venue};

    const RECV_NS: u64 = 1;

    fn change(price: &str, qty: &str) -> Change<'static> {
        Change::new(fixed(price), fixed(qty))
    }

    fn entry(spec: InstrumentSpec) -> InstrumentEntry {
        let map = InstrumentMap::new(Venue::Okx, MarketKind::Spot, &[spec]).expect("a map");
        map.lookup("BTC-USDT").cloned().expect("the instrument")
    }

    fn depth() -> InstrumentEntry {
        entry(instrument("BTC-USDT", MarketKind::Spot).with_depth())
    }

    /// A snapshot at id 10 with one level a side.
    fn snapshot() -> BookMsg<'static> {
        BookMsg {
            snapshot: true,
            next_id: Some(10),
            bids: vec![change("100", "1")],
            asks: vec![change("101", "1")],
            ..BookMsg::default()
        }
    }

    fn update(prev_id: u64, next_id: u64, bids: Vec<Change<'static>>) -> BookMsg<'static> {
        BookMsg {
            prev_id: Some(prev_id),
            next_id: Some(next_id),
            bids,
            ..BookMsg::default()
        }
    }

    const CHAINED: BookRule = BookRule::new(Continuity::UpdateId);

    /// Applies each message, and keeps what each emitted or the error.
    fn keep(
        rule: BookRule,
        entry: &InstrumentEntry,
        messages: impl IntoIterator<Item = Result<BookMsg<'static>, DecodeError>>,
    ) -> Vec<Result<Vec<Observation>, DecodeError>> {
        let mut keeper = BookKeeper::default();
        messages
            .into_iter()
            .map(|message| {
                let mut out = Vec::new();
                keeper
                    .apply(rule, entry, message, RECV_NS, &mut out)
                    .map(|()| out)
            })
            .collect()
    }

    fn best_bid(outcome: &Result<Vec<Observation>, DecodeError>) -> Option<Fixed> {
        outcome.as_ref().ok()?.first()?.bid
    }

    #[test]
    fn levels_are_set_removed_and_ordered_best_first() {
        let mut book = LocalBook::default();
        book.set(Side::Bid, fixed("99"), fixed("1"));
        book.set(Side::Bid, fixed("100"), fixed("2"));
        book.set(Side::Ask, fixed("102"), fixed("1"));
        book.set(Side::Ask, fixed("101"), fixed("3"));
        assert_eq!(book.top(Side::Bid, 1)[0].price, fixed("100"));
        assert_eq!(book.top(Side::Ask, 1)[0].price, fixed("101"));

        book.set(Side::Bid, fixed("100"), Fixed::ZERO);
        assert_eq!(book.top(Side::Bid, 5).len(), 1);
        assert_eq!(book.top(Side::Bid, 1)[0].price, fixed("99"));
    }

    #[test]
    fn truncate_drops_the_worst_levels() {
        let mut book = LocalBook::default();
        for price in ["97", "98", "99"] {
            book.set(Side::Bid, fixed(price), fixed("1"));
        }
        for price in ["101", "102", "103"] {
            book.set(Side::Ask, fixed(price), fixed("1"));
        }
        book.truncate(2);
        let prices = |side| -> Vec<Fixed> { book.top(side, 5).iter().map(|l| l.price).collect() };
        assert_eq!(prices(Side::Bid), [fixed("99"), fixed("98")]);
        assert_eq!(prices(Side::Ask), [fixed("101"), fixed("102")]);
    }

    #[test]
    fn text_is_kept_only_where_given() {
        let mut book = LocalBook::default();
        book.set_with_text(Side::Ask, fixed("101"), fixed("1"), Some(("101.0", "1.00")));
        assert_eq!(book.top_text(Side::Ask, 1), Some(vec![("101.0", "1.00")]));
        book.set(Side::Ask, fixed("100"), fixed("1"));
        assert_eq!(book.top_text(Side::Ask, 2), None);
    }

    #[test]
    fn a_chained_update_applies_and_emits_the_book() {
        let outcomes = keep(
            CHAINED,
            &depth(),
            [
                Ok(snapshot()),
                Ok(update(10, 11, vec![change("100.5", "2")])),
            ],
        );
        assert_eq!(best_bid(&outcomes[1]), Some(fixed("100.5")));
        let emitted = outcomes[1].as_ref().expect("emitted");
        assert_eq!(emitted[0].kind, ObsKind::Depth);
        assert_eq!(emitted[0].seq, Some(11));
        assert_eq!(emitted[0].price, fixed("100.75"));
    }

    #[test]
    fn an_update_that_skips_an_id_resyncs() {
        let outcomes = keep(
            CHAINED,
            &depth(),
            [
                Ok(snapshot()),
                Ok(update(11, 12, vec![change("100.5", "2")])),
            ],
        );
        assert!(matches!(outcomes[1], Err(DecodeError::Resync(_))));
    }

    /// An update with no ids cannot prove that it follows the last one.
    #[test]
    fn an_update_without_its_ids_resyncs() {
        let no_ids = BookMsg {
            bids: vec![change("100.5", "2")],
            ..BookMsg::default()
        };
        let outcomes = keep(CHAINED, &depth(), [Ok(snapshot()), Ok(no_ids)]);
        assert!(matches!(outcomes[1], Err(DecodeError::Resync(_))));
    }

    #[test]
    fn an_update_before_any_snapshot_resyncs() {
        for rule in [CHAINED, BookRule::new(Continuity::Unproved)] {
            let outcomes = keep(rule, &depth(), [Ok(update(10, 11, Vec::new()))]);
            assert!(
                matches!(outcomes[0], Err(DecodeError::Resync(_))),
                "{rule:?}"
            );
        }
    }

    #[test]
    fn a_numbered_update_must_be_one_above_the_last() {
        let rule = BookRule::new(Continuity::NextSequence);
        let next = |id| BookMsg {
            next_id: Some(id),
            ..BookMsg::default()
        };
        let outcomes = keep(rule, &depth(), [Ok(snapshot()), Ok(next(11)), Ok(next(13))]);
        assert!(outcomes[1].is_ok());
        assert!(matches!(outcomes[2], Err(DecodeError::Resync(_))));
    }

    /// A change that does not parse is lost, so a chained book cannot go on;
    /// a whole book is replaced by the next one, so the error stays as it is.
    #[test]
    fn a_change_that_does_not_parse_resyncs_unless_the_venue_sends_whole_books() {
        let bad = || {
            Err(DecodeError::BadDecimal {
                field: "price",
                value: "x".to_owned(),
            })
        };
        let chained = keep(CHAINED, &depth(), [Ok(snapshot()), bad()]);
        assert!(matches!(chained[1], Err(DecodeError::Resync(_))));
        let whole = keep(BookRule::new(Continuity::WholeBook), &depth(), [bad()]);
        assert!(
            matches!(&whole[0], Err(DecodeError::Lost { error, .. })
                if matches!(**error, DecodeError::BadDecimal { .. })),
            "the book is lost, so its last quote stops: {:?}",
            whole[0]
        );
    }

    /// A locked book is as wrong as a crossed one.
    #[test]
    fn a_locked_or_crossed_book_resyncs() {
        for ask in ["100", "99"] {
            let locked = BookMsg {
                asks: vec![change(ask, "1")],
                ..snapshot()
            };
            let outcomes = keep(CHAINED, &depth(), [Ok(locked)]);
            assert!(matches!(outcomes[0], Err(DecodeError::Resync(_))), "{ask}");
        }
    }

    #[test]
    fn a_book_with_an_empty_side_is_halted() {
        let emptied = update(10, 11, Vec::new());
        let emptied = BookMsg {
            asks: vec![change("101", "0")],
            ..emptied
        };
        let entry = depth();
        let outcomes = keep(CHAINED, &entry, [Ok(snapshot()), Ok(emptied)]);
        assert_eq!(
            outcomes[1].as_ref().err(),
            Some(&DecodeError::halted(&entry.instrument))
        );
    }

    #[test]
    fn a_market_without_depth_gets_only_its_best_bid_and_ask() {
        let top = entry(instrument("BTC-USDT", MarketKind::Spot));
        let outcomes = keep(CHAINED, &top, [Ok(snapshot())]);
        let emitted = outcomes[0].as_ref().expect("emitted");
        assert_eq!(emitted[0].kind, ObsKind::BookTop);
        assert!(emitted[0].book.is_none());
    }

    #[test]
    fn the_book_is_cut_to_the_venue_depth() {
        const KEPT: usize = 2;
        let rule = CHAINED.depth(KEPT);
        let deep = BookMsg {
            bids: vec![change("100", "1"), change("99", "1"), change("98", "1")],
            ..snapshot()
        };
        let outcomes = keep(rule, &depth(), [Ok(deep)]);
        let emitted = outcomes[0].as_ref().expect("emitted");
        let levels = emitted[0].book.as_deref().expect("depth");
        assert_eq!(levels.bids.len(), KEPT);
    }

    /// The checksum of this book is the sum of its bid sizes.
    fn bid_sizes(book: &LocalBook) -> Option<u32> {
        let sum = book
            .top(Side::Bid, usize::MAX)
            .iter()
            .map(|level| level.qty)
            .try_fold(Fixed::ZERO, Fixed::checked_add)?;
        sum.to_string().parse().ok()
    }

    #[test]
    fn a_checksum_that_does_not_match_resyncs() {
        let rule = BookRule::new(Continuity::Checksum).checksum(bid_sizes);
        let with = |checksum| BookMsg {
            checksum: Some(checksum),
            ..snapshot()
        };
        let outcomes = keep(rule, &depth(), [Ok(with(1)), Ok(with(2))]);
        assert!(outcomes[0].is_ok());
        assert!(matches!(outcomes[1], Err(DecodeError::Resync(_))));
    }

    /// The depth of an unchanged top is the same allocation as the last one.
    #[test]
    fn an_unchanged_top_emits_the_last_depth_again() {
        let below_the_top = (1..=DEPTH_LEVELS + 1)
            .map(|index| change(&(100 - index).to_string(), "1"))
            .collect();
        let deep = BookMsg {
            bids: below_the_top,
            ..snapshot()
        };
        let worst = format!("{}", 100 - DEPTH_LEVELS - 1);
        let outcomes = keep(
            CHAINED,
            &depth(),
            [
                Ok(deep),
                Ok(update(10, 11, vec![change(&worst, "2")])),
                Ok(update(11, 12, vec![change("100", "2")])),
            ],
        );
        let depth_of = |index: usize| {
            Arc::clone(
                outcomes[index].as_ref().expect("emitted")[0]
                    .book
                    .as_ref()
                    .expect("depth"),
            )
        };
        assert!(Arc::ptr_eq(&depth_of(0), &depth_of(1)), "below the top");
        assert!(!Arc::ptr_eq(&depth_of(1), &depth_of(2)), "at the top");
    }

    #[test]
    fn a_skipped_message_number_resyncs() {
        let mut keeper = BookKeeper::default();
        assert!(keeper.next_message(7).is_ok());
        assert!(keeper.next_message(8).is_ok());
        assert!(matches!(
            keeper.next_message(10),
            Err(DecodeError::Resync(_))
        ));
    }
}
