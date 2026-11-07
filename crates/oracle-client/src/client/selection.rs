//! The choice of one node's book and one node's funding frame: the node nearest
//! the median of the nodes. A node signs its own times, so no time decides it.

use std::collections::HashSet;
use std::time::Duration;

use oracle_agg::stats;
use oracle_types::{BookLevel, Fixed, InstrumentId};
use oracle_wire::Address;

use super::OracleClient;
use crate::age::Frame;
use crate::book::Book;
use crate::verify::AcceptedFunding;

/// The notional, in quote units, of the impact price that [`OracleClient::book`]
/// compares on each side. A node that copies the top and invents depth then
/// differs from the median.
const CHOICE_NOTIONAL: i64 = 10_000;

/// How long the chosen node may stay farther from the median than the nearest
/// node and the slack before [`OracleClient::book`] moves. Each move is a full
/// snapshot for a proxy's subscribers, and a node one frame behind in a trend
/// is far for a moment only.
const BOOK_SWITCH_MARGIN: Duration = Duration::from_secs(1);

/// The node that [`OracleClient::book`] chose last for one instrument.
#[derive(Clone, Copy, Debug)]
pub(super) struct Choice {
    pub(super) node: Address,
    /// When this node was first farther than the nearest and the slack, if it still is.
    worse_since_ns: Option<u64>,
}

impl OracleClient {
    /// One node's valid book for `instrument`, younger than `max_age`: the one whose
    /// top and depth are nearest the median of the nodes, or `None`.
    ///
    /// The median needs three or more nodes; with two, a tie keeps the last choice,
    /// then takes the lower address, and the same tie-break applies at every count.
    pub fn book(&mut self, instrument: &InstrumentId, now_ns: u64) -> Option<&Book> {
        let max_age = nanos(self.quorum_config.ages().max_age(Frame::Book));
        let usable: Vec<&Book> = self
            .registry
            .nodes()
            .iter()
            .filter_map(|node| self.books.get(&(node.address, instrument.clone())))
            .filter(|book| {
                book.is_valid() && now_ns.saturating_sub(book.publish_time_ns) <= max_age
            })
            .collect();
        let profiles: Vec<Profile> = usable.iter().map(|book| Profile::of(book)).collect();
        let median = Profile::median(&profiles);
        let scored: Vec<(&Book, Fixed)> = usable
            .iter()
            .zip(&profiles)
            .map(|(book, profile)| (*book, median.distance(profile)))
            .collect();
        let previous = self.book_nodes.get(instrument).copied();
        let last = previous.map(|choice| choice.node);
        let Some(&(nearest, nearest_distance)) = scored
            .iter()
            .min_by_key(|(book, distance)| (*distance, Some(book.node) != last, book.node))
        else {
            self.book_nodes.remove(instrument);
            return None;
        };
        let current = scored.iter().find(|(book, _)| Some(book.node) == last);
        let (chosen, worse_since_ns) = match (current, previous) {
            (Some(&(current, distance)), Some(choice)) if current.node != nearest.node => {
                if distance <= nearest_distance.saturating_add(median.spread()) {
                    (current, None)
                } else {
                    let since = choice.worse_since_ns.unwrap_or(now_ns);
                    if now_ns.saturating_sub(since) < nanos(BOOK_SWITCH_MARGIN) {
                        (current, Some(since))
                    } else {
                        (nearest, None)
                    }
                }
            }
            _ => (nearest, None),
        };
        self.book_nodes.insert(
            instrument.clone(),
            Choice {
                node: chosen.node,
                worse_since_ns,
            },
        );
        Some(chosen)
    }

    /// The funding frame for `perpetual` nearest the median of the nodes on its
    /// rate, interval and next funding time, among frames younger than two heartbeats.
    ///
    /// The median needs three or more nodes; a tie keeps the last choice, then
    /// takes the lower address.
    pub fn funding(&mut self, perpetual: &InstrumentId, now_ns: u64) -> Option<&AcceptedFunding> {
        let max_age = nanos(self.quorum_config.ages().max_age(Frame::Funding));
        let fresh: Vec<&AcceptedFunding> = self
            .registry
            .nodes()
            .iter()
            .filter_map(|node| self.funding.get(&(node.address, perpetual.clone())))
            .filter(|accepted| now_ns.saturating_sub(accepted.update.publish_time_ns) <= max_age)
            .collect();
        let fields = |accepted: &AcceptedFunding| {
            let update = &accepted.update;
            [
                Some(i128::from(update.rate)),
                update.interval_ns.map(i128::from),
                update.next_funding_time_ns.map(i128::from),
            ]
        };
        let medians: Vec<Option<i128>> = (0..3)
            .map(|field| {
                // Each field is a plain integer in `Fixed::from_raw`, so the shared median applies.
                let mut values: Vec<Fixed> = fresh
                    .iter()
                    .filter_map(|accepted| fields(accepted).get(field).copied().flatten())
                    .map(Fixed::from_raw)
                    .collect();
                stats::median(&mut values).map(Fixed::raw)
            })
            .collect();
        let last = self.funding_nodes.get(perpetual).copied();
        let Some(chosen) = fresh.into_iter().min_by_key(|accepted| {
            let gaps: Vec<u128> = fields(accepted)
                .iter()
                .zip(&medians)
                .map(|(value, median)| match (value, median) {
                    (_, None) => 0,
                    (Some(value), Some(median)) => value.abs_diff(*median),
                    (None, Some(_)) => u128::MAX,
                })
                .collect();
            let off = gaps.iter().filter(|gap| **gap > 0).count();
            (off, gaps, Some(accepted.signer) != last, accepted.signer)
        }) else {
            self.funding_nodes.remove(perpetual);
            return None;
        };
        self.funding_nodes.insert(perpetual.clone(), chosen.signer);
        Some(chosen)
    }

    /// Every perpetual a node has sent funding for, each once.
    pub fn funding_instruments(&self) -> impl Iterator<Item = &InstrumentId> {
        let mut seen = HashSet::new();
        self.funding
            .keys()
            .map(|(_, instrument)| instrument)
            .filter(move |instrument| seen.insert(*instrument))
    }

    /// Every book a node has sent, each once.
    pub fn book_instruments(&self) -> impl Iterator<Item = &InstrumentId> {
        let mut seen = HashSet::new();
        self.books
            .keys()
            .map(|(_, instrument)| instrument)
            .filter(move |instrument| seen.insert(*instrument))
    }
}

/// What the book choice compares: the best bid, the best ask, and the impact
/// price of each side at [`CHOICE_NOTIONAL`].
struct Profile([Option<Fixed>; 4]);

impl Profile {
    fn of(book: &Book) -> Self {
        Self([
            price(book.best_bid()),
            price(book.best_ask()),
            impact(book.bids()),
            impact(book.asks()),
        ])
    }

    fn median(profiles: &[Self]) -> Self {
        let mut median = [None; 4];
        for (slot, value) in median.iter_mut().enumerate() {
            let mut values: Vec<Fixed> = profiles
                .iter()
                .filter_map(|profile| profile.0.get(slot).copied().flatten())
                .collect();
            *value = stats::median(&mut values);
        }
        Self(median)
    }

    /// The sum of the gaps to `self`, the median. A value that the median has
    /// and the book lacks is as far as can be.
    fn distance(&self, profile: &Self) -> Fixed {
        self.0
            .iter()
            .zip(&profile.0)
            .map(|(median, value)| match (median, value) {
                (None, _) => Fixed::ZERO,
                (Some(median), Some(value)) => value
                    .checked_sub(*median)
                    .and_then(Fixed::checked_abs)
                    .unwrap_or(Fixed::MAX),
                (Some(_), None) => Fixed::MAX,
            })
            .fold(Fixed::ZERO, Fixed::saturating_add)
    }

    /// The median spread, the slack of the choice.
    fn spread(&self) -> Fixed {
        let [bid, ask, ..] = self.0;
        ask.zip(bid)
            .and_then(|(ask, bid)| ask.checked_sub(bid))
            .filter(|spread| *spread >= Fixed::ZERO)
            .unwrap_or(Fixed::ZERO)
    }
}

fn price(level: Option<BookLevel>) -> Option<Fixed> {
    Book::level_fixed(level?).ok().map(|(price, _)| price)
}

/// The average price of a fill of [`CHOICE_NOTIONAL`] on one side, or of the
/// whole side when it holds less.
fn impact(levels: impl Iterator<Item = BookLevel>) -> Option<Fixed> {
    let target = Fixed::from_int(CHOICE_NOTIONAL).ok()?;
    let (mut notional, mut base) = (Fixed::ZERO, Fixed::ZERO);
    for level in levels {
        let (price, qty) = Book::level_fixed(level).ok()?;
        let room = target.checked_sub(notional)?;
        let value = price.checked_mul(qty)?;
        if value >= room {
            base = base.checked_add(room.checked_div(price)?)?;
            notional = target;
            break;
        }
        notional = notional.checked_add(value)?;
        base = base.checked_add(qty)?;
    }
    notional.checked_div(base)
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}
