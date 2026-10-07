//! The book update payload and its frame.
//!
//! ```text
//! payload:
//! [0]       u8       version = 1
//! [1]       u8       kind = 0x04
//! [2]       u8       venue
//! [3]       u8       market
//! [4]       u8       symbol length L, 1..=32
//! [5..5+L]           symbol, printable ASCII
//! then      u64      publish time, unix ns
//!           u64      seq
//!           u8       flags: bit 0 snapshot
//!           i32      price exponent = -8
//!           i32      size exponent = -8
//!           u64      venue time, 0 when the venue sends none
//!           u64      our receipt time
//!           u8, u8   bid count, ask count, each at most 128
//!           16 × n   bids, then asks: price i64, size u64
//!
//! frame: [0] type = 3 ‖ [1..21] signer hint ‖ payload ‖ 65-byte signature
//! ```

use oracle_types::{
    BOOK_EXPO, BookLevel, BookUpdate, MAX_BOOK_LEVELS, MAX_BOOK_SYMBOL, MarketKind, Venue,
};

use crate::codec::{Reader, Sink as _};
use crate::payload::{KIND_BOOK_UPDATE, PAYLOAD_VERSION};
use crate::registry::VerifiedRegistry;
use crate::varframe::{self, RawFrame};
use crate::{Address, Signature, Signer, VerifyError, WireError};

/// Frame type for a book update.
pub const FRAME_TYPE_BOOK_UPDATE: u8 = 3;

/// Payload bytes besides the symbol and the levels.
const FIXED_SIZE: usize = 5 + 8 + 8 + 1 + 4 + 4 + 8 + 8 + 2;
const LEVEL_SIZE: usize = 16;
const SNAPSHOT: u8 = 1;

/// The largest book update payload.
pub const MAX_BOOK_PAYLOAD: usize = FIXED_SIZE + MAX_BOOK_SYMBOL + 2 * MAX_BOOK_LEVELS * LEVEL_SIZE;

/// Encodes a book update into its canonical bytes.
///
/// # Errors
///
/// Returns [`WireError`] for a symbol that is empty, too long or not printable
/// ASCII, a side above [`MAX_BOOK_LEVELS`], or levels that are out of order,
/// repeated, or of size zero in a snapshot.
pub fn encode_book_update(update: &BookUpdate) -> Result<Vec<u8>, WireError> {
    let symbol = update.symbol.as_bytes();
    check_symbol(symbol)?;
    let bids = count(&update.bids)?;
    let asks = count(&update.asks)?;
    check_side(&update.bids, update.snapshot, |a, b| a > b)?;
    check_side(&update.asks, update.snapshot, |a, b| a < b)?;

    let mut buf = Vec::with_capacity(
        FIXED_SIZE + symbol.len() + (update.bids.len() + update.asks.len()) * LEVEL_SIZE,
    );
    buf.put_u8(PAYLOAD_VERSION);
    buf.put_u8(KIND_BOOK_UPDATE);
    buf.put_u8(update.venue.index());
    buf.put_u8(update.market.index());
    buf.put_u8(u8::try_from(symbol.len()).unwrap_or(u8::MAX));
    buf.put_bytes(symbol);
    buf.put_u64(update.publish_time_ns);
    buf.put_u64(update.seq);
    buf.put_u8(if update.snapshot { SNAPSHOT } else { 0 });
    buf.put_i32(BOOK_EXPO);
    buf.put_i32(BOOK_EXPO);
    buf.put_u64(update.exchange_time_ns.unwrap_or(0));
    buf.put_u64(update.local_recv_ns);
    buf.put_u8(bids);
    buf.put_u8(asks);
    for level in update.bids.iter().chain(&update.asks) {
        buf.put_i64(level.price);
        buf.put_u64(level.qty);
    }
    Ok(buf)
}

/// Decodes a canonical book update payload.
///
/// # Errors
///
/// Returns [`WireError`] if the bytes are not exactly one canonical v1 book
/// update; see [`encode_book_update`] for the rules.
pub fn decode_book_update(bytes: &[u8]) -> Result<BookUpdate, WireError> {
    let mut reader = Reader::new(bytes);
    let version = reader.u8()?;
    if version != PAYLOAD_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }
    let kind = reader.u8()?;
    if kind != KIND_BOOK_UPDATE {
        return Err(WireError::UnexpectedKind {
            expected: KIND_BOOK_UPDATE,
            actual: kind,
        });
    }
    let code = |field, value: u8| WireError::UnknownCode { field, value };
    let venue = reader.u8()?;
    let venue = Venue::from_index(venue).ok_or_else(|| code("venue", venue))?;
    let market = reader.u8()?;
    let market = MarketKind::from_index(market).ok_or_else(|| code("market", market))?;
    let length = usize::from(reader.u8()?);
    let symbol = reader.take(length)?;
    check_symbol(symbol)?;
    let symbol = String::from_utf8(symbol.to_vec())
        .map_err(|_| WireError::NonCanonical("a symbol that is not ASCII"))?;
    let publish_time_ns = reader.u64()?;
    let seq = reader.u64()?;
    let snapshot = match reader.u8()? {
        0 => false,
        SNAPSHOT => true,
        _ => return Err(WireError::NonCanonical("an unknown book flag")),
    };
    if reader.i32()? != BOOK_EXPO || reader.i32()? != BOOK_EXPO {
        return Err(WireError::NonCanonical("a book exponent other than -8"));
    }
    let exchange_time_ns = Some(reader.u64()?).filter(|time| *time != 0);
    let local_recv_ns = reader.u64()?;
    let bid_count = usize::from(reader.u8()?);
    let ask_count = usize::from(reader.u8()?);
    if bid_count.max(ask_count) > MAX_BOOK_LEVELS {
        return Err(WireError::TooManyEntries {
            actual: bid_count.max(ask_count),
            limit: MAX_BOOK_LEVELS,
        });
    }
    let mut levels = |count| -> Result<Vec<BookLevel>, WireError> {
        (0..count)
            .map(|_| {
                Ok(BookLevel {
                    price: reader.i64()?,
                    qty: reader.u64()?,
                })
            })
            .collect()
    };
    let bids = levels(bid_count)?;
    let asks = levels(ask_count)?;
    reader.finish()?;
    check_side(&bids, snapshot, |a, b| a > b)?;
    check_side(&asks, snapshot, |a, b| a < b)?;
    Ok(BookUpdate {
        venue,
        market,
        symbol,
        publish_time_ns,
        seq,
        snapshot,
        exchange_time_ns,
        local_recv_ns,
        bids,
        asks,
    })
}

fn check_symbol(symbol: &[u8]) -> Result<(), WireError> {
    if symbol.is_empty() || symbol.len() > MAX_BOOK_SYMBOL {
        return Err(WireError::FieldTooLong {
            field: "book symbol",
            actual: symbol.len(),
            limit: MAX_BOOK_SYMBOL,
        });
    }
    if !symbol.iter().all(u8::is_ascii_graphic) {
        return Err(WireError::NonCanonical(
            "a symbol that is not printable ASCII",
        ));
    }
    Ok(())
}

fn count(levels: &[BookLevel]) -> Result<u8, WireError> {
    u8::try_from(levels.len())
        .ok()
        .filter(|_| levels.len() <= MAX_BOOK_LEVELS)
        .ok_or(WireError::TooManyEntries {
            actual: levels.len(),
            limit: MAX_BOOK_LEVELS,
        })
}

/// One order per side, best first, gives each update one byte form.
fn check_side(
    levels: &[BookLevel],
    snapshot: bool,
    better: fn(i64, i64) -> bool,
) -> Result<(), WireError> {
    if levels
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if !better(a.price, b.price)))
    {
        return Err(WireError::NonCanonical("book levels out of order"));
    }
    if snapshot && levels.iter().any(|level| level.qty == 0) {
        return Err(WireError::NonCanonical("a snapshot level of size zero"));
    }
    Ok(())
}

/// A book update this node has just signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBookUpdate {
    update: BookUpdate,
    payload: Vec<u8>,
    signature: Signature,
    signer: Address,
}

impl SignedBookUpdate {
    /// Returns the update.
    #[must_use]
    pub const fn update(&self) -> &BookUpdate {
        &self.update
    }

    /// Returns the signing address.
    #[must_use]
    pub const fn signer(&self) -> Address {
        self.signer
    }

    /// Returns the canonical signed bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the signature.
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }

    /// Encodes the wire frame.
    #[must_use]
    pub fn encode_frame(&self) -> Vec<u8> {
        varframe::encode(
            FRAME_TYPE_BOOK_UPDATE,
            self.signer,
            &self.payload,
            self.signature,
        )
    }
}

impl Signer {
    /// Signs a book update.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if the update cannot be encoded; see
    /// [`encode_book_update`].
    ///
    /// # Panics
    ///
    /// See [`Signer::sign_digest`].
    pub fn sign_book_update(&self, update: &BookUpdate) -> Result<SignedBookUpdate, WireError> {
        let payload = encode_book_update(update)?;
        let signature = self.sign_payload(&payload);
        Ok(SignedBookUpdate {
            update: update.clone(),
            payload,
            signature,
            signer: self.address(),
        })
    }
}

/// A structurally valid book frame that has **not** been checked against a
/// registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedBookFrame {
    raw: RawFrame,
}

impl UnverifiedBookFrame {
    /// Parses a frame, checking only its structure.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::UnknownFrameType`] for another frame type, a length
    /// error outside the payload bounds, and signature errors from
    /// [`Signature::from_bytes`].
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        RawFrame::parse(
            bytes,
            FRAME_TYPE_BOOK_UPDATE,
            FIXED_SIZE + 1,
            MAX_BOOK_PAYLOAD,
        )
        .map(|raw| Self { raw })
    }

    /// Returns the address the frame *claims* to be from. Outside the signature.
    #[must_use]
    pub const fn signer_hint(&self) -> Address {
        self.raw.signer_hint
    }

    /// Decodes the payload **without** any trust check. For tooling only.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if the payload is not a canonical book update.
    pub fn decode_unverified(&self) -> Result<BookUpdate, WireError> {
        decode_book_update(&self.raw.payload)
    }

    /// Verifies the frame against a trusted registry. Freshness and the
    /// sequence are the consumer's job, as for a price frame.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError`] for malformed payloads and unknown signers.
    pub fn verify(&self, registry: &VerifiedRegistry) -> Result<VerifiedBookUpdate, VerifyError> {
        let update = decode_book_update(&self.raw.payload)?;
        let signer = self.raw.recover_signer()?;
        let node_index = registry.authorize(signer)?;
        Ok(VerifiedBookUpdate {
            update,
            signer,
            node_index,
        })
    }
}

/// A book update that a registered node provably signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBookUpdate {
    update: BookUpdate,
    signer: Address,
    node_index: usize,
}

impl VerifiedBookUpdate {
    /// Returns the update.
    #[must_use]
    pub const fn update(&self) -> &BookUpdate {
        &self.update
    }

    /// Consumes this wrapper and returns the update.
    #[must_use]
    pub fn into_update(self) -> BookUpdate {
        self.update
    }

    /// Returns the signing address.
    #[must_use]
    pub const fn signer(&self) -> Address {
        self.signer
    }

    /// Returns the index of the signing node in the registry it was verified against.
    #[must_use]
    pub const fn node_index(&self) -> usize {
        self.node_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{NodeEntry, Quorum, Registry};
    use crate::{decode_venue_report, encode_venue_report};
    use oracle_types::{FeedId, VenueReport};

    fn node() -> Signer {
        Signer::from_secret_bytes([0x21; 32]).expect("valid key")
    }

    fn registry() -> VerifiedRegistry {
        let governance = Signer::from_secret_bytes([0x91; 32]).expect("valid key");
        let entry = NodeEntry {
            address: node().address(),
            endpoints: vec!["wss://eu1.example/v2/ws".to_owned()],
            weight: 1,
        };
        let quorum = Quorum {
            min_nodes: 1,
            recommended: 3,
        };
        Registry::sign(&governance, 1, 1_754_582_400, vec![entry], quorum)
            .expect("signs")
            .verify(governance.address(), 0)
            .expect("verifies")
    }

    fn level(price: i64, qty: u64) -> BookLevel {
        BookLevel { price, qty }
    }

    fn snapshot() -> BookUpdate {
        BookUpdate {
            venue: Venue::Binance,
            market: MarketKind::Spot,
            symbol: "BTCUSDT".to_owned(),
            publish_time_ns: 1_754_582_400_123_456_789,
            seq: 9,
            snapshot: true,
            exchange_time_ns: Some(1_754_582_400_100_000_000),
            local_recv_ns: 1_754_582_400_110_000_000,
            bids: vec![
                level(6_431_250_000_000, 150_000_000),
                level(6_431_240_000_000, 7),
            ],
            asks: vec![level(6_431_260_000_000, 200_000_000)],
        }
    }

    #[test]
    fn an_update_round_trips_through_its_bytes() {
        let bytes = encode_book_update(&snapshot()).expect("encodes");
        assert_eq!(bytes.len(), FIXED_SIZE + 7 + 3 * LEVEL_SIZE);
        assert_eq!(decode_book_update(&bytes), Ok(snapshot()));

        let delta = BookUpdate {
            snapshot: false,
            exchange_time_ns: None,
            bids: vec![level(6_431_250_000_000, 0)],
            asks: Vec::new(),
            ..snapshot()
        };
        let bytes = encode_book_update(&delta).expect("a delta may remove a level");
        assert_eq!(decode_book_update(&bytes), Ok(delta));
    }

    #[test]
    fn a_signed_frame_verifies_and_a_stranger_does_not() {
        let signed = node().sign_book_update(&snapshot()).expect("signs");
        let frame = UnverifiedBookFrame::parse(&signed.encode_frame()).expect("parses");
        assert_eq!(
            frame.verify(&registry()).expect("verifies").update(),
            &snapshot()
        );
        let stranger = Signer::from_secret_bytes([0x33; 32]).expect("valid key");
        let forged = stranger.sign_book_update(&snapshot()).expect("signs");
        let frame = UnverifiedBookFrame::parse(&forged.encode_frame()).expect("parses");
        assert!(frame.verify(&registry()).is_err());
    }

    #[test]
    fn non_canonical_books_are_refused() {
        let mut unordered = snapshot();
        unordered.bids.reverse();
        assert_eq!(
            encode_book_update(&unordered),
            Err(WireError::NonCanonical("book levels out of order"))
        );
        let mut empty_level = snapshot();
        if let Some(ask) = empty_level.asks.first_mut() {
            ask.qty = 0;
        }
        assert_eq!(
            encode_book_update(&empty_level),
            Err(WireError::NonCanonical("a snapshot level of size zero"))
        );
        let long = BookUpdate {
            symbol: "X".repeat(MAX_BOOK_SYMBOL + 1),
            ..snapshot()
        };
        assert!(encode_book_update(&long).is_err());

        let mut bytes = encode_book_update(&snapshot()).expect("encodes");
        bytes.push(0);
        assert!(decode_book_update(&bytes).is_err(), "trailing bytes");
    }

    #[test]
    fn kinds_do_not_cross() {
        let book = encode_book_update(&snapshot()).expect("encodes");
        assert!(decode_venue_report(&book).is_err());
        let report = VenueReport {
            feed_id: FeedId::from_bytes([7; 32]),
            publish_time_ns: 1,
            seq: 1,
            expo: -8,
            entries: Vec::new(),
        };
        let venues = encode_venue_report(&report).expect("encodes");
        assert!(decode_book_update(&venues).is_err());
    }
}
