//! The venue report payload and its frame.
//!
//! ```text
//! payload, 55 + 95 × n bytes:
//! [0]       u8       version = 1
//! [1]       u8       kind = 0x03
//! [2..34]   [u8;32]  feed id
//! [34..42]  u64      publish time, unix ns
//! [42..50]  u64      seq
//! [50..54]  i32      price exponent
//! [54]      u8       n, at most 32
//! then n entries of 95 bytes:
//! [0]       u8       venue
//! [1]       u8       market
//! [2]       u8       status
//! [3..5]    u16      fields present, bit i for slot i
//! [5..7]    u16      weight, basis points
//! [7..87]   10 × 8   bid, ask, bid size, ask size, impact bid, impact ask,
//!                    mark, index, funding, venue time; zero when absent
//! [87..95]  u64      our receipt time
//!
//! frame: [0] type = 2 ‖ [1..21] signer hint ‖ payload ‖ 65-byte signature
//! ```
//!
//! The frame has the same typestate as a price frame: parsing gives an
//! [`UnverifiedVenueFrame`], and only a registry turns it into a report.

use oracle_types::{
    FeedId, MAX_VENUE_ENTRIES, MarketKind, SourceStatus, Venue, VenueEntry, VenueReport,
};

use crate::codec::{Reader, Sink as _};
use crate::payload::{KIND_VENUE_REPORT, PAYLOAD_VERSION};
use crate::registry::VerifiedRegistry;
use crate::signature::SIGNATURE_LEN;
use crate::varframe::{self, RawFrame};
use crate::{Address, Signature, Signer, VerifyError, WireError};

/// Frame type for a venue report.
pub const FRAME_TYPE_VENUE_REPORT: u8 = 2;

/// Size of the payload before the entries.
pub const VENUE_HEADER_SIZE: usize = 55;

/// Size of one entry.
pub const VENUE_ENTRY_SIZE: usize = 95;

/// The largest venue report frame.
pub const MAX_VENUE_FRAME_SIZE: usize =
    1 + Address::LEN + VENUE_HEADER_SIZE + VENUE_ENTRY_SIZE * MAX_VENUE_ENTRIES + SIGNATURE_LEN;

/// The ten optional slots, in wire order.
const SLOTS: usize = 10;
const KNOWN_FIELDS: u16 = (1 << SLOTS) - 1;
const MAX_WEIGHT_BPS: u16 = 10_000;

/// Encodes a venue report into its canonical bytes.
///
/// # Errors
///
/// Returns [`WireError::TooManyEntries`] above [`MAX_VENUE_ENTRIES`], or
/// [`WireError::NonCanonical`] for a weight above 10,000 basis points.
pub fn encode_venue_report(report: &VenueReport) -> Result<Vec<u8>, WireError> {
    let count = report.entries.len();
    let count_byte = u8::try_from(count)
        .ok()
        .filter(|_| count <= MAX_VENUE_ENTRIES)
        .ok_or(WireError::TooManyEntries {
            actual: count,
            limit: MAX_VENUE_ENTRIES,
        })?;
    let mut buf = Vec::with_capacity(VENUE_HEADER_SIZE + VENUE_ENTRY_SIZE * count);
    buf.put_u8(PAYLOAD_VERSION);
    buf.put_u8(KIND_VENUE_REPORT);
    buf.put_bytes(report.feed_id.as_bytes());
    buf.put_u64(report.publish_time_ns);
    buf.put_u64(report.seq);
    buf.put_i32(report.expo);
    buf.put_u8(count_byte);
    for entry in &report.entries {
        if entry.weight_bps > MAX_WEIGHT_BPS {
            return Err(WireError::NonCanonical("a weight above 10,000 bp"));
        }
        let slots = slots_of(entry);
        let present = slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.is_some())
            .fold(0_u16, |bits, (index, _)| bits | (1 << index));
        buf.put_u8(entry.venue.index());
        buf.put_u8(entry.market.index());
        buf.put_u8(entry.status.index());
        buf.put_u16(present);
        buf.put_u16(entry.weight_bps);
        for slot in slots {
            buf.put_bytes(&slot.unwrap_or_default());
        }
        buf.put_u64(entry.local_recv_ns);
    }
    Ok(buf)
}

/// The optional fields as raw big-endian slots, in wire order.
fn slots_of(entry: &VenueEntry) -> [Option<[u8; 8]>; SLOTS] {
    let signed = |value: Option<i64>| value.map(i64::to_be_bytes);
    let unsigned = |value: Option<u64>| value.map(u64::to_be_bytes);
    [
        signed(entry.bid),
        signed(entry.ask),
        unsigned(entry.bid_qty),
        unsigned(entry.ask_qty),
        signed(entry.impact_bid),
        signed(entry.impact_ask),
        signed(entry.mark),
        signed(entry.index),
        signed(entry.funding),
        unsigned(entry.exchange_time_ns),
    ]
}

/// Decodes a canonical venue report payload.
///
/// # Errors
///
/// Returns [`WireError`] if the bytes are not exactly one canonical v1 venue
/// report: a wrong length, header, or entry count; an unknown venue, market or
/// status code; an unknown field bit; a non-zero absent slot; or a weight above
/// 10,000 basis points.
pub fn decode_venue_report(bytes: &[u8]) -> Result<VenueReport, WireError> {
    let mut reader = Reader::new(bytes);
    let version = reader.u8()?;
    if version != PAYLOAD_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }
    let kind = reader.u8()?;
    if kind != KIND_VENUE_REPORT {
        return Err(WireError::UnexpectedKind {
            expected: KIND_VENUE_REPORT,
            actual: kind,
        });
    }
    let feed_id = FeedId::from_bytes(reader.array::<32>()?);
    let publish_time_ns = reader.u64()?;
    let seq = reader.u64()?;
    let expo = reader.i32()?;
    let count = usize::from(reader.u8()?);
    if count > MAX_VENUE_ENTRIES {
        return Err(WireError::TooManyEntries {
            actual: count,
            limit: MAX_VENUE_ENTRIES,
        });
    }
    let expected = VENUE_HEADER_SIZE + VENUE_ENTRY_SIZE * count;
    if bytes.len() < expected {
        return Err(WireError::Truncated {
            expected,
            actual: bytes.len(),
        });
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(decode_entry(&mut reader)?);
    }
    reader.finish()?;
    Ok(VenueReport {
        feed_id,
        publish_time_ns,
        seq,
        expo,
        entries,
    })
}

fn decode_entry(reader: &mut Reader<'_>) -> Result<VenueEntry, WireError> {
    let code = |field, value: u8| WireError::UnknownCode { field, value };
    let venue = reader.u8()?;
    let venue = Venue::from_index(venue).ok_or_else(|| code("venue", venue))?;
    let market = reader.u8()?;
    let market = MarketKind::from_index(market).ok_or_else(|| code("market", market))?;
    let status = reader.u8()?;
    let status = SourceStatus::from_index(status).ok_or_else(|| code("status", status))?;
    let present = reader.u16()?;
    if present & !KNOWN_FIELDS != 0 {
        return Err(WireError::NonCanonical("an unknown field bit"));
    }
    let weight_bps = reader.u16()?;
    if weight_bps > MAX_WEIGHT_BPS {
        return Err(WireError::NonCanonical("a weight above 10,000 bp"));
    }
    let mut slots = [None; SLOTS];
    for (index, slot) in slots.iter_mut().enumerate() {
        let bytes = reader.array::<8>()?;
        if present & (1 << index) != 0 {
            *slot = Some(bytes);
        } else if bytes != [0; 8] {
            return Err(WireError::NonCanonical("a non-zero absent field"));
        }
    }
    let local_recv_ns = reader.u64()?;
    let [
        bid,
        ask,
        bid_qty,
        ask_qty,
        impact_bid,
        impact_ask,
        mark,
        index,
        funding,
        venue_time,
    ] = slots;
    let signed = |slot: Option<[u8; 8]>| slot.map(i64::from_be_bytes);
    let unsigned = |slot: Option<[u8; 8]>| slot.map(u64::from_be_bytes);
    Ok(VenueEntry {
        venue,
        market,
        status,
        weight_bps,
        bid: signed(bid),
        ask: signed(ask),
        bid_qty: unsigned(bid_qty),
        ask_qty: unsigned(ask_qty),
        impact_bid: signed(impact_bid),
        impact_ask: signed(impact_ask),
        mark: signed(mark),
        index: signed(index),
        funding: signed(funding),
        exchange_time_ns: unsigned(venue_time),
        local_recv_ns,
    })
}

/// A venue report this node has just signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedVenueReport {
    report: VenueReport,
    payload: Vec<u8>,
    signature: Signature,
    signer: Address,
}

impl SignedVenueReport {
    /// Returns the report.
    #[must_use]
    pub const fn report(&self) -> &VenueReport {
        &self.report
    }

    /// Returns the canonical signed bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the signing address.
    #[must_use]
    pub const fn signer(&self) -> Address {
        self.signer
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
            FRAME_TYPE_VENUE_REPORT,
            self.signer,
            &self.payload,
            self.signature,
        )
    }
}

impl Signer {
    /// Signs a venue report.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if the report cannot be encoded; see
    /// [`encode_venue_report`].
    ///
    /// # Panics
    ///
    /// See [`Signer::sign_digest`].
    pub fn sign_venue_report(&self, report: &VenueReport) -> Result<SignedVenueReport, WireError> {
        let payload = encode_venue_report(report)?;
        let signature = self.sign_payload(&payload);
        Ok(SignedVenueReport {
            report: report.clone(),
            payload,
            signature,
            signer: self.address(),
        })
    }
}

/// A structurally valid venue frame that has **not** been checked against a
/// registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedVenueFrame {
    raw: RawFrame,
}

impl UnverifiedVenueFrame {
    /// Parses a frame, checking only its structure.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::UnknownFrameType`] for another frame type,
    /// [`WireError::Truncated`] below the smallest frame,
    /// [`WireError::TrailingBytes`] above the largest, and signature errors from
    /// [`Signature::from_bytes`].
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        RawFrame::parse(
            bytes,
            FRAME_TYPE_VENUE_REPORT,
            VENUE_HEADER_SIZE,
            VENUE_HEADER_SIZE + VENUE_ENTRY_SIZE * MAX_VENUE_ENTRIES,
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
    /// Returns [`WireError`] if the payload is not a canonical venue report.
    pub fn decode_unverified(&self) -> Result<VenueReport, WireError> {
        decode_venue_report(&self.raw.payload)
    }

    /// Verifies the frame against a trusted registry.
    ///
    /// Freshness and sequence checks are the consumer's job, as for a price
    /// frame.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError`] for malformed payloads and unknown signers.
    pub fn verify(&self, registry: &VerifiedRegistry) -> Result<VerifiedVenueReport, VerifyError> {
        let report = decode_venue_report(&self.raw.payload)?;
        let signer = self.raw.recover_signer()?;
        let node_index = registry.authorize(signer)?;
        Ok(VerifiedVenueReport {
            report,
            signer,
            node_index,
        })
    }
}

/// A venue report that a registered node provably signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedVenueReport {
    report: VenueReport,
    signer: Address,
    node_index: usize,
}

impl VerifiedVenueReport {
    /// Returns the report.
    #[must_use]
    pub const fn report(&self) -> &VenueReport {
        &self.report
    }

    /// Consumes this wrapper and returns the report.
    #[must_use]
    pub fn into_report(self) -> VenueReport {
        self.report
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
    use crate::{decode_price_update, encode_price_update};
    use oracle_types::{Flags, PriceUpdate, VenueSet};

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

    fn entry(venue: Venue, status: SourceStatus) -> VenueEntry {
        VenueEntry {
            venue,
            market: MarketKind::Spot,
            status,
            weight_bps: 0,
            bid: None,
            ask: None,
            bid_qty: None,
            ask_qty: None,
            impact_bid: None,
            impact_ask: None,
            mark: None,
            index: None,
            funding: None,
            exchange_time_ns: None,
            local_recv_ns: 0,
        }
    }

    fn report() -> VenueReport {
        VenueReport {
            feed_id: FeedId::from_bytes([7; 32]),
            publish_time_ns: 1_754_582_400_123_456_789,
            seq: 42,
            expo: -8,
            entries: vec![
                VenueEntry {
                    weight_bps: 6_000,
                    bid: Some(6_431_250_000_000),
                    ask: Some(6_431_260_000_000),
                    bid_qty: Some(150_000_000),
                    ask_qty: Some(200_000_000),
                    impact_bid: Some(6_431_100_000_000),
                    impact_ask: Some(6_431_400_000_000),
                    exchange_time_ns: Some(1_754_582_400_090_000_000),
                    local_recv_ns: 1_754_582_400_100_000_000,
                    ..entry(Venue::Binance, SourceStatus::Used)
                },
                VenueEntry {
                    market: MarketKind::InversePerp,
                    mark: Some(6_432_000_000_000),
                    index: Some(6_431_900_000_000),
                    funding: Some(-12_500),
                    local_recv_ns: 1_754_582_400_050_000_000,
                    ..entry(Venue::Deribit, SourceStatus::Stale)
                },
                entry(Venue::Kraken, SourceStatus::NoData),
            ],
        }
    }

    #[test]
    fn a_report_round_trips_through_its_bytes() {
        let bytes = encode_venue_report(&report()).expect("encodes");
        assert_eq!(bytes.len(), VENUE_HEADER_SIZE + 3 * VENUE_ENTRY_SIZE);
        assert_eq!(decode_venue_report(&bytes), Ok(report()));
    }

    #[test]
    fn a_signed_frame_verifies_against_the_registry() {
        let signed = node().sign_venue_report(&report()).expect("signs");
        let frame = UnverifiedVenueFrame::parse(&signed.encode_frame()).expect("parses");
        let verified = frame.verify(&registry()).expect("a listed node signed it");
        assert_eq!(verified.report(), &report());
        assert_eq!(verified.signer(), node().address());
    }

    #[test]
    fn a_stranger_is_refused() {
        let stranger = Signer::from_secret_bytes([0x33; 32]).expect("valid key");
        let signed = stranger.sign_venue_report(&report()).expect("signs");
        let frame = UnverifiedVenueFrame::parse(&signed.encode_frame()).expect("parses");
        assert!(frame.verify(&registry()).is_err());
    }

    #[test]
    fn a_changed_byte_breaks_the_signature() {
        let signed = node().sign_venue_report(&report()).expect("signs");
        let mut bytes = signed.encode_frame();
        // The first entry's bid, in the middle of the payload.
        let at = 1 + Address::LEN + VENUE_HEADER_SIZE + 7 + 7;
        if let Some(byte) = bytes.get_mut(at) {
            *byte ^= 1;
        }
        let frame = UnverifiedVenueFrame::parse(&bytes).expect("still parses");
        assert!(frame.verify(&registry()).is_err());
    }

    #[test]
    fn a_price_payload_never_decodes_as_a_venue_report() {
        let update = PriceUpdate {
            feed_id: FeedId::from_bytes([7; 32]),
            flags: Flags::NONE,
            price: 1,
            conf: 0,
            expo: -8,
            publish_time_ns: 2,
            observation_time_ns: 1,
            prev_publish_time_ns: 0,
            seq: 1,
            num_sources: 0,
            sources: VenueSet::EMPTY,
        };
        let price = encode_price_update(&update);
        assert!(matches!(
            decode_venue_report(&price),
            Err(WireError::UnexpectedKind { .. })
        ));
        let venues = encode_venue_report(&report()).expect("encodes");
        assert!(decode_price_update(&venues).is_err());
    }

    #[test]
    fn non_canonical_bytes_are_refused() {
        let bytes = encode_venue_report(&report()).expect("encodes");
        let entry = VENUE_HEADER_SIZE + 2 * VENUE_ENTRY_SIZE;

        let mut absent = bytes.clone();
        if let Some(byte) = absent.get_mut(entry + 7) {
            *byte = 1;
        }
        assert_eq!(
            decode_venue_report(&absent),
            Err(WireError::NonCanonical("a non-zero absent field"))
        );

        let mut status = bytes.clone();
        if let Some(byte) = status.get_mut(entry + 2) {
            *byte = 9;
        }
        assert_eq!(
            decode_venue_report(&status),
            Err(WireError::UnknownCode {
                field: "status",
                value: 9
            })
        );

        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_venue_report(&trailing).is_err());
    }

    #[test]
    fn too_many_entries_do_not_encode() {
        let mut report = report();
        report.entries = vec![entry(Venue::Kraken, SourceStatus::NoData); MAX_VENUE_ENTRIES + 1];
        assert!(matches!(
            encode_venue_report(&report),
            Err(WireError::TooManyEntries { .. })
        ));
    }
}
