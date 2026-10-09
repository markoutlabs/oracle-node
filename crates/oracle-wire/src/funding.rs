//! The funding update payload and its frame.
//!
//! ```text
//! payload:
//! [0]       u8       version = 1
//! [1]       u8       kind = 0x05
//! [2]       u8       venue
//! [3]       u8       market
//! [4]       u8       symbol length L, 1..=32
//! [5..5+L]           symbol, printable ASCII
//! then      u64      publish time, unix ns
//!           u64      seq
//!           u8       flags: bit 0 predicted rate, bit 1 interval, bit 2 next
//!                    funding time, bit 3 settled rate, bit 4 open interest
//!           u8       basis: 0 per interval, 1 per 8 hours
//!           u8       open interest unit: 0 base, 1 contracts, 2 quote
//!           i32      rate exponent = -12
//!           i32      open interest exponent = -8
//!           i64      rate
//!           i64      predicted rate
//!           u64      interval, ns
//!           u64      next funding time, unix ns
//!           i64      settled rate
//!           u64      settled time, unix ns
//!           u64      open interest
//!           u64      venue time, 0 when the venue sends none
//!           u64      our receipt time
//!
//! A field whose flag is clear is zero, and so is the unit without open interest.
//!
//! frame: [0] type = 4 ‖ [1..21] signer hint ‖ payload ‖ 65-byte signature
//! ```

use oracle_types::{
    FUNDING_EXPO, FundingBasis, FundingUpdate, MAX_VENUE_SYMBOL, MarketKind, OPEN_INTEREST_EXPO,
    OpenInterest, OpenInterestUnit, SettledFunding, Venue,
};

use crate::books::check_symbol;
use crate::codec::{Reader, Sink as _};
use crate::payload::{KIND_FUNDING_UPDATE, PAYLOAD_VERSION};
use crate::registry::VerifiedRegistry;
use crate::varframe::{self, RawFrame};
use crate::{Address, Signature, Signer, VerifyError, WireError};

/// Frame type for a funding update.
pub const FRAME_TYPE_FUNDING_UPDATE: u8 = 4;

/// Payload bytes besides the symbol.
const FIXED_SIZE: usize = 5 + 8 + 8 + 1 + 1 + 1 + 4 + 4 + 9 * 8;
const PREDICTED: u8 = 1;
const INTERVAL: u8 = 1 << 1;
const NEXT_TIME: u8 = 1 << 2;
const SETTLED: u8 = 1 << 3;
const OPEN_INTEREST: u8 = 1 << 4;
const FLAGS: u8 = PREDICTED | INTERVAL | NEXT_TIME | SETTLED | OPEN_INTEREST;

/// The largest funding update payload.
pub const MAX_FUNDING_PAYLOAD: usize = FIXED_SIZE + MAX_VENUE_SYMBOL;

/// Encodes a funding update into its canonical bytes.
///
/// # Errors
///
/// Returns [`WireError`] for a symbol that is empty, too long or not printable
/// ASCII.
pub fn encode_funding_update(update: &FundingUpdate) -> Result<Vec<u8>, WireError> {
    let symbol = update.symbol.as_bytes();
    check_symbol(symbol, "funding symbol")?;
    let mut flags = 0;
    for (present, flag) in [
        (update.predicted_rate.is_some(), PREDICTED),
        (update.interval_ns.is_some(), INTERVAL),
        (update.next_funding_time_ns.is_some(), NEXT_TIME),
        (update.settled.is_some(), SETTLED),
        (update.open_interest.is_some(), OPEN_INTEREST),
    ] {
        if present {
            flags |= flag;
        }
    }
    let mut buf = Vec::with_capacity(FIXED_SIZE + symbol.len());
    buf.put_u8(PAYLOAD_VERSION);
    buf.put_u8(KIND_FUNDING_UPDATE);
    buf.put_u8(update.venue.index());
    buf.put_u8(update.market.index());
    buf.put_u8(u8::try_from(symbol.len()).unwrap_or(u8::MAX));
    buf.put_bytes(symbol);
    buf.put_u64(update.publish_time_ns);
    buf.put_u64(update.seq);
    buf.put_u8(flags);
    buf.put_u8(update.basis.index());
    buf.put_u8(update.open_interest.map_or(0, |oi| oi.unit.index()));
    buf.put_i32(FUNDING_EXPO);
    buf.put_i32(OPEN_INTEREST_EXPO);
    buf.put_i64(update.rate);
    buf.put_i64(update.predicted_rate.unwrap_or(0));
    buf.put_u64(update.interval_ns.unwrap_or(0));
    buf.put_u64(update.next_funding_time_ns.unwrap_or(0));
    buf.put_i64(update.settled.map_or(0, |settled| settled.rate));
    buf.put_u64(update.settled.map_or(0, |settled| settled.time_ns));
    buf.put_u64(update.open_interest.map_or(0, |oi| oi.amount));
    buf.put_u64(update.exchange_time_ns.unwrap_or(0));
    buf.put_u64(update.local_recv_ns);
    Ok(buf)
}

/// Decodes a canonical funding update payload.
///
/// # Errors
///
/// Returns [`WireError`] if the bytes are not exactly one canonical v1 funding
/// update: an unknown code or flag, another exponent, or a nonzero field whose
/// flag is clear.
pub fn decode_funding_update(bytes: &[u8]) -> Result<FundingUpdate, WireError> {
    let mut reader = Reader::new(bytes);
    let version = reader.u8()?;
    if version != PAYLOAD_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }
    let kind = reader.u8()?;
    if kind != KIND_FUNDING_UPDATE {
        return Err(WireError::UnexpectedKind {
            expected: KIND_FUNDING_UPDATE,
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
    check_symbol(symbol, "funding symbol")?;
    let symbol = String::from_utf8(symbol.to_vec())
        .map_err(|_| WireError::NonCanonical("a symbol that is not ASCII"))?;
    let publish_time_ns = reader.u64()?;
    let seq = reader.u64()?;
    let flags = reader.u8()?;
    if flags & !FLAGS != 0 {
        return Err(WireError::NonCanonical("an unknown funding flag"));
    }
    let basis = reader.u8()?;
    let basis = FundingBasis::from_index(basis).ok_or_else(|| code("funding basis", basis))?;
    let unit = reader.u8()?;
    if reader.i32()? != FUNDING_EXPO || reader.i32()? != OPEN_INTEREST_EXPO {
        return Err(WireError::NonCanonical(
            "a funding exponent other than -12 and -8",
        ));
    }
    let rate = reader.i64()?;
    let predicted = reader.i64()?;
    let interval = reader.u64()?;
    let next_time = reader.u64()?;
    let settled_rate = reader.i64()?;
    let settled_time = reader.u64()?;
    let open_interest = reader.u64()?;
    let exchange_time_ns = Some(reader.u64()?).filter(|time| *time != 0);
    let local_recv_ns = reader.u64()?;
    reader.finish()?;

    // A clear flag needs zeros, so each update has one byte form.
    let field = |flag: u8, zero: bool| -> Result<bool, WireError> {
        match (flags & flag != 0, zero) {
            (true, _) => Ok(true),
            (false, true) => Ok(false),
            (false, false) => Err(WireError::NonCanonical("a funding field without its flag")),
        }
    };
    let predicted_rate = field(PREDICTED, predicted == 0)?.then_some(predicted);
    let interval_ns = field(INTERVAL, interval == 0)?.then_some(interval);
    let next_funding_time_ns = field(NEXT_TIME, next_time == 0)?.then_some(next_time);
    let settled =
        field(SETTLED, settled_rate == 0 && settled_time == 0)?.then_some(SettledFunding {
            rate: settled_rate,
            time_ns: settled_time,
        });
    let open_interest = if field(OPEN_INTEREST, open_interest == 0 && unit == 0)? {
        Some(OpenInterest {
            amount: open_interest,
            unit: OpenInterestUnit::from_index(unit)
                .ok_or_else(|| code("open interest unit", unit))?,
        })
    } else {
        None
    };
    Ok(FundingUpdate {
        venue,
        market,
        symbol,
        publish_time_ns,
        seq,
        basis,
        rate,
        predicted_rate,
        interval_ns,
        next_funding_time_ns,
        settled,
        open_interest,
        exchange_time_ns,
        local_recv_ns,
    })
}

/// A funding update this node has just signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedFundingUpdate {
    update: FundingUpdate,
    payload: Vec<u8>,
    signature: Signature,
    signer: Address,
}

impl SignedFundingUpdate {
    /// Returns the update.
    #[must_use]
    pub const fn update(&self) -> &FundingUpdate {
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
            FRAME_TYPE_FUNDING_UPDATE,
            self.signer,
            &self.payload,
            self.signature,
        )
    }
}

impl Signer {
    /// Signs a funding update.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if the update cannot be encoded; see
    /// [`encode_funding_update`].
    ///
    /// # Panics
    ///
    /// See [`Signer::sign_digest`].
    pub fn sign_funding_update(
        &self,
        update: &FundingUpdate,
    ) -> Result<SignedFundingUpdate, WireError> {
        let payload = encode_funding_update(update)?;
        let signature = self.sign_payload(&payload);
        Ok(SignedFundingUpdate {
            update: update.clone(),
            payload,
            signature,
            signer: self.address(),
        })
    }
}

/// A structurally valid funding frame that has **not** been checked against a
/// registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedFundingFrame {
    raw: RawFrame,
}

impl UnverifiedFundingFrame {
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
            FRAME_TYPE_FUNDING_UPDATE,
            FIXED_SIZE + 1,
            MAX_FUNDING_PAYLOAD,
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
    /// Returns [`WireError`] if the payload is not a canonical funding update.
    pub fn decode_unverified(&self) -> Result<FundingUpdate, WireError> {
        decode_funding_update(&self.raw.payload)
    }

    /// Verifies the frame against a trusted registry. Freshness and the
    /// sequence are the consumer's job, as for a price frame.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError`] for malformed payloads and unknown signers.
    pub fn verify(
        &self,
        registry: &VerifiedRegistry,
    ) -> Result<VerifiedFundingUpdate, VerifyError> {
        let update = decode_funding_update(&self.raw.payload)?;
        let signer = self.raw.recover_signer()?;
        let node_index = registry.authorize(signer)?;
        Ok(VerifiedFundingUpdate {
            update,
            signer,
            node_index,
        })
    }
}

/// A funding update that a registered node provably signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFundingUpdate {
    update: FundingUpdate,
    signer: Address,
    node_index: usize,
}

impl VerifiedFundingUpdate {
    /// Returns the update.
    #[must_use]
    pub const fn update(&self) -> &FundingUpdate {
        &self.update
    }

    /// Consumes this wrapper and returns the update.
    #[must_use]
    pub fn into_update(self) -> FundingUpdate {
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
    use crate::encode_book_update;
    use crate::registry::{NodeEntry, Quorum, Registry};
    use oracle_types::BookUpdate;

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

    fn okx() -> FundingUpdate {
        FundingUpdate {
            venue: Venue::Okx,
            market: MarketKind::LinearPerp,
            symbol: "BTC-USDT-SWAP".to_owned(),
            publish_time_ns: 1_754_582_400_123_456_789,
            seq: 4,
            basis: FundingBasis::Interval,
            rate: -30_339_016,
            predicted_rate: None,
            interval_ns: Some(8 * 3_600 * 1_000_000_000),
            next_funding_time_ns: Some(1_754_582_400_000_000_000 + 3_600_000_000_000),
            settled: Some(SettledFunding {
                rate: 6_729_944,
                time_ns: 1_754_582_400_000_000_000 - 3_600_000_000_000,
            }),
            open_interest: None,
            exchange_time_ns: Some(1_754_582_400_100_000_000),
            local_recv_ns: 1_754_582_400_110_000_000,
        }
    }

    fn deribit() -> FundingUpdate {
        FundingUpdate {
            venue: Venue::Deribit,
            market: MarketKind::InversePerp,
            symbol: "BTC-PERPETUAL".to_owned(),
            basis: FundingBasis::EightHours,
            rate: 108_460_000,
            interval_ns: None,
            next_funding_time_ns: None,
            settled: None,
            open_interest: Some(OpenInterest {
                amount: 81_919_585_000_000_000,
                unit: OpenInterestUnit::Quote,
            }),
            ..okx()
        }
    }

    #[test]
    fn updates_round_trip_through_their_bytes() {
        for update in [okx(), deribit()] {
            let bytes = encode_funding_update(&update).expect("encodes");
            assert_eq!(bytes.len(), FIXED_SIZE + update.symbol.len());
            assert_eq!(decode_funding_update(&bytes), Ok(update));
        }
    }

    #[test]
    fn a_signed_frame_verifies_and_a_stranger_does_not() {
        let signed = node().sign_funding_update(&okx()).expect("signs");
        let frame = UnverifiedFundingFrame::parse(&signed.encode_frame()).expect("parses");
        assert_eq!(
            frame.verify(&registry()).expect("verifies").update(),
            &okx()
        );
        let stranger = Signer::from_secret_bytes([0x33; 32]).expect("valid key");
        let forged = stranger.sign_funding_update(&okx()).expect("signs");
        let frame = UnverifiedFundingFrame::parse(&forged.encode_frame()).expect("parses");
        assert!(frame.verify(&registry()).is_err());
    }

    #[test]
    fn non_canonical_updates_are_refused() {
        let bytes = encode_funding_update(&okx()).expect("encodes");
        let symbol_end = 5 + okx().symbol.len();
        let flags_at = symbol_end + 16;
        let predicted_at = flags_at + 3 + 8 + 8;
        let unit_at = flags_at + 2;

        // A value under a clear flag.
        let mut hidden = bytes.clone();
        if let Some(byte) = hidden.get_mut(predicted_at + 7) {
            *byte = 1;
        }
        assert_eq!(
            decode_funding_update(&hidden),
            Err(WireError::NonCanonical("a funding field without its flag"))
        );
        // A unit without open interest.
        let mut unit = bytes.clone();
        if let Some(byte) = unit.get_mut(unit_at) {
            *byte = 2;
        }
        assert!(decode_funding_update(&unit).is_err());
        // An unknown flag, and an unknown basis.
        let mut flag = bytes.clone();
        if let Some(byte) = flag.get_mut(flags_at) {
            *byte |= 1 << 7;
        }
        assert!(decode_funding_update(&flag).is_err());
        let mut basis = bytes.clone();
        if let Some(byte) = basis.get_mut(flags_at + 1) {
            *byte = 9;
        }
        assert!(decode_funding_update(&basis).is_err());

        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_funding_update(&trailing).is_err());
    }

    #[test]
    fn kinds_do_not_cross() {
        let funding = encode_funding_update(&okx()).expect("encodes");
        assert!(crate::decode_book_update(&funding).is_err());
        let book = BookUpdate {
            venue: Venue::Okx,
            market: MarketKind::LinearPerp,
            symbol: "BTC-USDT-SWAP".to_owned(),
            publish_time_ns: 1,
            seq: 1,
            snapshot: true,
            exchange_time_ns: None,
            local_recv_ns: 1,
            venue_seq: None,
            bids: Vec::new(),
            asks: Vec::new(),
        };
        let book = encode_book_update(&book).expect("encodes");
        assert!(decode_funding_update(&book).is_err());
    }
}
