//! The canonical 96-byte price update payload.
//!
//! This byte layout **is** the protocol. Everything else — JSON views, frame
//! wrappers, SDK types — is presentation. A signature commits to these 96 bytes
//! and nothing else, so a verifier must hash the bytes it received rather than
//! bytes it reconstructed from a decoded representation.

use oracle_types::{FeedId, Flags, PriceUpdate, Symbol, VenueSet};

use crate::WireError;
use crate::codec::{FixedBuf, Reader, Sink as _};
use crate::keccak::keccak256;

/// Protocol version carried in byte 0 of every payload.
pub const PAYLOAD_VERSION: u8 = 1;

/// Payload kind for a price update.
pub const KIND_PRICE_UPDATE: u8 = 0x01;

/// Payload kind for a venue report. `0x02` stays reserved for batched price
/// updates (SPEC §3.4).
pub const KIND_VENUE_REPORT: u8 = 0x03;

/// Payload kind for a node registry.
///
/// Control-plane kinds have the high bit set, so a data payload can never be
/// confused with one even though both share a digest function. `0x81` signed
/// the retired signing-key certificate and is never reused.
pub const KIND_REGISTRY: u8 = 0x82;

/// Payload kind for a client's transport authentication (SPEC §6.1).
pub const KIND_CLIENT_AUTH: u8 = 0x83;

/// Payload kind for a node's acceptance of a transport session.
pub const KIND_NODE_AUTH_OK: u8 = 0x84;

/// Payload kind for the client allow-list.
pub const KIND_CLIENT_LIST: u8 = 0x85;

/// Size of an encoded price update.
pub const PRICE_UPDATE_SIZE: usize = 96;

/// Derives a feed identifier from a canonical symbol.
///
/// `keccak256(canonical_symbol)`. Because [`Symbol`] cannot hold a non-canonical
/// value, any two implementations that agree on the symbol grammar necessarily
/// agree on every feed id, with no registry to coordinate.
///
/// # Examples
///
/// ```
/// use oracle_types::Symbol;
/// use oracle_wire::feed_id;
///
/// let symbol: Symbol = "CRYPTO.BTC/USD".parse()?;
/// // Same symbol, same id, on any machine, forever.
/// assert_eq!(feed_id(&symbol), feed_id(&"CRYPTO.BTC/USD".parse()?));
/// # Ok::<(), oracle_types::SymbolError>(())
/// ```
#[must_use]
pub fn feed_id(symbol: &Symbol) -> FeedId {
    FeedId::from_bytes(keccak256(symbol.canonical().as_bytes()))
}

/// Encodes a price update into its canonical 96 bytes.
///
/// # Panics
///
/// Cannot panic: the layout is fixed and totals exactly [`PRICE_UPDATE_SIZE`].
/// The assertion inside guards against the encoder and the constant drifting apart.
#[must_use]
pub fn encode_price_update(update: &PriceUpdate) -> [u8; PRICE_UPDATE_SIZE] {
    let mut buf = FixedBuf::<PRICE_UPDATE_SIZE>::new();
    buf.put_u8(PAYLOAD_VERSION); //  0
    buf.put_u8(KIND_PRICE_UPDATE); //  1
    buf.put_u16(update.flags.bits()); //  2
    buf.put_bytes(update.feed_id.as_bytes()); //  4
    buf.put_i64(update.price); // 36
    buf.put_u64(update.conf); // 44
    buf.put_i32(update.expo); // 52
    buf.put_u64(update.publish_time_ns); // 56
    buf.put_u64(update.observation_time_ns); // 64
    buf.put_u64(update.prev_publish_time_ns); // 72
    buf.put_u64(update.seq); // 80
    buf.put_u32(update.num_sources); // 88
    buf.put_u32(update.sources.bits()); // 92
    buf.finish()
}

/// Decodes a canonical price update payload.
///
/// # Errors
///
/// - [`WireError::Truncated`] or [`WireError::TrailingBytes`] if the input is
///   not exactly [`PRICE_UPDATE_SIZE`] bytes.
/// - [`WireError::UnsupportedVersion`] or [`WireError::UnexpectedKind`] if the
///   header does not describe a v1 price update.
/// - [`WireError::ReservedFlags`] or [`WireError::UnassignedVenueBits`] if the
///   payload sets bits this build does not understand. Both fail closed: a
///   verifier that silently dropped an unknown status bit would report a warning
///   it could not read as no warning at all.
pub fn decode_price_update(bytes: &[u8]) -> Result<PriceUpdate, WireError> {
    if bytes.len() < PRICE_UPDATE_SIZE {
        return Err(WireError::Truncated {
            expected: PRICE_UPDATE_SIZE,
            actual: bytes.len(),
        });
    }
    let mut reader = Reader::new(bytes);

    let version = reader.u8()?;
    if version != PAYLOAD_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }
    let kind = reader.u8()?;
    if kind != KIND_PRICE_UPDATE {
        return Err(WireError::UnexpectedKind {
            expected: KIND_PRICE_UPDATE,
            actual: kind,
        });
    }

    let flag_bits = reader.u16()?;
    let flags = Flags::from_bits(flag_bits).ok_or(WireError::ReservedFlags(flag_bits))?;
    let feed_id = FeedId::from_bytes(reader.array::<32>()?);
    let price = reader.i64()?;
    let conf = reader.u64()?;
    let expo = reader.i32()?;
    let publish_time_ns = reader.u64()?;
    let observation_time_ns = reader.u64()?;
    let prev_publish_time_ns = reader.u64()?;
    let seq = reader.u64()?;
    let num_sources = reader.u32()?;
    let source_bits = reader.u32()?;
    let sources = VenueSet::from_bits(source_bits)
        .map_err(|_| WireError::UnassignedVenueBits(source_bits))?;

    reader.finish()?;

    Ok(PriceUpdate {
        feed_id,
        flags,
        price,
        conf,
        expo,
        publish_time_ns,
        observation_time_ns,
        prev_publish_time_ns,
        seq,
        num_sources,
        sources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_types::Venue;

    fn sample() -> PriceUpdate {
        PriceUpdate {
            feed_id: feed_id(&"CRYPTO.BTC/USD".parse().expect("valid symbol")),
            flags: Flags::NONE,
            price: 6_431_250_000_000,
            conf: 3_200_000,
            expo: -8,
            publish_time_ns: 1_754_582_400_123_456_789,
            observation_time_ns: 1_754_582_400_121_000_000,
            prev_publish_time_ns: 1_754_582_399_123_456_789,
            seq: 918_273,
            num_sources: 3,
            sources: [Venue::Binance, Venue::Coinbase, Venue::Kraken]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn encoding_is_exactly_the_declared_size() {
        assert_eq!(encode_price_update(&sample()).len(), PRICE_UPDATE_SIZE);
    }

    #[test]
    fn header_bytes_are_where_the_spec_says() {
        let bytes = encode_price_update(&sample());
        assert_eq!(bytes.first(), Some(&PAYLOAD_VERSION));
        assert_eq!(bytes.get(1), Some(&KIND_PRICE_UPDATE));
        assert_eq!(
            bytes.get(4..36),
            Some(sample().feed_id.as_bytes().as_slice())
        );
    }

    #[test]
    fn round_trips() {
        let update = sample();
        assert_eq!(
            decode_price_update(&encode_price_update(&update)).expect("valid"),
            update
        );
    }

    #[test]
    fn round_trips_with_flags_and_extremes() {
        let mut update = sample();
        update.flags = Flags::HALTED | Flags::DEGRADED | Flags::SYNTHETIC_QUOTE;
        update.price = i64::MIN;
        update.conf = u64::MAX;
        update.expo = i32::MIN;
        update.seq = u64::MAX;
        update.num_sources = u32::MAX;
        assert_eq!(
            decode_price_update(&encode_price_update(&update)).expect("valid"),
            update
        );
    }

    #[test]
    fn rejects_wrong_length() {
        let bytes = encode_price_update(&sample());
        assert!(matches!(
            decode_price_update(&bytes[..95]),
            Err(WireError::Truncated {
                expected: 96,
                actual: 95
            })
        ));
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(decode_price_update(&long), Err(WireError::TrailingBytes(1)));
    }

    #[test]
    fn rejects_wrong_version_and_kind() {
        let mut bytes = encode_price_update(&sample());
        bytes[0] = 2;
        assert_eq!(
            decode_price_update(&bytes),
            Err(WireError::UnsupportedVersion(2))
        );

        let mut bytes = encode_price_update(&sample());
        bytes[1] = KIND_REGISTRY;
        assert_eq!(
            decode_price_update(&bytes),
            Err(WireError::UnexpectedKind {
                expected: KIND_PRICE_UPDATE,
                actual: KIND_REGISTRY
            })
        );
    }

    #[test]
    fn rejects_unknown_flag_and_venue_bits() {
        let mut bytes = encode_price_update(&sample());
        bytes[3] = 0x08; // a reserved flag bit
        assert!(matches!(
            decode_price_update(&bytes),
            Err(WireError::ReservedFlags(0x0008))
        ));

        let mut bytes = encode_price_update(&sample());
        bytes[92] = 0x80; // a venue bit with no assigned venue
        assert!(matches!(
            decode_price_update(&bytes),
            Err(WireError::UnassignedVenueBits(_))
        ));
    }

    #[test]
    fn feed_ids_differ_by_symbol_and_kind() {
        let spot = feed_id(&"CRYPTO.BTC/USD".parse().expect("valid"));
        let mark = feed_id(&"CRYPTO.BTC/USD.PERP_MARK".parse().expect("valid"));
        let eth = feed_id(&"CRYPTO.ETH/USD".parse().expect("valid"));
        assert_ne!(spot, mark);
        assert_ne!(spot, eth);
    }

    /// Any single-bit change to the payload must produce different bytes, so no
    /// two distinct updates can ever share a signature.
    #[test]
    fn every_field_is_covered_by_the_encoding() {
        let base = encode_price_update(&sample());
        let mut mutations: Vec<PriceUpdate> = Vec::new();
        let field_mutators: [fn(&mut PriceUpdate); 11] = [
            |u| u.flags = Flags::HALTED,
            |u| u.feed_id = FeedId::from_bytes([0xEE; 32]),
            |u| u.price = u.price.wrapping_add(1),
            |u| u.conf = u.conf.wrapping_add(1),
            |u| u.expo = u.expo.wrapping_add(1),
            |u| u.publish_time_ns = u.publish_time_ns.wrapping_add(1),
            |u| u.observation_time_ns = u.observation_time_ns.wrapping_add(1),
            |u| u.prev_publish_time_ns = u.prev_publish_time_ns.wrapping_add(1),
            |u| u.seq = u.seq.wrapping_add(1),
            |u| u.num_sources = u.num_sources.wrapping_add(1),
            |u| u.sources = u.sources.with(Venue::Bybit),
        ];
        for mutate in field_mutators {
            let mut update = sample();
            mutate(&mut update);
            mutations.push(update);
        }
        for update in mutations {
            assert_ne!(
                encode_price_update(&update),
                base,
                "field not covered: {update:?}"
            );
        }
    }
}
