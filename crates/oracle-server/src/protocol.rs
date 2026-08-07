//! Subscriber wire protocol: control messages and the JSON data view.

use oracle_types::{PriceUpdate, Symbol};
use oracle_wire::{Address, SignedUpdate};
use serde::{Deserialize, Serialize};

/// The wildcard feed selector.
pub const FIREHOSE: &str = "*";

/// How a subscriber wants data frames.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    /// The canonical 182-byte frame. Fewer bytes, and nothing to misparse.
    #[default]
    Binary,
    /// A JSON view. Convenient, and easy to verify incorrectly — see
    /// [`JsonUpdate`].
    Json,
}

/// A message from a subscriber.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ClientMessage {
    /// Subscribe to feeds. `["*"]` requests the firehose.
    Subscribe {
        /// Canonical symbols.
        feeds: Vec<String>,
        /// Frame encoding; binary if omitted.
        #[serde(default)]
        encoding: Option<Encoding>,
    },
    /// Stop receiving the listed feeds.
    Unsubscribe {
        /// Canonical symbols.
        feeds: Vec<String>,
    },
    /// Liveness check.
    Ping {
        /// Echoed back in the reply.
        #[serde(default)]
        id: Option<u64>,
    },
}

/// A control message from the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ServerMessage {
    /// Subscription result. `unknown` lists symbols this node does not serve.
    SubscribeAck {
        /// Accepted symbols.
        feeds: Vec<String>,
        /// Symbols this node does not serve.
        unknown: Vec<String>,
    },
    /// Unsubscription result.
    UnsubscribeAck {
        /// Removed symbols.
        feeds: Vec<String>,
    },
    /// Reply to a ping.
    Pong {
        /// The id from the ping.
        id: Option<u64>,
    },
    /// The subscriber fell behind and is being disconnected.
    ///
    /// Sent rather than silently dropping data: a consumer that quietly misses
    /// updates has no way to know its prices went stale.
    Lagged {
        /// Updates conflated away while the subscriber was behind.
        dropped: u64,
    },
    /// A request was rejected.
    Error {
        /// Machine-readable code.
        code: String,
        /// Human-readable detail.
        message: String,
    },
}

impl ServerMessage {
    /// Builds an error message.
    #[must_use]
    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Self::Error {
            code: code.to_owned(),
            message: message.into(),
        }
    }
}

/// The JSON view of a price update.
///
/// # This is a convenience view, not the protocol
///
/// The signature commits to `payload` and to nothing else. A client that
/// reconstructs bytes from the decoded fields and hashes those will eventually
/// hit a mismatch, "fix" it by skipping verification, and end up trusting
/// whatever arrives. Verify `payload`.
///
/// Every 64-bit field crosses as a **string**. JSON numbers are IEEE-754 doubles
/// in most consumers, and a nanosecond timestamp is around `1.75e18` — far past
/// the `2^53` where doubles stop being exact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JsonUpdate {
    /// Always `price_update`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// Canonical symbol.
    pub feed: String,
    /// Feed id, `0x`-hex.
    pub feed_id: String,
    /// Price mantissa, as a string.
    pub price: String,
    /// Confidence mantissa, as a string.
    pub conf: String,
    /// Decimal exponent for both.
    pub expo: i32,
    /// Publish time in unix nanoseconds, as a string.
    pub publish_time_ns: String,
    /// Freshest contributing observation, as a string.
    pub observation_time_ns: String,
    /// This node's previous publish time, as a string.
    pub prev_publish_time_ns: String,
    /// Monotonic sequence, as a string.
    pub seq: String,
    /// Contributing venue count. A claim, not a proof.
    pub num_sources: u32,
    /// Status bits.
    pub flags: u16,
    /// Signing address, `0x`-hex. Recovered from `signature`, not trusted from here.
    pub signer: String,
    /// The signed bytes, `0x`-hex. **This is what the signature covers.**
    pub payload: String,
    /// The signature, `0x`-hex.
    pub signature: String,
}

impl JsonUpdate {
    /// Builds the JSON view of a signed update.
    #[must_use]
    pub fn new(symbol: &Symbol, signed: &SignedUpdate) -> Self {
        let update: &PriceUpdate = signed.update();
        Self {
            kind: "price_update",
            feed: symbol.to_string(),
            feed_id: update.feed_id.to_string(),
            price: update.price.to_string(),
            conf: update.conf.to_string(),
            expo: update.expo,
            publish_time_ns: update.publish_time_ns.to_string(),
            observation_time_ns: update.observation_time_ns.to_string(),
            prev_publish_time_ns: update.prev_publish_time_ns.to_string(),
            seq: update.seq.to_string(),
            num_sources: update.num_sources,
            flags: update.flags.bits(),
            signer: signed.signer().to_string(),
            payload: format!("0x{}", hex::encode(signed.payload())),
            signature: signed.signature().to_string(),
        }
    }

    /// Returns the signer address as typed bytes.
    ///
    /// # Errors
    ///
    /// Returns the parse error if the field is malformed.
    pub fn signer_address(&self) -> Result<Address, oracle_wire::WireError> {
        self.signer.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_types::{FeedId, Flags, Venue, VenueSet};
    use oracle_wire::Signer;

    fn signed() -> SignedUpdate {
        let signer = Signer::from_secret_bytes([5; 32]).expect("valid key");
        signer.sign_update(&PriceUpdate {
            feed_id: FeedId::from_bytes([7; 32]),
            flags: Flags::DEGRADED,
            price: 6_400_000_000_000,
            conf: 50_000_000,
            expo: -8,
            publish_time_ns: 1_754_582_400_123_456_789,
            observation_time_ns: 1_754_582_400_120_000_000,
            prev_publish_time_ns: 1_754_582_399_123_456_789,
            seq: 42,
            num_sources: 5,
            sources: Venue::ALL.into_iter().collect::<VenueSet>(),
        })
    }

    #[test]
    fn subscribe_parses_with_and_without_an_encoding() {
        let plain: ClientMessage =
            serde_json::from_str(r#"{"op":"subscribe","feeds":["CRYPTO.BTC/USD"]}"#)
                .expect("parses");
        assert_eq!(
            plain,
            ClientMessage::Subscribe {
                feeds: vec!["CRYPTO.BTC/USD".to_owned()],
                encoding: None
            }
        );

        let explicit: ClientMessage = serde_json::from_str(
            r#"{"op":"subscribe","feeds":["CRYPTO.BTC/USD"],"encoding":"json"}"#,
        )
        .expect("parses");
        assert!(matches!(
            explicit,
            ClientMessage::Subscribe {
                encoding: Some(Encoding::Json),
                ..
            }
        ));
    }

    #[test]
    fn unsubscribe_and_ping_parse() {
        assert_eq!(
            serde_json::from_str::<ClientMessage>(r#"{"op":"unsubscribe","feeds":["A.B/C"]}"#)
                .expect("parses"),
            ClientMessage::Unsubscribe {
                feeds: vec!["A.B/C".to_owned()]
            }
        );
        assert_eq!(
            serde_json::from_str::<ClientMessage>(r#"{"op":"ping","id":7}"#).expect("parses"),
            ClientMessage::Ping { id: Some(7) }
        );
        assert_eq!(
            serde_json::from_str::<ClientMessage>(r#"{"op":"ping"}"#).expect("parses"),
            ClientMessage::Ping { id: None }
        );
    }

    #[test]
    fn unknown_operations_are_refused() {
        assert!(serde_json::from_str::<ClientMessage>(r#"{"op":"drop_tables"}"#).is_err());
        assert!(serde_json::from_str::<ClientMessage>("not json").is_err());
    }

    #[test]
    fn json_updates_carry_every_64_bit_field_as_a_string() {
        let symbol: Symbol = "CRYPTO.BTC/USD".parse().expect("valid");
        let view = JsonUpdate::new(&symbol, &signed());
        let value = serde_json::to_value(&view).expect("serializes");

        for field in [
            "price",
            "conf",
            "publish_time_ns",
            "observation_time_ns",
            "prev_publish_time_ns",
            "seq",
        ] {
            assert!(
                value.get(field).is_some_and(serde_json::Value::is_string),
                "{field} must be a string, not a JSON number"
            );
        }
        // The value that actually exceeds 2^53 and would be mangled.
        assert_eq!(
            value.get("publish_time_ns"),
            Some(&"1754582400123456789".into())
        );
        assert!(value.get("expo").is_some_and(serde_json::Value::is_number));
    }

    /// The JSON view must let a client verify the real bytes, not a
    /// reconstruction of them.
    #[test]
    fn the_json_payload_field_is_the_signed_bytes() {
        let symbol: Symbol = "CRYPTO.BTC/USD".parse().expect("valid");
        let signed = signed();
        let view = JsonUpdate::new(&symbol, &signed);

        let decoded = hex::decode(view.payload.trim_start_matches("0x")).expect("valid hex");
        assert_eq!(decoded, signed.payload().as_slice());

        let recovered =
            oracle_wire::recover_payload_signer(&decoded, &view.signature.parse().expect("valid"))
                .expect("recovers");
        assert_eq!(recovered, signed.signer());
        assert_eq!(view.signer_address().expect("valid"), signed.signer());
    }

    #[test]
    fn server_messages_serialize_with_an_op_tag() {
        let ack = ServerMessage::SubscribeAck {
            feeds: vec!["CRYPTO.BTC/USD".to_owned()],
            unknown: vec![],
        };
        let json = serde_json::to_string(&ack).expect("serializes");
        assert!(json.contains(r#""op":"subscribe_ack""#), "got {json}");

        let lagged =
            serde_json::to_string(&ServerMessage::Lagged { dropped: 17 }).expect("serializes");
        assert!(lagged.contains(r#""op":"lagged""#));
        assert!(lagged.contains(r#""dropped":17"#));
    }
}
