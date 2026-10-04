//! Subscriber control messages, carried sealed on the control channel.

use serde::{Deserialize, Serialize};

/// The wildcard feed selector.
pub const FIREHOSE: &str = "*";

/// A message from a subscriber.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ClientMessage {
    /// Subscribe to feeds. `["*"]` requests the firehose.
    Subscribe {
        /// Canonical symbols.
        feeds: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_parses() {
        let parsed: ClientMessage =
            serde_json::from_str(r#"{"op":"subscribe","feeds":["CRYPTO.BTC/USD"]}"#)
                .expect("parses");
        assert_eq!(
            parsed,
            ClientMessage::Subscribe {
                feeds: vec!["CRYPTO.BTC/USD".to_owned()],
            }
        );
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
    fn server_messages_serialize_with_an_op_tag() {
        let ack = ServerMessage::SubscribeAck {
            feeds: vec!["CRYPTO.BTC/USD".to_owned()],
            unknown: vec![],
        };
        let json = serde_json::to_string(&ack).expect("serializes");
        assert!(json.contains(r#""op":"subscribe_ack""#), "got {json}");
    }
}
