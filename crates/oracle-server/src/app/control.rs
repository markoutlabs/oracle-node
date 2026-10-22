//! What a session asks for over its control channel: subscribe, unsubscribe
//! and ping.

use oracle_types::FeedId;
use tracing::debug;

use super::ServerState;
use crate::protocol::{ClientMessage, FIREHOSE, ServerMessage};

/// Applies one control message and returns the reply.
pub(super) fn handle_control(
    raw: &str,
    state: &ServerState,
    subscriber: &crate::hub::Subscriber,
) -> ServerMessage {
    let parsed: ClientMessage = match serde_json::from_str(raw) {
        Ok(parsed) => parsed,
        Err(error) => {
            debug!(%error, "malformed control message");
            return ServerMessage::error("bad_request", error.to_string());
        }
    };

    match parsed {
        ClientMessage::Subscribe {
            feeds,
            venues,
            books,
            funding,
        } => {
            let mut unknown = Vec::new();
            let (venues, venue_ids) = known(state, venues, &mut unknown);
            subscriber.add_venues(venue_ids);
            let (books, book_ids) = known(state, books, &mut unknown);
            let instruments = state.books_of(&book_ids);
            subscriber.add_books(instruments.iter().cloned());
            state.hub.replay_books(subscriber, &instruments);
            let funding = if funding.iter().any(|feed| feed == FIREHOSE) {
                subscriber.add_all_funding();
                vec![FIREHOSE.to_owned()]
            } else {
                let (funding, funding_ids) = known(state, funding, &mut unknown);
                subscriber.add_funding(state.perps_of(&funding_ids));
                funding
            };
            state.hub.replay_funding(subscriber);
            if feeds.iter().any(|feed| feed == FIREHOSE) {
                subscriber.select_firehose();
                return ServerMessage::SubscribeAck {
                    feeds: vec![FIREHOSE.to_owned()],
                    venues,
                    books,
                    funding,
                    unknown,
                };
            }
            let (feeds, ids) = known(state, feeds, &mut unknown);
            subscriber.add(ids);
            ServerMessage::SubscribeAck {
                feeds,
                venues,
                books,
                funding,
                unknown,
            }
        }
        ClientMessage::Unsubscribe {
            feeds,
            venues,
            books,
            funding,
        } => {
            let ids = |symbols: &[String]| -> Vec<FeedId> {
                symbols
                    .iter()
                    .filter_map(|feed| state.lookup(feed))
                    .collect()
            };
            subscriber.remove(ids(&feeds));
            subscriber.remove_venues(ids(&venues));
            subscriber.remove_books(&state.books_of(&ids(&books)));
            subscriber.remove_funding(
                &state.perps_of(&ids(&funding)),
                funding.iter().any(|feed| feed == FIREHOSE),
            );
            ServerMessage::UnsubscribeAck {
                feeds,
                venues,
                books,
                funding,
            }
        }
        ClientMessage::Ping { id } => ServerMessage::Pong { id },
    }
}

/// Splits symbols into those this node serves, with their ids, and the rest.
fn known(
    state: &ServerState,
    symbols: Vec<String>,
    unknown: &mut Vec<String>,
) -> (Vec<String>, Vec<FeedId>) {
    let mut known = Vec::new();
    let mut ids = Vec::new();
    for symbol in symbols {
        match state.lookup(&symbol) {
            Some(id) => {
                ids.push(id);
                known.push(symbol);
            }
            None => unknown.push(symbol),
        }
    }
    (known, ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tests::state;
    use crate::hub::Channel;

    #[test]
    fn subscribing_selects_known_feeds_and_reports_unknown_ones() {
        let state = state();
        let subscriber = state
            .hub()
            .subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        let json = serde_json::to_string(&handle_control(
            r#"{"op":"subscribe","feeds":["CRYPTO.BTC/USD","CRYPTO.DOGE/USD"]}"#,
            &state,
            &subscriber,
        ))
        .expect("serialises");
        assert!(json.contains("subscribe_ack"));
        assert!(
            json.contains("CRYPTO.DOGE/USD"),
            "unknown feeds must be reported: {json}"
        );

        assert!(subscriber.wants(
            Channel::Prices,
            state.lookup("CRYPTO.BTC/USD").expect("known")
        ));
        assert!(!subscriber.wants(
            Channel::Prices,
            state.lookup("CRYPTO.ETH/USD").expect("known")
        ));
    }

    #[test]
    fn venue_reports_are_subscribed_apart_from_prices() {
        let state = state();
        let subscriber = state
            .hub()
            .subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        let json = serde_json::to_string(&handle_control(
            r#"{"op":"subscribe","feeds":["*"],"venues":["CRYPTO.BTC/USD","CRYPTO.DOGE/USD"]}"#,
            &state,
            &subscriber,
        ))
        .expect("serialises");
        assert!(json.contains(r#""venues":["CRYPTO.BTC/USD"]"#), "{json}");
        assert!(json.contains("CRYPTO.DOGE/USD"), "{json}");
        let btc = state.lookup("CRYPTO.BTC/USD").expect("known");
        let eth = state.lookup("CRYPTO.ETH/USD").expect("known");
        assert!(subscriber.wants(Channel::Venues, btc));
        assert!(
            !subscriber.wants(Channel::Venues, eth),
            "the price firehose does not cover venue reports"
        );

        let _ = handle_control(
            r#"{"op":"unsubscribe","venues":["CRYPTO.BTC/USD"]}"#,
            &state,
            &subscriber,
        );
        assert!(!subscriber.wants(Channel::Venues, btc));
        assert!(subscriber.wants(Channel::Prices, btc));
    }

    #[test]
    fn the_firehose_selects_everything() {
        let state = state();
        let subscriber = state
            .hub()
            .subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        let _ = handle_control(r#"{"op":"subscribe","feeds":["*"]}"#, &state, &subscriber);
        assert!(subscriber.wants(
            Channel::Prices,
            state.lookup("CRYPTO.BTC/USD").expect("known")
        ));
        assert!(subscriber.wants(
            Channel::Prices,
            state.lookup("CRYPTO.ETH/USD").expect("known")
        ));
    }

    #[test]
    fn unsubscribing_removes_the_feed() {
        let state = state();
        let subscriber = state
            .hub()
            .subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        let _ = handle_control(
            r#"{"op":"subscribe","feeds":["CRYPTO.BTC/USD"]}"#,
            &state,
            &subscriber,
        );
        let _ = handle_control(
            r#"{"op":"unsubscribe","feeds":["CRYPTO.BTC/USD"]}"#,
            &state,
            &subscriber,
        );
        assert!(!subscriber.wants(
            Channel::Prices,
            state.lookup("CRYPTO.BTC/USD").expect("known")
        ));
    }

    #[test]
    fn a_ping_is_answered_with_its_id() {
        let state = state();
        let subscriber = state
            .hub()
            .subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        let json = serde_json::to_string(&handle_control(
            r#"{"op":"ping","id":99}"#,
            &state,
            &subscriber,
        ))
        .expect("serialises");
        assert!(json.contains(r#""op":"pong""#));
        assert!(json.contains(r#""id":99"#));
    }

    #[test]
    fn a_malformed_control_message_is_answered_not_fatal() {
        let state = state();
        let subscriber = state
            .hub()
            .subscribe(oracle_wire::Address::from_bytes([0xC1; 20]));
        let json = serde_json::to_string(&handle_control("{not json", &state, &subscriber))
            .expect("serialises");
        assert!(json.contains(r#""op":"error""#));
        assert!(json.contains("bad_request"));
    }
}
