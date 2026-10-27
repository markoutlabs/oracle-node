//! Signing rounds: each change publishes the document it changed, at once.

use std::cell::Cell;

use crate::certify::certify_documents;
use crate::runtime::{STATE, adopt_registry, now_secs, read_state};
use crate::signing::{ensure_governance_key, sign};
use crate::state::{State, StateError};

thread_local! {
    /// A signing round is in flight.
    static BUSY: Cell<bool> = const { Cell::new(false) };
}

/// The signed documents the canister publishes.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Document {
    Registry,
    Clients,
    Feeds,
}

/// Refuses a change while a signing round runs: the round's own checks read
/// the state it replaces, and so do those of `set_feeds` and `set_price_window`.
pub(crate) fn idle() -> Result<(), String> {
    if BUSY.get() {
        return Err("a signing round is in flight; retry shortly".to_owned());
    }
    Ok(())
}

/// Runs a mutation, then one signing round for `document`. Returns its new version.
///
/// The round works on a copy and commits only after the signature, so a failed
/// round changes nothing and governance retries the same call.
pub(crate) async fn mutate_and_publish(
    document: Document,
    mutation: impl FnOnce(&mut State) -> Result<(), StateError>,
) -> Result<u64, String> {
    idle()?;
    BUSY.set(true);
    let result = round(document, mutation).await;
    BUSY.set(false);
    result
}

async fn round(
    document: Document,
    mutation: impl FnOnce(&mut State) -> Result<(), StateError>,
) -> Result<u64, String> {
    let mut next = read_state(State::clone);
    mutation(&mut next).map_err(|error| error.to_string())?;
    // The first round caches the key in `STATE`; the copy must keep it too.
    next.set_governance_key(ensure_governance_key().await?);
    let now = now_secs();
    let version = match document {
        Document::Registry => {
            let unsigned = next
                .unsigned_document(now)
                .map_err(|error| error.to_string())?;
            let signature = sign(&unsigned.signing_bytes).await?;
            next.publish(unsigned, signature)
                .map_err(|error| error.to_string())?
        }
        Document::Clients => {
            let unsigned = next
                .unsigned_client_list(now)
                .map_err(|error| error.to_string())?;
            let signature = sign(&unsigned.signing_bytes).await?;
            next.publish_clients(unsigned, signature)
                .map_err(|error| error.to_string())?
        }
        Document::Feeds => {
            let unsigned = next
                .unsigned_feed_set(now)
                .map_err(|error| error.to_string())?;
            let signature = sign(&unsigned.signing_bytes).await?;
            next.publish_feeds(unsigned, signature)
                .map_err(|error| error.to_string())?
        }
    };
    STATE.with(|cell| *cell.borrow_mut() = Some(next));
    adopt_registry();
    certify_documents();
    Ok(version)
}
