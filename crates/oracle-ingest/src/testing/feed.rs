//! Recorded frames through one connection's decoder, with no session.

use oracle_types::{Fixed, MarketKind, ObsKind, Observation, Venue};

use crate::session::MessageHandler;
use crate::venues::{DecodeFn, VenueHandler};
use crate::{DecodeError, InstrumentMap, InstrumentSpec};

/// The receipt time that a [`Feed`] stamps, unless [`Feed::at`] sets another.
pub const RECV_NS: u64 = 1_754_582_400_500_000_000;

/// One connection's decoder, fed one payload at a time as the session does.
pub struct Feed {
    handler: Box<dyn MessageHandler>,
    recv_ns: u64,
}

/// What a replay decoded, and the errors that are not benign.
#[derive(Debug, Default)]
pub struct Replayed {
    /// Every observation, in order.
    pub observations: Vec<Observation>,
    /// Each error that is not benign, in order.
    pub errors: Vec<DecodeError>,
}

impl Feed {
    /// A feed through any handler, such as Binance's.
    #[must_use]
    pub fn new(handler: impl MessageHandler + 'static) -> Self {
        Self {
            handler: Box::new(handler),
            recv_ns: RECV_NS,
        }
    }

    /// A feed through a venue's decoder, over `instruments` of one market.
    ///
    /// # Panics
    ///
    /// Panics if the instruments do not make a map, such as a symbol twice.
    #[must_use]
    pub fn venue(
        decode: DecodeFn,
        venue: Venue,
        market: MarketKind,
        instruments: &[InstrumentSpec],
    ) -> Self {
        let map = InstrumentMap::new(venue, market, instruments).expect("a valid test map");
        Self::new(VenueHandler::new(map, decode))
    }

    /// Stamps each observation with `recv_ns`.
    #[must_use]
    pub const fn at(mut self, recv_ns: u64) -> Self {
        self.recv_ns = recv_ns;
        self
    }

    /// Decodes one payload.
    ///
    /// # Errors
    ///
    /// Returns what the decoder returns, and drops the observations decoded
    /// before the error. See [`Feed::halted`] for the ones a halt keeps.
    pub fn push(&mut self, payload: impl AsRef<[u8]>) -> Result<Vec<Observation>, DecodeError> {
        let (out, result) = self.sent(payload.as_ref());
        result.map(|()| out)
    }

    /// What the session sends for one payload, and the decoder's result. A
    /// halt keeps the observations decoded before it; any other error drops them.
    fn sent(&mut self, payload: &[u8]) -> (Vec<Observation>, Result<(), DecodeError>) {
        let mut out = Vec::new();
        let result = self.handler.on_payload(payload, self.recv_ns, &mut out);
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, DecodeError::Halted(_)))
        {
            out.clear();
        }
        (out, result)
    }

    /// Decodes a payload that must halt books, and gives the observations that
    /// stand with it and the venue symbol of each halted book.
    ///
    /// # Panics
    ///
    /// Panics unless the payload is [`DecodeError::Halted`].
    #[must_use]
    pub fn halted(&mut self, payload: impl AsRef<[u8]>) -> (Vec<Observation>, Vec<String>) {
        let payload = payload.as_ref();
        match self.sent(payload) {
            (out, Err(DecodeError::Halted(halted))) => {
                let symbols = halted.iter().map(|id| id.symbol.to_string()).collect();
                (out, symbols)
            }
            (_, other) => panic!(
                "no halt but {other:?} from {}",
                String::from_utf8_lossy(payload)
            ),
        }
    }

    /// Decodes a payload that must decode.
    ///
    /// # Panics
    ///
    /// Panics if the payload does not decode.
    #[must_use]
    pub fn decoded(&mut self, payload: impl AsRef<[u8]>) -> Vec<Observation> {
        let payload = payload.as_ref();
        self.push(payload).unwrap_or_else(|error| {
            panic!("{error}: {}", String::from_utf8_lossy(payload));
        })
    }

    /// Decodes a payload that must fail, and that pushes nothing as it fails.
    ///
    /// # Panics
    ///
    /// Panics if the payload decodes, or pushes an observation before its error.
    #[must_use]
    pub fn refused(&mut self, payload: impl AsRef<[u8]>) -> DecodeError {
        let payload = payload.as_ref();
        let text = String::from_utf8_lossy(payload);
        let mut out = Vec::new();
        match self.handler.on_payload(payload, self.recv_ns, &mut out) {
            Ok(()) => panic!("decoded {out:?} from {text}"),
            Err(error) => {
                assert!(
                    out.is_empty(),
                    "pushed {out:?} before `{error}` from {text}"
                );
                error
            }
        }
    }

    /// Decodes each payload, and keeps what came out and each error that is not benign.
    pub fn replay_all<P: AsRef<[u8]>>(
        &mut self,
        payloads: impl IntoIterator<Item = P>,
    ) -> Replayed {
        let mut replayed = Replayed::default();
        for payload in payloads {
            let (out, result) = self.sent(payload.as_ref());
            replayed.observations.extend(out);
            match result {
                Err(error) if !error.is_benign() => replayed.errors.push(error),
                _ => {}
            }
        }
        replayed
    }

    /// Decodes each payload, all of which must be data or benign.
    ///
    /// # Panics
    ///
    /// Panics at the first error that is not benign.
    pub fn replay<P: AsRef<[u8]>>(
        &mut self,
        payloads: impl IntoIterator<Item = P>,
    ) -> Vec<Observation> {
        let mut all = Vec::new();
        for payload in payloads {
            let payload = payload.as_ref();
            let (out, result) = self.sent(payload);
            all.extend(out);
            match result {
                Err(error) if !error.is_benign() => {
                    panic!("{error}: {}", String::from_utf8_lossy(payload))
                }
                _ => {}
            }
        }
        all
    }

    /// Starts a new connection: the handler drops every book.
    pub fn reconnect(&mut self) {
        self.handler.on_connect();
    }
}

/// An instrument of `market` for a test map. The canonical feed is a
/// placeholder: no decoder reads it.
///
/// # Panics
///
/// Cannot panic: the placeholder parses.
#[must_use]
pub fn instrument(symbol: &str, market: MarketKind) -> InstrumentSpec {
    InstrumentSpec::new(symbol, market, "CRYPTO.X/USD").expect("the placeholder parses")
}

/// `spec` with its contract size, for a venue that counts in contracts.
#[must_use]
pub fn contracts_of(spec: InstrumentSpec, contract_size: &str) -> InstrumentSpec {
    InstrumentSpec {
        contract_size: Some(fixed(contract_size)),
        ..spec
    }
}

/// A decimal from its text.
///
/// # Panics
///
/// Panics if the text is not a decimal.
#[must_use]
pub fn fixed(text: &str) -> Fixed {
    text.parse()
        .unwrap_or_else(|_| panic!("`{text}` is a decimal"))
}

/// The observations of one venue symbol and kind, in order.
#[must_use]
pub fn of<'a>(all: &'a [Observation], symbol: &str, kind: ObsKind) -> Vec<&'a Observation> {
    all.iter()
        .filter(|observation| &*observation.instrument.symbol == symbol && observation.kind == kind)
        .collect()
}

/// The kind of each observation, in order.
#[must_use]
pub fn kinds(all: &[Observation]) -> Vec<ObsKind> {
    all.iter().map(|observation| observation.kind).collect()
}
