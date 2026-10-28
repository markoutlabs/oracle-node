//! The network's feed set: every feed the nodes serve, and the venues each one
//! is built from.
//!
//! Governance signs it with the same key as the [`Registry`](crate::Registry),
//! under its own kind byte. Nodes and the web proxy verify it against the
//! governance address that they already pin (SPEC §3.8).

mod content;
mod slots;

use oracle_types::MAX_VENUE_ENTRIES;
use serde::{Deserialize, Serialize};

use crate::codec::Sink as _;
use crate::payload::{KIND_FEED_SET, PAYLOAD_VERSION};
use crate::registry::check_governance;
use crate::{Address, Signature, Signer, VerifyError, WireError};

pub use content::FeedContent;
pub use slots::{SLOT_LEAD_SECS, SLOT_SECS, Slots};

/// Maximum feeds in one set.
pub const MAX_FEEDS: usize = 4096;

/// Maximum bytes of one text field, such as a symbol or a decimal.
pub const MAX_FEED_FIELD_LEN: usize = 128;

/// Maximum observation kinds of one source.
pub const MAX_SOURCE_KINDS: usize = 8;

/// One feed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedSettings {
    /// Canonical symbol.
    pub symbol: String,
    /// The peg feed converted sources are priced through, such as `CRYPTO.USDT/USD`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peg: Option<String>,
    /// Peg confidence above which this feed degrades, in basis points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_peg_conf_bps: Option<String>,
    /// Surviving venues required before the feed publishes a usable price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_sources: Option<u32>,
    /// Publish on a move of at least this many basis points, as a decimal string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deviation_bps: Option<String>,
    /// Never publish more often than this, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_interval_ms: Option<u64>,
    /// Drop a venue whose newest data is older than this, in milliseconds. A
    /// quiet book, such as a stablecoin pair, can stay unchanged far longer
    /// than the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_ms: Option<u64>,
    /// Price each venue at the average fill for this notional, in quote units,
    /// from depth snapshots, as a decimal string. Subscribes to depth where the
    /// venue offers it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact_notional: Option<String>,
    /// Halts outside `[low, high]` times the slow reference price, as decimal strings; 0.5 to 2 by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanity_band: Option<[String; 2]>,
    /// Contributing venues.
    pub sources: Vec<SourceSettings>,
}

/// One venue's contribution to a feed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSettings {
    /// Venue name, as in `oracle_types::Venue`.
    pub venue: String,
    /// `spot` or `linear_perp`.
    pub market: String,
    /// The venue's own symbol.
    pub symbol: String,
    /// Observation kinds in preference order; `["book_top", "trade"]` by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    /// Static trust weight as a decimal string; `1` by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<String>,

    /// This source is quoted in the feed's peg asset and must be converted.
    ///
    /// Set on every USDT-quoted source of a `/USD` feed. Publishing those
    /// unconverted is a lie that costs money the day the peg breaks — and a
    /// silent one, because on an ordinary day the two agree to a basis point.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub converted: bool,
    /// Base units per contract, as a decimal string, for a venue that sizes in
    /// contracts: OKX swaps (`ctVal` on OKX's instruments endpoint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_size: Option<String>,
}

/// The push pace that governance sets for every node, since each push costs the canister cycles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushPolicy {
    /// Seconds after which a feed is pushed even when its price did not move.
    pub heartbeat_secs: u64,
    /// A price move this large since the last push, in basis points, pushes the feed at once.
    pub deviation_bps: u32,
    /// Seconds between two pushes, at least.
    pub min_interval_secs: u64,
}

impl PushPolicy {
    /// The longest heartbeat, so that the price window holds two of them.
    pub const MAX_HEARTBEAT_SECS: u64 = 60;

    /// The shortest price window for a heartbeat: a quiet feed must count for two heartbeats.
    #[must_use]
    pub const fn min_window_secs(heartbeat_secs: u64) -> u64 {
        heartbeat_secs.saturating_mul(2)
    }

    /// Checks the heartbeat, the minimum interval and the deviation against their ranges.
    ///
    /// # Errors
    ///
    /// Returns which rule the pace breaks.
    pub fn check(self) -> Result<Self, String> {
        if self.heartbeat_secs == 0 || self.heartbeat_secs > Self::MAX_HEARTBEAT_SECS {
            return Err(format!(
                "heartbeat_secs must be 1 to {}",
                Self::MAX_HEARTBEAT_SECS
            ));
        }
        if self.min_interval_secs == 0 || self.min_interval_secs > self.heartbeat_secs {
            return Err("min_interval_secs must be 1 to heartbeat_secs".to_owned());
        }
        if self.deviation_bps == 0 {
            return Err("deviation_bps must be above zero".to_owned());
        }
        Ok(self)
    }
}

/// A governance-signed feed set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedSet {
    /// Monotonic version. Readers reject anything not strictly newer.
    pub version: u64,
    /// Issue time, unix seconds. The nodes' change slots count from it.
    pub effective_from: u64,
    /// The oldest node version that can serve every feed, such as `0.1.0`; empty for any.
    pub min_node_version: String,
    /// The push pace. `None`: each node's own `[publish]` settings.
    pub push: Option<PushPolicy>,
    /// The feeds, in the order the nodes report them.
    pub feeds: Vec<FeedSettings>,
    /// Governance signature over the canonical encoding.
    pub governance_signature: Signature,
}

fn put_opt_str(
    out: &mut Vec<u8>,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), WireError> {
    match value {
        None => out.put_u8(0),
        Some(text) => {
            out.put_u8(1);
            out.try_put_str(field, text, MAX_FEED_FIELD_LEN)?;
        }
    }
    Ok(())
}

fn put_opt_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => out.put_u8(0),
        Some(number) => {
            out.put_u8(1);
            out.put_u64(number);
        }
    }
}

fn count<T>(field: &'static str, items: &[T], limit: usize) -> Result<u16, WireError> {
    let too_many = || WireError::FieldTooLong {
        field,
        actual: items.len(),
        limit,
    };
    if items.len() > limit {
        return Err(too_many());
    }
    u16::try_from(items.len()).map_err(|_| too_many())
}

fn put_source(out: &mut Vec<u8>, source: &SourceSettings) -> Result<(), WireError> {
    out.try_put_str("venue", &source.venue, MAX_FEED_FIELD_LEN)?;
    out.try_put_str("market", &source.market, MAX_FEED_FIELD_LEN)?;
    out.try_put_str("source symbol", &source.symbol, MAX_FEED_FIELD_LEN)?;
    match &source.kinds {
        None => out.put_u8(0),
        Some(kinds) => {
            out.put_u8(1);
            out.put_u16(count("kinds", kinds, MAX_SOURCE_KINDS)?);
            for kind in kinds {
                out.try_put_str("kind", kind, MAX_FEED_FIELD_LEN)?;
            }
        }
    }
    put_opt_str(out, "weight", source.weight.as_deref())?;
    out.put_u8(u8::from(source.converted));
    put_opt_str(out, "contract_size", source.contract_size.as_deref())
}

fn put_feed(out: &mut Vec<u8>, feed: &FeedSettings) -> Result<(), WireError> {
    out.try_put_str("symbol", &feed.symbol, MAX_FEED_FIELD_LEN)?;
    put_opt_str(out, "peg", feed.peg.as_deref())?;
    put_opt_str(out, "max_peg_conf_bps", feed.max_peg_conf_bps.as_deref())?;
    put_opt_u64(out, feed.min_sources.map(u64::from));
    put_opt_str(out, "deviation_bps", feed.deviation_bps.as_deref())?;
    put_opt_u64(out, feed.min_interval_ms);
    put_opt_u64(out, feed.max_age_ms);
    put_opt_str(out, "impact_notional", feed.impact_notional.as_deref())?;
    match &feed.sanity_band {
        None => out.put_u8(0),
        Some([low, high]) => {
            out.put_u8(1);
            out.try_put_str("sanity_band", low, MAX_FEED_FIELD_LEN)?;
            out.try_put_str("sanity_band", high, MAX_FEED_FIELD_LEN)?;
        }
    }
    out.put_u16(count("sources", &feed.sources, MAX_VENUE_ENTRIES)?);
    for source in &feed.sources {
        put_source(out, source)?;
    }
    Ok(())
}

impl FeedSet {
    /// Builds the canonical bytes the governance key signs, with feeds and sources in report order.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::FieldTooLong`] if any field exceeds its cap.
    pub fn signing_bytes(
        version: u64,
        effective_from: u64,
        min_node_version: &str,
        push: Option<PushPolicy>,
        feeds: &[FeedSettings],
    ) -> Result<Vec<u8>, WireError> {
        let too_many = || WireError::FieldTooLong {
            field: "feeds",
            actual: feeds.len(),
            limit: MAX_FEEDS,
        };
        if feeds.len() > MAX_FEEDS {
            return Err(too_many());
        }
        let mut out = Vec::with_capacity(64 + feeds.len() * 512);
        out.put_u8(PAYLOAD_VERSION);
        out.put_u8(KIND_FEED_SET);
        out.put_u64(version);
        out.put_u64(effective_from);
        out.try_put_str("min_node_version", min_node_version, MAX_FEED_FIELD_LEN)?;
        match push {
            None => out.put_u8(0),
            Some(policy) => {
                out.put_u8(1);
                out.put_u64(policy.heartbeat_secs);
                out.put_u32(policy.deviation_bps);
                out.put_u64(policy.min_interval_secs);
            }
        }
        out.put_u32(u32::try_from(feeds.len()).map_err(|_| too_many())?);
        for feed in feeds {
            put_feed(&mut out, feed)?;
        }
        Ok(out)
    }

    /// Assembles and signs a feed set.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if any field exceeds its cap.
    pub fn sign(
        governance: &Signer,
        version: u64,
        effective_from: u64,
        min_node_version: String,
        push: Option<PushPolicy>,
        feeds: Vec<FeedSettings>,
    ) -> Result<Self, WireError> {
        let bytes = Self::signing_bytes(version, effective_from, &min_node_version, push, &feeds)?;
        Ok(Self {
            version,
            effective_from,
            min_node_version,
            push,
            feeds,
            governance_signature: governance.sign_payload(&bytes),
        })
    }

    /// Returns this set's canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if any field exceeds its cap.
    pub fn to_signing_bytes(&self) -> Result<Vec<u8>, WireError> {
        Self::signing_bytes(
            self.version,
            self.effective_from,
            &self.min_node_version,
            self.push,
            &self.feeds,
        )
    }

    /// Verifies the set against a pinned governance address and a version floor.
    ///
    /// # Errors
    ///
    /// - [`VerifyError::StaleFeedSet`] if `version` is not above `min_version`.
    /// - [`VerifyError::UntrustedGovernance`] if the signature is not the pinned key's.
    /// - [`VerifyError::MalformedFeedSet`] for content that [`FeedContent::canonical`] refuses.
    pub fn verify(
        &self,
        governance: Address,
        min_version: u64,
    ) -> Result<VerifiedFeedSet, VerifyError> {
        if self.version <= min_version {
            return Err(VerifyError::StaleFeedSet {
                found: self.version,
                minimum: min_version,
            });
        }
        check_governance(
            &self.to_signing_bytes()?,
            &self.governance_signature,
            governance,
        )?;
        content::check(&self.min_node_version, self.push, &self.feeds)
            .map_err(VerifyError::MalformedFeedSet)?;
        Ok(VerifiedFeedSet { set: self.clone() })
    }
}

/// A feed set whose governance signature and structure have been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFeedSet {
    set: FeedSet,
}

impl VerifiedFeedSet {
    /// Returns the version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.set.version
    }

    /// Returns the issue time, unix seconds.
    #[must_use]
    pub const fn effective_from(&self) -> u64 {
        self.set.effective_from
    }

    /// Returns the oldest node version that can serve every feed; empty for any.
    #[must_use]
    pub fn min_node_version(&self) -> &str {
        &self.set.min_node_version
    }

    /// Whether a node of `node_version`, such as `0.1.0`, can serve this set; an unparsable version cannot.
    #[must_use]
    pub fn serves(&self, node_version: &str) -> bool {
        if self.set.min_node_version.is_empty() {
            return true;
        }
        match (
            semver::Version::parse(node_version),
            semver::Version::parse(&self.set.min_node_version),
        ) {
            (Ok(node), Ok(minimum)) => node >= minimum,
            _ => false,
        }
    }

    /// Returns the push pace, if governance set one.
    #[must_use]
    pub const fn push(&self) -> Option<PushPolicy> {
        self.set.push
    }

    /// Returns the feeds.
    #[must_use]
    pub fn feeds(&self) -> &[FeedSettings] {
        &self.set.feeds
    }

    /// Returns the underlying set.
    #[must_use]
    pub const fn as_feed_set(&self) -> &FeedSet {
        &self.set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_754_582_400;

    fn governance() -> Signer {
        Signer::from_secret_bytes([0xC0; 32]).expect("valid key")
    }

    fn source(venue: &str, symbol: &str) -> SourceSettings {
        SourceSettings {
            venue: venue.to_owned(),
            market: "spot".to_owned(),
            symbol: symbol.to_owned(),
            ..SourceSettings::default()
        }
    }

    fn feed(symbol: &str) -> FeedSettings {
        FeedSettings {
            symbol: symbol.to_owned(),
            min_sources: Some(2),
            sources: vec![source("binance", "ETHBTC"), source("okx", "ETH-BTC")],
            ..FeedSettings::default()
        }
    }

    const PUSH: PushPolicy = PushPolicy {
        heartbeat_secs: 7,
        deviation_bps: 10,
        min_interval_secs: 5,
    };

    fn set(version: u64, feeds: Vec<FeedSettings>) -> FeedSet {
        FeedSet::sign(
            &governance(),
            version,
            NOW,
            "0.1.0".to_owned(),
            Some(PUSH),
            feeds,
        )
        .expect("signs")
    }

    #[test]
    fn a_signed_set_verifies_and_round_trips_through_json() {
        let signed = set(1, vec![feed("CRYPTO.ETH/BTC"), feed("CRYPTO.SOL/BTC")]);
        let json = serde_json::to_string(&signed).expect("serialises");
        // An absent setting stays out of the document.
        assert!(!json.contains("converted"), "{json}");
        let parsed: FeedSet = serde_json::from_str(&json).expect("parses");
        let verified = parsed.verify(governance().address(), 0).expect("verifies");
        assert_eq!(verified.version(), 1);
        assert_eq!(verified.push(), Some(PUSH));
        assert_eq!(verified.min_node_version(), "0.1.0");
        assert_eq!(verified.feeds().len(), 2);
    }

    #[test]
    fn every_field_is_covered_by_the_signature() {
        let mut base = feed("CRYPTO.ETH/BTC");
        base.peg = Some("CRYPTO.USDT/USD".to_owned());
        base.max_peg_conf_bps = Some("50".to_owned());
        base.deviation_bps = Some("1".to_owned());
        base.min_interval_ms = Some(100);
        base.max_age_ms = Some(2_000);
        base.impact_notional = Some("20000".to_owned());
        if let Some(first) = base.sources.first_mut() {
            first.kinds = Some(vec!["book_top".to_owned()]);
            first.weight = Some("2".to_owned());
            first.contract_size = Some("0.01".to_owned());
        }
        let signed = set(2, vec![base, feed("CRYPTO.USDT/USD")]);
        let gov = governance().address();
        signed.verify(gov, 0).expect("verifies");
        let tampers: Vec<fn(&mut FeedSet)> = vec![
            |s| s.effective_from += 1,
            |s| s.min_node_version = "0.2.0".to_owned(),
            |s| s.push = None,
            |s| {
                s.feeds
                    .iter_mut()
                    .for_each(|f| f.symbol = "CRYPTO.ETH/USD".to_owned())
            },
            |s| s.feeds.iter_mut().for_each(|f| f.peg = None),
            |s| s.feeds.iter_mut().for_each(|f| f.max_peg_conf_bps = None),
            |s| s.feeds.iter_mut().for_each(|f| f.min_sources = Some(1)),
            |s| {
                s.feeds
                    .iter_mut()
                    .for_each(|f| f.deviation_bps = Some("2".to_owned()))
            },
            |s| s.feeds.iter_mut().for_each(|f| f.min_interval_ms = None),
            |s| s.feeds.iter_mut().for_each(|f| f.max_age_ms = Some(1)),
            |s| s.feeds.iter_mut().for_each(|f| f.impact_notional = None),
            |s| s.feeds.iter_mut().for_each(|f| f.sources.reverse()),
            |s| {
                s.feeds
                    .iter_mut()
                    .for_each(|f| f.sources.iter_mut().for_each(|x| x.converted = true))
            },
            |s| {
                s.feeds
                    .iter_mut()
                    .for_each(|f| f.sources.iter_mut().for_each(|x| x.kinds = None))
            },
            |s| {
                s.feeds
                    .iter_mut()
                    .for_each(|f| f.sources.iter_mut().for_each(|x| x.weight = None))
            },
            |s| {
                s.feeds
                    .iter_mut()
                    .for_each(|f| f.sources.iter_mut().for_each(|x| x.contract_size = None))
            },
            |s| {
                s.feeds.iter_mut().for_each(|f| {
                    f.sources
                        .iter_mut()
                        .for_each(|x| x.market = "linear_perp".to_owned())
                })
            },
            |s| {
                s.feeds
                    .iter_mut()
                    .for_each(|f| f.sources.iter_mut().for_each(|x| x.symbol.push('X')))
            },
        ];
        for tamper in tampers {
            let mut changed = signed.clone();
            tamper(&mut changed);
            assert!(
                matches!(
                    changed.verify(gov, 0),
                    Err(VerifyError::UntrustedGovernance { .. })
                ),
                "{changed:?}"
            );
        }
    }

    #[test]
    fn a_set_must_be_newer_and_signed_by_governance() {
        let signed = set(3, vec![feed("CRYPTO.ETH/BTC")]);
        let gov = governance().address();
        assert!(matches!(
            signed.verify(gov, 3),
            Err(VerifyError::StaleFeedSet {
                found: 3,
                minimum: 3
            })
        ));
        let impostor = Signer::from_secret_bytes([0xF0; 32]).expect("valid key");
        let forged = FeedSet::sign(
            &impostor,
            4,
            NOW,
            String::new(),
            None,
            vec![feed("CRYPTO.ETH/BTC")],
        )
        .expect("signs");
        assert!(matches!(
            forged.verify(gov, 3),
            Err(VerifyError::UntrustedGovernance { .. })
        ));
        assert!(set(4, vec![feed("CRYPTO.ETH/BTC")]).verify(gov, 3).is_ok());
    }

    #[test]
    fn an_empty_set_a_feed_without_a_source_and_a_twice_listed_feed_are_refused() {
        let gov = governance().address();
        let malformed = |feeds: Vec<FeedSettings>| {
            matches!(
                set(1, feeds).verify(gov, 0),
                Err(VerifyError::MalformedFeedSet(_))
            )
        };
        assert!(malformed(vec![]));
        let mut bare = feed("CRYPTO.ETH/BTC");
        bare.sources.clear();
        assert!(malformed(vec![bare]));
        assert!(malformed(vec![
            feed("CRYPTO.ETH/BTC"),
            feed("CRYPTO.ETH/BTC")
        ]));
    }

    #[test]
    fn a_node_older_than_the_set_cannot_serve_it() {
        let verified = set(1, vec![feed("CRYPTO.ETH/BTC")])
            .verify(governance().address(), 0)
            .expect("verifies");
        assert!(verified.serves("0.1.0"));
        assert!(verified.serves("0.2.0"));
        assert!(!verified.serves("0.0.9"));
        assert!(!verified.serves("not a version"));
        let bad = FeedSet::sign(
            &governance(),
            1,
            NOW,
            "one".to_owned(),
            None,
            vec![feed("CRYPTO.ETH/BTC")],
        )
        .expect("signs");
        assert!(matches!(
            bad.verify(governance().address(), 0),
            Err(VerifyError::MalformedFeedSet(_))
        ));
    }

    #[test]
    fn a_source_list_longer_than_a_venue_report_does_not_encode() {
        let mut wide = feed("CRYPTO.ETH/BTC");
        wide.sources = (0..=MAX_VENUE_ENTRIES)
            .map(|n| source("binance", &format!("A{n}")))
            .collect();
        assert!(matches!(
            FeedSet::signing_bytes(1, NOW, "", None, &[wide]),
            Err(WireError::FieldTooLong {
                field: "sources",
                ..
            })
        ));
    }

    #[test]
    fn a_client_list_signature_cannot_pass_as_a_feed_set() {
        let list = crate::ClientList::sign(&governance(), 1, NOW, 60, Vec::new()).expect("signs");
        let borrowed = FeedSet {
            version: 1,
            effective_from: NOW,
            min_node_version: String::new(),
            push: None,
            feeds: vec![feed("CRYPTO.ETH/BTC")],
            governance_signature: list.governance_signature,
        };
        assert!(matches!(
            borrowed.verify(governance().address(), 0),
            Err(VerifyError::UntrustedGovernance { .. })
        ));
    }
}
