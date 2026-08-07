//! Status flags carried inside every signed price update.

use core::fmt;
use core::ops::{BitOr, BitOrAssign};

/// Status bits describing how much to trust an update.
///
/// # Forward compatibility
///
/// [`Flags::from_bits`] **rejects** reserved bits rather than masking them off.
/// A future protocol revision that adds a flag will therefore be refused by a
/// v1 verifier instead of being silently downgraded to "no flags set". For an
/// oracle that is the correct direction to fail: an old client that cannot
/// understand a new warning must not conclude there is no warning.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Flags(u16);

impl Flags {
    /// No flags set: the feed is healthy.
    pub const NONE: Self = Self(0);

    /// The feed is halted. The carried price is the last good value and MUST NOT
    /// be used for settlement or liquidation.
    pub const HALTED: Self = Self(1 << 0);

    /// The feed is live but its inputs are impaired; the confidence interval has
    /// been widened to reflect that.
    pub const DEGRADED: Self = Self(1 << 1);

    /// At least one contributing source was converted from a stablecoin quote
    /// through a peg feed, so the price inherits the peg's uncertainty.
    pub const SYNTHETIC_QUOTE: Self = Self(1 << 2);

    /// Mask of all flags defined in this protocol version.
    const KNOWN: u16 = 0b0000_0000_0000_0111;

    /// Builds flags from raw bits.
    ///
    /// Returns `None` if any reserved bit is set. See the type documentation for
    /// why this is a rejection and not a mask.
    #[inline]
    #[must_use]
    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::KNOWN != 0 {
            return None;
        }
        Some(Self(bits))
    }

    /// Returns the raw bits.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns `true` if every flag in `other` is set.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns `true` if no flags are set.
    #[inline]
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if the feed is halted.
    #[inline]
    #[must_use]
    pub const fn is_halted(self) -> bool {
        self.contains(Self::HALTED)
    }

    /// Returns `true` if the feed is degraded.
    #[inline]
    #[must_use]
    pub const fn is_degraded(self) -> bool {
        self.contains(Self::DEGRADED)
    }

    /// Returns `true` if any input was converted through a peg feed.
    #[inline]
    #[must_use]
    pub const fn is_synthetic_quote(self) -> bool {
        self.contains(Self::SYNTHETIC_QUOTE)
    }

    /// Returns `true` if the update is safe to use for settlement.
    ///
    /// Degraded updates pass: their widened confidence interval is the signal a
    /// consumer should act on, and refusing them entirely would make every
    /// venue hiccup an outage.
    #[inline]
    #[must_use]
    pub const fn is_usable(self) -> bool {
        !self.is_halted()
    }
}

impl BitOr for Flags {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Flags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_none() {
            return f.write_str("Flags(NONE)");
        }
        let mut set = f.debug_set();
        for (flag, name) in [
            (Self::HALTED, "HALTED"),
            (Self::DEGRADED, "DEGRADED"),
            (Self::SYNTHETIC_QUOTE, "SYNTHETIC_QUOTE"),
        ] {
            if self.contains(flag) {
                set.entry(&name);
            }
        }
        set.finish()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Flags {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Flags {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = u16::deserialize(deserializer)?;
        Self::from_bits(bits)
            .ok_or_else(|| serde::de::Error::custom(format!("reserved flag bits set: {bits:#06x}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_bits_round_trip() {
        for bits in 0..=Flags::KNOWN {
            let flags = Flags::from_bits(bits).expect("known bits");
            assert_eq!(flags.bits(), bits);
        }
    }

    #[test]
    fn reserved_bits_are_rejected_not_masked() {
        assert_eq!(Flags::from_bits(1 << 3), None);
        assert_eq!(Flags::from_bits(0xFFFF), None);
        // A reserved bit alongside known bits still fails closed.
        assert_eq!(Flags::from_bits(Flags::HALTED.bits() | (1 << 15)), None);
    }

    #[test]
    fn combination_and_queries() {
        let flags = Flags::DEGRADED | Flags::SYNTHETIC_QUOTE;
        assert!(flags.is_degraded());
        assert!(flags.is_synthetic_quote());
        assert!(!flags.is_halted());
        assert!(flags.is_usable());

        let halted = flags | Flags::HALTED;
        assert!(halted.is_halted());
        assert!(!halted.is_usable());
    }

    #[test]
    fn debug_lists_set_flags() {
        assert_eq!(format!("{:?}", Flags::NONE), "Flags(NONE)");
        assert_eq!(
            format!("{:?}", Flags::HALTED | Flags::DEGRADED),
            r#"{"HALTED", "DEGRADED"}"#
        );
    }
}
