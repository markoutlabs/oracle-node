//! When the nodes take a new feed set: a lead after the publish, then one
//! node each slot, so that two nodes never change at once (SPEC §3.8). The web
//! proxy follows when the slots have passed.

/// Seconds from a publish to the first node's change, by default: every node polls within it.
pub const SLOT_LEAD_SECS: u64 = 120;

/// Seconds between two nodes' changes, by default: one node's venues reconnect in it.
pub const SLOT_SECS: u64 = 90;

/// When the nodes change; every node of a network must use the same values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slots {
    /// Seconds from the publish to the first node's change.
    pub lead_secs: u64,
    /// Seconds between two nodes' changes.
    pub slot_secs: u64,
}

impl Default for Slots {
    fn default() -> Self {
        Self {
            lead_secs: SLOT_LEAD_SECS,
            slot_secs: SLOT_SECS,
        }
    }
}

impl Slots {
    fn slot(self, effective_from: u64, place: usize) -> u64 {
        let place = u64::try_from(place).unwrap_or(u64::MAX);
        effective_from
            .saturating_add(self.lead_secs)
            .saturating_add(place.saturating_mul(self.slot_secs))
    }

    /// When the node at `index` of `nodes` applies a set; a late node goes after every node's slot.
    #[must_use]
    pub fn apply_at(self, effective_from: u64, index: usize, nodes: usize, now: u64) -> u64 {
        let own = self.slot(effective_from, index);
        if now <= own {
            return own;
        }
        self.slot(effective_from, nodes.saturating_add(index))
            .max(now)
    }

    /// When every node that saw the set in time has changed.
    #[must_use]
    pub fn settled(self, effective_from: u64, nodes: usize) -> u64 {
        self.slot(effective_from, nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_node_changes_in_its_own_slot_and_a_late_one_after_all() {
        let issued = 1_000;
        let slots = Slots::default();
        assert_eq!(slots.apply_at(issued, 0, 3, issued), issued + 120);
        assert_eq!(
            slots.apply_at(issued, 2, 3, issued + 30),
            issued + 120 + 180
        );
        // Node 1 saw the set only after its own slot: it goes after node 2.
        assert_eq!(
            slots.apply_at(issued, 1, 3, issued + 211),
            issued + 120 + 4 * 90
        );
        // Very late: at once.
        assert_eq!(
            slots.apply_at(issued, 1, 3, issued + 10_000),
            issued + 10_000
        );
        assert_eq!(slots.settled(issued, 3), issued + 120 + 270);
    }
}
