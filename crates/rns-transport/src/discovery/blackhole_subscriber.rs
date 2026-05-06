//! Pure-data subscriber state machine for the distributed blackhole list.
//!
//! Tracks per-source "last pulled at" timestamps and decides which sources
//! are due for a refresh on the current tick. The actual link
//! establishment + `/list` request lives in the runtime layer; this module
//! is intentionally free of tokio so the due-source logic can be unit
//! tested without timers or fakes.
//!
//! Mirrors the scheduling half of Python's `BlackholeUpdater.job()` loop
//! (RNS/Discovery.py:693) with the same constants:
//! `INITIAL_WAIT=20s`, `JOB_INTERVAL=60s`, `UPDATE_INTERVAL=3600s`.

use std::collections::HashMap;
use std::time::Duration;

use rns_wire::types::IdentityHash;

/// Python `BlackholeUpdater.INITIAL_WAIT` — delay before the first job tick.
pub const INITIAL_WAIT: Duration = Duration::from_secs(20);

/// Python `BlackholeUpdater.JOB_INTERVAL` — time between scheduling sweeps.
pub const JOB_INTERVAL: Duration = Duration::from_secs(60);

/// Python `BlackholeUpdater.UPDATE_INTERVAL` — minimum gap between
/// successful pulls from the same source (1 hour).
pub const UPDATE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Python `BlackholeUpdater.SOURCE_TIMEOUT` — kept here for parity but
/// currently unused; the runtime wrapper races it against the link
/// establishment / request when it lands.
pub const SOURCE_TIMEOUT: Duration = Duration::from_secs(25);

/// Per-process subscriber state. Cheap to clone-on-snapshot via the
/// [`SubscriberState::snapshot`] helper; the runtime owner holds the
/// authoritative copy.
#[derive(Debug, Default, Clone)]
pub struct SubscriberState {
    /// Unix-seconds timestamp of the most recent successful pull, keyed by
    /// source identity hash. Missing key ⇒ "never pulled".
    last_updates: HashMap<IdentityHash, f64>,
}

impl SubscriberState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful pull from `source` at `now` (Unix seconds).
    pub fn mark_updated(&mut self, source: IdentityHash, now: f64) {
        self.last_updates.insert(source, now);
    }

    /// Clear the last-update cursor for `source`, forcing the next tick
    /// to re-pull even if `UPDATE_INTERVAL` has not elapsed. Useful when
    /// an operator edits `blackhole_sources` and wants an immediate
    /// refresh.
    pub fn forget(&mut self, source: &IdentityHash) {
        self.last_updates.remove(source);
    }

    /// Returns the list of sources that should be pulled on this tick,
    /// given the configured source list and the current time.
    ///
    /// Order is deterministic (sorted by identity hash) so the runtime
    /// does not accidentally thundering-herd one source ahead of another
    /// after a restart.
    pub fn due_sources(&self, configured: &[IdentityHash], now: f64) -> Vec<IdentityHash> {
        let mut due: Vec<IdentityHash> = configured
            .iter()
            .copied()
            .filter(|src| {
                let last = self.last_updates.get(src).copied().unwrap_or(0.0);
                now - last >= UPDATE_INTERVAL.as_secs_f64()
            })
            .collect();
        due.sort();
        due.dedup();
        due
    }

    /// Drop cursors for sources that no longer appear in `configured`.
    /// Keeps the table bounded when an operator rotates their source
    /// list.
    pub fn prune(&mut self, configured: &[IdentityHash]) {
        self.last_updates
            .retain(|src, _| configured.iter().any(|c| c == src));
    }

    /// Snapshot the cursor map. Test-only surface.
    #[cfg(test)]
    pub fn snapshot(&self) -> HashMap<IdentityHash, f64> {
        self.last_updates.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> IdentityHash {
        [b; 16].into()
    }

    #[test]
    fn no_sources_means_nothing_due() {
        let s = SubscriberState::new();
        assert!(s.due_sources(&[], 10_000.0).is_empty());
    }

    #[test]
    fn fresh_subscribers_are_due_immediately() {
        let s = SubscriberState::new();
        let sources = vec![h(0x11), h(0x22)];
        let due = s.due_sources(&sources, 10_000.0);
        assert_eq!(due, vec![h(0x11), h(0x22)]);
    }

    #[test]
    fn due_list_is_deterministic_sorted() {
        let s = SubscriberState::new();
        let sources = vec![h(0x33), h(0x11), h(0x22)];
        let due = s.due_sources(&sources, 10_000.0);
        assert_eq!(due, vec![h(0x11), h(0x22), h(0x33)]);
    }

    #[test]
    fn mark_updated_suppresses_source_until_interval_elapses() {
        let mut s = SubscriberState::new();
        s.mark_updated(h(0x11), 10_000.0);

        // 30 minutes later — still inside the 1h interval.
        let due = s.due_sources(&[h(0x11)], 10_000.0 + 1_800.0);
        assert!(due.is_empty());

        // Right at the interval boundary — due again.
        let due = s.due_sources(&[h(0x11)], 10_000.0 + UPDATE_INTERVAL.as_secs_f64());
        assert_eq!(due, vec![h(0x11)]);
    }

    #[test]
    fn mark_updated_does_not_affect_other_sources() {
        let mut s = SubscriberState::new();
        s.mark_updated(h(0x11), 10_000.0);

        let due = s.due_sources(&[h(0x11), h(0x22)], 10_000.0 + 30.0);
        assert_eq!(due, vec![h(0x22)]);
    }

    #[test]
    fn forget_forces_immediate_re_pull() {
        let mut s = SubscriberState::new();
        s.mark_updated(h(0x11), 10_000.0);
        s.forget(&h(0x11));

        let due = s.due_sources(&[h(0x11)], 10_000.0 + 10.0);
        assert_eq!(due, vec![h(0x11)]);
    }

    #[test]
    fn duplicate_source_entries_collapse() {
        let s = SubscriberState::new();
        let sources = vec![h(0x11), h(0x11), h(0x22), h(0x22), h(0x22)];
        let due = s.due_sources(&sources, 10_000.0);
        assert_eq!(due, vec![h(0x11), h(0x22)]);
    }

    #[test]
    fn prune_drops_cursors_for_removed_sources() {
        let mut s = SubscriberState::new();
        s.mark_updated(h(0x11), 10_000.0);
        s.mark_updated(h(0x22), 10_000.0);

        s.prune(&[h(0x22)]);

        assert!(s.snapshot().contains_key(&h(0x22)));
        assert!(!s.snapshot().contains_key(&h(0x11)));
    }

    #[test]
    fn prune_keeps_all_cursors_when_list_matches() {
        let mut s = SubscriberState::new();
        s.mark_updated(h(0x11), 10_000.0);
        s.mark_updated(h(0x22), 10_000.0);

        s.prune(&[h(0x11), h(0x22)]);

        assert_eq!(s.snapshot().len(), 2);
    }
}
