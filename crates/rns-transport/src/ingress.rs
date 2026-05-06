//! Per-interface ingress control: announce flood protection.
//!
//! Each interface owns one `IngressController`. The inbound path consults it
//! on every announce — when the incoming rate crosses the burst threshold the
//! controller activates a hold state, shunts subsequent announces into a
//! per-destination hold buffer, and the maintenance tick releases them later
//! in hop-priority order. The split thresholds for freshly-seen vs. mature
//! interfaces (`IC_BURST_FREQ_NEW` vs. `IC_BURST_FREQ`) give newly-online
//! links time to catch up from the network backlog without triggering the
//! limiter on the first burst of announces.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::constants::{
    IA_FREQ_SAMPLES, IC_BURST_FREQ, IC_BURST_FREQ_NEW, IC_BURST_HOLD, IC_BURST_PENALTY,
    IC_DEQUE_MIN_SAMPLE, IC_HELD_RELEASE_INTERVAL, IC_NEW_TIME, MAX_HELD_ANNOUNCES,
    OA_FREQ_SAMPLES,
};

/// Per-interface ingress overrides parsed from `[interface.<name>] ic_*` keys.
/// Any field left `None` falls back to the corresponding crate-level constant.
#[derive(Debug, Clone, Default)]
pub struct IngressOverrides {
    pub enabled: Option<bool>,
    pub burst_freq_new: Option<f64>,
    pub burst_freq: Option<f64>,
    pub new_time: Option<f64>,
    pub burst_hold: Option<f64>,
    pub burst_penalty: Option<f64>,
    pub max_held: Option<usize>,
    pub held_release_interval: Option<f64>,
}

impl IngressOverrides {
    pub fn is_empty(&self) -> bool {
        self.enabled.is_none()
            && self.burst_freq_new.is_none()
            && self.burst_freq.is_none()
            && self.new_time.is_none()
            && self.burst_hold.is_none()
            && self.burst_penalty.is_none()
            && self.max_held.is_none()
            && self.held_release_interval.is_none()
    }
}

/// An announce parked in the hold buffer, awaiting release.
#[derive(Debug, Clone)]
pub struct HeldAnnounce {
    pub raw: Bytes,
    pub destination_hash: [u8; 16],
    /// Hops at reception — lower values win release priority.
    pub hops: u8,
    pub receiving_interface_id: u64,
}

#[derive(Debug)]
pub struct IngressController {
    created: Instant,
    enabled: bool,
    /// Incoming announce timestamps; capped at `IA_FREQ_SAMPLES`.
    ia_freq_deque: VecDeque<Instant>,
    /// Outgoing announce timestamps; capped at `OA_FREQ_SAMPLES`.
    oa_freq_deque: VecDeque<Instant>,
    burst_active: bool,
    burst_activated: Instant,
    /// Earliest instant at which the next held announce may be released.
    held_release: Instant,
    held_announces: HashMap<[u8; 16], HeldAnnounce>,

    burst_freq_new: f64,
    burst_freq: f64,
    new_time: f64,
    burst_hold: f64,
    burst_penalty: f64,
    max_held: usize,
    held_release_interval: f64,
}

impl IngressController {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            created: now,
            enabled: true,
            ia_freq_deque: VecDeque::with_capacity(IA_FREQ_SAMPLES),
            oa_freq_deque: VecDeque::with_capacity(OA_FREQ_SAMPLES),
            burst_active: false,
            burst_activated: now,
            held_release: now,
            held_announces: HashMap::new(),
            burst_freq_new: IC_BURST_FREQ_NEW,
            burst_freq: IC_BURST_FREQ,
            new_time: IC_NEW_TIME,
            burst_hold: IC_BURST_HOLD,
            burst_penalty: IC_BURST_PENALTY,
            max_held: MAX_HELD_ANNOUNCES,
            held_release_interval: IC_HELD_RELEASE_INTERVAL,
        }
    }

    /// Always-permissive controller — use when ingress control is switched off
    /// at the transport or interface level. The state machine still compiles
    /// samples so operators can read frequency stats, but `should_ingress_limit`
    /// is hard-wired to `false`.
    pub fn disabled() -> Self {
        let mut ctrl = Self::new();
        ctrl.enabled = false;
        ctrl
    }

    /// Controller with per-interface overrides applied; unset fields keep
    /// their compile-time defaults.
    pub fn with_overrides(overrides: &IngressOverrides) -> Self {
        let mut ctrl = Self::new();
        if let Some(v) = overrides.enabled {
            ctrl.enabled = v;
        }
        if let Some(v) = overrides.burst_freq_new {
            ctrl.burst_freq_new = v;
        }
        if let Some(v) = overrides.burst_freq {
            ctrl.burst_freq = v;
        }
        if let Some(v) = overrides.new_time {
            ctrl.new_time = v;
        }
        if let Some(v) = overrides.burst_hold {
            ctrl.burst_hold = v;
        }
        if let Some(v) = overrides.burst_penalty {
            ctrl.burst_penalty = v;
        }
        if let Some(v) = overrides.max_held {
            ctrl.max_held = v;
        }
        if let Some(v) = overrides.held_release_interval {
            ctrl.held_release_interval = v;
        }
        ctrl
    }

    pub fn burst_freq(&self) -> f64 {
        self.burst_freq
    }

    pub fn burst_freq_new(&self) -> f64 {
        self.burst_freq_new
    }

    pub fn held_release_interval(&self) -> f64 {
        self.held_release_interval
    }

    /// Earliest instant at which the next held announce may be released. The
    /// cooldown starts when burst mode activates (not deactivates) so a
    /// prolonged burst cannot starve existing holds.
    pub fn held_release_at(&self) -> Instant {
        self.held_release
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn age(&self) -> f64 {
        self.created.elapsed().as_secs_f64()
    }

    pub fn received_announce(&mut self) {
        let now = Instant::now();
        if self.ia_freq_deque.len() >= IA_FREQ_SAMPLES {
            self.ia_freq_deque.pop_front();
        }
        self.ia_freq_deque.push_back(now);
    }

    pub fn sent_announce(&mut self) {
        let now = Instant::now();
        if self.oa_freq_deque.len() >= OA_FREQ_SAMPLES {
            self.oa_freq_deque.pop_front();
        }
        self.oa_freq_deque.push_back(now);
    }

    pub fn incoming_announce_frequency(&self) -> f64 {
        frequency_from_deque(&self.ia_freq_deque)
    }

    pub fn outgoing_announce_frequency(&self) -> f64 {
        frequency_from_deque(&self.oa_freq_deque)
    }

    /// Whether inbound announces should currently be held. Also updates the
    /// internal burst state — an exit from burst only happens once the
    /// frequency has dropped *and* `burst_hold` seconds have passed since
    /// activation, preventing flapping on a noisy interface.
    pub fn should_ingress_limit(&mut self) -> bool {
        if !self.enabled {
            return false;
        }

        let freq_threshold = if self.age() < self.new_time {
            self.burst_freq_new
        } else {
            self.burst_freq
        };

        let ia_freq = self.incoming_announce_frequency();
        let now = Instant::now();

        if self.burst_active {
            if ia_freq < freq_threshold
                && now.duration_since(self.burst_activated)
                    > Duration::from_secs_f64(self.burst_hold)
            {
                self.burst_active = false;
            }
            true
        } else if ia_freq > freq_threshold {
            self.burst_active = true;
            self.burst_activated = now;
            self.held_release = now + Duration::from_secs_f64(self.burst_penalty);
            true
        } else {
            false
        }
    }

    pub fn hold_announce(&mut self, announce: HeldAnnounce) {
        if self.held_announces.contains_key(&announce.destination_hash)
            || self.held_announces.len() < self.max_held
        {
            self.held_announces
                .insert(announce.destination_hash, announce);
        }
    }

    /// Release at most one held announce per call — the one with the lowest
    /// hop count, so short-path announces win priority. `None` means either
    /// the burst is still active, the release cooldown has not elapsed, or
    /// the buffer is empty.
    pub fn try_release_held(&mut self) -> Option<HeldAnnounce> {
        if self.should_ingress_limit() || self.held_announces.is_empty() {
            return None;
        }

        let now = Instant::now();
        if now < self.held_release {
            return None;
        }

        let freq_threshold = if self.age() < self.new_time {
            self.burst_freq_new
        } else {
            self.burst_freq
        };

        if self.incoming_announce_frequency() >= freq_threshold {
            return None;
        }

        let best_hash = self
            .held_announces
            .iter()
            .min_by_key(|(_, a)| a.hops)
            .map(|(hash, _)| *hash)?;

        let announce = self.held_announces.remove(&best_hash)?;
        self.held_release = now + Duration::from_secs_f64(self.held_release_interval);
        Some(announce)
    }

    pub fn held_count(&self) -> usize {
        self.held_announces.len()
    }

    pub fn is_burst_active(&self) -> bool {
        self.burst_active
    }
}

impl Default for IngressController {
    fn default() -> Self {
        Self::new()
    }
}

/// Announces-per-second estimate over a timestamp deque. Returns 0 until
/// enough samples have accumulated (`IC_DEQUE_MIN_SAMPLE`) so the first few
/// entries on a new interface cannot trip the limiter by themselves.
fn frequency_from_deque(deque: &VecDeque<Instant>) -> f64 {
    let n = deque.len();
    if n <= IC_DEQUE_MIN_SAMPLE {
        return 0.0;
    }
    let span = match deque.front() {
        Some(oldest) => oldest.elapsed().as_secs_f64(),
        None => return 0.0,
    };
    if span <= 0.0 { 0.0 } else { n as f64 / span }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingress_controller_default_state() {
        let ctrl = IngressController::new();
        assert!(ctrl.is_enabled());
        assert!(!ctrl.is_burst_active());
        assert_eq!(ctrl.held_count(), 0);
        assert_eq!(ctrl.incoming_announce_frequency(), 0.0);
    }

    #[test]
    fn ingress_disabled_never_limits() {
        let mut ctrl = IngressController::disabled();
        for _ in 0..100 {
            ctrl.received_announce();
        }
        assert!(!ctrl.should_ingress_limit());
    }

    #[test]
    fn hold_announce_dedups_by_destination() {
        let mut ctrl = IngressController::new();
        let a = HeldAnnounce {
            raw: Bytes::from_static(&[1, 2, 3]),
            destination_hash: [0u8; 16],
            hops: 1,
            receiving_interface_id: 1,
        };
        ctrl.hold_announce(a);
        assert_eq!(ctrl.held_count(), 1);

        let a2 = HeldAnnounce {
            raw: Bytes::from_static(&[4, 5, 6]),
            destination_hash: [0u8; 16],
            hops: 2,
            receiving_interface_id: 1,
        };
        ctrl.hold_announce(a2);
        assert_eq!(ctrl.held_count(), 1);

        let a3 = HeldAnnounce {
            raw: Bytes::from_static(&[7, 8, 9]),
            destination_hash: [1u8; 16],
            hops: 0,
            receiving_interface_id: 1,
        };
        ctrl.hold_announce(a3);
        assert_eq!(ctrl.held_count(), 2);
    }

    #[test]
    fn hold_announce_capped_at_max() {
        let mut ctrl = IngressController::new();
        for i in 0..MAX_HELD_ANNOUNCES {
            let mut h = [0u8; 16];
            h[0] = (i & 0xFF) as u8;
            h[1] = ((i >> 8) & 0xFF) as u8;
            ctrl.hold_announce(HeldAnnounce {
                raw: Bytes::new(),
                destination_hash: h,
                hops: 0,
                receiving_interface_id: 1,
            });
        }
        assert_eq!(ctrl.held_count(), MAX_HELD_ANNOUNCES);

        ctrl.hold_announce(HeldAnnounce {
            raw: Bytes::new(),
            destination_hash: [0xFF; 16],
            hops: 0,
            receiving_interface_id: 1,
        });
        assert_eq!(ctrl.held_count(), MAX_HELD_ANNOUNCES);
    }
}
