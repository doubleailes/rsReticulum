//! Pluggable proof-of-work stamper for discovery announces.
//!
//! Python `RNS.Discovery.InterfaceAnnouncer` imports `LXMF.LXStamper`.
//! rsReticulum avoids an upward dependency on rsLXMF, so discovery accepts a
//! trait object. The concrete implementation lives in
//! `lxmf-core::discovery_stamper::LxmfDiscoveryStamper` and is wired at startup
//! by the embedding application.

/// Minimal PoW stamp interface consumed by the discovery subsystem.
///
/// A stamper must be **deterministic for a given `(infohash, target_value)`
/// pair** and independent across calls — the announcer caches its last
/// successful stamp per info-hash and reuses it until the payload changes.
pub trait DiscoveryStamper: Send + Sync {
    /// Generate a `STAMP_SIZE`-byte stamp whose SHA-256-derived value meets
    /// or exceeds `target_value` (number of leading zero bits, as in the
    /// Python `LXStamper.generate_stamp` contract).
    ///
    /// Returns `None` if generation was cancelled or failed.
    fn generate(&self, infohash: &[u8; 32], target_value: u8) -> Option<Vec<u8>>;

    /// Compute the stamp's current value (Python `LXStamper.stamp_value`).
    /// Used by the receiver to log the learned stamp quality.
    fn value(&self, infohash: &[u8; 32], stamp: &[u8]) -> u8;

    /// Validate a stamp against `required_value` (Python
    /// `LXStamper.stamp_valid`). Returns true iff the stamp meets the bar.
    fn valid(&self, infohash: &[u8; 32], stamp: &[u8], required_value: u8) -> bool;
}

/// A no-op stamper used when on-network discovery is not enabled.
///
/// Never generates a stamp — so the announcer short-circuits each tick and
/// the receiver rejects every inbound stamp. This keeps discovery silent
/// when no stamper is installed (Python panics in this case; we don't).
pub struct NullStamper;

impl DiscoveryStamper for NullStamper {
    fn generate(&self, _infohash: &[u8; 32], _target_value: u8) -> Option<Vec<u8>> {
        None
    }

    fn value(&self, _infohash: &[u8; 32], _stamp: &[u8]) -> u8 {
        0
    }

    fn valid(&self, _infohash: &[u8; 32], _stamp: &[u8], _required_value: u8) -> bool {
        false
    }
}
