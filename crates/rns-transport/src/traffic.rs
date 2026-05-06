use std::collections::HashMap;

use crate::messages::InterfaceId;

#[derive(Debug, Clone, Default)]
pub struct InterfaceTraffic {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Previous sample, retained so `update_speeds` can compute a delta
    /// without keeping a ring buffer of samples.
    pub rx_bytes_prev: u64,
    pub tx_bytes_prev: u64,
    /// Bytes per second, over the last `update_speeds` interval.
    pub rx_speed: f64,
    pub tx_speed: f64,
}

pub struct TrafficCounter {
    interfaces: HashMap<InterfaceId, InterfaceTraffic>,
}

impl TrafficCounter {
    pub fn new() -> Self {
        Self {
            interfaces: HashMap::new(),
        }
    }

    pub fn record_rx(&mut self, interface_id: InterfaceId, bytes: u64) {
        let entry = self.interfaces.entry(interface_id).or_default();
        entry.rx_bytes += bytes;
    }

    pub fn record_tx(&mut self, interface_id: InterfaceId, bytes: u64) {
        let entry = self.interfaces.entry(interface_id).or_default();
        entry.tx_bytes += bytes;
    }

    /// Compute per-second speeds from the delta since the last call. Intended
    /// to run on a 1 Hz tick so the delta equals bytes-per-second directly.
    pub fn update_speeds(&mut self) {
        for entry in self.interfaces.values_mut() {
            entry.rx_speed = (entry.rx_bytes - entry.rx_bytes_prev) as f64;
            entry.tx_speed = (entry.tx_bytes - entry.tx_bytes_prev) as f64;
            entry.rx_bytes_prev = entry.rx_bytes;
            entry.tx_bytes_prev = entry.tx_bytes;
        }
    }

    pub fn get(&self, interface_id: &InterfaceId) -> Option<&InterfaceTraffic> {
        self.interfaces.get(interface_id)
    }

    pub fn all(&self) -> &HashMap<InterfaceId, InterfaceTraffic> {
        &self.interfaces
    }
}

impl Default for TrafficCounter {
    fn default() -> Self {
        Self::new()
    }
}
