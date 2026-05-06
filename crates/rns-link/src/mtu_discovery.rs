use crate::constants::{MODE_BYTEMASK, MTU_BYTEMASK};

/// MTU and encryption-mode signalling packed into 3 bytes (big-endian).
///
/// Wire layout: `[23:21] mode (0..=7)`, `[20:0] mtu (0..=2_097_151)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignallingData {
    pub mode: u8,
    pub mtu: u32,
}

impl SignallingData {
    pub fn new(mode: u8, mtu: u32) -> Self {
        Self {
            mode: mode & 0x07,
            mtu: mtu & MTU_BYTEMASK,
        }
    }

    /// Pack into 3 big-endian bytes.
    pub fn pack(&self) -> [u8; 3] {
        let value = (self.mtu & MTU_BYTEMASK) | ((((self.mode as u32) << 5) & MODE_BYTEMASK) << 16);
        let bytes = value.to_be_bytes();
        // Value fits in 24 bits; drop the high byte of the u32.
        [bytes[1], bytes[2], bytes[3]]
    }

    /// Parse 3 big-endian bytes. Returns `None` if the input is shorter.
    pub fn unpack(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 3 {
            return None;
        }
        let value = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
        let mtu = value & MTU_BYTEMASK;
        let mode = ((value >> 21) & 0x07) as u8;
        Some(Self { mode, mtu })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DEFAULT_MODE, MODE_AES256_CBC};

    #[test]
    fn test_pack_unpack_roundtrip() {
        let sd = SignallingData::new(MODE_AES256_CBC, 500);
        let packed = sd.pack();
        let unpacked = SignallingData::unpack(&packed).unwrap();
        assert_eq!(unpacked.mode, MODE_AES256_CBC);
        assert_eq!(unpacked.mtu, 500);
    }

    #[test]
    fn test_mode_zero_mtu_500() {
        let sd = SignallingData::new(0, 500);
        let packed = sd.pack();
        let unpacked = SignallingData::unpack(&packed).unwrap();
        assert_eq!(unpacked.mode, 0);
        assert_eq!(unpacked.mtu, 500);
    }

    #[test]
    fn test_mode_bits_isolated() {
        // Setting the mode must not corrupt the MTU field.
        let sd = SignallingData::new(1, 500);
        let packed = sd.pack();
        let unpacked = SignallingData::unpack(&packed).unwrap();
        assert_eq!(unpacked.mtu, 500);
        assert_eq!(unpacked.mode, 1);
    }

    #[test]
    fn test_max_mtu_value() {
        let max_mtu = MTU_BYTEMASK;
        let sd = SignallingData::new(7, max_mtu);
        let packed = sd.pack();
        let unpacked = SignallingData::unpack(&packed).unwrap();
        assert_eq!(unpacked.mtu, max_mtu);
        assert_eq!(unpacked.mode, 7);
    }

    #[test]
    fn test_default_mode() {
        let sd = SignallingData::new(DEFAULT_MODE, 500);
        assert_eq!(sd.mode, MODE_AES256_CBC);
    }

    #[test]
    fn test_too_short() {
        assert!(SignallingData::unpack(&[0x00, 0x01]).is_none());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn proptest_signalling_pack_unpack_roundtrip(
            mode in 0u8..=7,
            mtu in 0u32..=MTU_BYTEMASK,
        ) {
            let sd = SignallingData::new(mode, mtu);
            let packed = sd.pack();
            let unpacked = SignallingData::unpack(&packed).unwrap();
            prop_assert_eq!(unpacked.mode, mode);
            prop_assert_eq!(unpacked.mtu, mtu);
            prop_assert_eq!(unpacked.pack(), packed);
        }

        #[test]
        fn proptest_signalling_bytes_canonical(bytes: [u8; 3]) {
            let sd = SignallingData::unpack(&bytes).unwrap();
            prop_assert_eq!(sd.pack(), bytes);
        }
    }
}
