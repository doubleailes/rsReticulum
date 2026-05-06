//! OS-CSPRNG-backed random byte helpers.

use alloc::vec;
use alloc::vec::Vec;
use rand::RngCore;
use rand_core::OsRng;

/// Cryptographically secure random bytes from the OS CSPRNG.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// 16 random bytes, sized for AES IVs and truncated hashes.
pub fn random_16() -> [u8; 16] {
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// 32 random bytes.
pub fn random_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes_length() {
        assert_eq!(random_bytes(0).len(), 0);
        assert_eq!(random_bytes(16).len(), 16);
        assert_eq!(random_bytes(64).len(), 64);
    }

    #[test]
    fn test_random_not_zero() {
        let r = random_32();
        assert!(r.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_unique() {
        let a = random_32();
        let b = random_32();
        assert_ne!(a, b);
    }
}
