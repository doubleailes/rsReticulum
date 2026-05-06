//! HMAC-SHA256 tag computation and constant-time verification.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 (RFC 2104), returning the 32-byte tag.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Verify an HMAC-SHA256 tag in constant time.
pub fn hmac_verify(key: &[u8], data: &[u8], expected: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    let computed = hmac_sha256(key, data);
    computed.ct_eq(expected).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_rfc4231_vector1() {
        // RFC 4231 Test Case 1.
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        assert_eq!(hex::encode(hmac_sha256(&key, data)), expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_vector2() {
        // RFC 4231 Test Case 2.
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assert_eq!(hex::encode(hmac_sha256(key, data)), expected);
    }

    #[test]
    fn test_hmac_verify_correct() {
        let key = b"test_key";
        let data = b"test_data";
        let mac = hmac_sha256(key, data);
        assert!(hmac_verify(key, data, &mac));
    }

    #[test]
    fn test_hmac_verify_wrong() {
        let key = b"test_key";
        let data = b"test_data";
        let mut mac = hmac_sha256(key, data);
        mac[0] ^= 1;
        assert!(!hmac_verify(key, data, &mac));
    }
}
