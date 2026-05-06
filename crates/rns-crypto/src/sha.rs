//! SHA-256 / SHA-512 digests.

use sha2::{Digest, Sha256, Sha512};

/// SHA-256 hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-512 hash.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-256 truncated to 128 bits, used for destination and identity hashes.
pub fn truncated_hash(data: &[u8]) -> [u8; 16] {
    let full = sha256(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Alias for [`sha256`].
pub fn full_hash(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

/// SHA-256 of an app-name string truncated to 80 bits.
pub fn name_hash(name: &str) -> [u8; 10] {
    let full = sha256(name.as_bytes());
    let mut out = [0u8; 10];
    out.copy_from_slice(&full[..10]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn test_sha256_hello() {
        let hash = sha256(b"hello");
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn test_sha512_empty() {
        let hash = sha512(b"");
        let expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn test_truncated_hash() {
        let hash = truncated_hash(b"test");
        assert_eq!(hash.len(), 16);
        let full = sha256(b"test");
        assert_eq!(&hash[..], &full[..16]);
    }

    #[test]
    fn test_name_hash() {
        let hash = name_hash("test.app");
        assert_eq!(hash.len(), 10);
        let full = sha256(b"test.app");
        assert_eq!(&hash[..], &full[..10]);
    }
}
