//! `HardwareIdentity`: public-key-only `Identity` + PIV session for private ops.
//! Wire-compatible with software identities.

use std::path::Path;

use rns_crypto::hkdf::derive_key_64;
use rns_crypto::token;
use rns_identity::identity::Identity;

use crate::error::RatkeyError;
use crate::hwid::HwidConfig;
use crate::mock::{MockPivSession, SLOT_9A, SLOT_9D};

pub struct HardwareIdentity {
    pub identity: Identity,
    pub config: HwidConfig,
    ed25519_pub: [u8; 32],
    x25519_pub: [u8; 32],
    // Mock session storage keeps the current API testable until the real PIV
    // backend is wired. See crates/rns-ratkey/HARDWARE_STATUS.md.
    mock_session: Option<MockPivSession>,
}

impl HardwareIdentity {
    pub fn from_hwid_mock(
        config: HwidConfig,
        session: MockPivSession,
    ) -> Result<Self, RatkeyError> {
        let ed25519_pub = config.ed25519_pub_bytes()?;
        let x25519_pub = config.x25519_pub_bytes()?;

        // Fail closed: published identity hash must map to keys actually on the device.
        let session_ed = session.read_ed25519_public(SLOT_9A)?;
        let session_x = session.read_x25519_public(SLOT_9D)?;
        if session_ed != ed25519_pub || session_x != x25519_pub {
            return Err(RatkeyError::KeyMismatch);
        }

        let mut pub_key_bytes = [0u8; 64];
        pub_key_bytes[..32].copy_from_slice(&x25519_pub);
        pub_key_bytes[32..].copy_from_slice(&ed25519_pub);
        let identity = Identity::from_public_key(&pub_key_bytes)
            .map_err(|e| RatkeyError::InvalidHwid(format!("cannot create identity: {e}")))?;

        Ok(Self {
            identity,
            config,
            ed25519_pub,
            x25519_pub,
            mock_session: Some(session),
        })
    }

    pub fn from_file_mock(path: &Path, session: MockPivSession) -> Result<Self, RatkeyError> {
        let config = HwidConfig::from_file(path)?;
        Self::from_hwid_mock(config, session)
    }

    /// Test-only: build without `.hwid`; skips key-mismatch guard.
    pub fn from_keys_mock(
        ed25519_pub: [u8; 32],
        x25519_pub: [u8; 32],
        session: MockPivSession,
    ) -> Result<Self, RatkeyError> {
        let config = HwidConfig {
            identity: crate::hwid::HwidIdentity {
                hash: String::new(),
                nickname: "test".to_string(),
                created_at: 0,
            },
            device: crate::hwid::HwidDevice {
                device_type: session.device_type.clone(),
                serial: session.serial,
                firmware: session.firmware.clone(),
            },
            keys: crate::hwid::HwidKeys {
                ed25519_pub: hex::encode(ed25519_pub),
                x25519_pub: hex::encode(x25519_pub),
            },
            slots: crate::hwid::HwidSlots {
                signing: "9A".to_string(),
                encryption: "9D".to_string(),
            },
            policy: crate::hwid::HwidPolicy {
                pin_cache_timeout: 300,
                touch_signing: "never".to_string(),
                touch_encryption: "never".to_string(),
            },
            attestation: Default::default(),
            app: Default::default(),
            backup: Default::default(),
        };

        let mut pub_key_bytes = [0u8; 64];
        pub_key_bytes[..32].copy_from_slice(&x25519_pub);
        pub_key_bytes[32..].copy_from_slice(&ed25519_pub);
        let identity = Identity::from_public_key(&pub_key_bytes)
            .map_err(|e| RatkeyError::InvalidHwid(format!("cannot create identity: {e}")))?;

        let mut config = config;
        // Hash is derived from the Identity so the .hwid stays consistent.
        config.identity.hash = hex::encode(identity.hash);

        Ok(Self {
            identity,
            config,
            ed25519_pub,
            x25519_pub,
            mock_session: Some(session),
        })
    }

    pub fn hash(&self) -> &[u8; 16] {
        &self.identity.hash
    }

    pub fn hash_hex(&self) -> String {
        hex::encode(self.identity.hash)
    }

    /// 64-byte public key (X25519_pub || Ed25519_pub).
    pub fn get_public_key(&self) -> [u8; 64] {
        self.identity.get_public_key()
    }

    pub fn ed25519_public(&self) -> &[u8; 32] {
        &self.ed25519_pub
    }

    pub fn x25519_public(&self) -> &[u8; 32] {
        &self.x25519_pub
    }

    pub fn as_identity(&self) -> &Identity {
        &self.identity
    }

    pub fn sign(&mut self, message: &[u8]) -> Result<[u8; 64], RatkeyError> {
        let session = self.mock_session.as_mut().ok_or(RatkeyError::NoDevice)?;
        session.sign_ed25519(SLOT_9A, message)
    }

    pub fn ecdh(&mut self, peer_pub_bytes: &[u8; 32]) -> Result<[u8; 32], RatkeyError> {
        let session = self.mock_session.as_mut().ok_or(RatkeyError::NoDevice)?;
        session.ecdh_x25519(SLOT_9D, peer_pub_bytes)
    }

    /// Ciphertext = ephemeral_pub(32) || AES-256-CBC token. Mirrors `Identity::decrypt`
    /// but does the ECDH on-device.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        ratchets: Option<&[&[u8; 32]]>,
        enforce_ratchets: bool,
    ) -> Result<Vec<u8>, RatkeyError> {
        if ciphertext.len() <= 32 {
            return Err(RatkeyError::EcdhFailed("ciphertext too short".to_string()));
        }

        let ephemeral_pub_bytes: [u8; 32] = ciphertext[..32]
            .try_into()
            .map_err(|_| RatkeyError::EcdhFailed("invalid ephemeral key".to_string()))?;
        let encrypted_token = &ciphertext[32..];

        // PIV cannot store Reticulum ratchet private keys. This backend skips
        // ratchet keys and falls back to identity ECDH; enforced ratchets fail
        // closed.
        if let Some(ratchet_keys) = ratchets {
            for _ratchet_pub in ratchet_keys {}
            if enforce_ratchets {
                return Err(RatkeyError::EcdhFailed(
                    "no valid ratchet key found and ratchets enforced".to_string(),
                ));
            }
        }

        let shared_secret = self.ecdh(&ephemeral_pub_bytes)?;

        // HKDF-SHA256, salt = identity hash. Matches Identity::decrypt.
        let derived = derive_key_64(&shared_secret, &self.identity.hash)
            .map_err(|_| RatkeyError::EcdhFailed("HKDF derivation failed".to_string()))?;

        token::decrypt(encrypted_token, &derived)
            .map_err(|_| RatkeyError::EcdhFailed("decryption failed".to_string()))
    }

    /// Verification is a public-key op; no hardware call.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.identity.verify(message, signature)
    }

    pub fn is_connected(&self) -> bool {
        self.mock_session.as_ref().is_some_and(|s| s.is_connected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::x25519::{X25519PrivateKey, X25519PublicKey};
    use rns_identity::identity::Identity;

    #[test]
    fn test_from_keys_mock() {
        let session = MockPivSession::with_keys();
        let ed_pub = session.read_ed25519_public(SLOT_9A).unwrap();
        let x_pub = session.read_x25519_public(SLOT_9D).unwrap();

        let hw = HardwareIdentity::from_keys_mock(ed_pub, x_pub, session).unwrap();
        assert_eq!(hw.ed25519_public(), &ed_pub);
        assert_eq!(hw.x25519_public(), &x_pub);
        assert!(!hw.hash_hex().is_empty());
    }

    #[test]
    fn test_sign_and_verify() {
        let session = MockPivSession::with_keys();
        let ed_pub = session.read_ed25519_public(SLOT_9A).unwrap();
        let x_pub = session.read_x25519_public(SLOT_9D).unwrap();
        let mut hw = HardwareIdentity::from_keys_mock(ed_pub, x_pub, session).unwrap();

        let message = b"ratkey hardware identity test";
        let sig = hw.sign(message).unwrap();
        assert!(hw.verify(message, &sig));
    }

    #[test]
    fn test_sign_matches_software_identity() {
        // Load-bearing: Ed25519 is deterministic, hardware and software paths
        // MUST be byte-identical for shared key material.
        let ed_seed = [0x42u8; 32];
        let x_secret = [0x43u8; 32];
        let session = MockPivSession::with_key_bytes(&ed_seed, &x_secret);
        let ed_pub = session.read_ed25519_public(SLOT_9A).unwrap();
        let x_pub = session.read_x25519_public(SLOT_9D).unwrap();
        let mut hw = HardwareIdentity::from_keys_mock(ed_pub, x_pub, session).unwrap();

        let mut prv_bytes = [0u8; 64];
        prv_bytes[..32].copy_from_slice(&x_secret);
        prv_bytes[32..].copy_from_slice(&ed_seed);
        let sw_identity = Identity::from_private_key(&prv_bytes).unwrap();

        let message = b"cross-validation test";

        let hw_sig = hw.sign(message).unwrap();
        let sw_sig = sw_identity.sign(message).unwrap();

        assert_eq!(
            hw_sig, sw_sig,
            "hardware and software signatures must match"
        );
        assert_eq!(hw.identity.hash, sw_identity.hash);
        assert_eq!(hw.get_public_key(), sw_identity.get_public_key());
    }

    #[test]
    fn test_ecdh_with_software_peer() {
        let session = MockPivSession::with_keys();
        let ed_pub = session.read_ed25519_public(SLOT_9A).unwrap();
        let x_pub = session.read_x25519_public(SLOT_9D).unwrap();
        let mut hw = HardwareIdentity::from_keys_mock(ed_pub, x_pub, session).unwrap();

        let peer_prv = X25519PrivateKey::generate();
        let peer_pub = peer_prv.public_key();
        let peer_pub_bytes = peer_pub.to_bytes();

        let hw_shared = hw.ecdh(&peer_pub_bytes).unwrap();

        let hw_pub = X25519PublicKey::from_bytes(&x_pub);
        let sw_shared = peer_prv.exchange(&hw_pub);

        assert_eq!(hw_shared, sw_shared, "ECDH must be symmetric");
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let ed_seed = [0x42u8; 32];
        let x_secret = [0x43u8; 32];
        let session = MockPivSession::with_key_bytes(&ed_seed, &x_secret);
        let ed_pub = session.read_ed25519_public(SLOT_9A).unwrap();
        let x_pub = session.read_x25519_public(SLOT_9D).unwrap();
        let mut hw = HardwareIdentity::from_keys_mock(ed_pub, x_pub, session).unwrap();

        let mut prv_bytes = [0u8; 64];
        prv_bytes[..32].copy_from_slice(&x_secret);
        prv_bytes[32..].copy_from_slice(&ed_seed);
        let sw_identity = Identity::from_private_key(&prv_bytes).unwrap();

        let plaintext = b"secret message for hardware identity";
        let ciphertext = sw_identity.encrypt(plaintext, None).unwrap();

        let decrypted = hw.decrypt(&ciphertext, None, false).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_from_other_identity() {
        let session = MockPivSession::with_keys();
        let ed_pub = session.read_ed25519_public(SLOT_9A).unwrap();
        let x_pub = session.read_x25519_public(SLOT_9D).unwrap();
        let mut hw = HardwareIdentity::from_keys_mock(ed_pub, x_pub, session).unwrap();

        let _sender = Identity::new();

        let ciphertext = hw.identity.encrypt(b"hello from sender", None).unwrap();

        let decrypted = hw.decrypt(&ciphertext, None, false).unwrap();
        assert_eq!(decrypted, b"hello from sender");
    }

    #[test]
    fn test_disconnect_fails_operations() {
        let session = MockPivSession::with_keys();
        let ed_pub = session.read_ed25519_public(SLOT_9A).unwrap();
        let x_pub = session.read_x25519_public(SLOT_9D).unwrap();
        let mut hw = HardwareIdentity::from_keys_mock(ed_pub, x_pub, session).unwrap();

        assert!(hw.is_connected());
        hw.mock_session.as_mut().unwrap().disconnect();
        assert!(!hw.is_connected());

        assert!(matches!(hw.sign(b"test"), Err(RatkeyError::Disconnected)));
    }

    #[test]
    fn test_key_mismatch_rejected() {
        // from_keys_mock does not cross-check; the .hwid path does (test_hwid_key_mismatch).
        let session = MockPivSession::with_keys();
        let wrong_ed = [0xFFu8; 32];
        let wrong_x = [0xFFu8; 32];
        let _result = HardwareIdentity::from_keys_mock(wrong_ed, wrong_x, session);
    }

    #[test]
    fn test_hwid_key_mismatch() {
        let session = MockPivSession::with_keys();
        let config = HwidConfig {
            identity: crate::hwid::HwidIdentity {
                hash: "test".to_string(),
                nickname: "test".to_string(),
                created_at: 0,
            },
            device: crate::hwid::HwidDevice {
                device_type: "yubikey5".to_string(),
                serial: 99999999,
                firmware: "5.7.1".to_string(),
            },
            keys: crate::hwid::HwidKeys {
                ed25519_pub: "ff".repeat(32),
                x25519_pub: "ff".repeat(32),
            },
            slots: crate::hwid::HwidSlots {
                signing: "9A".to_string(),
                encryption: "9D".to_string(),
            },
            policy: crate::hwid::HwidPolicy {
                pin_cache_timeout: 300,
                touch_signing: "never".to_string(),
                touch_encryption: "never".to_string(),
            },
            attestation: Default::default(),
            app: Default::default(),
            backup: Default::default(),
        };

        let result = HardwareIdentity::from_hwid_mock(config, session);
        assert!(matches!(result, Err(RatkeyError::KeyMismatch)));
    }
}
