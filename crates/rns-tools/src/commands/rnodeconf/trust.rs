//! Trust-store and device-signing helpers for rnodeconf.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rns_identity::identity::Identity;
use rns_interface::rnode_admin::{self, AdminFrame};

pub const SIGNING_KEY_RELATIVE_PATH: &[&str] = &["firmware", "signing.key"];
pub const DEVICE_KEY_FILENAME: &str = "device.key";

pub fn trusted_key_filename(public_key_der: &[u8]) -> String {
    format!(
        "{}.pubkey",
        hex::encode(rns_crypto::sha::sha256(public_key_der))
    )
}

pub fn trusted_key_path(root: &Path, public_key_der: &[u8]) -> PathBuf {
    root.join("trusted_keys")
        .join(trusted_key_filename(public_key_der))
}

pub fn write_trusted_key(root: &Path, public_key_der: &[u8]) -> io::Result<PathBuf> {
    let path = trusted_key_path(root, public_key_der);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, public_key_der)?;
    Ok(path)
}

pub fn signing_key_path(root: &Path) -> PathBuf {
    SIGNING_KEY_RELATIVE_PATH
        .iter()
        .fold(root.to_path_buf(), |path, component| path.join(component))
}

pub fn device_key_path(root: &Path) -> PathBuf {
    root.join(DEVICE_KEY_FILENAME)
}

pub fn load_device_identity(path: &Path) -> Result<Identity, String> {
    Identity::from_file(path).map_err(|e| format!("could not load device identity: {e}"))
}

pub fn sign_device_hash(identity: &Identity, device_hash: &[u8; 32]) -> Result<[u8; 64], String> {
    identity
        .sign(device_hash)
        .ok_or_else(|| "device identity does not contain a private signing key".to_string())
}

pub fn device_signature_frame(signature: &[u8; 64]) -> AdminFrame {
    rnode_admin::device_signature_frame(signature)
}

pub fn firmware_hash_frame(hash: &[u8; 32]) -> AdminFrame {
    rnode_admin::firmware_hash_frame(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_key_filename_is_sha256_pubkey_name() {
        let der = b"not-real-der-but-stable";
        assert_eq!(
            trusted_key_filename(der),
            format!("{}.pubkey", hex::encode(rns_crypto::sha::sha256(der)))
        );
    }

    #[test]
    fn device_hash_signing_uses_reticulum_identity_key() {
        let private = [7u8; 64];
        let identity = Identity::from_private_key(&private).unwrap();
        let device_hash = [9u8; 32];
        let signature = sign_device_hash(&identity, &device_hash).unwrap();
        assert!(identity.verify(&device_hash, &signature));
        assert_eq!(
            device_signature_frame(&signature),
            rnode_admin::device_signature_frame(&signature)
        );
    }
}
