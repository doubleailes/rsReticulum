//! Firmware manifest, cache and hash helpers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::model;

pub const DEFAULT_FIRMWARE_VERSION_URL: &str =
    "https://github.com/markqvist/rnode_firmware/releases/latest/download/release.json";
pub const FIRMWARE_UPDATE_URL: &str =
    "https://github.com/markqvist/RNode_Firmware/releases/download/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareRelease {
    pub filename: String,
    pub version: String,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePaths {
    pub root: PathBuf,
    pub update: PathBuf,
    pub firmware: PathBuf,
    pub extracted: PathBuf,
    pub trusted_keys: PathBuf,
    pub eeprom: PathBuf,
}

impl CachePaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            update: root.join("update"),
            firmware: root.join("firmware"),
            extracted: root.join("extracted"),
            trusted_keys: root.join("trusted_keys"),
            eeprom: root.join("eeprom"),
            root,
        }
    }

    pub fn update_version_file(&self, version: &str, filename: &str) -> PathBuf {
        self.update
            .join(version)
            .join(format!("{filename}.version"))
    }
}

#[derive(Debug, Deserialize)]
struct ManifestEntry {
    version: String,
    hash: String,
}

pub fn parse_release_manifest(json: &str) -> Result<Vec<FirmwareRelease>, String> {
    let entries: BTreeMap<String, ManifestEntry> =
        serde_json::from_str(json).map_err(|e| format!("invalid release manifest: {e}"))?;
    entries
        .into_iter()
        .map(|(filename, entry)| {
            let hash = parse_sha256_hex(&entry.hash)?;
            Ok(FirmwareRelease {
                filename,
                version: entry.version,
                hash,
            })
        })
        .collect()
}

pub fn selected_release<'a>(
    releases: &'a [FirmwareRelease],
    filename: &str,
) -> Option<&'a FirmwareRelease> {
    releases.iter().find(|release| release.filename == filename)
}

pub fn cache_version_record(version: &str, hash: &[u8; 32]) -> String {
    format!("{version} {}", hex::encode(hash))
}

pub fn verify_package_hash(data: &[u8], expected: &[u8; 32]) -> bool {
    &rns_crypto::sha::sha256(data) == expected
}

pub fn partition_hash(platform: u8, firmware_data: &[u8]) -> Option<[u8; 32]> {
    match platform {
        model::PLATFORM_AVR | model::PLATFORM_ESP32 => {
            let payload = firmware_data.get(..firmware_data.len().checked_sub(32)?)?;
            let embedded: [u8; 32] = firmware_data[firmware_data.len() - 32..].try_into().ok()?;
            (rns_crypto::sha::sha256(payload) == embedded).then_some(embedded)
        }
        model::PLATFORM_NRF52 => Some(rns_crypto::sha::sha256(firmware_data)),
        _ => None,
    }
}

pub fn extracted_required_files(root: &Path) -> [PathBuf; 5] {
    [
        root.join("extracted_rnode_firmware.bin"),
        root.join("extracted_rnode_firmware.boot_app0"),
        root.join("extracted_rnode_firmware.bootloader"),
        root.join("extracted_rnode_firmware.partitions"),
        root.join("extracted_console_image.bin"),
    ]
}

pub fn parse_sha256_hex(hex_value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_value).map_err(|e| format!("invalid SHA-256 hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 32-byte SHA-256, got {} bytes", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_manifest_parses_hashes_by_filename() {
        let json = r#"{
            "rnode_firmware.hex": {
                "version": "1.73",
                "hash": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            },
            "rnode_firmware_t3s3.zip": {
                "version": "1.74",
                "hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            }
        }"#;
        let releases = parse_release_manifest(json).unwrap();
        assert_eq!(releases.len(), 2);
        let release = selected_release(&releases, "rnode_firmware.hex").unwrap();
        assert_eq!(release.version, "1.73");
        assert_eq!(release.hash[0], 0x00);
        assert_eq!(release.hash[31], 0xFF);
    }

    #[test]
    fn cache_paths_match_upstream_layout() {
        let paths = CachePaths::new("/tmp/rnodeconf");
        assert_eq!(paths.update, PathBuf::from("/tmp/rnodeconf/update"));
        assert_eq!(paths.firmware, PathBuf::from("/tmp/rnodeconf/firmware"));
        assert_eq!(
            paths.update_version_file("1.73", "rnode_firmware.hex"),
            PathBuf::from("/tmp/rnodeconf/update/1.73/rnode_firmware.hex.version")
        );
    }

    #[test]
    fn partition_hash_matches_upstream_platform_rules() {
        let payload = b"firmware-image";
        let hash = rns_crypto::sha::sha256(payload);
        let mut esp32 = payload.to_vec();
        esp32.extend_from_slice(&hash);
        assert_eq!(partition_hash(model::PLATFORM_ESP32, &esp32), Some(hash));

        let nrf_hash = rns_crypto::sha::sha256(&esp32);
        assert_eq!(
            partition_hash(model::PLATFORM_NRF52, &esp32),
            Some(nrf_hash)
        );

        esp32[0] ^= 1;
        assert_eq!(partition_hash(model::PLATFORM_ESP32, &esp32), None);
    }
}
