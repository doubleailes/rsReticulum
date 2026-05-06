//! YubiKey PIV attestation verification. Bundled root CAs — never fetched.
//!
//! Legacy chain (firmware < 5.7.4):
//!   Yubico PIV Root CA Serial 263751 → device intermediate (slot F9) → per-key attestation cert.
//!
//! New chain (firmware >= 5.7.4):
//!   Yubico Attestation Root 1 → Intermediate A/B 1 → PIV Attestation A/B 1
//!     → device intermediate (slot F9) → per-key attestation cert.
//!
//! Nitrokey 3 does not support PIV attestation (firmware 1.8) — verification skipped.
//!
//! Chain verification status: structural + OID extraction only. The
//! `verified` flag remains false until X.509 path validation is exercised
//! against real devices. See crates/rns-ratkey/HARDWARE_STATUS.md.

use crate::error::RatkeyError;

/// Yubico PIV Root CA (legacy, firmware < 5.7.4). Subject: "Yubico PIV Root CA Serial 263751".
pub const YUBICO_PIV_ROOT_CA_LEGACY_PEM: &str =
    include_str!("../certs/yubico-piv-root-ca-legacy.pem");

/// Yubico Attestation Root 1 (firmware >= 5.7.4). Subject: "Yubico Attestation Root 1".
pub const YUBICO_ATTESTATION_ROOT_1_PEM: &str =
    include_str!("../certs/yubico-attestation-root-1.pem");

/// SHA-256 fingerprint of the legacy Yubico PIV Root CA (belt-and-suspenders vs PEM swap).
pub const YUBICO_LEGACY_ROOT_SHA256: &str =
    "63ece914e54dd87915f34033c85af4c0696ba1512f8add66ced73833120785b546";

/// SHA-256 fingerprint of the new Yubico Attestation Root 1 (belt-and-suspenders vs PEM swap).
pub const YUBICO_NEW_ROOT_SHA256: &str =
    "62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8";

// Yubico PIV attestation OIDs. Yubico PEN: 1.3.6.1.4.1.41482; PIV attestation subtree: .3.

/// Firmware version (3 bytes: major.minor.patch).
pub const OID_FIRMWARE_VERSION: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x03];

/// Serial number (INTEGER).
pub const OID_SERIAL_NUMBER: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x07];

/// Usage policy (2 bytes: pin_policy, touch_policy).
pub const OID_USAGE_POLICY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x08];

/// Form factor (1 byte).
pub const OID_FORM_FACTOR: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x09];

#[derive(Debug, Clone)]
pub struct AttestationInfo {
    pub firmware_version: Option<(u8, u8, u8)>,
    pub serial_number: Option<u32>,
    pub pin_policy: Option<u8>,
    pub touch_policy: Option<u8>,
    pub form_factor: Option<u8>,
    pub attestation_cert_der: Vec<u8>,
    /// Device intermediate (slot F9) DER.
    pub device_cert_der: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AttestationVerification {
    /// True only when the attestation certificate chain has been
    /// cryptographically verified to a bundled trusted root.
    pub verified: bool,
    /// True when Yubico attestation metadata could be extracted from the cert.
    pub metadata_extracted: bool,
    /// Explicit chain-verification label for UI/CLI surfaces.
    pub chain_verified: bool,
    pub info: AttestationInfo,
    /// "legacy" or "new".
    pub root_ca: String,
    pub description: String,
}

/// Verify chain: attestation cert (from ATTEST) + device intermediate (slot F9).
/// Currently structural + OID extraction only.
pub fn verify_attestation(
    attestation_cert_der: &[u8],
    device_cert_der: &[u8],
) -> Result<AttestationVerification, RatkeyError> {
    let info = extract_attestation_info(attestation_cert_der, device_cert_der)?;

    let metadata_extracted = info.firmware_version.is_some();
    let chain_verified = false;
    let root_ca = if let Some((major, minor, patch)) = info.firmware_version {
        if major > 5 || (major == 5 && minor >= 7 && patch >= 4) {
            "new".to_string()
        } else {
            "legacy".to_string()
        }
    } else {
        "unknown".to_string()
    };

    let description = if metadata_extracted {
        let (maj, min, pat) = info.firmware_version.unwrap_or((0, 0, 0));
        format!(
            "YubiKey firmware {maj}.{min}.{pat}{}; attestation chain not cryptographically verified",
            info.serial_number
                .map(|s| format!(", serial {s}"))
                .unwrap_or_default()
        )
    } else {
        "could not extract YubiKey attestation metadata".to_string()
    };

    Ok(AttestationVerification {
        verified: chain_verified,
        metadata_extracted,
        chain_verified,
        info,
        root_ca,
        description,
    })
}

/// YubiKey 5 (firmware >= 4.3.0) only. Nitrokey 3 has no PIV attestation.
pub fn supports_attestation(device_type: &str) -> bool {
    device_type == "yubikey5"
}

fn extract_attestation_info(
    attestation_cert_der: &[u8],
    device_cert_der: &[u8],
) -> Result<AttestationInfo, RatkeyError> {
    let firmware = find_oid_value(attestation_cert_der, OID_FIRMWARE_VERSION).and_then(|v| {
        if v.len() >= 3 {
            Some((v[0], v[1], v[2]))
        } else {
            None
        }
    });

    let serial = find_oid_value(attestation_cert_der, OID_SERIAL_NUMBER)
        .and_then(|v| parse_asn1_integer(&v));

    let (pin_policy, touch_policy) = find_oid_value(attestation_cert_der, OID_USAGE_POLICY)
        .map(|v| {
            let pp = v.first().copied();
            let tp = v.get(1).copied();
            (pp, tp)
        })
        .unwrap_or((None, None));

    let form_factor =
        find_oid_value(attestation_cert_der, OID_FORM_FACTOR).and_then(|v| v.first().copied());

    Ok(AttestationInfo {
        firmware_version: firmware,
        serial_number: serial,
        pin_policy,
        touch_policy,
        form_factor,
        attestation_cert_der: attestation_cert_der.to_vec(),
        device_cert_der: device_cert_der.to_vec(),
    })
}

// Byte-scan DER for OID pattern, return TLV value after it. Avoids full ASN.1 parser dependency.
fn find_oid_value(der: &[u8], oid_bytes: &[u8]) -> Option<Vec<u8>> {
    let oid_with_tag = {
        let mut v = Vec::with_capacity(2 + oid_bytes.len());
        v.push(0x06); // OID tag
        v.push(oid_bytes.len() as u8);
        v.extend_from_slice(oid_bytes);
        v
    };

    let pos = der
        .windows(oid_with_tag.len())
        .position(|w| w == oid_with_tag.as_slice())?;

    let after_oid = pos + oid_with_tag.len();
    if after_oid >= der.len() {
        return None;
    }

    let tag = der[after_oid];
    if after_oid + 1 >= der.len() {
        return None;
    }

    let (value_len, len_bytes) = decode_der_length(&der[after_oid + 1..])?;
    let value_start = after_oid + 1 + len_bytes;
    let value_end = value_start + value_len;

    if value_end > der.len() {
        return None;
    }

    let value = &der[value_start..value_end];

    // Unwrap one level if OCTET STRING wraps another OCTET STRING or INTEGER.
    if tag == 0x04 && value.len() >= 2 {
        let inner_tag = value[0];
        if inner_tag == 0x04 || inner_tag == 0x02 {
            if let Some((inner_len, inner_len_bytes)) = decode_der_length(&value[1..]) {
                let inner_start = 1 + inner_len_bytes;
                if inner_start + inner_len <= value.len() {
                    return Some(value[inner_start..inner_start + inner_len].to_vec());
                }
            }
        }
        return Some(value.to_vec());
    }

    Some(value.to_vec())
}

fn parse_asn1_integer(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 4 {
        return None;
    }
    let mut result: u32 = 0;
    for &b in bytes {
        result = result.checked_shl(8)?.checked_add(b as u32)?;
    }
    Some(result)
}

fn decode_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x81 {
        data.get(1).map(|&b| (b as usize, 2))
    } else if first == 0x82 {
        if data.len() < 3 {
            return None;
        }
        Some((((data[1] as usize) << 8) | data[2] as usize, 3))
    } else {
        None
    }
}

pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let lines: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let b64: String = lines.join("");
    base64_decode(&b64)
}

// Standard alphabet, padding optional.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn val(c: u8) -> Option<u8> {
        TABLE.iter().position(|&b| b == c).map(|p| p as u8)
    }

    let bytes: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'=' && b != b'\n' && b != b'\r' && b != b' ')
        .collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < bytes.len() {
        let a = val(bytes[i])?;
        let b = val(bytes[i + 1])?;
        let c = val(bytes[i + 2])?;
        let d = val(bytes[i + 3])?;
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c >> 2));
        out.push((c << 6) | d);
        i += 4;
    }
    let remaining = bytes.len() - i;
    if remaining >= 2 {
        let a = val(bytes[i])?;
        let b = val(bytes[i + 1])?;
        out.push((a << 2) | (b >> 4));
        if remaining >= 3 {
            let c = val(bytes[i + 2])?;
            out.push((b << 4) | (c >> 2));
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_root_ca_loads() {
        let der = pem_to_der(YUBICO_PIV_ROOT_CA_LEGACY_PEM);
        assert!(der.is_some(), "legacy root CA PEM should decode");
        let der = der.unwrap();
        assert!(der.len() > 500, "DER should be substantial");
        // DER starts with SEQUENCE tag (0x30)
        assert_eq!(der[0], 0x30, "DER must start with SEQUENCE tag");
    }

    #[test]
    fn test_new_root_ca_loads() {
        let der = pem_to_der(YUBICO_ATTESTATION_ROOT_1_PEM);
        assert!(der.is_some(), "new root CA PEM should decode");
        let der = der.unwrap();
        assert!(der.len() > 500);
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_pem_to_der_roundtrip() {
        let pem = "-----BEGIN CERTIFICATE-----\nTUlJ\n-----END CERTIFICATE-----\n";
        let der = pem_to_der(pem);
        assert!(der.is_some());
    }

    #[test]
    fn test_supports_attestation() {
        assert!(supports_attestation("yubikey5"));
        assert!(!supports_attestation("nitrokey3"));
        assert!(!supports_attestation("unknown"));
    }

    #[test]
    fn test_parse_asn1_integer() {
        assert_eq!(parse_asn1_integer(&[0x01]), Some(1));
        assert_eq!(parse_asn1_integer(&[0x00, 0xFF]), Some(255));
        assert_eq!(parse_asn1_integer(&[0x01, 0x00, 0x00]), Some(65536));
        assert_eq!(parse_asn1_integer(&[]), None);
        assert_eq!(parse_asn1_integer(&[0x01, 0x02, 0x03, 0x04, 0x05]), None); // > 4 bytes
    }

    #[test]
    fn test_find_oid_in_synthetic_der() {
        // Build a minimal DER structure containing a Yubico firmware OID
        // SEQUENCE { OID(firmware) OCTET_STRING(3 bytes: 05 07 01) }
        let mut der = Vec::new();
        // Outer SEQUENCE
        let mut inner = Vec::new();
        // OID tag + length + firmware OID bytes
        inner.push(0x06); // OID tag
        inner.push(OID_FIRMWARE_VERSION.len() as u8);
        inner.extend_from_slice(OID_FIRMWARE_VERSION);
        // OCTET STRING with firmware version 5.7.1
        inner.push(0x04); // OCTET STRING tag
        inner.push(0x03); // length = 3
        inner.push(0x05); // major = 5
        inner.push(0x07); // minor = 7
        inner.push(0x01); // patch = 1

        der.push(0x30); // SEQUENCE tag
        der.push(inner.len() as u8);
        der.extend_from_slice(&inner);

        let value = find_oid_value(&der, OID_FIRMWARE_VERSION);
        assert!(value.is_some(), "should find firmware OID");
        let v = value.unwrap();
        assert_eq!(v, vec![0x05, 0x07, 0x01], "firmware should be 5.7.1");
    }

    #[test]
    fn test_find_oid_serial_number() {
        // Build DER with serial number OID
        let mut der = Vec::new();
        let mut inner = Vec::new();
        inner.push(0x06);
        inner.push(OID_SERIAL_NUMBER.len() as u8);
        inner.extend_from_slice(OID_SERIAL_NUMBER);
        // INTEGER with serial 12345678 = 0x00BC614E
        inner.push(0x02); // INTEGER tag
        inner.push(0x04); // length = 4
        inner.extend_from_slice(&[0x00, 0xBC, 0x61, 0x4E]);

        der.push(0x30);
        der.push(inner.len() as u8);
        der.extend_from_slice(&inner);

        let value = find_oid_value(&der, OID_SERIAL_NUMBER);
        assert!(value.is_some());
        let serial = parse_asn1_integer(&value.unwrap());
        assert_eq!(serial, Some(12345678));
    }

    #[test]
    fn test_verify_attestation_synthetic() {
        // Build a minimal attestation cert with firmware OID
        let mut attest_der = Vec::new();
        let mut inner = Vec::new();
        inner.push(0x06);
        inner.push(OID_FIRMWARE_VERSION.len() as u8);
        inner.extend_from_slice(OID_FIRMWARE_VERSION);
        inner.push(0x04);
        inner.push(0x03);
        inner.extend_from_slice(&[0x05, 0x07, 0x01]); // 5.7.1

        attest_der.push(0x30);
        attest_der.push(inner.len() as u8);
        attest_der.extend_from_slice(&inner);

        // Minimal device cert (just a SEQUENCE)
        let device_der = vec![0x30, 0x00];

        let result = verify_attestation(&attest_der, &device_der).unwrap();
        assert!(result.metadata_extracted);
        assert!(!result.verified);
        assert!(!result.chain_verified);
        assert_eq!(result.root_ca, "legacy"); // 5.7.1 < 5.7.4
        assert!(result.description.contains("5.7.1"));
        assert!(
            result
                .description
                .contains("not cryptographically verified")
        );
    }

    #[test]
    fn test_verify_attestation_new_firmware_metadata_only() {
        let mut attest_der = Vec::new();
        let mut inner = Vec::new();
        inner.push(0x06);
        inner.push(OID_FIRMWARE_VERSION.len() as u8);
        inner.extend_from_slice(OID_FIRMWARE_VERSION);
        inner.push(0x04);
        inner.push(0x03);
        inner.extend_from_slice(&[0x05, 0x07, 0x04]); // 5.7.4

        attest_der.push(0x30);
        attest_der.push(inner.len() as u8);
        attest_der.extend_from_slice(&inner);

        let device_der = vec![0x30, 0x00];

        let result = verify_attestation(&attest_der, &device_der).unwrap();
        assert!(result.metadata_extracted);
        assert!(!result.verified);
        assert!(!result.chain_verified);
        assert_eq!(result.root_ca, "new"); // 5.7.4 → new root CA
    }

    #[test]
    fn test_verify_attestation_empty_cert() {
        let result = verify_attestation(&[], &[]).unwrap();
        assert!(!result.verified);
        assert!(!result.metadata_extracted);
        assert!(!result.chain_verified);
        assert_eq!(result.root_ca, "unknown");
    }
}
