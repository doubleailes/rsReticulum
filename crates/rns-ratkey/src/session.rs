//! Real PIV session over PC/SC (YubiKey 5, Nitrokey 3).
//! Requires `hardware` feature + PC/SC daemon (macOS CryptoTokenKit / Linux pcscd / Windows WinSCard).

use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use tracing::{debug, warn};
use zeroize::Zeroize;

use crate::apdu;
use crate::detect::DeviceType;
use crate::error::RatkeyError;
use crate::pin::PinCache;

const MAX_RESPONSE: usize = 4096;

pub struct PivSession {
    card: Card,
    device_type: DeviceType,
    reader_name: String,
    serial: Option<u32>,
    firmware: Option<String>,
    pin_cache: PinCache,
}

impl PivSession {
    pub fn connect() -> Result<Self, RatkeyError> {
        let devices = crate::detect::detect_devices()?;
        let device = devices.first().ok_or(RatkeyError::NoDevice)?;
        Self::connect_reader(&device.reader_name)
    }

    pub fn connect_reader(reader_name: &str) -> Result<Self, RatkeyError> {
        let ctx = Context::establish(Scope::User)?;
        let reader = std::ffi::CString::new(reader_name)
            .map_err(|_| RatkeyError::UnsupportedDevice(reader_name.to_string()))?;

        let card = ctx.connect(&reader, ShareMode::Shared, Protocols::ANY)?;

        let resp = transmit(&card, &apdu::select_piv())?;
        apdu::check_response(&resp)?;

        let device_type = crate::detect::detect_device_type(reader_name);
        debug!(
            "PIV session established with {} ({})",
            reader_name,
            device_type.as_str()
        );

        let (serial, firmware) = crate::detect::read_identity(&card, device_type);

        Ok(Self {
            card,
            device_type,
            reader_name: reader_name.to_string(),
            serial,
            firmware,
            pin_cache: PinCache::default_timeout(),
        })
    }

    pub fn device_type(&self) -> DeviceType {
        self.device_type
    }

    pub fn reader_name(&self) -> &str {
        &self.reader_name
    }

    pub fn serial(&self) -> Option<u32> {
        self.serial
    }

    pub fn firmware(&self) -> Option<&str> {
        self.firmware.as_deref()
    }

    /// Probes the attestation slot (F9) — always present on provisioned tokens.
    pub fn is_connected(&self) -> bool {
        let cmd = apdu::get_metadata(apdu::SLOT_ATTESTATION);
        let mut buf = vec![0u8; 256];
        self.card.transmit(&cmd, &mut buf).is_ok()
    }

    pub fn verify_pin(&mut self, pin: &str) -> Result<(), RatkeyError> {
        let cmd = apdu::verify_pin(pin);
        let resp = transmit(&self.card, &cmd)?;
        apdu::check_response(&resp)?;
        self.pin_cache.cache(pin);
        debug!("PIN verified");
        Ok(())
    }

    pub fn change_pin(&mut self, old_pin: &str, new_pin: &str) -> Result<(), RatkeyError> {
        let cmd = apdu::change_pin(old_pin, new_pin);
        let resp = transmit(&self.card, &cmd)?;
        apdu::check_response(&resp)?;
        self.pin_cache.cache(new_pin);
        debug!("PIN changed");
        Ok(())
    }

    pub fn generate_ed25519(
        &self,
        slot: u8,
        pin_policy: Option<u8>,
        touch_policy: Option<u8>,
    ) -> Result<[u8; 32], RatkeyError> {
        let cmd = apdu::generate_key(slot, apdu::ALG_ED25519, pin_policy, touch_policy);
        let resp = transmit(&self.card, &cmd)?;
        let data = apdu::check_response(&resp)?;
        apdu::parse_generate_response(data)
    }

    pub fn generate_x25519(
        &self,
        slot: u8,
        pin_policy: Option<u8>,
        touch_policy: Option<u8>,
    ) -> Result<[u8; 32], RatkeyError> {
        let cmd = apdu::generate_key(slot, apdu::ALG_X25519, pin_policy, touch_policy);
        let resp = transmit(&self.card, &cmd)?;
        let data = apdu::check_response(&resp)?;
        apdu::parse_generate_response(data)
    }

    pub fn sign_ed25519(&self, slot: u8, message: &[u8]) -> Result<[u8; 64], RatkeyError> {
        let cmd = apdu::sign_ed25519(slot, message);
        let resp = transmit(&self.card, &cmd)?;
        let data = apdu::check_response(&resp)?;
        apdu::parse_sign_response(data)
    }

    pub fn ecdh_x25519(&self, slot: u8, peer_pub: &[u8; 32]) -> Result<[u8; 32], RatkeyError> {
        let cmd = apdu::ecdh_x25519(slot, peer_pub);
        let resp = transmit(&self.card, &cmd)?;
        let data = apdu::check_response(&resp)?;
        let mut secret = apdu::parse_ecdh_response(data)?;
        // Wipes local stack copy only. Caller must zeroize the returned bytes.
        let result = secret;
        secret.zeroize();
        Ok(result)
    }

    /// Returns DER-encoded X.509 attestation certificate.
    pub fn attest_key(&self, slot: u8) -> Result<Vec<u8>, RatkeyError> {
        let cmd = apdu::attest_key(slot);
        let resp = transmit(&self.card, &cmd)?;
        let data = apdu::check_response(&resp)?;
        Ok(data.to_vec())
    }

    pub fn read_certificate(&self, slot: u8) -> Result<Vec<u8>, RatkeyError> {
        let cmd = apdu::get_data(slot).ok_or(RatkeyError::EmptySlot { slot })?;
        let resp = transmit(&self.card, &cmd)?;
        let data = apdu::check_response(&resp)?;
        Ok(data.to_vec())
    }

    /// Returns raw metadata TLV bytes.
    pub fn read_metadata(&self, slot: u8) -> Result<Vec<u8>, RatkeyError> {
        let cmd = apdu::get_metadata(slot);
        let resp = transmit(&self.card, &cmd)?;
        let data = apdu::check_response(&resp)?;
        Ok(data.to_vec())
    }
}

fn transmit(card: &Card, command: &[u8]) -> Result<Vec<u8>, RatkeyError> {
    let mut response_buf = vec![0u8; MAX_RESPONSE];
    let response = card.transmit(command, &mut response_buf).map_err(|e| {
        warn!("PC/SC transmit failed: {}", e);
        RatkeyError::Disconnected
    })?;
    Ok(response.to_vec())
}
