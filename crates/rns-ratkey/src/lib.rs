//! Hardware-backed identity (YubiKey 5, Nitrokey 3) via PIV. Ed25519 sign + X25519
//! ECDH keys live on-device; only public keys and results leave the token.
//! Wire-compatible with software identities. `hardware` feature enables real PIV via `pcsc`.

pub mod apdu;
pub mod attestation;
pub mod error;
pub mod hardware;
pub mod hwid;
pub mod mock;
pub mod pin;
pub mod provision;

#[cfg(feature = "hardware")]
pub mod detect;
#[cfg(feature = "hardware")]
pub mod session;

pub use error::RatkeyError;
pub use hardware::HardwareIdentity;
pub use hwid::HwidConfig;
pub use mock::MockPivSession;
pub use pin::PinCache;
pub use provision::{ProvisionConfig, ProvisionResult};
