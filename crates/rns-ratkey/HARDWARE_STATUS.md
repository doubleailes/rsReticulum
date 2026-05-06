# RatKey Hardware Status

RatKey hardware identity support is intentionally not release-grade until it is
verified against real devices. The mock-backed tests cover public identity
shape, signing, ECDH, decrypt flow, and fail-closed key mismatch behavior, but
they do not prove PIV transport, touch/PIN policy, or X.509 chain verification.

Required before hardware RatKey is documented as supported:

- Replace the mock-only `HardwareIdentity` session storage with a real PIV
  backend abstraction and YubiKey/Nitrokey implementations.
- Verify signing and ECDH against physical YubiKeys, including disconnect,
  wrong PIN, touch timeout, and slot mismatch cases.
- Implement cryptographic attestation certificate chain verification against
  the bundled Yubico roots and intermediates.
- Decide and document the ratchet policy for hardware identities. PIV cannot
  hold Reticulum ratchet private keys, so enforced-ratchet decrypt currently
  fails closed.
- Add hardware-gated tests that are skipped by default but run when a device is
  explicitly selected by environment/config.

Until those items pass on real devices, CLI/UI surfaces must label hardware
RatKey support as experimental.
