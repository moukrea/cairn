use std::time::Duration;

use qrcode::EcLevel;

use super::{MechanismError, MechanismType, PairingMechanism, PairingPayload};

/// Maximum payload size for QR code encoding (256 bytes).
const MAX_QR_PAYLOAD_SIZE: usize = 256;

/// Default TTL for QR code pairing payloads (5 minutes).
const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// QR code pairing mechanism.
///
/// Generates a binary CBOR payload suitable for QR code encoding at EC Level M.
/// Maximum payload size is 256 bytes, fitting within QR Version 14 (73x73 modules).
pub struct QrCodeMechanism {
    pub ttl: Duration,
}

impl Default for QrCodeMechanism {
    fn default() -> Self {
        Self { ttl: DEFAULT_TTL }
    }
}

impl QrCodeMechanism {
    /// Create a new QR code mechanism with a custom TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self { ttl }
    }

    /// Generate a QR code image from a pairing payload.
    ///
    /// Returns the QR code as a string of '0' and '1' characters representing
    /// the module grid. The caller can render this however they like.
    pub fn to_qr_code(&self, payload: &PairingPayload) -> Result<qrcode::QrCode, MechanismError> {
        let cbor = payload.to_cbor()?;
        if cbor.len() > MAX_QR_PAYLOAD_SIZE {
            return Err(MechanismError::PayloadTooLarge {
                max: MAX_QR_PAYLOAD_SIZE,
                actual: cbor.len(),
            });
        }
        qrcode::QrCode::with_error_correction_level(&cbor, EcLevel::M)
            .map_err(|e| MechanismError::InvalidFormat(format!("QR encoding failed: {e}")))
    }
}

impl PairingMechanism for QrCodeMechanism {
    fn mechanism_type(&self) -> MechanismType {
        MechanismType::Initiation
    }

    fn generate_payload(&self, payload: &PairingPayload) -> Result<Vec<u8>, MechanismError> {
        let cbor = payload.to_cbor()?;
        if cbor.len() > MAX_QR_PAYLOAD_SIZE {
            return Err(MechanismError::PayloadTooLarge {
                max: MAX_QR_PAYLOAD_SIZE,
                actual: cbor.len(),
            });
        }
        Ok(cbor)
    }

    fn consume_payload(&self, raw: &[u8]) -> Result<PairingPayload, MechanismError> {
        if raw.len() > MAX_QR_PAYLOAD_SIZE {
            return Err(MechanismError::PayloadTooLarge {
                max: MAX_QR_PAYLOAD_SIZE,
                actual: raw.len(),
            });
        }
        let payload = PairingPayload::from_cbor(raw)?;

        // Validate expiry using current system time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if payload.is_expired(now) {
            return Err(MechanismError::Expired);
        }

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;
    use crate::pairing::mechanisms::ConnectionHint;

    fn make_payload(expires_at: u64) -> PairingPayload {
        let identity = LocalIdentity::generate();
        PairingPayload {
            peer_id: identity.peer_id().clone(),
            nonce: [0x42; 16],
            pake_credential: vec![0xAB; 32],
            connection_hints: Some(vec![ConnectionHint {
                hint_type: "rendezvous".into(),
                value: "relay.example.com:9090".into(),
            }]),
            created_at: 1700000000,
            expires_at,
        }
    }

    #[test]
    fn qr_generate_and_consume_roundtrip() {
        let mechanism = QrCodeMechanism::default();
        // Use a far-future expiry so the payload is valid
        let payload = make_payload(u64::MAX);

        let raw = mechanism.generate_payload(&payload).unwrap();
        assert!(raw.len() <= 256);

        let restored = mechanism.consume_payload(&raw).unwrap();
        assert_eq!(payload.peer_id, restored.peer_id);
        assert_eq!(payload.nonce, restored.nonce);
        assert_eq!(payload.pake_credential, restored.pake_credential);
    }

    #[test]
    fn qr_mechanism_type_is_initiation() {
        let mechanism = QrCodeMechanism::default();
        assert_eq!(mechanism.mechanism_type(), MechanismType::Initiation);
    }

    #[test]
    fn qr_rejects_expired_payload() {
        let mechanism = QrCodeMechanism::default();
        // Expired in the past
        let payload = make_payload(1000);
        let raw = payload.to_cbor().unwrap();
        let result = mechanism.consume_payload(&raw);
        assert!(matches!(result, Err(MechanismError::Expired)));
    }

    #[test]
    fn qr_rejects_oversized_payload() {
        let mechanism = QrCodeMechanism::default();
        let identity = LocalIdentity::generate();
        let payload = PairingPayload {
            peer_id: identity.peer_id().clone(),
            nonce: [0x42; 16],
            pake_credential: vec![0xAB; 32],
            // Lots of hints to exceed 256 bytes
            connection_hints: Some(
                (0..20)
                    .map(|i| ConnectionHint {
                        hint_type: format!("type-{i}"),
                        value: format!("very-long-value-{i}-padding-data-here"),
                    })
                    .collect(),
            ),
            created_at: 1700000000,
            expires_at: u64::MAX,
        };

        let result = mechanism.generate_payload(&payload);
        assert!(matches!(
            result,
            Err(MechanismError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn qr_typical_payload_fits() {
        let mechanism = QrCodeMechanism::default();
        let identity = LocalIdentity::generate();
        let payload = PairingPayload {
            peer_id: identity.peer_id().clone(),
            nonce: [0x42; 16],
            pake_credential: vec![0xAB; 32],
            connection_hints: Some(vec![ConnectionHint {
                hint_type: "rendezvous".into(),
                value: "relay.example.com:9090".into(),
            }]),
            created_at: 1700000000,
            expires_at: u64::MAX,
        };

        let raw = mechanism.generate_payload(&payload).unwrap();
        // Typical payload should be ~160 bytes per spec
        assert!(raw.len() <= 200, "payload was {} bytes", raw.len());
    }

    #[test]
    fn qr_code_generation_works() {
        let mechanism = QrCodeMechanism::default();
        let payload = make_payload(u64::MAX);
        let qr = mechanism.to_qr_code(&payload).unwrap();
        // QR version should be <= 14
        // Verify QR code was generated successfully - the qrcode crate
        // auto-selects the minimum version for the actual payload size.
        let width = qr.width();
        // Version 14 = 73x73 modules, so width should be <= 73
        assert!(width <= 73, "QR width was {width}, exceeds version 14 (73)");
    }

    #[test]
    fn qr_custom_ttl() {
        let mechanism = QrCodeMechanism::with_ttl(Duration::from_secs(60));
        assert_eq!(mechanism.ttl, Duration::from_secs(60));
    }
}
