/// Payload exchanged during custom pairing flows.
///
/// Contains the data needed to bootstrap a PAKE handshake via a
/// custom transport (NFC, Bluetooth LE, email, hardware token, etc.).
///
/// This is distinct from `super::PairingPayload` which is the standard
/// pairing payload used by built-in mechanisms (QR, Pin, Link).
#[derive(Debug, Clone)]
pub struct CustomPayload {
    /// Raw payload data in the application's chosen format.
    pub data: Vec<u8>,
    /// Human-readable description of the transport used.
    pub transport: String,
}

/// Error type for custom adapter operations.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("payload generation failed: {0}")]
    GenerationFailed(String),
    #[error("payload consumption failed: {0}")]
    ConsumptionFailed(String),
    #[error("PAKE input derivation failed: {0}")]
    DerivationFailed(String),
    #[error("invalid payload: {0}")]
    InvalidPayload(String),
}

/// Applications implement this trait for domain-specific pairing flows.
///
/// Examples: NFC tap, Bluetooth LE OOB, email-based verification, hardware token.
///
/// The adapter handles the transport-specific encoding/decoding of pairing
/// payloads, while the library handles the PAKE handshake and trust establishment.
pub trait CustomPairingAdapter: Send + Sync {
    /// Create the pairing payload in the application's chosen format/transport.
    fn generate_payload(&self, payload: &CustomPayload) -> Result<Vec<u8>, AdapterError>;

    /// Parse and validate a received pairing payload from the custom transport.
    fn consume_payload(&self, raw: &[u8]) -> Result<CustomPayload, AdapterError>;

    /// Derive the SPAKE2 password bytes from the custom payload.
    ///
    /// Returns the bytes to use as the PAKE password input.
    fn derive_pake_input(&self, payload: &CustomPayload) -> Result<Vec<u8>, AdapterError>;

    /// Human-readable name of this mechanism (e.g., "nfc", "bluetooth-le").
    fn name(&self) -> &str;
}

/// Wrapper that bridges a `CustomPairingAdapter` into the pairing system.
///
/// This struct holds a boxed adapter and provides methods that the
/// pairing session can call during the initiation flow.
pub struct CustomMechanism {
    adapter: Box<dyn CustomPairingAdapter>,
}

impl CustomMechanism {
    pub fn new(adapter: Box<dyn CustomPairingAdapter>) -> Self {
        Self { adapter }
    }

    /// Get the mechanism name from the underlying adapter.
    pub fn name(&self) -> &str {
        self.adapter.name()
    }

    /// Generate a pairing payload via the custom adapter.
    pub fn generate_payload(&self, payload: &CustomPayload) -> Result<Vec<u8>, AdapterError> {
        self.adapter.generate_payload(payload)
    }

    /// Consume a received pairing payload via the custom adapter.
    pub fn consume_payload(&self, raw: &[u8]) -> Result<CustomPayload, AdapterError> {
        self.adapter.consume_payload(raw)
    }

    /// Derive the PAKE input from a payload via the custom adapter.
    pub fn derive_pake_input(&self, payload: &CustomPayload) -> Result<Vec<u8>, AdapterError> {
        self.adapter.derive_pake_input(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test adapter that uses a simple passthrough encoding.
    struct PassthroughAdapter;

    impl CustomPairingAdapter for PassthroughAdapter {
        fn generate_payload(&self, payload: &CustomPayload) -> Result<Vec<u8>, AdapterError> {
            Ok(payload.data.clone())
        }

        fn consume_payload(&self, raw: &[u8]) -> Result<CustomPayload, AdapterError> {
            Ok(CustomPayload {
                data: raw.to_vec(),
                transport: "passthrough".into(),
            })
        }

        fn derive_pake_input(&self, payload: &CustomPayload) -> Result<Vec<u8>, AdapterError> {
            Ok(payload.data.clone())
        }

        fn name(&self) -> &str {
            "passthrough"
        }
    }

    /// A test adapter that simulates failures.
    struct FailingAdapter;

    impl CustomPairingAdapter for FailingAdapter {
        fn generate_payload(&self, _payload: &CustomPayload) -> Result<Vec<u8>, AdapterError> {
            Err(AdapterError::GenerationFailed(
                "device not available".into(),
            ))
        }

        fn consume_payload(&self, _raw: &[u8]) -> Result<CustomPayload, AdapterError> {
            Err(AdapterError::ConsumptionFailed("invalid format".into()))
        }

        fn derive_pake_input(&self, _payload: &CustomPayload) -> Result<Vec<u8>, AdapterError> {
            Err(AdapterError::DerivationFailed("hardware error".into()))
        }

        fn name(&self) -> &str {
            "failing"
        }
    }

    #[test]
    fn passthrough_generate_and_consume() {
        let adapter = PassthroughAdapter;
        let mechanism = CustomMechanism::new(Box::new(adapter));

        let payload = CustomPayload {
            data: vec![1, 2, 3, 4],
            transport: "test".into(),
        };

        let encoded = mechanism.generate_payload(&payload).unwrap();
        assert_eq!(encoded, vec![1, 2, 3, 4]);

        let decoded = mechanism.consume_payload(&encoded).unwrap();
        assert_eq!(decoded.data, vec![1, 2, 3, 4]);
        assert_eq!(decoded.transport, "passthrough");
    }

    #[test]
    fn passthrough_derive_pake_input() {
        let adapter = PassthroughAdapter;
        let mechanism = CustomMechanism::new(Box::new(adapter));

        let payload = CustomPayload {
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            transport: "test".into(),
        };

        let pake_input = mechanism.derive_pake_input(&payload).unwrap();
        assert_eq!(pake_input, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn mechanism_name() {
        let mechanism = CustomMechanism::new(Box::new(PassthroughAdapter));
        assert_eq!(mechanism.name(), "passthrough");

        let mechanism = CustomMechanism::new(Box::new(FailingAdapter));
        assert_eq!(mechanism.name(), "failing");
    }

    #[test]
    fn failing_adapter_generate() {
        let mechanism = CustomMechanism::new(Box::new(FailingAdapter));
        let payload = CustomPayload {
            data: vec![1],
            transport: "test".into(),
        };
        let err = mechanism.generate_payload(&payload).unwrap_err();
        assert!(matches!(err, AdapterError::GenerationFailed(_)));
        assert!(err.to_string().contains("device not available"));
    }

    #[test]
    fn failing_adapter_consume() {
        let mechanism = CustomMechanism::new(Box::new(FailingAdapter));
        let err = mechanism.consume_payload(&[1, 2, 3]).unwrap_err();
        assert!(matches!(err, AdapterError::ConsumptionFailed(_)));
        assert!(err.to_string().contains("invalid format"));
    }

    #[test]
    fn failing_adapter_derive_pake() {
        let mechanism = CustomMechanism::new(Box::new(FailingAdapter));
        let payload = CustomPayload {
            data: vec![1],
            transport: "test".into(),
        };
        let err = mechanism.derive_pake_input(&payload).unwrap_err();
        assert!(matches!(err, AdapterError::DerivationFailed(_)));
        assert!(err.to_string().contains("hardware error"));
    }

    #[test]
    fn error_display() {
        let err = AdapterError::GenerationFailed("test".into());
        assert!(err.to_string().contains("generation failed"));
        assert!(err.to_string().contains("test"));

        let err = AdapterError::ConsumptionFailed("test".into());
        assert!(err.to_string().contains("consumption failed"));

        let err = AdapterError::DerivationFailed("test".into());
        assert!(err.to_string().contains("derivation failed"));

        let err = AdapterError::InvalidPayload("test".into());
        assert!(err.to_string().contains("invalid payload"));
    }

    #[test]
    fn pairing_payload_debug() {
        let payload = CustomPayload {
            data: vec![1, 2, 3],
            transport: "nfc".into(),
        };
        let debug = format!("{payload:?}");
        assert!(debug.contains("nfc"));
    }

    #[test]
    fn adapter_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CustomMechanism>();
    }
}
