use crate::crypto::exchange::hkdf_sha256;

/// HKDF info string for PSK rendezvous ID derivation.
const HKDF_INFO_PSK_RENDEZVOUS: &[u8] = b"cairn-psk-rendezvous-v1";

/// Default minimum entropy in bytes (128 bits).
const DEFAULT_MIN_ENTROPY_BYTES: usize = 16;

/// Errors specific to PSK mechanism operations.
#[derive(Debug, thiserror::Error)]
pub enum PskError {
    #[error("insufficient entropy: got {got} bytes, need at least {min} bytes (128 bits)")]
    InsufficientEntropy { got: usize, min: usize },
    #[error("empty pre-shared key")]
    EmptyKey,
    #[error("key derivation failed: {0}")]
    DerivationFailed(String),
}

/// Pre-Shared Key (PSK) pairing mechanism.
///
/// A secret configured on both peers ahead of time (config file, environment
/// variable, secrets manager). Used as PAKE input; rendezvous ID derived from it.
/// Can be long-lived but should be rotated periodically.
///
/// Minimum entropy: 128 bits (e.g., 26 Crockford Base32 characters) since not time-limited.
pub struct PskMechanism {
    /// Minimum entropy in bytes. Default: 16 (128 bits).
    min_entropy_bytes: usize,
}

impl PskMechanism {
    pub fn new() -> Self {
        Self {
            min_entropy_bytes: DEFAULT_MIN_ENTROPY_BYTES,
        }
    }

    /// Create with a custom minimum entropy requirement.
    pub fn with_min_entropy(min_bytes: usize) -> Self {
        Self {
            min_entropy_bytes: min_bytes,
        }
    }

    /// Validate that the PSK has sufficient entropy.
    ///
    /// For Crockford Base32 input: 26 chars * 5 bits = 130 bits >= 128 bits.
    /// For raw bytes: must be >= 16 bytes (128 bits).
    pub fn validate_entropy(&self, psk: &[u8]) -> Result<(), PskError> {
        if psk.is_empty() {
            return Err(PskError::EmptyKey);
        }
        if psk.len() < self.min_entropy_bytes {
            return Err(PskError::InsufficientEntropy {
                got: psk.len(),
                min: self.min_entropy_bytes,
            });
        }
        Ok(())
    }

    /// Derive a 32-byte rendezvous ID from the PSK.
    ///
    /// Uses HKDF-SHA256 with:
    /// - ikm: psk_bytes
    /// - salt: empty
    /// - info: "cairn-psk-rendezvous-v1"
    pub fn derive_rendezvous_id(&self, psk: &[u8]) -> Result<[u8; 32], PskError> {
        self.validate_entropy(psk)?;
        let mut output = [0u8; 32];
        hkdf_sha256(psk, None, HKDF_INFO_PSK_RENDEZVOUS, &mut output)
            .map_err(|e| PskError::DerivationFailed(e.to_string()))?;
        Ok(output)
    }

    /// Get the SPAKE2 password input from the PSK.
    ///
    /// The PSK is used directly as the SPAKE2 password bytes.
    pub fn pake_input(&self, psk: &[u8]) -> Result<Vec<u8>, PskError> {
        self.validate_entropy(psk)?;
        Ok(psk.to_vec())
    }

    /// Get the minimum entropy requirement in bytes.
    pub fn min_entropy_bytes(&self) -> usize {
        self.min_entropy_bytes
    }
}

impl Default for PskMechanism {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uses_default_entropy() {
        let psk = PskMechanism::new();
        assert_eq!(psk.min_entropy_bytes(), 16);
    }

    #[test]
    fn default_matches_new() {
        let a = PskMechanism::new();
        let b = PskMechanism::default();
        assert_eq!(a.min_entropy_bytes(), b.min_entropy_bytes());
    }

    #[test]
    fn validate_entropy_accepts_sufficient_key() {
        let psk = PskMechanism::new();
        let key = [0xAB; 16]; // exactly 128 bits
        assert!(psk.validate_entropy(&key).is_ok());
    }

    #[test]
    fn validate_entropy_accepts_longer_key() {
        let psk = PskMechanism::new();
        let key = [0xAB; 32]; // 256 bits
        assert!(psk.validate_entropy(&key).is_ok());
    }

    #[test]
    fn validate_entropy_rejects_short_key() {
        let psk = PskMechanism::new();
        let key = [0xAB; 15]; // 120 bits < 128 bits
        let err = psk.validate_entropy(&key).unwrap_err();
        match err {
            PskError::InsufficientEntropy { got, min } => {
                assert_eq!(got, 15);
                assert_eq!(min, 16);
            }
            _ => panic!("expected InsufficientEntropy, got: {err}"),
        }
    }

    #[test]
    fn validate_entropy_rejects_empty_key() {
        let psk = PskMechanism::new();
        let err = psk.validate_entropy(&[]).unwrap_err();
        assert!(matches!(err, PskError::EmptyKey));
    }

    #[test]
    fn custom_min_entropy() {
        let psk = PskMechanism::with_min_entropy(32);
        assert_eq!(psk.min_entropy_bytes(), 32);
        // 16 bytes now rejected
        assert!(psk.validate_entropy(&[0xAB; 16]).is_err());
        // 32 bytes accepted
        assert!(psk.validate_entropy(&[0xAB; 32]).is_ok());
    }

    #[test]
    fn derive_rendezvous_id_is_deterministic() {
        let psk = PskMechanism::new();
        let key = [0x42; 16];
        let id1 = psk.derive_rendezvous_id(&key).unwrap();
        let id2 = psk.derive_rendezvous_id(&key).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn derive_rendezvous_id_differs_for_different_keys() {
        let psk = PskMechanism::new();
        let id1 = psk.derive_rendezvous_id(&[0x01; 16]).unwrap();
        let id2 = psk.derive_rendezvous_id(&[0x02; 16]).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn derive_rendezvous_id_rejects_insufficient_entropy() {
        let psk = PskMechanism::new();
        let err = psk.derive_rendezvous_id(&[0xAB; 8]).unwrap_err();
        assert!(matches!(err, PskError::InsufficientEntropy { .. }));
    }

    #[test]
    fn pake_input_returns_raw_psk() {
        let psk = PskMechanism::new();
        let key = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xAA, 0xBB,
        ];
        let input = psk.pake_input(&key).unwrap();
        assert_eq!(input, key);
    }

    #[test]
    fn pake_input_rejects_short_key() {
        let psk = PskMechanism::new();
        assert!(psk.pake_input(&[0xAB; 4]).is_err());
    }

    #[test]
    fn crockford_base32_26_chars_pass_validation() {
        let psk = PskMechanism::new();
        // 26 Crockford Base32 chars = 26 bytes when raw (> 16 bytes).
        // In practice, 26 chars * 5 bits = 130 bits, but when stored as
        // bytes (the string representation), 26 bytes > 16.
        let key = b"ABCDEFGHJKMNPQRSTVWXYZ0123";
        assert_eq!(key.len(), 26);
        assert!(psk.validate_entropy(key).is_ok());
    }

    #[test]
    fn error_display() {
        let err = PskError::InsufficientEntropy { got: 8, min: 16 };
        assert!(err.to_string().contains("8 bytes"));
        assert!(err.to_string().contains("16 bytes"));

        let err = PskError::EmptyKey;
        assert!(err.to_string().contains("empty"));

        let err = PskError::DerivationFailed("test".into());
        assert!(err.to_string().contains("test"));
    }
}
