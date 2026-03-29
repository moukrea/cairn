use std::time::Duration;

use crate::crypto::exchange::hkdf_sha256;

use super::{MechanismError, MechanismType, PairingMechanism, PairingPayload};

/// Crockford Base32 alphabet (excludes I, L, O, U).
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Pin code length in characters (before formatting).
const PIN_LENGTH: usize = 8;

/// Default TTL for pin code pairing payloads (5 minutes).
const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// HKDF info string for deriving the rendezvous ID from a pin code.
const HKDF_INFO_PIN_RENDEZVOUS: &[u8] = b"cairn-pin-rendezvous-v1";

/// Pin code pairing mechanism.
///
/// Generates an 8-character Crockford Base32 code formatted as `XXXX-XXXX` (40 bits entropy).
/// The pin code serves as both the SPAKE2 password and the source for the rendezvous ID.
pub struct PinCodeMechanism {
    pub ttl: Duration,
}

impl Default for PinCodeMechanism {
    fn default() -> Self {
        Self { ttl: DEFAULT_TTL }
    }
}

impl PinCodeMechanism {
    /// Create a new pin code mechanism with a custom TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self { ttl }
    }

    /// Derive a rendezvous ID from a pin code.
    ///
    /// Uses HKDF-SHA256 with info="cairn-pin-rendezvous-v1" to derive a 32-byte ID.
    pub fn derive_rendezvous_id(pin_bytes: &[u8]) -> Result<Vec<u8>, MechanismError> {
        let mut rendezvous_id = vec![0u8; 32];
        hkdf_sha256(
            pin_bytes,
            Some(b""),
            HKDF_INFO_PIN_RENDEZVOUS,
            &mut rendezvous_id,
        )
        .map_err(|e| MechanismError::InvalidFormat(format!("HKDF failed: {e}")))?;
        Ok(rendezvous_id)
    }
}

/// Generate a random 8-character Crockford Base32 pin code.
///
/// Returns the raw 8-character string (without formatting).
fn generate_pin() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 5]; // 40 bits
    rand::thread_rng().fill_bytes(&mut bytes);
    encode_crockford(&bytes)
}

/// Encode 5 bytes (40 bits) to 8 Crockford Base32 characters.
fn encode_crockford(bytes: &[u8; 5]) -> String {
    // Convert 5 bytes to a 40-bit integer
    let mut bits: u64 = 0;
    for &b in bytes {
        bits = (bits << 8) | (b as u64);
    }

    // Extract 8 x 5-bit chunks from the top
    let mut result = String::with_capacity(8);
    for i in (0..8).rev() {
        let index = ((bits >> (i * 5)) & 0x1F) as usize;
        result.push(CROCKFORD_ALPHABET[index] as char);
    }
    result
}

/// Decode a Crockford Base32 string (8 chars, normalized) to 5 bytes.
fn decode_crockford(input: &str) -> Result<[u8; 5], MechanismError> {
    if input.len() != PIN_LENGTH {
        return Err(MechanismError::InvalidPinCode(format!(
            "expected {PIN_LENGTH} characters, got {}",
            input.len()
        )));
    }

    let mut bits: u64 = 0;
    for ch in input.chars() {
        let idx = CROCKFORD_ALPHABET
            .iter()
            .position(|&c| c == ch as u8)
            .ok_or_else(|| MechanismError::InvalidPinCode(format!("invalid character: '{ch}'")))?;
        bits = (bits << 5) | (idx as u64);
    }

    // Extract 5 bytes from the 40-bit value
    let mut result = [0u8; 5];
    for i in (0..5).rev() {
        result[4 - i] = ((bits >> (i * 8)) & 0xFF) as u8;
    }
    Ok(result)
}

/// Format a pin code as `XXXX-XXXX` (default format).
pub fn format_pin(pin: &str) -> String {
    format_pin_with(pin, 4, "-")
}

/// Format a pin code with custom group size and separator.
pub fn format_pin_with(pin: &str, group_size: usize, separator: &str) -> String {
    if group_size == 0 || pin.len() <= group_size {
        return pin.to_string();
    }
    let mut result = String::with_capacity(pin.len() + (pin.len() / group_size) * separator.len());
    for (i, ch) in pin.chars().enumerate() {
        if i > 0 && i % group_size == 0 {
            result.push_str(separator);
        }
        result.push(ch);
    }
    result
}

/// Normalize a pin code input: uppercase, strip separators, apply Crockford substitutions.
///
/// - Case-insensitive (uppercased)
/// - `I`/`L` -> `1`
/// - `O` -> `0`
/// - `U` removed (Crockford excludes U)
/// - Hyphens and spaces stripped
pub fn normalize_pin(input: &str) -> String {
    input
        .chars()
        .filter(|c| *c != '-' && *c != ' ')
        .map(|c| c.to_ascii_uppercase())
        .filter(|c| *c != 'U') // Crockford excludes U
        .map(|c| match c {
            'I' | 'L' => '1',
            'O' => '0',
            _ => c,
        })
        .collect()
}

impl PairingMechanism for PinCodeMechanism {
    fn mechanism_type(&self) -> MechanismType {
        MechanismType::Initiation
    }

    fn generate_payload(&self, _payload: &PairingPayload) -> Result<Vec<u8>, MechanismError> {
        let pin = generate_pin();
        let formatted = format_pin(&pin);
        Ok(formatted.into_bytes())
    }

    fn consume_payload(&self, raw: &[u8]) -> Result<PairingPayload, MechanismError> {
        let input = std::str::from_utf8(raw)
            .map_err(|_| MechanismError::InvalidPinCode("input is not valid UTF-8".into()))?;

        let normalized = normalize_pin(input);
        if normalized.len() != PIN_LENGTH {
            return Err(MechanismError::InvalidPinCode(format!(
                "normalized pin has {} characters, expected {PIN_LENGTH}",
                normalized.len()
            )));
        }

        // Validate that all characters are in the Crockford alphabet
        let _decoded = decode_crockford(&normalized)?;

        // The pin code is used as the PAKE password and to derive the rendezvous ID.
        // The actual PairingPayload will be constructed by the caller from the
        // SPAKE2 exchange. Here we construct a minimal payload with the pin as
        // the PAKE credential.
        let nonce = {
            use rand::RngCore;
            let mut n = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut n);
            n
        };

        // Use a zero PeerId as placeholder — the real peer ID comes from the PAKE exchange.
        let peer_id_bytes = [0u8; 34];
        let mut peer_id_arr = peer_id_bytes;
        peer_id_arr[0] = 0x12;
        peer_id_arr[1] = 0x20;
        let peer_id = crate::identity::PeerId::from_bytes(&peer_id_arr)
            .map_err(|e| MechanismError::InvalidFormat(format!("peer_id construction: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(PairingPayload {
            peer_id,
            nonce,
            pake_credential: normalized.into_bytes(),
            connection_hints: None,
            created_at: now,
            expires_at: now + self.ttl.as_secs(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;

    fn make_payload() -> PairingPayload {
        let identity = LocalIdentity::generate();
        PairingPayload {
            peer_id: identity.peer_id().clone(),
            nonce: [0x42; 16],
            pake_credential: vec![0xAB; 32],
            connection_hints: None,
            created_at: 1700000000,
            expires_at: u64::MAX,
        }
    }

    #[test]
    fn pin_generation_format() {
        let pin = generate_pin();
        assert_eq!(pin.len(), 8);
        let formatted = format_pin(&pin);
        assert_eq!(formatted.len(), 9); // 8 chars + hyphen
        assert_eq!(&formatted[4..5], "-");
    }

    #[test]
    fn pin_generation_only_crockford_chars() {
        for _ in 0..100 {
            let pin = generate_pin();
            for ch in pin.chars() {
                assert!(
                    CROCKFORD_ALPHABET.contains(&(ch as u8)),
                    "unexpected char: '{ch}'"
                );
            }
        }
    }

    #[test]
    fn crockford_encode_decode_roundtrip() {
        for _ in 0..100 {
            use rand::RngCore;
            let mut bytes = [0u8; 5];
            rand::thread_rng().fill_bytes(&mut bytes);
            let encoded = encode_crockford(&bytes);
            let decoded = decode_crockford(&encoded).unwrap();
            assert_eq!(bytes, decoded);
        }
    }

    #[test]
    fn crockford_known_values() {
        // All zeros -> "00000000"
        let encoded = encode_crockford(&[0, 0, 0, 0, 0]);
        assert_eq!(encoded, "00000000");

        // All ones -> "ZZZZZZZZ"
        let encoded = encode_crockford(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(encoded, "ZZZZZZZZ");
    }

    #[test]
    fn normalize_pin_case_insensitive() {
        assert_eq!(normalize_pin("abcd-efgh"), "ABCDEFGH");
    }

    #[test]
    fn normalize_pin_strips_separators() {
        assert_eq!(normalize_pin("AB CD-EF GH"), "ABCDEFGH");
    }

    #[test]
    fn normalize_pin_substitutions() {
        // I -> 1, L -> 1, O -> 0
        assert_eq!(normalize_pin("ILOO-AAAA"), "1100AAAA");
    }

    #[test]
    fn normalize_pin_removes_u() {
        assert_eq!(normalize_pin("AUBU-CUDU"), "ABCD");
    }

    #[test]
    fn pin_mechanism_type_is_initiation() {
        let mechanism = PinCodeMechanism::default();
        assert_eq!(mechanism.mechanism_type(), MechanismType::Initiation);
    }

    #[test]
    fn pin_generate_payload_returns_formatted_pin() {
        let mechanism = PinCodeMechanism::default();
        let payload = make_payload();
        let raw = mechanism.generate_payload(&payload).unwrap();
        let pin_str = std::str::from_utf8(&raw).unwrap();
        assert_eq!(pin_str.len(), 9); // XXXX-XXXX
        assert_eq!(&pin_str[4..5], "-");
    }

    #[test]
    fn pin_consume_validates_crockford() {
        let mechanism = PinCodeMechanism::default();
        let valid_pin = b"98AF-XZ2A";
        let result = mechanism.consume_payload(valid_pin);
        assert!(result.is_ok());
    }

    #[test]
    fn pin_consume_rejects_invalid_chars() {
        let mechanism = PinCodeMechanism::default();
        // After normalization, '!' is not in Crockford alphabet
        let result = mechanism.consume_payload(b"!!!!");
        assert!(result.is_err());
    }

    #[test]
    fn pin_consume_rejects_wrong_length() {
        let mechanism = PinCodeMechanism::default();
        let result = mechanism.consume_payload(b"ABC");
        assert!(result.is_err());
    }

    #[test]
    fn pin_consume_handles_case_insensitive_input() {
        let mechanism = PinCodeMechanism::default();
        let result = mechanism.consume_payload(b"98af-xz2a");
        assert!(result.is_ok());
    }

    #[test]
    fn rendezvous_id_derivation() {
        let id1 = PinCodeMechanism::derive_rendezvous_id(b"98AFXZ2A").unwrap();
        let id2 = PinCodeMechanism::derive_rendezvous_id(b"98AFXZ2A").unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);

        // Different pins give different IDs
        let id3 = PinCodeMechanism::derive_rendezvous_id(b"ABCDEFGH").unwrap();
        assert_ne!(id1, id3);
    }

    #[test]
    fn pin_custom_ttl() {
        let mechanism = PinCodeMechanism::with_ttl(Duration::from_secs(60));
        assert_eq!(mechanism.ttl, Duration::from_secs(60));
    }

    #[test]
    fn pin_40_bits_entropy() {
        // 8 Crockford Base32 chars = 8 * 5 = 40 bits
        // Verify by generating many pins and checking they encode to 5 bytes
        for _ in 0..50 {
            let pin = generate_pin();
            let decoded = decode_crockford(&pin).unwrap();
            assert_eq!(decoded.len(), 5);
        }
    }
}
