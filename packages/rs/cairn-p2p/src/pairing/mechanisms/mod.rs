pub mod adapter;
pub mod link;
pub mod pin;
pub mod psk;
pub mod qr;

use serde::{Deserialize, Serialize};

use crate::crypto::exchange::hkdf_sha256;
use crate::identity::PeerId;

// --- Error type ---

/// Errors specific to pairing mechanism operations.
#[derive(Debug, thiserror::Error)]
pub enum MechanismError {
    #[error("payload exceeds maximum size of {max} bytes (actual: {actual})")]
    PayloadTooLarge { max: usize, actual: usize },
    #[error("payload has expired")]
    Expired,
    #[error("invalid payload format: {0}")]
    InvalidFormat(String),
    #[error("invalid pin code: {0}")]
    InvalidPinCode(String),
    #[error("invalid URI: {0}")]
    InvalidUri(String),
    #[error("CBOR serialization error: {0}")]
    CborError(String),
}

// --- Connection hint ---

/// A hint for how to reach a peer (e.g., rendezvous server address, direct IP).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionHint {
    pub hint_type: String,
    pub value: String,
}

// --- Pairing payload ---

/// The data exchanged during pairing initiation.
///
/// Contains everything a peer needs to bootstrap a connection and PAKE handshake.
#[derive(Debug, Clone)]
pub struct PairingPayload {
    pub peer_id: PeerId,
    pub nonce: [u8; 16],
    pub pake_credential: Vec<u8>,
    pub connection_hints: Option<Vec<ConnectionHint>>,
    pub created_at: u64,
    pub expires_at: u64,
}

impl PairingPayload {
    /// Check whether this payload has expired relative to the given timestamp.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix > self.expires_at
    }

    /// Serialize to CBOR using compact integer keys.
    ///
    /// Key mapping: 0=peer_id, 1=nonce, 2=pake_credential, 3=hints, 4=created_at, 5=expires_at
    pub fn to_cbor(&self) -> Result<Vec<u8>, MechanismError> {
        use ciborium::Value;

        let mut entries: Vec<(Value, Value)> = vec![
            (
                Value::Integer(0.into()),
                Value::Bytes(self.peer_id.as_bytes().to_vec()),
            ),
            (Value::Integer(1.into()), Value::Bytes(self.nonce.to_vec())),
            (
                Value::Integer(2.into()),
                Value::Bytes(self.pake_credential.clone()),
            ),
        ];

        if let Some(ref hints) = self.connection_hints {
            let hint_values: Vec<Value> = hints
                .iter()
                .map(|h| {
                    Value::Array(vec![
                        Value::Text(h.hint_type.clone()),
                        Value::Text(h.value.clone()),
                    ])
                })
                .collect();
            entries.push((Value::Integer(3.into()), Value::Array(hint_values)));
        }

        entries.push((
            Value::Integer(4.into()),
            Value::Integer(self.created_at.into()),
        ));
        entries.push((
            Value::Integer(5.into()),
            Value::Integer(self.expires_at.into()),
        ));

        let cbor_map = Value::Map(entries);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf)
            .map_err(|e| MechanismError::CborError(e.to_string()))?;
        Ok(buf)
    }

    /// Deserialize from CBOR with compact integer keys.
    pub fn from_cbor(data: &[u8]) -> Result<Self, MechanismError> {
        use ciborium::Value;

        let value: Value =
            ciborium::from_reader(data).map_err(|e| MechanismError::CborError(e.to_string()))?;

        let map = match value {
            Value::Map(m) => m,
            _ => return Err(MechanismError::InvalidFormat("expected CBOR map".into())),
        };

        let mut peer_id_bytes: Option<Vec<u8>> = None;
        let mut nonce_bytes: Option<Vec<u8>> = None;
        let mut pake_credential: Option<Vec<u8>> = None;
        let mut connection_hints: Option<Vec<ConnectionHint>> = None;
        let mut created_at: Option<u64> = None;
        let mut expires_at: Option<u64> = None;

        for (k, v) in map {
            let key = match k {
                Value::Integer(i) => {
                    let val: i128 = i.into();
                    val as u64
                }
                _ => continue,
            };
            match key {
                0 => {
                    peer_id_bytes = match v {
                        Value::Bytes(b) => Some(b),
                        _ => {
                            return Err(MechanismError::InvalidFormat(
                                "peer_id must be bytes".into(),
                            ))
                        }
                    };
                }
                1 => {
                    nonce_bytes = match v {
                        Value::Bytes(b) => Some(b),
                        _ => {
                            return Err(MechanismError::InvalidFormat("nonce must be bytes".into()))
                        }
                    };
                }
                2 => {
                    pake_credential = match v {
                        Value::Bytes(b) => Some(b),
                        _ => {
                            return Err(MechanismError::InvalidFormat(
                                "pake_credential must be bytes".into(),
                            ))
                        }
                    };
                }
                3 => {
                    let arr = match v {
                        Value::Array(a) => a,
                        _ => {
                            return Err(MechanismError::InvalidFormat("hints must be array".into()))
                        }
                    };
                    let mut hints = Vec::new();
                    for item in arr {
                        let pair = match item {
                            Value::Array(a) if a.len() == 2 => a,
                            _ => {
                                return Err(MechanismError::InvalidFormat(
                                    "hint must be [type, value]".into(),
                                ))
                            }
                        };
                        let hint_type = match &pair[0] {
                            Value::Text(s) => s.clone(),
                            _ => {
                                return Err(MechanismError::InvalidFormat(
                                    "hint_type must be text".into(),
                                ))
                            }
                        };
                        let value = match &pair[1] {
                            Value::Text(s) => s.clone(),
                            _ => {
                                return Err(MechanismError::InvalidFormat(
                                    "hint value must be text".into(),
                                ))
                            }
                        };
                        hints.push(ConnectionHint { hint_type, value });
                    }
                    connection_hints = Some(hints);
                }
                4 => {
                    created_at = match v {
                        Value::Integer(i) => Some(i128::from(i) as u64),
                        _ => {
                            return Err(MechanismError::InvalidFormat(
                                "created_at must be integer".into(),
                            ))
                        }
                    };
                }
                5 => {
                    expires_at = match v {
                        Value::Integer(i) => Some(i128::from(i) as u64),
                        _ => {
                            return Err(MechanismError::InvalidFormat(
                                "expires_at must be integer".into(),
                            ))
                        }
                    };
                }
                _ => {} // ignore unknown keys
            }
        }

        let pid_bytes =
            peer_id_bytes.ok_or_else(|| MechanismError::InvalidFormat("missing peer_id".into()))?;
        let peer_id = PeerId::from_bytes(&pid_bytes)
            .map_err(|e| MechanismError::InvalidFormat(format!("invalid peer_id: {e}")))?;

        let nonce_vec =
            nonce_bytes.ok_or_else(|| MechanismError::InvalidFormat("missing nonce".into()))?;
        let nonce: [u8; 16] = nonce_vec
            .try_into()
            .map_err(|_| MechanismError::InvalidFormat("nonce must be 16 bytes".into()))?;

        let pake = pake_credential
            .ok_or_else(|| MechanismError::InvalidFormat("missing pake_credential".into()))?;

        Ok(PairingPayload {
            peer_id,
            nonce,
            pake_credential: pake,
            connection_hints,
            created_at: created_at.unwrap_or(0),
            expires_at: expires_at.unwrap_or(0),
        })
    }
}

// --- Mechanism trait ---

/// Distinguishes whether a mechanism initiates pairing or only verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MechanismType {
    /// Numeric SAS, Emoji SAS — verify an already-completed key exchange.
    VerificationOnly,
    /// QR, Pin, Link, PSK — bootstrap the entire pairing process.
    Initiation,
}

/// Pluggable pairing mechanism interface.
///
/// Implementations produce and consume pairing payloads in mechanism-specific formats
/// (QR code binary, pin code string, URI, etc.).
pub trait PairingMechanism: Send + Sync {
    /// Returns whether this mechanism is verification-only or initiation.
    fn mechanism_type(&self) -> MechanismType;

    /// Generate the pairing payload in the mechanism's format.
    ///
    /// - QR: returns raw CBOR bytes suitable for QR encoding.
    /// - Pin: returns the 8-char Crockford Base32 code as UTF-8 bytes.
    /// - Link: returns the `cairn://` URI string as UTF-8 bytes.
    fn generate_payload(&self, payload: &PairingPayload) -> Result<Vec<u8>, MechanismError>;

    /// Parse and validate a received payload.
    fn consume_payload(&self, raw: &[u8]) -> Result<PairingPayload, MechanismError>;
}

// --- SAS derivation utilities ---

/// HKDF info string for numeric SAS derivation.
const HKDF_INFO_SAS_NUMERIC: &[u8] = b"cairn-sas-numeric-v1";

/// HKDF info string for emoji SAS derivation.
const HKDF_INFO_SAS_EMOJI: &[u8] = b"cairn-sas-emoji-v1";

/// Emoji list for SAS derivation: 64 visually distinct, cross-platform emoji.
const SAS_EMOJI_LIST: [&str; 64] = [
    "\u{1F436}", // dog face
    "\u{1F431}", // cat face
    "\u{1F41F}", // fish
    "\u{1F426}", // bird
    "\u{1F43B}", // bear
    "\u{1F981}", // lion
    "\u{1F43A}", // wolf
    "\u{1F98A}", // fox
    "\u{1F98C}", // deer
    "\u{1F989}", // owl
    "\u{1F41D}", // honeybee
    "\u{1F41C}", // ant
    "\u{2B50}",  // star
    "\u{1F319}", // crescent moon
    "\u{2600}",  // sun
    "\u{1F525}", // fire
    "\u{1F333}", // deciduous tree
    "\u{1F343}", // leaf fluttering
    "\u{1F339}", // rose
    "\u{1F30A}", // wave
    "\u{1F327}", // cloud with rain
    "\u{2744}",  // snowflake
    "\u{26A1}",  // lightning bolt
    "\u{1F32C}", // wind face
    "\u{1FAA8}", // rock
    "\u{1F48E}", // gem stone
    "\u{1F514}", // bell
    "\u{1F511}", // key
    "\u{1F512}", // lock
    "\u{1F3F3}", // white flag
    "\u{1F4D6}", // open book
    "\u{1F58A}", // pen
    "\u{2615}",  // hot beverage
    "\u{1F3A9}", // top hat
    "\u{1F45F}", // running shoe
    "\u{1F48D}", // ring
    "\u{1F382}", // birthday cake
    "\u{1F381}", // wrapped gift
    "\u{1F4A1}", // light bulb
    "\u{2699}",  // gear
    "\u{1F6A2}", // ship
    "\u{1F697}", // automobile
    "\u{1F6B2}", // bicycle
    "\u{1F941}", // drum
    "\u{1F4EF}", // postal horn
    "\u{1F3B5}", // musical note
    "\u{1F3B2}", // game die
    "\u{1FA99}", // coin
    "\u{1F5FA}", // world map
    "\u{26FA}",  // tent
    "\u{1F451}", // crown
    "\u{2694}",  // crossed swords
    "\u{1F6E1}", // shield
    "\u{1F3F9}", // bow and arrow
    "\u{1FA93}", // axe
    "\u{1F528}", // hammer
    "\u{2693}",  // anchor
    "\u{2638}",  // wheel of dharma
    "\u{23F0}",  // alarm clock
    "\u{2764}",  // red heart
    "\u{1F480}", // skull
    "\u{1F47B}", // ghost
    "\u{1F916}", // robot
    "\u{1F47D}", // alien
];

/// Derive a 6-digit numeric SAS from a handshake transcript.
///
/// Uses HKDF-SHA256 with info="cairn-sas-numeric-v1".
/// Takes the first 4 bytes of output, interprets as big-endian u32,
/// then computes `code = value % 1_000_000`, zero-padded to 6 digits.
pub fn derive_numeric_sas(transcript: &[u8]) -> Result<String, MechanismError> {
    let mut derived = [0u8; 4];
    hkdf_sha256(transcript, None, HKDF_INFO_SAS_NUMERIC, &mut derived)
        .map_err(|e| MechanismError::InvalidFormat(format!("HKDF failed: {e}")))?;
    let value = u32::from_be_bytes(derived) % 1_000_000;
    Ok(format!("{value:06}"))
}

/// Derive an emoji SAS from a handshake transcript.
///
/// Uses HKDF-SHA256 with info="cairn-sas-emoji-v1".
/// Takes 8 bytes of output, splits into 4 x 2-byte values,
/// each `value % EMOJI_LIST.len()` selects an emoji.
pub fn derive_emoji_sas(transcript: &[u8]) -> Result<Vec<String>, MechanismError> {
    let mut derived = [0u8; 8];
    hkdf_sha256(transcript, None, HKDF_INFO_SAS_EMOJI, &mut derived)
        .map_err(|e| MechanismError::InvalidFormat(format!("HKDF failed: {e}")))?;

    let emojis = (0..4)
        .map(|i| {
            let val = u16::from_be_bytes([derived[i * 2], derived[i * 2 + 1]]);
            SAS_EMOJI_LIST[(val as usize) % SAS_EMOJI_LIST.len()].to_string()
        })
        .collect();
    Ok(emojis)
}

// Re-export mechanism implementations
pub use adapter::{AdapterError, CustomMechanism, CustomPairingAdapter, CustomPayload};
pub use link::PairingLinkMechanism;
pub use pin::PinCodeMechanism;
pub use psk::{PskError, PskMechanism};
pub use qr::QrCodeMechanism;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;

    fn test_payload() -> PairingPayload {
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
            expires_at: 1700000300,
        }
    }

    #[test]
    fn cbor_roundtrip() {
        let payload = test_payload();
        let cbor = payload.to_cbor().unwrap();
        let restored = PairingPayload::from_cbor(&cbor).unwrap();

        assert_eq!(payload.peer_id, restored.peer_id);
        assert_eq!(payload.nonce, restored.nonce);
        assert_eq!(payload.pake_credential, restored.pake_credential);
        assert_eq!(payload.created_at, restored.created_at);
        assert_eq!(payload.expires_at, restored.expires_at);
        assert_eq!(
            payload.connection_hints.as_ref().unwrap().len(),
            restored.connection_hints.as_ref().unwrap().len()
        );
    }

    #[test]
    fn cbor_roundtrip_without_hints() {
        let identity = LocalIdentity::generate();
        let payload = PairingPayload {
            peer_id: identity.peer_id().clone(),
            nonce: [0xFF; 16],
            pake_credential: vec![0x00; 32],
            connection_hints: None,
            created_at: 100,
            expires_at: 400,
        };
        let cbor = payload.to_cbor().unwrap();
        let restored = PairingPayload::from_cbor(&cbor).unwrap();
        assert!(restored.connection_hints.is_none());
        assert_eq!(payload.nonce, restored.nonce);
    }

    #[test]
    fn payload_expiry_check() {
        let payload = test_payload();
        assert!(!payload.is_expired(1700000100));
        assert!(payload.is_expired(1700000301));
        assert!(!payload.is_expired(1700000300));
    }

    #[test]
    fn numeric_sas_produces_6_digits() {
        let transcript = [0xABu8; 32];
        let sas = derive_numeric_sas(&transcript).unwrap();
        assert_eq!(sas.len(), 6);
        assert!(sas.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn numeric_sas_is_deterministic() {
        let transcript = [0x42u8; 32];
        let sas1 = derive_numeric_sas(&transcript).unwrap();
        let sas2 = derive_numeric_sas(&transcript).unwrap();
        assert_eq!(sas1, sas2);
    }

    #[test]
    fn numeric_sas_differs_for_different_transcripts() {
        let sas1 = derive_numeric_sas(&[0x01u8; 32]).unwrap();
        let sas2 = derive_numeric_sas(&[0x02u8; 32]).unwrap();
        assert_ne!(sas1, sas2);
    }

    #[test]
    fn emoji_sas_produces_4_emojis() {
        let transcript = [0xABu8; 32];
        let emojis = derive_emoji_sas(&transcript).unwrap();
        assert_eq!(emojis.len(), 4);
        for emoji in &emojis {
            assert!(!emoji.is_empty());
        }
    }

    #[test]
    fn emoji_sas_is_deterministic() {
        let transcript = [0x42u8; 32];
        let e1 = derive_emoji_sas(&transcript).unwrap();
        let e2 = derive_emoji_sas(&transcript).unwrap();
        assert_eq!(e1, e2);
    }

    #[test]
    fn emoji_sas_differs_for_different_transcripts() {
        let e1 = derive_emoji_sas(&[0x01u8; 32]).unwrap();
        let e2 = derive_emoji_sas(&[0x02u8; 32]).unwrap();
        assert_ne!(e1, e2);
    }

    #[test]
    fn cbor_rejects_invalid_data() {
        let result = PairingPayload::from_cbor(&[0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn cbor_rejects_non_map() {
        let mut buf = Vec::new();
        ciborium::into_writer(&ciborium::Value::Integer(42.into()), &mut buf).unwrap();
        let result = PairingPayload::from_cbor(&buf);
        assert!(matches!(result, Err(MechanismError::InvalidFormat(_))));
    }
}
