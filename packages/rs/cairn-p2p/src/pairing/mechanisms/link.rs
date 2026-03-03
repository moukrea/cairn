use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use url::Url;

use crate::identity::PeerId;

use super::{ConnectionHint, MechanismError, MechanismType, PairingMechanism, PairingPayload};

/// Default URI scheme.
const DEFAULT_SCHEME: &str = "cairn";

/// Default TTL for pairing link payloads (5 minutes).
const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// Pairing link / URI mechanism.
///
/// Generates and parses `cairn://pair?pid=...&nonce=...&pake=...&hints=...` URIs.
/// The scheme is configurable for applications that register custom URI schemes.
pub struct PairingLinkMechanism {
    pub scheme: String,
    pub ttl: Duration,
}

impl Default for PairingLinkMechanism {
    fn default() -> Self {
        Self {
            scheme: DEFAULT_SCHEME.into(),
            ttl: DEFAULT_TTL,
        }
    }
}

impl PairingLinkMechanism {
    /// Create a new pairing link mechanism with custom scheme and TTL.
    pub fn new(scheme: impl Into<String>, ttl: Duration) -> Self {
        Self {
            scheme: scheme.into(),
            ttl,
        }
    }

    /// Encode connection hints to CBOR then base64url.
    fn encode_hints(hints: &[ConnectionHint]) -> Result<String, MechanismError> {
        use ciborium::Value;

        let hint_values: Vec<Value> = hints
            .iter()
            .map(|h| {
                Value::Array(vec![
                    Value::Text(h.hint_type.clone()),
                    Value::Text(h.value.clone()),
                ])
            })
            .collect();

        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Array(hint_values), &mut buf)
            .map_err(|e| MechanismError::CborError(e.to_string()))?;

        Ok(URL_SAFE_NO_PAD.encode(&buf))
    }

    /// Decode connection hints from base64url-encoded CBOR.
    fn decode_hints(encoded: &str) -> Result<Vec<ConnectionHint>, MechanismError> {
        use ciborium::Value;

        let cbor_bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| MechanismError::InvalidUri(format!("invalid base64url hints: {e}")))?;

        let value: Value = ciborium::from_reader(&cbor_bytes[..])
            .map_err(|e| MechanismError::CborError(e.to_string()))?;

        let arr = match value {
            Value::Array(a) => a,
            _ => {
                return Err(MechanismError::InvalidUri(
                    "hints must be CBOR array".into(),
                ))
            }
        };

        let mut hints = Vec::new();
        for item in arr {
            let pair = match item {
                Value::Array(a) if a.len() == 2 => a,
                _ => {
                    return Err(MechanismError::InvalidUri(
                        "each hint must be [type, value]".into(),
                    ))
                }
            };
            let hint_type = match &pair[0] {
                Value::Text(s) => s.clone(),
                _ => return Err(MechanismError::InvalidUri("hint type must be text".into())),
            };
            let value = match &pair[1] {
                Value::Text(s) => s.clone(),
                _ => return Err(MechanismError::InvalidUri("hint value must be text".into())),
            };
            hints.push(ConnectionHint { hint_type, value });
        }

        Ok(hints)
    }
}

impl PairingMechanism for PairingLinkMechanism {
    fn mechanism_type(&self) -> MechanismType {
        MechanismType::Initiation
    }

    fn generate_payload(&self, payload: &PairingPayload) -> Result<Vec<u8>, MechanismError> {
        let pid = bs58::encode(payload.peer_id.as_bytes()).into_string();
        let nonce = hex::encode(payload.nonce);
        let pake = hex::encode(&payload.pake_credential);

        let mut uri = format!(
            "{}://pair?pid={}&nonce={}&pake={}",
            self.scheme, pid, nonce, pake
        );

        if let Some(ref hints) = payload.connection_hints {
            if !hints.is_empty() {
                let encoded_hints = Self::encode_hints(hints)?;
                uri.push_str(&format!("&hints={encoded_hints}"));
            }
        }

        // Append timestamps
        uri.push_str(&format!(
            "&t={}&x={}",
            payload.created_at, payload.expires_at
        ));

        Ok(uri.into_bytes())
    }

    fn consume_payload(&self, raw: &[u8]) -> Result<PairingPayload, MechanismError> {
        let uri_str = std::str::from_utf8(raw)
            .map_err(|_| MechanismError::InvalidUri("input is not valid UTF-8".into()))?;

        let url = Url::parse(uri_str)
            .map_err(|e| MechanismError::InvalidUri(format!("failed to parse URI: {e}")))?;

        // Validate scheme
        if url.scheme() != self.scheme {
            return Err(MechanismError::InvalidUri(format!(
                "expected scheme '{}', got '{}'",
                self.scheme,
                url.scheme()
            )));
        }

        // Validate host/path
        if url.host_str() != Some("pair") {
            return Err(MechanismError::InvalidUri(
                "expected host 'pair' in URI".into(),
            ));
        }

        // Extract query parameters
        let params: std::collections::HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        // pid (base58 PeerId)
        let pid_str = params
            .get("pid")
            .ok_or_else(|| MechanismError::InvalidUri("missing 'pid' parameter".into()))?;
        let pid_bytes = bs58::decode(pid_str)
            .into_vec()
            .map_err(|e| MechanismError::InvalidUri(format!("invalid base58 pid: {e}")))?;
        let peer_id = PeerId::from_bytes(&pid_bytes)
            .map_err(|e| MechanismError::InvalidUri(format!("invalid peer_id: {e}")))?;

        // nonce (hex)
        let nonce_str = params
            .get("nonce")
            .ok_or_else(|| MechanismError::InvalidUri("missing 'nonce' parameter".into()))?;
        let nonce_vec = hex::decode(nonce_str)
            .map_err(|e| MechanismError::InvalidUri(format!("invalid hex nonce: {e}")))?;
        let nonce: [u8; 16] = nonce_vec
            .try_into()
            .map_err(|_| MechanismError::InvalidUri("nonce must be 16 bytes".into()))?;

        // pake (hex)
        let pake_str = params
            .get("pake")
            .ok_or_else(|| MechanismError::InvalidUri("missing 'pake' parameter".into()))?;
        let pake_credential = hex::decode(pake_str)
            .map_err(|e| MechanismError::InvalidUri(format!("invalid hex pake: {e}")))?;

        // hints (optional, base64url-encoded CBOR)
        let connection_hints = if let Some(hints_str) = params.get("hints") {
            Some(Self::decode_hints(hints_str)?)
        } else {
            None
        };

        // timestamps
        let created_at = params
            .get("t")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let expires_at = params
            .get("x")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let payload = PairingPayload {
            peer_id,
            nonce,
            pake_credential,
            connection_hints,
            created_at,
            expires_at,
        };

        // Validate expiry
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
    fn link_generate_and_consume_roundtrip() {
        let mechanism = PairingLinkMechanism::default();
        let payload = make_payload(u64::MAX);

        let raw = mechanism.generate_payload(&payload).unwrap();
        let uri_str = std::str::from_utf8(&raw).unwrap();
        assert!(uri_str.starts_with("cairn://pair?"));

        let restored = mechanism.consume_payload(&raw).unwrap();
        assert_eq!(payload.peer_id, restored.peer_id);
        assert_eq!(payload.nonce, restored.nonce);
        assert_eq!(payload.pake_credential, restored.pake_credential);
        assert_eq!(payload.created_at, restored.created_at);
        assert_eq!(payload.expires_at, restored.expires_at);

        let orig_hints = payload.connection_hints.unwrap();
        let rest_hints = restored.connection_hints.unwrap();
        assert_eq!(orig_hints.len(), rest_hints.len());
        assert_eq!(orig_hints[0].hint_type, rest_hints[0].hint_type);
        assert_eq!(orig_hints[0].value, rest_hints[0].value);
    }

    #[test]
    fn link_roundtrip_without_hints() {
        let mechanism = PairingLinkMechanism::default();
        let identity = LocalIdentity::generate();
        let payload = PairingPayload {
            peer_id: identity.peer_id().clone(),
            nonce: [0xFF; 16],
            pake_credential: vec![0x00; 32],
            connection_hints: None,
            created_at: 1700000000,
            expires_at: u64::MAX,
        };

        let raw = mechanism.generate_payload(&payload).unwrap();
        let restored = mechanism.consume_payload(&raw).unwrap();
        assert!(restored.connection_hints.is_none());
        assert_eq!(payload.nonce, restored.nonce);
    }

    #[test]
    fn link_mechanism_type_is_initiation() {
        let mechanism = PairingLinkMechanism::default();
        assert_eq!(mechanism.mechanism_type(), MechanismType::Initiation);
    }

    #[test]
    fn link_rejects_expired_payload() {
        let mechanism = PairingLinkMechanism::default();
        let payload = make_payload(1000); // expired in the past
        let raw = mechanism.generate_payload(&payload).unwrap();
        let result = mechanism.consume_payload(&raw);
        assert!(matches!(result, Err(MechanismError::Expired)));
    }

    #[test]
    fn link_rejects_wrong_scheme() {
        let mechanism = PairingLinkMechanism::default();
        let result = mechanism.consume_payload(b"https://pair?pid=abc&nonce=abc&pake=abc");
        assert!(matches!(result, Err(MechanismError::InvalidUri(_))));
    }

    #[test]
    fn link_rejects_missing_pid() {
        let mechanism = PairingLinkMechanism::default();
        let result = mechanism.consume_payload(b"cairn://pair?nonce=aa&pake=bb");
        assert!(matches!(result, Err(MechanismError::InvalidUri(_))));
    }

    #[test]
    fn link_rejects_missing_nonce() {
        let mechanism = PairingLinkMechanism::default();
        let result = mechanism.consume_payload(b"cairn://pair?pid=abc&pake=bb");
        assert!(matches!(result, Err(MechanismError::InvalidUri(_))));
    }

    #[test]
    fn link_rejects_missing_pake() {
        let mechanism = PairingLinkMechanism::default();
        let result = mechanism.consume_payload(b"cairn://pair?pid=abc&nonce=aa");
        assert!(matches!(result, Err(MechanismError::InvalidUri(_))));
    }

    #[test]
    fn link_custom_scheme() {
        let mechanism = PairingLinkMechanism::new("myapp", Duration::from_secs(300));
        let payload = make_payload(u64::MAX);
        let raw = mechanism.generate_payload(&payload).unwrap();
        let uri_str = std::str::from_utf8(&raw).unwrap();
        assert!(uri_str.starts_with("myapp://pair?"));

        let restored = mechanism.consume_payload(&raw).unwrap();
        assert_eq!(payload.peer_id, restored.peer_id);
    }

    #[test]
    fn link_custom_scheme_rejects_default() {
        let mechanism = PairingLinkMechanism::new("myapp", Duration::from_secs(300));
        // A cairn:// URI should be rejected by a myapp:// mechanism
        let default_mechanism = PairingLinkMechanism::default();
        let payload = make_payload(u64::MAX);
        let raw = default_mechanism.generate_payload(&payload).unwrap();
        let result = mechanism.consume_payload(&raw);
        assert!(matches!(result, Err(MechanismError::InvalidUri(_))));
    }

    #[test]
    fn link_rejects_invalid_utf8() {
        let mechanism = PairingLinkMechanism::default();
        let result = mechanism.consume_payload(&[0xFF, 0xFE]);
        assert!(matches!(result, Err(MechanismError::InvalidUri(_))));
    }

    #[test]
    fn link_hints_encode_decode_roundtrip() {
        let hints = vec![
            ConnectionHint {
                hint_type: "rendezvous".into(),
                value: "relay.example.com:9090".into(),
            },
            ConnectionHint {
                hint_type: "address".into(),
                value: "192.168.1.100:4433".into(),
            },
        ];

        let encoded = PairingLinkMechanism::encode_hints(&hints).unwrap();
        let decoded = PairingLinkMechanism::decode_hints(&encoded).unwrap();

        assert_eq!(hints.len(), decoded.len());
        for (h1, h2) in hints.iter().zip(decoded.iter()) {
            assert_eq!(h1.hint_type, h2.hint_type);
            assert_eq!(h1.value, h2.value);
        }
    }
}
