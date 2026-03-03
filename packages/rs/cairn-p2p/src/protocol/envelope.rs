use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{CairnError, Result};

/// Generates a new UUID v7 message ID as a 16-byte array.
///
/// UUID v7 provides timestamp-ordering with 74 bits of randomness per RFC 9562.
pub fn new_msg_id() -> [u8; 16] {
    *uuid::Uuid::now_v7().as_bytes()
}

/// The wire-level message envelope used for all cairn protocol messages.
///
/// Serialized as a CBOR map with integer keys (0-5) for compactness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEnvelope {
    /// Protocol version identifier (uint8). Initial version is 1.
    pub version: u8,
    /// Message type code (uint16) from the message type registry.
    pub msg_type: u16,
    /// UUID v7 message ID (16 bytes), timestamp-ordered.
    pub msg_id: [u8; 16],
    /// Session ID (32 bytes). None before session establishment.
    pub session_id: Option<[u8; 32]>,
    /// Type-specific CBOR-encoded payload.
    pub payload: Vec<u8>,
    /// HMAC or AEAD authentication tag. None before key establishment.
    pub auth_tag: Option<Vec<u8>>,
}

impl MessageEnvelope {
    /// Encode the envelope to CBOR bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| CairnError::Protocol(format!("CBOR encode error: {e}")))?;
        Ok(buf)
    }

    /// Encode the envelope to deterministic CBOR (RFC 8949 section 4.2).
    ///
    /// Keys are sorted by integer value (natural for our 0-5 keys) and all
    /// values use their shortest encoding. Used when the output will be input
    /// to a signature or HMAC computation.
    pub fn encode_deterministic(&self) -> Result<Vec<u8>> {
        // ciborium already uses shortest-form encoding for integers and byte
        // strings. Our Serialize impl emits keys in ascending order (0..5),
        // which satisfies deterministic CBOR key ordering. So the standard
        // encode path already produces deterministic output.
        self.encode()
    }

    /// Decode a `MessageEnvelope` from CBOR bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes)
            .map_err(|e| CairnError::Protocol(format!("CBOR decode error: {e}")))
    }
}

// -- Custom Serialize: CBOR map with integer keys 0-5 -------------------------

impl Serialize for MessageEnvelope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        // Count entries: version(0), type(1), msg_id(2), payload(4) are always
        // present. session_id(3) and auth_tag(5) are optional.
        let mut len = 4u64;
        if self.session_id.is_some() {
            len += 1;
        }
        if self.auth_tag.is_some() {
            len += 1;
        }

        let mut map = serializer.serialize_map(Some(len as usize))?;

        // Key 0: version
        map.serialize_entry(&0u8, &self.version)?;
        // Key 1: msg_type
        map.serialize_entry(&1u8, &self.msg_type)?;
        // Key 2: msg_id as byte string
        map.serialize_entry(&2u8, &serde_bytes::Bytes::new(&self.msg_id))?;
        // Key 3: session_id (optional)
        if let Some(ref sid) = self.session_id {
            map.serialize_entry(&3u8, &serde_bytes::Bytes::new(sid.as_slice()))?;
        }
        // Key 4: payload as byte string
        map.serialize_entry(&4u8, &serde_bytes::Bytes::new(&self.payload))?;
        // Key 5: auth_tag (optional)
        if let Some(ref tag) = self.auth_tag {
            map.serialize_entry(&5u8, &serde_bytes::Bytes::new(tag))?;
        }

        map.end()
    }
}

// -- Custom Deserialize: CBOR map with integer keys 0-5 -----------------------

impl<'de> Deserialize<'de> for MessageEnvelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_map(EnvelopeVisitor)
    }
}

struct EnvelopeVisitor;

impl<'de> Visitor<'de> for EnvelopeVisitor {
    type Value = MessageEnvelope;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a CBOR map with integer keys 0-5")
    }

    fn visit_map<A: MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut version: Option<u8> = None;
        let mut msg_type: Option<u16> = None;
        let mut msg_id: Option<[u8; 16]> = None;
        let mut session_id: Option<[u8; 32]> = None;
        let mut payload: Option<Vec<u8>> = None;
        let mut auth_tag: Option<Vec<u8>> = None;

        while let Some(key) = map.next_key::<u8>()? {
            match key {
                0 => {
                    if version.is_some() {
                        return Err(de::Error::duplicate_field("version"));
                    }
                    version = Some(map.next_value()?);
                }
                1 => {
                    if msg_type.is_some() {
                        return Err(de::Error::duplicate_field("msg_type"));
                    }
                    msg_type = Some(map.next_value()?);
                }
                2 => {
                    if msg_id.is_some() {
                        return Err(de::Error::duplicate_field("msg_id"));
                    }
                    let bytes: serde_bytes::ByteBuf = map.next_value()?;
                    let arr: [u8; 16] = bytes.as_ref().try_into().map_err(|_| {
                        de::Error::invalid_length(bytes.len(), &"16 bytes for msg_id")
                    })?;
                    msg_id = Some(arr);
                }
                3 => {
                    if session_id.is_some() {
                        return Err(de::Error::duplicate_field("session_id"));
                    }
                    let bytes: serde_bytes::ByteBuf = map.next_value()?;
                    let arr: [u8; 32] = bytes.as_ref().try_into().map_err(|_| {
                        de::Error::invalid_length(bytes.len(), &"32 bytes for session_id")
                    })?;
                    session_id = Some(arr);
                }
                4 => {
                    if payload.is_some() {
                        return Err(de::Error::duplicate_field("payload"));
                    }
                    let bytes: serde_bytes::ByteBuf = map.next_value()?;
                    payload = Some(bytes.into_vec());
                }
                5 => {
                    if auth_tag.is_some() {
                        return Err(de::Error::duplicate_field("auth_tag"));
                    }
                    let bytes: serde_bytes::ByteBuf = map.next_value()?;
                    auth_tag = Some(bytes.into_vec());
                }
                _ => {
                    // Skip unknown keys for forward compatibility.
                    let _: ciborium::Value = map.next_value()?;
                }
            }
        }

        let version = version.ok_or_else(|| de::Error::missing_field("version (key 0)"))?;
        let msg_type = msg_type.ok_or_else(|| de::Error::missing_field("msg_type (key 1)"))?;
        let msg_id = msg_id.ok_or_else(|| de::Error::missing_field("msg_id (key 2)"))?;
        let payload = payload.ok_or_else(|| de::Error::missing_field("payload (key 4)"))?;

        Ok(MessageEnvelope {
            version,
            msg_type,
            msg_id,
            session_id,
            payload,
            auth_tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::message_types;

    #[test]
    fn test_new_msg_id_is_16_bytes() {
        let id = new_msg_id();
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn test_new_msg_id_unique() {
        let id1 = new_msg_id();
        let id2 = new_msg_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_roundtrip_minimal_envelope() {
        let envelope = MessageEnvelope {
            version: 1,
            msg_type: message_types::HEARTBEAT,
            msg_id: new_msg_id(),
            session_id: None,
            payload: vec![],
            auth_tag: None,
        };

        let encoded = envelope.encode().unwrap();
        let decoded = MessageEnvelope::decode(&encoded).unwrap();
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn test_roundtrip_full_envelope() {
        let session_id = [0xABu8; 32];
        let envelope = MessageEnvelope {
            version: 1,
            msg_type: message_types::DATA_MESSAGE,
            msg_id: new_msg_id(),
            session_id: Some(session_id),
            payload: vec![0xCA, 0xFE, 0xBA, 0xBE],
            auth_tag: Some(vec![0xDE, 0xAD]),
        };

        let encoded = envelope.encode().unwrap();
        let decoded = MessageEnvelope::decode(&encoded).unwrap();
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn test_optional_fields_absent() {
        let envelope = MessageEnvelope {
            version: 1,
            msg_type: message_types::PAIR_REQUEST,
            msg_id: new_msg_id(),
            session_id: None,
            payload: vec![0x01],
            auth_tag: None,
        };

        let encoded = envelope.encode().unwrap();
        let decoded = MessageEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.session_id, None);
        assert_eq!(decoded.auth_tag, None);
    }

    #[test]
    fn test_deterministic_encoding_is_stable() {
        let envelope = MessageEnvelope {
            version: 1,
            msg_type: message_types::HEARTBEAT,
            msg_id: [1u8; 16],
            session_id: Some([2u8; 32]),
            payload: vec![0xFF],
            auth_tag: Some(vec![0x00, 0x01]),
        };

        let enc1 = envelope.encode_deterministic().unwrap();
        let enc2 = envelope.encode_deterministic().unwrap();
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn test_decode_invalid_cbor() {
        let result = MessageEnvelope::decode(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_version_field_preserved() {
        for v in [0u8, 1, 255] {
            let envelope = MessageEnvelope {
                version: v,
                msg_type: message_types::HEARTBEAT,
                msg_id: [0u8; 16],
                session_id: None,
                payload: vec![],
                auth_tag: None,
            };
            let decoded = MessageEnvelope::decode(&envelope.encode().unwrap()).unwrap();
            assert_eq!(decoded.version, v);
        }
    }
}
