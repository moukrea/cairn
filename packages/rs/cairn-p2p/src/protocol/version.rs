use serde::{Deserialize, Serialize};

use crate::error::{CairnError, Result};
use crate::protocol::envelope::{new_msg_id, MessageEnvelope};
use crate::protocol::message_types::VERSION_NEGOTIATE;

/// Current protocol version.
pub const CURRENT_PROTOCOL_VERSION: u8 = 1;

/// All protocol versions this implementation supports, highest first.
pub const SUPPORTED_VERSIONS: &[u8] = &[1];

/// Payload for `VersionNegotiate` messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionNegotiatePayload {
    /// Supported protocol versions, ordered highest first.
    pub versions: Vec<u8>,
}

/// Version mismatch error details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMismatch {
    /// Our supported versions.
    pub local_versions: Vec<u8>,
    /// Peer's supported versions.
    pub remote_versions: Vec<u8>,
}

impl std::fmt::Display for VersionMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "version mismatch: local supports {:?}, remote supports {:?}",
            self.local_versions, self.remote_versions
        )
    }
}

/// Select the highest mutually supported version.
///
/// - `our_versions`: our supported versions (highest first)
/// - `peer_versions`: peer's supported versions (highest first)
///
/// Returns the selected version, or a `VersionMismatch` error.
pub fn select_version(our_versions: &[u8], peer_versions: &[u8]) -> Result<u8> {
    for &v in our_versions {
        if peer_versions.contains(&v) {
            return Ok(v);
        }
    }
    Err(CairnError::version_mismatch(
        format!("{:?}", our_versions),
        format!("{:?}", peer_versions),
    ))
}

/// CBOR-encode a payload struct into bytes.
fn encode_payload<T: Serialize>(payload: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf)
        .map_err(|e| CairnError::Protocol(format!("CBOR payload encode error: {e}")))?;
    Ok(buf)
}

/// CBOR-decode a payload struct from bytes.
fn decode_payload<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T> {
    ciborium::from_reader(data)
        .map_err(|e| CairnError::Protocol(format!("CBOR payload decode error: {e}")))
}

/// Create a `VersionNegotiate` message envelope advertising our supported versions.
pub fn create_version_negotiate() -> Result<MessageEnvelope> {
    let payload = VersionNegotiatePayload {
        versions: SUPPORTED_VERSIONS.to_vec(),
    };

    Ok(MessageEnvelope {
        version: CURRENT_PROTOCOL_VERSION,
        msg_type: VERSION_NEGOTIATE,
        msg_id: new_msg_id(),
        session_id: None,
        payload: encode_payload(&payload)?,
        auth_tag: None,
    })
}

/// Parse a received `VersionNegotiate` envelope and extract the payload.
pub fn parse_version_negotiate(envelope: &MessageEnvelope) -> Result<VersionNegotiatePayload> {
    if envelope.msg_type != VERSION_NEGOTIATE {
        return Err(CairnError::Protocol(format!(
            "expected VERSION_NEGOTIATE (0x{:04X}), got 0x{:04X}",
            VERSION_NEGOTIATE, envelope.msg_type
        )));
    }
    decode_payload(&envelope.payload)
}

/// Process a received `VersionNegotiate` and produce a response.
///
/// If versions are compatible, returns `Ok((selected_version, response_envelope))`.
/// The response envelope contains a `VersionNegotiatePayload` with only the
/// selected version. If incompatible, returns `Err` with `VersionMismatch` details.
pub fn handle_version_negotiate(received: &MessageEnvelope) -> Result<(u8, MessageEnvelope)> {
    let peer_payload = parse_version_negotiate(received)?;
    let selected = select_version(SUPPORTED_VERSIONS, &peer_payload.versions)?;

    let response_payload = VersionNegotiatePayload {
        versions: vec![selected],
    };

    let response = MessageEnvelope {
        version: CURRENT_PROTOCOL_VERSION,
        msg_type: VERSION_NEGOTIATE,
        msg_id: new_msg_id(),
        session_id: None,
        payload: encode_payload(&response_payload)?,
        auth_tag: None,
    };

    Ok((selected, response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_protocol_version_is_1() {
        assert_eq!(CURRENT_PROTOCOL_VERSION, 1);
    }

    #[test]
    fn supported_versions_contains_current() {
        assert!(SUPPORTED_VERSIONS.contains(&CURRENT_PROTOCOL_VERSION));
    }

    #[test]
    fn supported_versions_highest_first() {
        for window in SUPPORTED_VERSIONS.windows(2) {
            assert!(
                window[0] >= window[1],
                "SUPPORTED_VERSIONS must be ordered highest first"
            );
        }
    }

    #[test]
    fn select_version_common_version() {
        assert_eq!(select_version(&[3, 2, 1], &[2, 1]).unwrap(), 2);
    }

    #[test]
    fn select_version_exact_match() {
        assert_eq!(select_version(&[1], &[1]).unwrap(), 1);
    }

    #[test]
    fn select_version_picks_highest_mutual() {
        assert_eq!(select_version(&[5, 3, 1], &[4, 3, 2, 1]).unwrap(), 3);
    }

    #[test]
    fn select_version_no_common() {
        let result = select_version(&[3, 2], &[5, 4]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CairnError::VersionMismatch { .. }));
    }

    #[test]
    fn select_version_empty_ours() {
        let result = select_version(&[], &[1]);
        assert!(result.is_err());
    }

    #[test]
    fn select_version_empty_peer() {
        let result = select_version(&[1], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn version_mismatch_display() {
        let mismatch = VersionMismatch {
            local_versions: vec![2, 1],
            remote_versions: vec![3],
        };
        let s = mismatch.to_string();
        assert!(s.contains("local supports"));
        assert!(s.contains("remote supports"));
    }

    #[test]
    fn payload_cbor_roundtrip() {
        let payload = VersionNegotiatePayload {
            versions: vec![3, 2, 1],
        };
        let encoded = encode_payload(&payload).unwrap();
        let decoded: VersionNegotiatePayload = decode_payload(&encoded).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn create_version_negotiate_envelope() {
        let envelope = create_version_negotiate().unwrap();
        assert_eq!(envelope.version, CURRENT_PROTOCOL_VERSION);
        assert_eq!(envelope.msg_type, VERSION_NEGOTIATE);
        assert!(envelope.session_id.is_none());
        assert!(envelope.auth_tag.is_none());

        let payload = parse_version_negotiate(&envelope).unwrap();
        assert_eq!(payload.versions, SUPPORTED_VERSIONS);
    }

    #[test]
    fn parse_version_negotiate_wrong_type() {
        let envelope = MessageEnvelope {
            version: 1,
            msg_type: 0x0100, // PAIR_REQUEST, not VERSION_NEGOTIATE
            msg_id: new_msg_id(),
            session_id: None,
            payload: vec![],
            auth_tag: None,
        };
        let result = parse_version_negotiate(&envelope);
        assert!(result.is_err());
    }

    #[test]
    fn handle_version_negotiate_compatible() {
        let initiator = create_version_negotiate().unwrap();
        let (selected, response) = handle_version_negotiate(&initiator).unwrap();
        assert_eq!(selected, 1);
        assert_eq!(response.msg_type, VERSION_NEGOTIATE);

        let resp_payload = parse_version_negotiate(&response).unwrap();
        assert_eq!(resp_payload.versions, vec![1]);
    }

    #[test]
    fn handle_version_negotiate_incompatible() {
        // Simulate a peer that only supports version 99.
        let peer_payload = VersionNegotiatePayload { versions: vec![99] };
        let envelope = MessageEnvelope {
            version: 99,
            msg_type: VERSION_NEGOTIATE,
            msg_id: new_msg_id(),
            session_id: None,
            payload: encode_payload(&peer_payload).unwrap(),
            auth_tag: None,
        };

        let result = handle_version_negotiate(&envelope);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CairnError::VersionMismatch { .. }
        ));
    }

    #[test]
    fn full_negotiation_roundtrip() {
        // Alice initiates.
        let alice_offer = create_version_negotiate().unwrap();
        let alice_wire = alice_offer.encode().unwrap();

        // Bob receives and responds.
        let bob_received = MessageEnvelope::decode(&alice_wire).unwrap();
        let (selected, bob_response) = handle_version_negotiate(&bob_received).unwrap();
        assert_eq!(selected, 1);
        let bob_wire = bob_response.encode().unwrap();

        // Alice processes the response.
        let alice_received = MessageEnvelope::decode(&bob_wire).unwrap();
        let resp_payload = parse_version_negotiate(&alice_received).unwrap();
        assert_eq!(resp_payload.versions, vec![1]);
    }

    #[test]
    fn version_negotiate_envelope_wire_roundtrip() {
        let envelope = create_version_negotiate().unwrap();
        let encoded = envelope.encode().unwrap();
        let decoded = MessageEnvelope::decode(&encoded).unwrap();
        assert_eq!(envelope, decoded);
    }
}
