use serde::{Deserialize, Serialize};

use crate::identity::PeerId;

/// Pairing flow type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairingFlowType {
    /// Verification-only (SAS) — uses Noise XX handshake, then out-of-band verification.
    Standard,
    /// Self-bootstrapping (QR, pin, link, PSK) — uses SPAKE2 PAKE.
    Initiation,
}

/// Reason for rejecting a pairing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairRejectReason {
    UserRejected,
    AuthenticationFailed,
    Timeout,
    RateLimited,
}

impl std::fmt::Display for PairRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PairRejectReason::UserRejected => write!(f, "user rejected"),
            PairRejectReason::AuthenticationFailed => write!(f, "authentication failed"),
            PairRejectReason::Timeout => write!(f, "timeout"),
            PairRejectReason::RateLimited => write!(f, "rate limited"),
        }
    }
}

/// 0x0100 — Initiates a pairing handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    pub peer_id: PeerId,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pake_msg: Option<Vec<u8>>,
    pub flow_type: PairingFlowType,
}

/// 0x0101 — PAKE challenge from the responder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairChallenge {
    pub peer_id: PeerId,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pake_msg: Vec<u8>,
}

/// 0x0102 — PAKE response / key confirmation from initiator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairResponse {
    #[serde(with = "serde_bytes")]
    pub key_confirmation: Vec<u8>,
}

/// 0x0103 — Pairing confirmation (mutual).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairConfirm {
    #[serde(with = "serde_bytes")]
    pub key_confirmation: Vec<u8>,
}

/// 0x0104 — Pairing rejection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairReject {
    pub reason: PairRejectReason,
}

/// 0x0105 — Unpairing notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRevoke {
    pub peer_id: PeerId,
}

/// Union of all pairing messages for dispatch.
#[derive(Debug, Clone)]
pub enum PairingMessage {
    Request(PairRequest),
    Challenge(PairChallenge),
    Response(PairResponse),
    Confirm(PairConfirm),
    Reject(PairReject),
    Revoke(PairRevoke),
}

impl PairingMessage {
    /// Returns the wire protocol message type code.
    pub fn type_code(&self) -> u16 {
        use crate::protocol::message_types::*;
        match self {
            PairingMessage::Request(_) => PAIR_REQUEST,
            PairingMessage::Challenge(_) => PAIR_CHALLENGE,
            PairingMessage::Response(_) => PAIR_RESPONSE,
            PairingMessage::Confirm(_) => PAIR_CONFIRM,
            PairingMessage::Reject(_) => PAIR_REJECT,
            PairingMessage::Revoke(_) => PAIR_REVOKE,
        }
    }

    /// Serialize this message to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, crate::error::CairnError> {
        let mut buf = Vec::new();
        match self {
            PairingMessage::Request(m) => ciborium::into_writer(m, &mut buf),
            PairingMessage::Challenge(m) => ciborium::into_writer(m, &mut buf),
            PairingMessage::Response(m) => ciborium::into_writer(m, &mut buf),
            PairingMessage::Confirm(m) => ciborium::into_writer(m, &mut buf),
            PairingMessage::Reject(m) => ciborium::into_writer(m, &mut buf),
            PairingMessage::Revoke(m) => ciborium::into_writer(m, &mut buf),
        }
        .map_err(|e| crate::error::CairnError::Protocol(format!("CBOR encode error: {e}")))?;
        Ok(buf)
    }

    /// Deserialize a pairing message from CBOR bytes given the type code.
    pub fn from_cbor(type_code: u16, data: &[u8]) -> Result<Self, crate::error::CairnError> {
        use crate::protocol::message_types::*;
        let err_fn = |e: ciborium::de::Error<std::io::Error>| {
            crate::error::CairnError::Protocol(format!("CBOR decode error: {e}"))
        };
        match type_code {
            PAIR_REQUEST => Ok(PairingMessage::Request(
                ciborium::from_reader(data).map_err(err_fn)?,
            )),
            PAIR_CHALLENGE => Ok(PairingMessage::Challenge(
                ciborium::from_reader(data).map_err(err_fn)?,
            )),
            PAIR_RESPONSE => Ok(PairingMessage::Response(
                ciborium::from_reader(data).map_err(err_fn)?,
            )),
            PAIR_CONFIRM => Ok(PairingMessage::Confirm(
                ciborium::from_reader(data).map_err(err_fn)?,
            )),
            PAIR_REJECT => Ok(PairingMessage::Reject(
                ciborium::from_reader(data).map_err(err_fn)?,
            )),
            PAIR_REVOKE => Ok(PairingMessage::Revoke(
                ciborium::from_reader(data).map_err(err_fn)?,
            )),
            _ => Err(crate::error::CairnError::Protocol(format!(
                "unknown pairing message type: 0x{type_code:04x}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;

    fn test_peer_id() -> PeerId {
        let id = LocalIdentity::generate();
        id.peer_id().clone()
    }

    #[test]
    fn pair_request_cbor_roundtrip() {
        let msg = PairingMessage::Request(PairRequest {
            peer_id: test_peer_id(),
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            pake_msg: Some(vec![0xAA, 0xBB]),
            flow_type: PairingFlowType::Initiation,
        });
        let cbor = msg.to_cbor().unwrap();
        let restored = PairingMessage::from_cbor(msg.type_code(), &cbor).unwrap();
        match restored {
            PairingMessage::Request(r) => {
                assert_eq!(r.flow_type, PairingFlowType::Initiation);
                assert!(r.pake_msg.is_some());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn pair_challenge_cbor_roundtrip() {
        let msg = PairingMessage::Challenge(PairChallenge {
            peer_id: test_peer_id(),
            nonce: vec![0; 16],
            pake_msg: vec![1, 2, 3],
        });
        let cbor = msg.to_cbor().unwrap();
        let restored = PairingMessage::from_cbor(msg.type_code(), &cbor).unwrap();
        assert!(matches!(restored, PairingMessage::Challenge(_)));
    }

    #[test]
    fn pair_response_cbor_roundtrip() {
        let msg = PairingMessage::Response(PairResponse {
            key_confirmation: vec![0xDE, 0xAD],
        });
        let cbor = msg.to_cbor().unwrap();
        let restored = PairingMessage::from_cbor(msg.type_code(), &cbor).unwrap();
        assert!(matches!(restored, PairingMessage::Response(_)));
    }

    #[test]
    fn pair_confirm_cbor_roundtrip() {
        let msg = PairingMessage::Confirm(PairConfirm {
            key_confirmation: vec![0xCA, 0xFE],
        });
        let cbor = msg.to_cbor().unwrap();
        let restored = PairingMessage::from_cbor(msg.type_code(), &cbor).unwrap();
        assert!(matches!(restored, PairingMessage::Confirm(_)));
    }

    #[test]
    fn pair_reject_cbor_roundtrip() {
        let msg = PairingMessage::Reject(PairReject {
            reason: PairRejectReason::UserRejected,
        });
        let cbor = msg.to_cbor().unwrap();
        let restored = PairingMessage::from_cbor(msg.type_code(), &cbor).unwrap();
        match restored {
            PairingMessage::Reject(r) => assert_eq!(r.reason, PairRejectReason::UserRejected),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn pair_revoke_cbor_roundtrip() {
        let pid = test_peer_id();
        let msg = PairingMessage::Revoke(PairRevoke {
            peer_id: pid.clone(),
        });
        let cbor = msg.to_cbor().unwrap();
        let restored = PairingMessage::from_cbor(msg.type_code(), &cbor).unwrap();
        match restored {
            PairingMessage::Revoke(r) => assert_eq!(r.peer_id, pid),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn unknown_type_code_rejected() {
        let result = PairingMessage::from_cbor(0x0199, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn type_codes_match_constants() {
        use crate::protocol::message_types::*;
        let pid = test_peer_id();
        assert_eq!(
            PairingMessage::Request(PairRequest {
                peer_id: pid.clone(),
                nonce: vec![],
                pake_msg: None,
                flow_type: PairingFlowType::Standard,
            })
            .type_code(),
            PAIR_REQUEST
        );
        assert_eq!(
            PairingMessage::Challenge(PairChallenge {
                peer_id: pid.clone(),
                nonce: vec![0; 16],
                pake_msg: vec![],
            })
            .type_code(),
            PAIR_CHALLENGE
        );
        assert_eq!(
            PairingMessage::Response(PairResponse {
                key_confirmation: vec![],
            })
            .type_code(),
            PAIR_RESPONSE
        );
        assert_eq!(
            PairingMessage::Confirm(PairConfirm {
                key_confirmation: vec![],
            })
            .type_code(),
            PAIR_CONFIRM
        );
        assert_eq!(
            PairingMessage::Reject(PairReject {
                reason: PairRejectReason::Timeout,
            })
            .type_code(),
            PAIR_REJECT
        );
        assert_eq!(
            PairingMessage::Revoke(PairRevoke { peer_id: pid }).type_code(),
            PAIR_REVOKE
        );
    }

    #[test]
    fn all_reject_reasons_display() {
        assert_eq!(PairRejectReason::UserRejected.to_string(), "user rejected");
        assert_eq!(
            PairRejectReason::AuthenticationFailed.to_string(),
            "authentication failed"
        );
        assert_eq!(PairRejectReason::Timeout.to_string(), "timeout");
        assert_eq!(PairRejectReason::RateLimited.to_string(), "rate limited");
    }

    #[test]
    fn standard_flow_request_has_no_pake_msg() {
        let msg = PairingMessage::Request(PairRequest {
            peer_id: test_peer_id(),
            nonce: vec![0; 16],
            pake_msg: None,
            flow_type: PairingFlowType::Standard,
        });
        let cbor = msg.to_cbor().unwrap();
        let restored = PairingMessage::from_cbor(msg.type_code(), &cbor).unwrap();
        match restored {
            PairingMessage::Request(r) => {
                assert_eq!(r.flow_type, PairingFlowType::Standard);
                assert!(r.pake_msg.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }
}
