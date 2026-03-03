use std::time::Duration;

use thiserror::Error;

/// Recommended recovery action for a given error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorBehavior {
    /// Retry with different transport configuration.
    Retry,
    /// Re-establish the session (no re-pairing needed).
    Reconnect,
    /// Stop — manual intervention required.
    Abort,
    /// Generate a new pairing payload.
    ReGenerate,
    /// Background poll / wait for availability.
    Wait,
    /// Inform the user — no automatic recovery.
    Inform,
}

#[derive(Debug, Error)]
pub enum CairnError {
    // --- Spec error types (task 022) ---
    #[error("all transports exhausted: {details}. Suggestion: {suggestion}")]
    TransportExhausted { details: String, suggestion: String },

    #[error("session expired after {expiry_duration:?}")]
    SessionExpired {
        session_id: String,
        expiry_duration: Duration,
    },

    #[error("peer {peer_id} unreachable at any rendezvous point within {timeout:?}")]
    PeerUnreachable { peer_id: String, timeout: Duration },

    #[error("authentication failed for session {session_id}: cryptographic verification failed (possible key compromise)")]
    AuthenticationFailed { session_id: String },

    #[error("pairing rejected by remote peer {peer_id}")]
    PairingRejected { peer_id: String },

    #[error("pairing payload expired after {expiry:?}. Generate a new payload to retry.")]
    PairingExpired { expiry: Duration },

    #[error("no mesh route found to {peer_id}: {suggestion}")]
    MeshRouteNotFound { peer_id: String, suggestion: String },

    #[error(
        "protocol version mismatch: local {local_version}, remote {remote_version}. {suggestion}"
    )]
    VersionMismatch {
        local_version: String,
        remote_version: String,
        suggestion: String,
    },

    // --- Internal/infrastructure error types (task 001) ---
    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("key store error: {0}")]
    KeyStore(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("discovery error: {0}")]
    Discovery(String),

    #[error("pairing error: {0}")]
    Pairing(String),

    #[error("identity error: {0}")]
    Identity(#[from] crate::identity::IdentityError),
}

impl CairnError {
    /// Create a `TransportExhausted` error with an auto-populated suggestion.
    pub fn transport_exhausted(details: impl Into<String>) -> Self {
        let details = details.into();
        let suggestion = if details.contains("symmetric NAT") || details.contains("all transports")
        {
            "deploy the cairn signaling server and/or TURN relay to resolve this — both peers appear to be behind restrictive NATs".to_string()
        } else {
            "check network connectivity and firewall settings, or deploy a TURN relay".to_string()
        };
        Self::TransportExhausted {
            details,
            suggestion,
        }
    }

    /// Create a `TransportExhausted` error with a custom suggestion.
    pub fn transport_exhausted_with_suggestion(
        details: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self::TransportExhausted {
            details: details.into(),
            suggestion: suggestion.into(),
        }
    }

    /// Create a `SessionExpired` error.
    pub fn session_expired(session_id: impl Into<String>, expiry: Duration) -> Self {
        Self::SessionExpired {
            session_id: session_id.into(),
            expiry_duration: expiry,
        }
    }

    /// Create a `PeerUnreachable` error.
    pub fn peer_unreachable(peer_id: impl Into<String>, timeout: Duration) -> Self {
        Self::PeerUnreachable {
            peer_id: peer_id.into(),
            timeout,
        }
    }

    /// Create an `AuthenticationFailed` error.
    pub fn auth_failed(session_id: impl Into<String>) -> Self {
        Self::AuthenticationFailed {
            session_id: session_id.into(),
        }
    }

    /// Create a `PairingRejected` error.
    pub fn pairing_rejected(peer_id: impl Into<String>) -> Self {
        Self::PairingRejected {
            peer_id: peer_id.into(),
        }
    }

    /// Create a `PairingExpired` error.
    pub fn pairing_expired(expiry: Duration) -> Self {
        Self::PairingExpired { expiry }
    }

    /// Create a `MeshRouteNotFound` error with an auto-populated suggestion.
    pub fn mesh_route_not_found(peer_id: impl Into<String>) -> Self {
        Self::MeshRouteNotFound {
            peer_id: peer_id.into(),
            suggestion: "try a direct connection or wait for mesh route discovery".to_string(),
        }
    }

    /// Create a `VersionMismatch` error with an auto-populated suggestion.
    pub fn version_mismatch(local: impl Into<String>, remote: impl Into<String>) -> Self {
        Self::VersionMismatch {
            local_version: local.into(),
            remote_version: remote.into(),
            suggestion: "peer needs to update to a compatible cairn version".to_string(),
        }
    }

    /// Returns the recommended recovery action for this error.
    pub fn error_behavior(&self) -> ErrorBehavior {
        match self {
            CairnError::TransportExhausted { .. } => ErrorBehavior::Retry,
            CairnError::SessionExpired { .. } => ErrorBehavior::Reconnect,
            CairnError::PeerUnreachable { .. } => ErrorBehavior::Wait,
            CairnError::AuthenticationFailed { .. } => ErrorBehavior::Abort,
            CairnError::PairingRejected { .. } => ErrorBehavior::Inform,
            CairnError::PairingExpired { .. } => ErrorBehavior::ReGenerate,
            CairnError::MeshRouteNotFound { .. } => ErrorBehavior::Wait,
            CairnError::VersionMismatch { .. } => ErrorBehavior::Abort,
            // Internal error types default to Abort (manual investigation needed).
            CairnError::Protocol(_)
            | CairnError::Crypto(_)
            | CairnError::KeyStore(_)
            | CairnError::Transport(_)
            | CairnError::Discovery(_)
            | CairnError::Pairing(_)
            | CairnError::Identity(_) => ErrorBehavior::Abort,
        }
    }
}

pub type Result<T> = std::result::Result<T, CairnError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_transport_exhausted() {
        let err = CairnError::TransportExhausted {
            details: "QUIC: timeout, TCP: refused".into(),
            suggestion: "deploy a TURN relay".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("all transports exhausted"));
        assert!(msg.contains("QUIC: timeout, TCP: refused"));
        assert!(msg.contains("deploy a TURN relay"));
    }

    #[test]
    fn behavior_transport_exhausted() {
        let err = CairnError::TransportExhausted {
            details: String::new(),
            suggestion: String::new(),
        };
        assert_eq!(err.error_behavior(), ErrorBehavior::Retry);
    }

    #[test]
    fn display_session_expired() {
        let err = CairnError::SessionExpired {
            session_id: "sess-123".into(),
            expiry_duration: Duration::from_secs(86400),
        };
        let msg = err.to_string();
        assert!(msg.contains("session expired after"));
        assert!(msg.contains("86400"));
    }

    #[test]
    fn behavior_session_expired() {
        let err = CairnError::SessionExpired {
            session_id: String::new(),
            expiry_duration: Duration::from_secs(0),
        };
        assert_eq!(err.error_behavior(), ErrorBehavior::Reconnect);
    }

    #[test]
    fn display_peer_unreachable() {
        let err = CairnError::PeerUnreachable {
            peer_id: "peer-abc".into(),
            timeout: Duration::from_secs(30),
        };
        let msg = err.to_string();
        assert!(msg.contains("peer peer-abc unreachable"));
        assert!(msg.contains("30"));
    }

    #[test]
    fn behavior_peer_unreachable() {
        let err = CairnError::PeerUnreachable {
            peer_id: String::new(),
            timeout: Duration::from_secs(0),
        };
        assert_eq!(err.error_behavior(), ErrorBehavior::Wait);
    }

    #[test]
    fn display_authentication_failed() {
        let err = CairnError::AuthenticationFailed {
            session_id: "sess-456".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("authentication failed for session sess-456"));
        assert!(msg.contains("possible key compromise"));
    }

    #[test]
    fn behavior_authentication_failed() {
        let err = CairnError::AuthenticationFailed {
            session_id: String::new(),
        };
        assert_eq!(err.error_behavior(), ErrorBehavior::Abort);
    }

    #[test]
    fn display_pairing_rejected() {
        let err = CairnError::PairingRejected {
            peer_id: "peer-xyz".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("pairing rejected by remote peer peer-xyz"));
    }

    #[test]
    fn behavior_pairing_rejected() {
        let err = CairnError::PairingRejected {
            peer_id: String::new(),
        };
        assert_eq!(err.error_behavior(), ErrorBehavior::Inform);
    }

    #[test]
    fn display_pairing_expired() {
        let err = CairnError::PairingExpired {
            expiry: Duration::from_secs(300),
        };
        let msg = err.to_string();
        assert!(msg.contains("pairing payload expired after"));
        assert!(msg.contains("300"));
        assert!(msg.contains("Generate a new payload to retry"));
    }

    #[test]
    fn behavior_pairing_expired() {
        let err = CairnError::PairingExpired {
            expiry: Duration::from_secs(0),
        };
        assert_eq!(err.error_behavior(), ErrorBehavior::ReGenerate);
    }

    #[test]
    fn display_mesh_route_not_found() {
        let err = CairnError::MeshRouteNotFound {
            peer_id: "peer-mesh".into(),
            suggestion: "try a direct connection".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("no mesh route found to peer-mesh"));
        assert!(msg.contains("try a direct connection"));
    }

    #[test]
    fn behavior_mesh_route_not_found() {
        let err = CairnError::MeshRouteNotFound {
            peer_id: String::new(),
            suggestion: String::new(),
        };
        assert_eq!(err.error_behavior(), ErrorBehavior::Wait);
    }

    #[test]
    fn display_version_mismatch() {
        let err = CairnError::VersionMismatch {
            local_version: "1.0".into(),
            remote_version: "2.0".into(),
            suggestion: "peer needs to update".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("protocol version mismatch"));
        assert!(msg.contains("local 1.0"));
        assert!(msg.contains("remote 2.0"));
        assert!(msg.contains("peer needs to update"));
    }

    #[test]
    fn behavior_version_mismatch() {
        let err = CairnError::VersionMismatch {
            local_version: String::new(),
            remote_version: String::new(),
            suggestion: String::new(),
        };
        assert_eq!(err.error_behavior(), ErrorBehavior::Abort);
    }

    #[test]
    fn existing_variants_preserved() {
        let cases = vec![
            CairnError::Protocol("test".into()),
            CairnError::Crypto("test".into()),
            CairnError::KeyStore("test".into()),
            CairnError::Transport("test".into()),
            CairnError::Discovery("test".into()),
        ];
        for err in &cases {
            assert_eq!(err.error_behavior(), ErrorBehavior::Abort);
            assert!(err.to_string().contains("test"));
        }
    }

    #[test]
    fn cairn_error_implements_std_error() {
        fn assert_std_error<T: std::error::Error>() {}
        assert_std_error::<CairnError>();
    }

    #[test]
    fn helper_transport_exhausted_symmetric_nat() {
        let err = CairnError::transport_exhausted("symmetric NAT detected");
        let msg = err.to_string();
        assert!(msg.contains("deploy the cairn signaling server and/or TURN relay"));
        assert_eq!(err.error_behavior(), ErrorBehavior::Retry);
    }

    #[test]
    fn helper_transport_exhausted_generic() {
        let err = CairnError::transport_exhausted("TCP: connection refused");
        let msg = err.to_string();
        assert!(msg.contains("check network connectivity"));
        assert_eq!(err.error_behavior(), ErrorBehavior::Retry);
    }

    #[test]
    fn helper_mesh_route_not_found_has_suggestion() {
        let err = CairnError::mesh_route_not_found("peer-123");
        let msg = err.to_string();
        assert!(msg.contains("try a direct connection or wait for mesh route discovery"));
        assert_eq!(err.error_behavior(), ErrorBehavior::Wait);
    }

    #[test]
    fn helper_version_mismatch_has_suggestion() {
        let err = CairnError::version_mismatch("1.0", "2.0");
        let msg = err.to_string();
        assert!(msg.contains("peer needs to update to a compatible cairn version"));
        assert_eq!(err.error_behavior(), ErrorBehavior::Abort);
    }

    #[test]
    fn helper_session_expired() {
        let err = CairnError::session_expired("sess-1", Duration::from_secs(3600));
        assert!(matches!(err, CairnError::SessionExpired { .. }));
        assert_eq!(err.error_behavior(), ErrorBehavior::Reconnect);
    }

    #[test]
    fn helper_peer_unreachable() {
        let err = CairnError::peer_unreachable("peer-1", Duration::from_secs(30));
        assert!(matches!(err, CairnError::PeerUnreachable { .. }));
        assert_eq!(err.error_behavior(), ErrorBehavior::Wait);
    }

    #[test]
    fn helper_auth_failed() {
        let err = CairnError::auth_failed("sess-1");
        assert!(matches!(err, CairnError::AuthenticationFailed { .. }));
        assert_eq!(err.error_behavior(), ErrorBehavior::Abort);
    }

    #[test]
    fn helper_pairing_rejected() {
        let err = CairnError::pairing_rejected("peer-1");
        assert!(matches!(err, CairnError::PairingRejected { .. }));
        assert_eq!(err.error_behavior(), ErrorBehavior::Inform);
    }

    #[test]
    fn helper_pairing_expired() {
        let err = CairnError::pairing_expired(Duration::from_secs(300));
        assert!(matches!(err, CairnError::PairingExpired { .. }));
        assert_eq!(err.error_behavior(), ErrorBehavior::ReGenerate);
    }
}
