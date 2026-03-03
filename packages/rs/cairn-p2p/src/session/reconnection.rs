//! Session resumption, re-establishment, exponential backoff, and network change handling.
//!
//! Implements spec/07-reconnection-sessions.md sections 2-4, 7.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

use super::SessionId;

/// Cryptographic proof for session resumption (spec section 3).
///
/// Contains a signed challenge using session keys to prevent hijacking.
#[derive(Debug, Clone)]
pub struct ChallengeProof {
    /// The signed challenge bytes.
    pub signature: Vec<u8>,
    /// The public key used to sign (for verification).
    pub public_key: Vec<u8>,
}

/// Session resumption request sent by the reconnecting peer (spec section 3).
///
/// Carries session identity, cryptographic proof, and replay-protection fields.
#[derive(Debug, Clone)]
pub struct SessionResumptionRequest {
    /// The session to resume.
    pub session_id: SessionId,
    /// Cryptographic proof of identity (signed challenge using session keys).
    pub proof: ChallengeProof,
    /// Last sequence number received by this peer.
    pub last_seen_seq: u64,
    /// Unix timestamp for replay protection.
    pub timestamp: u64,
    /// Random nonce for replay protection.
    pub nonce: [u8; 32],
}

/// Response to a session resumption request.
#[derive(Debug, Clone)]
pub enum SessionResumptionResponse {
    /// Resumption accepted. Contains the responder's last-seen sequence number.
    Accepted {
        /// The responder's last-seen sequence number.
        last_seen_seq: u64,
    },
    /// Resumption rejected.
    Rejected {
        /// Reason for rejection.
        reason: ResumptionRejectReason,
    },
}

/// Reasons a session resumption can be rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumptionRejectReason {
    /// Session ID not found.
    SessionNotFound,
    /// Session has expired.
    SessionExpired,
    /// Cryptographic proof is invalid.
    InvalidProof,
    /// Replay detected (stale timestamp or reused nonce).
    ReplayDetected,
}

impl std::fmt::Display for ResumptionRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionNotFound => write!(f, "session not found"),
            Self::SessionExpired => write!(f, "session expired"),
            Self::InvalidProof => write!(f, "invalid proof"),
            Self::ReplayDetected => write!(f, "replay detected"),
        }
    }
}

/// Exponential backoff configuration (spec section 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackoffConfig {
    /// Initial delay before the first retry. Default: 1 second.
    pub initial_delay: Duration,
    /// Maximum delay between retries. Default: 60 seconds.
    pub max_delay: Duration,
    /// Multiplicative factor for each attempt. Default: 2.0.
    pub factor: f64,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            factor: 2.0,
        }
    }
}

/// Tracks exponential backoff state across reconnection attempts.
pub struct BackoffState {
    config: BackoffConfig,
    current_attempt: u32,
}

impl BackoffState {
    /// Create a new backoff state with the given configuration.
    pub fn new(config: BackoffConfig) -> Self {
        Self {
            config,
            current_attempt: 0,
        }
    }

    /// Calculate and return the next delay, advancing the attempt counter.
    ///
    /// Delay = initial_delay * factor^attempt, capped at max_delay.
    pub fn next_delay(&mut self) -> Duration {
        let delay = self
            .config
            .initial_delay
            .mul_f64(self.config.factor.powi(self.current_attempt as i32));
        self.current_attempt += 1;
        delay.min(self.config.max_delay)
    }

    /// Reset the attempt counter (called on successful reconnection).
    pub fn reset(&mut self) {
        self.current_attempt = 0;
    }

    /// Get the current attempt number.
    pub fn attempt(&self) -> u32 {
        self.current_attempt
    }

    /// Get a reference to the backoff configuration.
    pub fn config(&self) -> &BackoffConfig {
        &self.config
    }
}

/// Network change events detected by OS-level monitoring (spec section 7).
///
/// On detecting network changes, the library proactively triggers reconnection
/// rather than waiting for heartbeat timeout.
#[derive(Debug, Clone)]
pub enum NetworkChange {
    /// A network interface came up.
    InterfaceUp(String),
    /// A network interface went down.
    InterfaceDown(String),
    /// An IP address changed on an interface.
    AddressChanged {
        /// The interface name.
        interface: String,
        /// The previous IP address (None if newly assigned).
        old: Option<IpAddr>,
        /// The new IP address.
        new: IpAddr,
    },
}

impl std::fmt::Display for NetworkChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkChange::InterfaceUp(iface) => write!(f, "interface up: {}", iface),
            NetworkChange::InterfaceDown(iface) => write!(f, "interface down: {}", iface),
            NetworkChange::AddressChanged { interface, new, .. } => {
                write!(f, "address changed on {}: {}", interface, new)
            }
        }
    }
}

/// Monitors network interface changes and emits `NetworkChange` events.
///
/// Uses platform-specific APIs (netlink on Linux) with a periodic polling fallback.
pub struct NetworkMonitor {
    change_tx: tokio::sync::mpsc::Sender<NetworkChange>,
}

impl NetworkMonitor {
    /// Create a new network monitor.
    ///
    /// Returns the monitor and a receiver for network change events.
    pub fn new(buffer_size: usize) -> (Self, tokio::sync::mpsc::Receiver<NetworkChange>) {
        let (change_tx, change_rx) = tokio::sync::mpsc::channel(buffer_size);
        (Self { change_tx }, change_rx)
    }

    /// Report a network change event.
    ///
    /// Called by platform-specific monitoring code or periodic polling.
    pub async fn report_change(&self, change: NetworkChange) -> Result<(), NetworkChange> {
        self.change_tx.send(change).await.map_err(|e| e.0)
    }

    /// Get a clone of the sender for external code to report changes.
    pub fn sender(&self) -> tokio::sync::mpsc::Sender<NetworkChange> {
        self.change_tx.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- BackoffConfig tests ---

    #[test]
    fn test_backoff_default() {
        let config = BackoffConfig::default();
        assert_eq!(config.initial_delay, Duration::from_secs(1));
        assert_eq!(config.max_delay, Duration::from_secs(60));
        assert!((config.factor - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_backoff_config_serde_roundtrip() {
        let config = BackoffConfig {
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            factor: 1.5,
        };
        let json = serde_json::to_string(&config).unwrap();
        let decoded: BackoffConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.initial_delay, config.initial_delay);
        assert_eq!(decoded.max_delay, config.max_delay);
        assert!((decoded.factor - config.factor).abs() < f64::EPSILON);
    }

    // --- BackoffState tests ---

    #[test]
    fn test_backoff_sequence() {
        let mut state = BackoffState::new(BackoffConfig::default());
        // attempt 0: 1s * 2^0 = 1s
        assert_eq!(state.next_delay(), Duration::from_secs(1));
        // attempt 1: 1s * 2^1 = 2s
        assert_eq!(state.next_delay(), Duration::from_secs(2));
        // attempt 2: 1s * 2^2 = 4s
        assert_eq!(state.next_delay(), Duration::from_secs(4));
        // attempt 3: 1s * 2^3 = 8s
        assert_eq!(state.next_delay(), Duration::from_secs(8));
        assert_eq!(state.attempt(), 4);
    }

    #[test]
    fn test_backoff_max_delay_cap() {
        let mut state = BackoffState::new(BackoffConfig::default());
        // Run through enough attempts to exceed 60s
        for _ in 0..10 {
            state.next_delay();
        }
        // After many attempts, delay should be capped at max_delay
        let delay = state.next_delay();
        assert_eq!(delay, Duration::from_secs(60));
    }

    #[test]
    fn test_backoff_reset() {
        let mut state = BackoffState::new(BackoffConfig::default());
        state.next_delay();
        state.next_delay();
        assert_eq!(state.attempt(), 2);

        state.reset();
        assert_eq!(state.attempt(), 0);
        // After reset, starts from initial again
        assert_eq!(state.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn test_backoff_custom_config() {
        let config = BackoffConfig {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            factor: 3.0,
        };
        let mut state = BackoffState::new(config);
        // 100ms * 3^0 = 100ms
        assert_eq!(state.next_delay(), Duration::from_millis(100));
        // 100ms * 3^1 = 300ms
        assert_eq!(state.next_delay(), Duration::from_millis(300));
        // 100ms * 3^2 = 900ms
        assert_eq!(state.next_delay(), Duration::from_millis(900));
        // 100ms * 3^3 = 2700ms
        assert_eq!(state.next_delay(), Duration::from_millis(2700));
        // 100ms * 3^4 = 8100ms -> capped to 5000ms
        assert_eq!(state.next_delay(), Duration::from_secs(5));
    }

    // --- ChallengeProof tests ---

    #[test]
    fn test_challenge_proof_construction() {
        let proof = ChallengeProof {
            signature: vec![1, 2, 3],
            public_key: vec![4, 5, 6],
        };
        assert_eq!(proof.signature.len(), 3);
        assert_eq!(proof.public_key.len(), 3);
    }

    // --- SessionResumptionRequest tests ---

    #[test]
    fn test_resumption_request_construction() {
        let req = SessionResumptionRequest {
            session_id: SessionId::new(),
            proof: ChallengeProof {
                signature: vec![0; 64],
                public_key: vec![0; 32],
            },
            last_seen_seq: 42,
            timestamp: 1_700_000_000,
            nonce: [0u8; 32],
        };
        assert_eq!(req.last_seen_seq, 42);
        assert_eq!(req.timestamp, 1_700_000_000);
    }

    // --- SessionResumptionResponse tests ---

    #[test]
    fn test_resumption_accepted() {
        let resp = SessionResumptionResponse::Accepted { last_seen_seq: 10 };
        assert!(matches!(
            resp,
            SessionResumptionResponse::Accepted { last_seen_seq: 10 }
        ));
    }

    #[test]
    fn test_resumption_rejected() {
        let resp = SessionResumptionResponse::Rejected {
            reason: ResumptionRejectReason::SessionExpired,
        };
        assert!(matches!(
            resp,
            SessionResumptionResponse::Rejected {
                reason: ResumptionRejectReason::SessionExpired
            }
        ));
    }

    #[test]
    fn test_rejection_reason_display() {
        assert_eq!(
            ResumptionRejectReason::SessionNotFound.to_string(),
            "session not found"
        );
        assert_eq!(
            ResumptionRejectReason::SessionExpired.to_string(),
            "session expired"
        );
        assert_eq!(
            ResumptionRejectReason::InvalidProof.to_string(),
            "invalid proof"
        );
        assert_eq!(
            ResumptionRejectReason::ReplayDetected.to_string(),
            "replay detected"
        );
    }

    // --- NetworkChange tests ---

    #[test]
    fn test_network_change_display() {
        let up = NetworkChange::InterfaceUp("wlan0".into());
        assert_eq!(up.to_string(), "interface up: wlan0");

        let down = NetworkChange::InterfaceDown("eth0".into());
        assert_eq!(down.to_string(), "interface down: eth0");

        let changed = NetworkChange::AddressChanged {
            interface: "wlan0".into(),
            old: Some("192.168.1.10".parse().unwrap()),
            new: "10.0.0.5".parse().unwrap(),
        };
        assert_eq!(changed.to_string(), "address changed on wlan0: 10.0.0.5");
    }

    // --- NetworkMonitor tests ---

    #[tokio::test]
    async fn test_network_monitor_send_receive() {
        let (monitor, mut rx) = NetworkMonitor::new(16);
        let change = NetworkChange::InterfaceUp("wlan0".into());
        monitor.report_change(change).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert!(matches!(received, NetworkChange::InterfaceUp(ref iface) if iface == "wlan0"));
    }

    #[tokio::test]
    async fn test_network_monitor_sender_clone() {
        let (monitor, mut rx) = NetworkMonitor::new(16);
        let sender = monitor.sender();

        sender
            .send(NetworkChange::InterfaceDown("eth0".into()))
            .await
            .unwrap();

        let received = rx.recv().await.unwrap();
        assert!(matches!(received, NetworkChange::InterfaceDown(ref iface) if iface == "eth0"));
    }

    #[tokio::test]
    async fn test_network_monitor_multiple_events() {
        let (monitor, mut rx) = NetworkMonitor::new(16);

        monitor
            .report_change(NetworkChange::InterfaceUp("wlan0".into()))
            .await
            .unwrap();
        monitor
            .report_change(NetworkChange::AddressChanged {
                interface: "wlan0".into(),
                old: None,
                new: "192.168.1.100".parse().unwrap(),
            })
            .await
            .unwrap();

        let e1 = rx.recv().await.unwrap();
        assert!(matches!(e1, NetworkChange::InterfaceUp(_)));

        let e2 = rx.recv().await.unwrap();
        assert!(matches!(e2, NetworkChange::AddressChanged { .. }));
    }
}
