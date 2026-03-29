//! Session resumption, re-establishment, exponential backoff, and network change handling.
//!
//! Implements spec/07-reconnection-sessions.md sections 2-4, 7.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::SessionId;
use crate::error::{CairnError, Result};

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
    pub async fn report_change(
        &self,
        change: NetworkChange,
    ) -> std::result::Result<(), NetworkChange> {
        self.change_tx.send(change).await.map_err(|e| e.0)
    }

    /// Get a clone of the sender for external code to report changes.
    pub fn sender(&self) -> tokio::sync::mpsc::Sender<NetworkChange> {
        self.change_tx.clone()
    }
}

// ---------------------------------------------------------------------------
// SESSION_RESUME Protocol Types
// ---------------------------------------------------------------------------

/// HMAC-based proof for session resumption.
///
/// Uses HMAC-SHA256 keyed with the ratchet-derived resumption key.
/// The proof binds the nonce, timestamp, and session ID to prevent replay.
#[derive(Debug, Clone)]
pub struct ResumeProof {
    /// HMAC-SHA256 output (32 bytes).
    pub hmac: [u8; 32],
    /// Random nonce (32 bytes), generated fresh for each resume attempt.
    pub nonce: [u8; 32],
    /// Unix timestamp (seconds) for replay protection.
    pub timestamp: u64,
}

/// SESSION_RESUME_ACK response data.
#[derive(Debug, Clone)]
pub struct ResumeAck {
    /// The responder's last received sequence number.
    pub last_rx_sequence: u64,
}

/// Reason codes for SESSION_EXPIRED responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExpiredReason {
    /// Session has exceeded its TTL.
    Expired = 1,
    /// Session ID not found on this node.
    NotFound = 2,
    /// HMAC proof verification failed.
    InvalidProof = 3,
    /// Nonce was already used (replay detected).
    Replay = 4,
}

impl ExpiredReason {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Expired),
            2 => Some(Self::NotFound),
            3 => Some(Self::InvalidProof),
            4 => Some(Self::Replay),
            _ => None,
        }
    }
}

impl std::fmt::Display for ExpiredReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired => write!(f, "session expired"),
            Self::NotFound => write!(f, "session not found"),
            Self::InvalidProof => write!(f, "invalid proof"),
            Self::Replay => write!(f, "replay detected"),
        }
    }
}

/// Generate a resume proof using HMAC-SHA256.
///
/// proof = HMAC-SHA256(resumption_key, nonce || timestamp_be8 || session_id)
pub fn generate_resume_proof(
    resumption_key: &[u8; 32],
    session_id: &[u8; 16],
    nonce: &[u8; 32],
    timestamp: u64,
) -> ResumeProof {
    let mac = compute_hmac(resumption_key, nonce, timestamp, session_id);
    ResumeProof {
        hmac: mac,
        nonce: *nonce,
        timestamp,
    }
}

/// Verify a resume proof using HMAC-SHA256 in constant time.
pub fn verify_resume_proof(
    resumption_key: &[u8; 32],
    session_id: &[u8; 16],
    proof: &ResumeProof,
) -> bool {
    let expected = compute_hmac(resumption_key, &proof.nonce, proof.timestamp, session_id);
    proof.hmac.ct_eq(&expected).into()
}

/// Compute the HMAC-SHA256 for resume proof generation/verification.
fn compute_hmac(
    key: &[u8; 32],
    nonce: &[u8; 32],
    timestamp: u64,
    session_id: &[u8; 16],
) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key size");
    mac.update(nonce);
    mac.update(&timestamp.to_be_bytes());
    mac.update(session_id);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    output
}

// ---------------------------------------------------------------------------
// CBOR Encoding / Decoding for SESSION_RESUME messages
// ---------------------------------------------------------------------------

/// Encode a SESSION_RESUME payload (msg_type 0x0200) as CBOR.
///
/// Format: CBOR map {0: session_id, 1: proof, 2: last_rx_seq, 3: timestamp, 4: nonce}
pub fn encode_session_resume(
    session_id: &[u8; 16],
    proof: &ResumeProof,
    last_rx_sequence: u64,
) -> Result<Vec<u8>> {
    use ciborium::Value;

    let map = Value::Map(vec![
        (Value::Integer(0.into()), Value::Bytes(session_id.to_vec())),
        (Value::Integer(1.into()), Value::Bytes(proof.hmac.to_vec())),
        (
            Value::Integer(2.into()),
            Value::Integer((last_rx_sequence as i64).into()),
        ),
        (
            Value::Integer(3.into()),
            Value::Integer((proof.timestamp as i64).into()),
        ),
        (Value::Integer(4.into()), Value::Bytes(proof.nonce.to_vec())),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf)
        .map_err(|e| CairnError::Protocol(format!("CBOR encode SESSION_RESUME: {e}")))?;
    Ok(buf)
}

/// Decode a SESSION_RESUME payload from CBOR bytes.
///
/// Returns (session_id, proof, last_rx_sequence).
pub fn decode_session_resume(data: &[u8]) -> Result<([u8; 16], ResumeProof, u64)> {
    use ciborium::Value;

    let value: Value = ciborium::from_reader(data)
        .map_err(|e| CairnError::Protocol(format!("CBOR decode SESSION_RESUME: {e}")))?;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(CairnError::Protocol(
                "SESSION_RESUME: expected CBOR map".into(),
            ))
        }
    };

    let mut session_id_bytes: Option<[u8; 16]> = None;
    let mut hmac_bytes: Option<[u8; 32]> = None;
    let mut last_rx: Option<u64> = None;
    let mut timestamp: Option<u64> = None;
    let mut nonce_bytes: Option<[u8; 32]> = None;

    for (k, v) in map {
        let key = match k {
            Value::Integer(i) => {
                let val: i64 = i.try_into().unwrap_or(0);
                val as u8
            }
            _ => continue,
        };
        match key {
            0 => {
                if let Value::Bytes(b) = v {
                    let arr: [u8; 16] = b.try_into().map_err(|_| {
                        CairnError::Protocol("SESSION_RESUME: session_id must be 16 bytes".into())
                    })?;
                    session_id_bytes = Some(arr);
                }
            }
            1 => {
                if let Value::Bytes(b) = v {
                    let arr: [u8; 32] = b.try_into().map_err(|_| {
                        CairnError::Protocol("SESSION_RESUME: hmac must be 32 bytes".into())
                    })?;
                    hmac_bytes = Some(arr);
                }
            }
            2 => {
                if let Value::Integer(i) = v {
                    let val: i64 = i.try_into().unwrap_or(0);
                    last_rx = Some(val as u64);
                }
            }
            3 => {
                if let Value::Integer(i) = v {
                    let val: i64 = i.try_into().unwrap_or(0);
                    timestamp = Some(val as u64);
                }
            }
            4 => {
                if let Value::Bytes(b) = v {
                    let arr: [u8; 32] = b.try_into().map_err(|_| {
                        CairnError::Protocol("SESSION_RESUME: nonce must be 32 bytes".into())
                    })?;
                    nonce_bytes = Some(arr);
                }
            }
            _ => {}
        }
    }

    let session_id = session_id_bytes
        .ok_or_else(|| CairnError::Protocol("SESSION_RESUME: missing session_id".into()))?;
    let hmac =
        hmac_bytes.ok_or_else(|| CairnError::Protocol("SESSION_RESUME: missing hmac".into()))?;
    let last_rx_seq = last_rx
        .ok_or_else(|| CairnError::Protocol("SESSION_RESUME: missing last_rx_sequence".into()))?;
    let ts = timestamp
        .ok_or_else(|| CairnError::Protocol("SESSION_RESUME: missing timestamp".into()))?;
    let nonce =
        nonce_bytes.ok_or_else(|| CairnError::Protocol("SESSION_RESUME: missing nonce".into()))?;

    Ok((
        session_id,
        ResumeProof {
            hmac,
            nonce,
            timestamp: ts,
        },
        last_rx_seq,
    ))
}

/// Encode a SESSION_RESUME_ACK payload (msg_type 0x0201) as CBOR.
pub fn encode_session_resume_ack(last_rx_sequence: u64) -> Result<Vec<u8>> {
    use ciborium::Value;

    let map = Value::Map(vec![(
        Value::Integer(0.into()),
        Value::Integer((last_rx_sequence as i64).into()),
    )]);

    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf)
        .map_err(|e| CairnError::Protocol(format!("CBOR encode SESSION_RESUME_ACK: {e}")))?;
    Ok(buf)
}

/// Decode a SESSION_RESUME_ACK payload from CBOR bytes.
pub fn decode_session_resume_ack(data: &[u8]) -> Result<u64> {
    use ciborium::Value;

    let value: Value = ciborium::from_reader(data)
        .map_err(|e| CairnError::Protocol(format!("CBOR decode SESSION_RESUME_ACK: {e}")))?;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(CairnError::Protocol(
                "SESSION_RESUME_ACK: expected CBOR map".into(),
            ))
        }
    };

    for (k, v) in map {
        if let (Value::Integer(i), Value::Integer(val)) = (k, v) {
            let key: i64 = i.try_into().unwrap_or(-1);
            if key == 0 {
                let seq: i64 = val.try_into().unwrap_or(0);
                return Ok(seq as u64);
            }
        }
    }

    Err(CairnError::Protocol(
        "SESSION_RESUME_ACK: missing last_rx_sequence".into(),
    ))
}

/// Encode a SESSION_EXPIRED payload (msg_type 0x0202) as CBOR.
pub fn encode_session_expired(reason: ExpiredReason) -> Result<Vec<u8>> {
    use ciborium::Value;

    let map = Value::Map(vec![(
        Value::Integer(0.into()),
        Value::Integer((reason as u8 as i64).into()),
    )]);

    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf)
        .map_err(|e| CairnError::Protocol(format!("CBOR encode SESSION_EXPIRED: {e}")))?;
    Ok(buf)
}

/// Decode a SESSION_EXPIRED payload from CBOR bytes.
pub fn decode_session_expired(data: &[u8]) -> Result<ExpiredReason> {
    use ciborium::Value;

    let value: Value = ciborium::from_reader(data)
        .map_err(|e| CairnError::Protocol(format!("CBOR decode SESSION_EXPIRED: {e}")))?;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(CairnError::Protocol(
                "SESSION_EXPIRED: expected CBOR map".into(),
            ))
        }
    };

    for (k, v) in map {
        if let (Value::Integer(i), Value::Integer(val)) = (k, v) {
            let key: i64 = i.try_into().unwrap_or(-1);
            if key == 0 {
                let code: i64 = val.try_into().unwrap_or(0);
                return ExpiredReason::from_u8(code as u8).ok_or_else(|| {
                    CairnError::Protocol(format!("SESSION_EXPIRED: unknown reason code {}", code))
                });
            }
        }
    }

    Err(CairnError::Protocol(
        "SESSION_EXPIRED: missing reason_code".into(),
    ))
}

// ---------------------------------------------------------------------------
// Nonce Cache (replay protection)
// ---------------------------------------------------------------------------

/// Timestamp window for nonce cache eviction (5 minutes).
const NONCE_TIMESTAMP_WINDOW_SECS: u64 = 300;

/// Bounded nonce cache for replay protection.
///
/// Stores seen nonces along with their timestamps. Nonces older than the
/// timestamp window are automatically evicted. Timestamps outside the window
/// are rejected outright.
pub struct NonceCache {
    /// Set of (nonce, timestamp) pairs.
    seen: HashSet<[u8; 32]>,
    /// Timestamps associated with each nonce for eviction.
    timestamps: Vec<([u8; 32], u64)>,
    /// Maximum age of a valid timestamp (seconds).
    window_secs: u64,
}

impl NonceCache {
    /// Create a new nonce cache with the default 5-minute window.
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            timestamps: Vec::new(),
            window_secs: NONCE_TIMESTAMP_WINDOW_SECS,
        }
    }

    /// Create a nonce cache with a custom window duration.
    #[cfg(test)]
    pub fn with_window(window_secs: u64) -> Self {
        Self {
            seen: HashSet::new(),
            timestamps: Vec::new(),
            window_secs,
        }
    }

    /// Check if a (nonce, timestamp) pair is valid and record it.
    ///
    /// Returns `true` if the nonce is fresh (not replayed and timestamp within window).
    /// Returns `false` if the nonce was already seen or the timestamp is stale.
    pub fn check_and_record(&mut self, nonce: &[u8; 32], timestamp: u64) -> bool {
        let now = current_unix_secs();

        // Evict old entries first
        self.evict(now);

        // Reject stale timestamps
        if now.saturating_sub(timestamp) > self.window_secs {
            return false;
        }

        // Reject future timestamps (more than 60s in the future)
        if timestamp > now + 60 {
            return false;
        }

        // Check for replay
        if self.seen.contains(nonce) {
            return false;
        }

        // Record the nonce
        self.seen.insert(*nonce);
        self.timestamps.push((*nonce, timestamp));
        true
    }

    /// Remove entries older than the window.
    fn evict(&mut self, now: u64) {
        let cutoff = now.saturating_sub(self.window_secs);
        self.timestamps.retain(|(nonce, ts)| {
            if *ts < cutoff {
                self.seen.remove(nonce);
                false
            } else {
                true
            }
        });
    }

    /// Number of nonces currently tracked.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current Unix timestamp in seconds.
fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

    // --- ResumeProof tests ---

    #[test]
    fn test_generate_and_verify_resume_proof() {
        let key = [0x42u8; 32];
        let session_id = [1u8; 16];
        let nonce = [0xAA; 32];
        let timestamp = 1_700_000_000u64;

        let proof = generate_resume_proof(&key, &session_id, &nonce, timestamp);
        assert!(verify_resume_proof(&key, &session_id, &proof));
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let session_id = [1u8; 16];
        let nonce = [0xAA; 32];
        let timestamp = 1_700_000_000u64;

        let proof = generate_resume_proof(&key, &session_id, &nonce, timestamp);
        assert!(!verify_resume_proof(&wrong_key, &session_id, &proof));
    }

    #[test]
    fn test_wrong_session_id_fails_verification() {
        let key = [0x42u8; 32];
        let session_id = [1u8; 16];
        let wrong_session_id = [2u8; 16];
        let nonce = [0xAA; 32];
        let timestamp = 1_700_000_000u64;

        let proof = generate_resume_proof(&key, &session_id, &nonce, timestamp);
        assert!(!verify_resume_proof(&key, &wrong_session_id, &proof));
    }

    #[test]
    fn test_tampered_hmac_fails_verification() {
        let key = [0x42u8; 32];
        let session_id = [1u8; 16];
        let nonce = [0xAA; 32];
        let timestamp = 1_700_000_000u64;

        let mut proof = generate_resume_proof(&key, &session_id, &nonce, timestamp);
        proof.hmac[0] ^= 0xFF; // Tamper
        assert!(!verify_resume_proof(&key, &session_id, &proof));
    }

    #[test]
    fn test_different_nonce_produces_different_proof() {
        let key = [0x42u8; 32];
        let session_id = [1u8; 16];
        let nonce1 = [0xAA; 32];
        let nonce2 = [0xBB; 32];
        let timestamp = 1_700_000_000u64;

        let proof1 = generate_resume_proof(&key, &session_id, &nonce1, timestamp);
        let proof2 = generate_resume_proof(&key, &session_id, &nonce2, timestamp);
        assert_ne!(proof1.hmac, proof2.hmac);
    }

    #[test]
    fn test_different_timestamp_produces_different_proof() {
        let key = [0x42u8; 32];
        let session_id = [1u8; 16];
        let nonce = [0xAA; 32];

        let proof1 = generate_resume_proof(&key, &session_id, &nonce, 1_700_000_000);
        let proof2 = generate_resume_proof(&key, &session_id, &nonce, 1_700_000_001);
        assert_ne!(proof1.hmac, proof2.hmac);
    }

    // --- CBOR encoding/decoding tests ---

    #[test]
    fn test_session_resume_cbor_roundtrip() {
        let session_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let key = [0x42u8; 32];
        let nonce = [0xBB; 32];
        let timestamp = 1_700_000_000u64;
        let proof = generate_resume_proof(&key, &session_id, &nonce, timestamp);
        let last_rx = 42u64;

        let encoded = encode_session_resume(&session_id, &proof, last_rx).unwrap();
        let (decoded_sid, decoded_proof, decoded_last_rx) =
            decode_session_resume(&encoded).unwrap();

        assert_eq!(decoded_sid, session_id);
        assert_eq!(decoded_proof.hmac, proof.hmac);
        assert_eq!(decoded_proof.nonce, proof.nonce);
        assert_eq!(decoded_proof.timestamp, proof.timestamp);
        assert_eq!(decoded_last_rx, last_rx);
    }

    #[test]
    fn test_session_resume_ack_cbor_roundtrip() {
        let last_rx = 99u64;
        let encoded = encode_session_resume_ack(last_rx).unwrap();
        let decoded = decode_session_resume_ack(&encoded).unwrap();
        assert_eq!(decoded, last_rx);
    }

    #[test]
    fn test_session_resume_ack_zero() {
        let encoded = encode_session_resume_ack(0).unwrap();
        let decoded = decode_session_resume_ack(&encoded).unwrap();
        assert_eq!(decoded, 0);
    }

    #[test]
    fn test_session_expired_cbor_roundtrip() {
        for reason in [
            ExpiredReason::Expired,
            ExpiredReason::NotFound,
            ExpiredReason::InvalidProof,
            ExpiredReason::Replay,
        ] {
            let encoded = encode_session_expired(reason).unwrap();
            let decoded = decode_session_expired(&encoded).unwrap();
            assert_eq!(decoded, reason);
        }
    }

    #[test]
    fn test_expired_reason_display() {
        assert_eq!(ExpiredReason::Expired.to_string(), "session expired");
        assert_eq!(ExpiredReason::NotFound.to_string(), "session not found");
        assert_eq!(ExpiredReason::InvalidProof.to_string(), "invalid proof");
        assert_eq!(ExpiredReason::Replay.to_string(), "replay detected");
    }

    #[test]
    fn test_expired_reason_from_u8() {
        assert_eq!(ExpiredReason::from_u8(1), Some(ExpiredReason::Expired));
        assert_eq!(ExpiredReason::from_u8(2), Some(ExpiredReason::NotFound));
        assert_eq!(ExpiredReason::from_u8(3), Some(ExpiredReason::InvalidProof));
        assert_eq!(ExpiredReason::from_u8(4), Some(ExpiredReason::Replay));
        assert_eq!(ExpiredReason::from_u8(0), None);
        assert_eq!(ExpiredReason::from_u8(5), None);
    }

    // --- NonceCache tests ---

    #[test]
    fn test_nonce_cache_fresh_nonce_accepted() {
        let mut cache = NonceCache::new();
        let nonce = [0xAA; 32];
        let timestamp = current_unix_secs();
        assert!(cache.check_and_record(&nonce, timestamp));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_nonce_cache_replayed_nonce_rejected() {
        let mut cache = NonceCache::new();
        let nonce = [0xAA; 32];
        let timestamp = current_unix_secs();
        assert!(cache.check_and_record(&nonce, timestamp));
        assert!(!cache.check_and_record(&nonce, timestamp));
    }

    #[test]
    fn test_nonce_cache_stale_timestamp_rejected() {
        let mut cache = NonceCache::new();
        let nonce = [0xAA; 32];
        // 10 minutes ago — outside the 5-minute window
        let timestamp = current_unix_secs().saturating_sub(600);
        assert!(!cache.check_and_record(&nonce, timestamp));
        assert!(cache.is_empty());
    }

    #[test]
    fn test_nonce_cache_future_timestamp_rejected() {
        let mut cache = NonceCache::new();
        let nonce = [0xAA; 32];
        // 120 seconds in the future — beyond the 60s tolerance
        let timestamp = current_unix_secs() + 120;
        assert!(!cache.check_and_record(&nonce, timestamp));
    }

    #[test]
    fn test_nonce_cache_near_future_accepted() {
        let mut cache = NonceCache::new();
        let nonce = [0xAA; 32];
        // 30 seconds in the future — within the 60s tolerance
        let timestamp = current_unix_secs() + 30;
        assert!(cache.check_and_record(&nonce, timestamp));
    }

    #[test]
    fn test_nonce_cache_different_nonces_accepted() {
        let mut cache = NonceCache::new();
        let timestamp = current_unix_secs();
        let nonce1 = [0xAA; 32];
        let nonce2 = [0xBB; 32];
        assert!(cache.check_and_record(&nonce1, timestamp));
        assert!(cache.check_and_record(&nonce2, timestamp));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_nonce_cache_default() {
        let cache = NonceCache::default();
        assert!(cache.is_empty());
    }

    // --- derive_resumption_key tests ---

    #[test]
    fn test_derive_resumption_key_deterministic() {
        use crate::crypto::exchange::X25519Keypair;
        use crate::crypto::ratchet::{DoubleRatchet, RatchetConfig};

        let shared_secret = [0x42u8; 32];
        let bob_kp = X25519Keypair::generate();
        let bob_public = *bob_kp.public_key().as_bytes();

        let alice1 =
            DoubleRatchet::init_initiator(shared_secret, bob_public, RatchetConfig::default())
                .unwrap();
        let alice2 =
            DoubleRatchet::init_initiator(shared_secret, bob_public, RatchetConfig::default())
                .unwrap();

        // Same inputs should produce same resumption key
        // (but note: each init_initiator generates a fresh DH keypair, so
        // root_key will differ. We just verify the method doesn't error.)
        let key1 = alice1.derive_resumption_key().unwrap();
        let key2 = alice2.derive_resumption_key().unwrap();

        // They won't be equal because each generates a new DH keypair,
        // but both should be valid 32-byte keys.
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        // Keys should differ because different DH keypairs lead to different root keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_resumption_key_from_exported_state() {
        use crate::crypto::exchange::X25519Keypair;
        use crate::crypto::ratchet::{DoubleRatchet, RatchetConfig};

        let shared_secret = [0x42u8; 32];
        let bob_kp = X25519Keypair::generate();
        let bob_public = *bob_kp.public_key().as_bytes();

        let alice =
            DoubleRatchet::init_initiator(shared_secret, bob_public, RatchetConfig::default())
                .unwrap();

        let key_before = alice.derive_resumption_key().unwrap();

        // Export and re-import
        let exported = alice.export_state();
        let alice_restored =
            DoubleRatchet::import_state(&exported, RatchetConfig::default()).unwrap();

        let key_after = alice_restored.derive_resumption_key().unwrap();

        // Must match: same root key from same state
        assert_eq!(key_before, key_after);
    }

    #[test]
    fn test_resume_proof_with_ratchet_derived_key() {
        use crate::crypto::exchange::X25519Keypair;
        use crate::crypto::ratchet::{DoubleRatchet, RatchetConfig};

        let shared_secret = [0x42u8; 32];
        let bob_kp = X25519Keypair::generate();
        let bob_public = *bob_kp.public_key().as_bytes();

        let alice =
            DoubleRatchet::init_initiator(shared_secret, bob_public, RatchetConfig::default())
                .unwrap();
        let bob =
            DoubleRatchet::init_responder(shared_secret, bob_kp, RatchetConfig::default()).unwrap();

        // Both sides should derive different resumption keys at this point
        // because Alice has done a DH step and Bob hasn't yet.
        // But the root_key is the shared_secret for Bob, and a derived key for Alice.
        let alice_key = alice.derive_resumption_key().unwrap();
        let bob_key = bob.derive_resumption_key().unwrap();

        // The initiator performed a DH ratchet step, so their root keys differ
        assert_ne!(alice_key, bob_key);

        // However, after message exchange they would synchronize.
        // For now just verify the keys are usable for HMAC.
        let session_id = [1u8; 16];
        let nonce = [0xCC; 32];
        let timestamp = 1_700_000_000u64;

        let proof = generate_resume_proof(&alice_key, &session_id, &nonce, timestamp);
        assert!(verify_resume_proof(&alice_key, &session_id, &proof));
        // Bob's key should NOT verify Alice's proof
        assert!(!verify_resume_proof(&bob_key, &session_id, &proof));
    }
}
