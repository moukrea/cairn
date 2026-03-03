//! Session management: state machine, session identity, and expiry tracking.
//!
//! The session layer survives transport disruptions, providing a stable abstraction
//! over ephemeral transport connections (spec/07-reconnection-sessions.md).

pub mod channel;
pub mod heartbeat;
pub mod queue;
pub mod reconnection;
pub mod state_machine;

use std::fmt;
use std::time::{Duration, SystemTime};

pub use state_machine::SessionStateMachine;

/// Default session expiry window (24 hours).
const DEFAULT_EXPIRY_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// Session identifier wrapping a UUID v7 (RFC 9562).
///
/// UUID v7 provides timestamp-ordered, globally unique identifiers suitable for
/// session tracking. Generated via `uuid::Uuid::now_v7()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(uuid::Uuid);

impl SessionId {
    /// Generate a new session ID using UUID v7.
    pub fn new() -> Self {
        Self(uuid::Uuid::now_v7())
    }

    /// Create a SessionId from an existing UUID (for deserialization/testing).
    pub fn from_uuid(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID.
    pub fn as_uuid(&self) -> &uuid::Uuid {
        &self.0
    }

    /// Get the raw 16-byte representation.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Connection lifecycle states per spec section 2.
///
/// ```text
/// Connected --> Unstable --> Disconnected --> Reconnecting --> Suspended
///     ^                                            |                |
///     |                                            v                v
///     +------------- Reconnected <-----------------+                |
///     |                                                             |
///     +------------------------- Failed <---------------------------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// Active, healthy connection. Data flows normally.
    Connected,
    /// Degradation detected (high latency, packet loss). Proactively probing alternatives.
    Unstable,
    /// Transport lost. Immediately enters reconnection.
    Disconnected,
    /// Actively attempting to re-establish transport.
    Reconnecting,
    /// Reconnection paused (exponential backoff). Retries periodically.
    Suspended,
    /// Transport re-established, session resumed, sequence state synchronized.
    Reconnected,
    /// Max retry budget exhausted or session expired. Application must decide next action.
    Failed,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionState::Connected => write!(f, "Connected"),
            SessionState::Unstable => write!(f, "Unstable"),
            SessionState::Disconnected => write!(f, "Disconnected"),
            SessionState::Reconnecting => write!(f, "Reconnecting"),
            SessionState::Suspended => write!(f, "Suspended"),
            SessionState::Reconnected => write!(f, "Reconnected"),
            SessionState::Failed => write!(f, "Failed"),
        }
    }
}

/// Event emitted on every state transition.
#[derive(Debug, Clone)]
pub struct SessionEvent {
    /// The session this event belongs to.
    pub session_id: SessionId,
    /// The state before the transition.
    pub from_state: SessionState,
    /// The state after the transition.
    pub to_state: SessionState,
    /// When the transition occurred.
    pub timestamp: std::time::Instant,
    /// Optional human-readable reason for the transition.
    pub reason: Option<String>,
}

/// A session that survives transport disruptions.
///
/// Holds session identity, state, sequence counters, and expiry information.
/// The session layer is the primary abstraction the application interacts with;
/// transport churn is invisible above this layer.
pub struct Session {
    /// Unique session identifier (UUID v7).
    pub id: SessionId,
    /// The remote peer's identifier.
    pub peer_id: String,
    /// The session state machine.
    state_machine: SessionStateMachine,
    /// When this session was created.
    pub created_at: SystemTime,
    /// How long until this session expires (default: 24 hours).
    pub expiry_duration: Duration,
    /// Outbound message sequence counter.
    pub sequence_tx: u64,
    /// Inbound message sequence counter.
    pub sequence_rx: u64,
    /// Ratchet epoch counter, incremented on each reconnection.
    pub ratchet_epoch: u32,
}

impl Session {
    /// Create a new session in the Connected state.
    ///
    /// Returns the session and a broadcast receiver for state transition events.
    pub fn new(peer_id: String) -> (Self, tokio::sync::broadcast::Receiver<SessionEvent>) {
        let id = SessionId::new();
        let (state_machine, event_rx) = SessionStateMachine::new(id, SessionState::Connected);

        let session = Self {
            id,
            peer_id,
            state_machine,
            created_at: SystemTime::now(),
            expiry_duration: DEFAULT_EXPIRY_DURATION,
            sequence_tx: 0,
            sequence_rx: 0,
            ratchet_epoch: 0,
        };

        (session, event_rx)
    }

    /// Create a new session with a custom expiry duration.
    pub fn with_expiry(
        peer_id: String,
        expiry_duration: Duration,
    ) -> (Self, tokio::sync::broadcast::Receiver<SessionEvent>) {
        let (mut session, rx) = Self::new(peer_id);
        session.expiry_duration = expiry_duration;
        (session, rx)
    }

    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed().unwrap_or(Duration::MAX) > self.expiry_duration
    }

    /// Get the current session state.
    pub fn state(&self) -> SessionState {
        self.state_machine.state()
    }

    /// Attempt a state transition.
    pub fn transition(
        &mut self,
        to: SessionState,
        reason: Option<String>,
    ) -> crate::error::Result<()> {
        self.state_machine.transition(to, reason)
    }

    /// Subscribe to session state transition events.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<SessionEvent> {
        self.state_machine.subscribe()
    }

    /// Increment and return the next outbound sequence number.
    pub fn next_sequence_tx(&mut self) -> u64 {
        let seq = self.sequence_tx;
        self.sequence_tx += 1;
        seq
    }

    /// Advance the ratchet epoch (called on reconnection).
    pub fn advance_ratchet_epoch(&mut self) {
        self.ratchet_epoch += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_unique() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_session_id_display() {
        let id = SessionId::new();
        let s = id.to_string();
        // UUID v7 format: 8-4-4-4-12 hex chars
        assert_eq!(s.len(), 36);
        assert!(s.contains('-'));
    }

    #[test]
    fn test_session_id_bytes_roundtrip() {
        let id = SessionId::new();
        let bytes = id.as_bytes();
        assert_eq!(bytes.len(), 16);
        let reconstructed = SessionId::from_uuid(uuid::Uuid::from_bytes(*bytes));
        assert_eq!(id, reconstructed);
    }

    #[test]
    fn test_session_id_default() {
        let id1 = SessionId::default();
        let id2 = SessionId::default();
        assert_ne!(id1, id2); // default generates new unique IDs
    }

    #[test]
    fn test_session_id_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let id = SessionId::new();
        set.insert(id);
        assert!(set.contains(&id));
    }

    #[test]
    fn test_session_state_display() {
        assert_eq!(SessionState::Connected.to_string(), "Connected");
        assert_eq!(SessionState::Unstable.to_string(), "Unstable");
        assert_eq!(SessionState::Disconnected.to_string(), "Disconnected");
        assert_eq!(SessionState::Reconnecting.to_string(), "Reconnecting");
        assert_eq!(SessionState::Suspended.to_string(), "Suspended");
        assert_eq!(SessionState::Reconnected.to_string(), "Reconnected");
        assert_eq!(SessionState::Failed.to_string(), "Failed");
    }

    #[test]
    fn test_session_new_starts_connected() {
        let (session, _rx) = Session::new("peer-abc".to_string());
        assert_eq!(session.state(), SessionState::Connected);
        assert_eq!(session.peer_id, "peer-abc");
        assert_eq!(session.sequence_tx, 0);
        assert_eq!(session.sequence_rx, 0);
        assert_eq!(session.ratchet_epoch, 0);
        assert_eq!(session.expiry_duration, DEFAULT_EXPIRY_DURATION);
    }

    #[test]
    fn test_session_with_custom_expiry() {
        let expiry = Duration::from_secs(3600);
        let (session, _rx) = Session::with_expiry("peer-abc".to_string(), expiry);
        assert_eq!(session.expiry_duration, expiry);
    }

    #[test]
    fn test_session_not_expired_immediately() {
        let (session, _rx) = Session::new("peer-abc".to_string());
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_expired_with_zero_duration() {
        let (mut session, _rx) = Session::new("peer-abc".to_string());
        session.expiry_duration = Duration::ZERO;
        // With zero duration, elapsed > 0 means expired
        assert!(session.is_expired());
    }

    #[test]
    fn test_session_transition() {
        let (mut session, _rx) = Session::new("peer-abc".to_string());
        session.transition(SessionState::Unstable, None).unwrap();
        assert_eq!(session.state(), SessionState::Unstable);
    }

    #[test]
    fn test_session_invalid_transition() {
        let (mut session, _rx) = Session::new("peer-abc".to_string());
        let result = session.transition(SessionState::Failed, None);
        assert!(result.is_err());
        assert_eq!(session.state(), SessionState::Connected);
    }

    #[test]
    fn test_session_next_sequence_tx() {
        let (mut session, _rx) = Session::new("peer-abc".to_string());
        assert_eq!(session.next_sequence_tx(), 0);
        assert_eq!(session.next_sequence_tx(), 1);
        assert_eq!(session.next_sequence_tx(), 2);
        assert_eq!(session.sequence_tx, 3);
    }

    #[test]
    fn test_session_advance_ratchet_epoch() {
        let (mut session, _rx) = Session::new("peer-abc".to_string());
        assert_eq!(session.ratchet_epoch, 0);
        session.advance_ratchet_epoch();
        assert_eq!(session.ratchet_epoch, 1);
        session.advance_ratchet_epoch();
        assert_eq!(session.ratchet_epoch, 2);
    }

    #[test]
    fn test_session_event_received() {
        let (mut session, mut rx) = Session::new("peer-abc".to_string());
        session
            .transition(SessionState::Unstable, Some("latency spike".into()))
            .unwrap();

        let event = rx.try_recv().unwrap();
        assert_eq!(event.session_id, session.id);
        assert_eq!(event.from_state, SessionState::Connected);
        assert_eq!(event.to_state, SessionState::Unstable);
        assert_eq!(event.reason.as_deref(), Some("latency spike"));
    }

    #[test]
    fn test_session_full_lifecycle() {
        let (mut session, mut rx) = Session::new("peer-abc".to_string());

        // Full reconnection cycle
        session.transition(SessionState::Unstable, None).unwrap();
        session
            .transition(SessionState::Disconnected, None)
            .unwrap();
        session
            .transition(SessionState::Reconnecting, None)
            .unwrap();
        session.advance_ratchet_epoch();
        session.transition(SessionState::Reconnected, None).unwrap();
        session.transition(SessionState::Connected, None).unwrap();

        assert_eq!(session.state(), SessionState::Connected);
        assert_eq!(session.ratchet_epoch, 1);

        // Should have received 5 events
        for _ in 0..5 {
            assert!(rx.try_recv().is_ok());
        }
    }

    #[test]
    fn test_session_subscribe_additional_receiver() {
        let (mut session, _rx) = Session::new("peer-abc".to_string());
        let mut rx2 = session.subscribe();

        session.transition(SessionState::Unstable, None).unwrap();

        let event = rx2.try_recv().unwrap();
        assert_eq!(event.to_state, SessionState::Unstable);
    }
}
