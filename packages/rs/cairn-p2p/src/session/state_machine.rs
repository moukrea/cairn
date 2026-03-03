//! Session state machine with transition validation and event emission.
//!
//! Enforces the 7-state connection lifecycle from spec/07-reconnection-sessions.md section 2.

use super::{SessionEvent, SessionId, SessionState};
use crate::error::CairnError;
use tokio::sync::broadcast;
use tracing::debug;

/// Validates and executes session state transitions, emitting events on each transition.
pub struct SessionStateMachine {
    session_id: SessionId,
    state: SessionState,
    event_tx: broadcast::Sender<SessionEvent>,
}

impl SessionStateMachine {
    /// Create a new state machine starting in the given state.
    ///
    /// Returns the state machine and a broadcast receiver for session events.
    pub fn new(
        session_id: SessionId,
        initial_state: SessionState,
    ) -> (Self, broadcast::Receiver<SessionEvent>) {
        let (event_tx, event_rx) = broadcast::channel(64);
        let sm = Self {
            session_id,
            state: initial_state,
            event_tx,
        };
        (sm, event_rx)
    }

    /// Get the current state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Get the session ID.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Subscribe to session events. Returns a new broadcast receiver.
    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.event_tx.subscribe()
    }

    /// Attempt a state transition. Returns `Ok(())` if valid, or `Err` if the
    /// transition is not allowed by the state diagram.
    pub fn transition(
        &mut self,
        to: SessionState,
        reason: Option<String>,
    ) -> Result<(), CairnError> {
        if !Self::is_valid_transition(self.state, to) {
            return Err(CairnError::Protocol(format!(
                "invalid session state transition: {:?} -> {:?}",
                self.state, to
            )));
        }

        let from = self.state;
        self.state = to;

        let event = SessionEvent {
            session_id: self.session_id,
            from_state: from,
            to_state: to,
            timestamp: std::time::Instant::now(),
            reason,
        };

        debug!(
            session_id = %self.session_id,
            from = ?from,
            to = ?to,
            "session state transition"
        );

        // Send is best-effort: if no receivers, that's fine.
        let _ = self.event_tx.send(event);

        Ok(())
    }

    /// Check whether a transition from `from` to `to` is valid per the spec state diagram.
    ///
    /// Valid transitions (spec section 2):
    /// - Connected -> Unstable (degradation detected)
    /// - Connected -> Disconnected (abrupt transport loss)
    /// - Unstable -> Disconnected (transport lost)
    /// - Unstable -> Connected (recovered)
    /// - Disconnected -> Reconnecting (immediate reconnection attempt)
    /// - Reconnecting -> Reconnected (transport re-established)
    /// - Reconnecting -> Suspended (backoff pause)
    /// - Suspended -> Reconnecting (retry after backoff)
    /// - Suspended -> Failed (max retries or session expired)
    /// - Reconnected -> Connected (session fully restored)
    pub fn is_valid_transition(from: SessionState, to: SessionState) -> bool {
        matches!(
            (from, to),
            (SessionState::Connected, SessionState::Unstable)
                | (SessionState::Connected, SessionState::Disconnected)
                | (SessionState::Unstable, SessionState::Disconnected)
                | (SessionState::Unstable, SessionState::Connected)
                | (SessionState::Disconnected, SessionState::Reconnecting)
                | (SessionState::Reconnecting, SessionState::Reconnected)
                | (SessionState::Reconnecting, SessionState::Suspended)
                | (SessionState::Suspended, SessionState::Reconnecting)
                | (SessionState::Suspended, SessionState::Failed)
                | (SessionState::Reconnected, SessionState::Connected)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let sid = SessionId::new();
        let (sm, _rx) = SessionStateMachine::new(sid, SessionState::Connected);
        assert_eq!(sm.state(), SessionState::Connected);
        assert_eq!(sm.session_id(), sid);
    }

    #[test]
    fn test_valid_transition_connected_to_unstable() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Connected);
        assert!(sm.transition(SessionState::Unstable, None).is_ok());
        assert_eq!(sm.state(), SessionState::Unstable);
    }

    #[test]
    fn test_valid_transition_connected_to_disconnected() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Connected);
        assert!(sm
            .transition(SessionState::Disconnected, Some("abrupt loss".into()))
            .is_ok());
        assert_eq!(sm.state(), SessionState::Disconnected);
    }

    #[test]
    fn test_valid_transition_unstable_to_connected() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Unstable);
        assert!(sm.transition(SessionState::Connected, None).is_ok());
        assert_eq!(sm.state(), SessionState::Connected);
    }

    #[test]
    fn test_valid_transition_unstable_to_disconnected() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Unstable);
        assert!(sm.transition(SessionState::Disconnected, None).is_ok());
        assert_eq!(sm.state(), SessionState::Disconnected);
    }

    #[test]
    fn test_valid_transition_disconnected_to_reconnecting() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Disconnected);
        assert!(sm.transition(SessionState::Reconnecting, None).is_ok());
        assert_eq!(sm.state(), SessionState::Reconnecting);
    }

    #[test]
    fn test_valid_transition_reconnecting_to_reconnected() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Reconnecting);
        assert!(sm.transition(SessionState::Reconnected, None).is_ok());
        assert_eq!(sm.state(), SessionState::Reconnected);
    }

    #[test]
    fn test_valid_transition_reconnecting_to_suspended() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Reconnecting);
        assert!(sm.transition(SessionState::Suspended, None).is_ok());
        assert_eq!(sm.state(), SessionState::Suspended);
    }

    #[test]
    fn test_valid_transition_suspended_to_reconnecting() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Suspended);
        assert!(sm.transition(SessionState::Reconnecting, None).is_ok());
        assert_eq!(sm.state(), SessionState::Reconnecting);
    }

    #[test]
    fn test_valid_transition_suspended_to_failed() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Suspended);
        assert!(sm
            .transition(SessionState::Failed, Some("max retries".into()))
            .is_ok());
        assert_eq!(sm.state(), SessionState::Failed);
    }

    #[test]
    fn test_valid_transition_reconnected_to_connected() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Reconnected);
        assert!(sm.transition(SessionState::Connected, None).is_ok());
        assert_eq!(sm.state(), SessionState::Connected);
    }

    #[test]
    fn test_invalid_transition_connected_to_failed() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Connected);
        let result = sm.transition(SessionState::Failed, None);
        assert!(result.is_err());
        assert_eq!(sm.state(), SessionState::Connected); // unchanged
    }

    #[test]
    fn test_invalid_transition_disconnected_to_connected() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Disconnected);
        let result = sm.transition(SessionState::Connected, None);
        assert!(result.is_err());
        assert_eq!(sm.state(), SessionState::Disconnected);
    }

    #[test]
    fn test_invalid_transition_failed_to_connected() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Failed);
        let result = sm.transition(SessionState::Connected, None);
        assert!(result.is_err());
        assert_eq!(sm.state(), SessionState::Failed);
    }

    #[test]
    fn test_invalid_transition_connected_to_reconnecting() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Connected);
        let result = sm.transition(SessionState::Reconnecting, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_transition_reconnected_to_failed() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Reconnected);
        let result = sm.transition(SessionState::Failed, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_self_transition_rejected() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Connected);
        let result = sm.transition(SessionState::Connected, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_event_emitted_on_transition() {
        let (mut sm, mut rx) = SessionStateMachine::new(SessionId::new(), SessionState::Connected);
        sm.transition(SessionState::Unstable, Some("high latency".into()))
            .unwrap();

        let event = rx.try_recv().unwrap();
        assert_eq!(event.from_state, SessionState::Connected);
        assert_eq!(event.to_state, SessionState::Unstable);
        assert_eq!(event.reason.as_deref(), Some("high latency"));
    }

    #[test]
    fn test_multiple_events_emitted() {
        let (mut sm, mut rx) = SessionStateMachine::new(SessionId::new(), SessionState::Connected);

        sm.transition(SessionState::Unstable, None).unwrap();
        sm.transition(SessionState::Disconnected, None).unwrap();
        sm.transition(SessionState::Reconnecting, None).unwrap();

        let e1 = rx.try_recv().unwrap();
        assert_eq!(e1.from_state, SessionState::Connected);
        assert_eq!(e1.to_state, SessionState::Unstable);

        let e2 = rx.try_recv().unwrap();
        assert_eq!(e2.from_state, SessionState::Unstable);
        assert_eq!(e2.to_state, SessionState::Disconnected);

        let e3 = rx.try_recv().unwrap();
        assert_eq!(e3.from_state, SessionState::Disconnected);
        assert_eq!(e3.to_state, SessionState::Reconnecting);
    }

    #[test]
    fn test_full_reconnection_cycle() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Connected);

        // Connected -> Unstable -> Disconnected -> Reconnecting -> Reconnected -> Connected
        sm.transition(SessionState::Unstable, None).unwrap();
        sm.transition(SessionState::Disconnected, None).unwrap();
        sm.transition(SessionState::Reconnecting, None).unwrap();
        sm.transition(SessionState::Reconnected, None).unwrap();
        sm.transition(SessionState::Connected, None).unwrap();
        assert_eq!(sm.state(), SessionState::Connected);
    }

    #[test]
    fn test_suspended_retry_cycle() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Connected);

        sm.transition(SessionState::Disconnected, None).unwrap();
        sm.transition(SessionState::Reconnecting, None).unwrap();
        sm.transition(SessionState::Suspended, None).unwrap();
        sm.transition(SessionState::Reconnecting, None).unwrap();
        sm.transition(SessionState::Suspended, None).unwrap();
        sm.transition(SessionState::Failed, Some("max retries".into()))
            .unwrap();

        assert_eq!(sm.state(), SessionState::Failed);
    }

    #[test]
    fn test_is_valid_transition_exhaustive() {
        // All 10 valid transitions should be true
        let valid = vec![
            (SessionState::Connected, SessionState::Unstable),
            (SessionState::Connected, SessionState::Disconnected),
            (SessionState::Unstable, SessionState::Disconnected),
            (SessionState::Unstable, SessionState::Connected),
            (SessionState::Disconnected, SessionState::Reconnecting),
            (SessionState::Reconnecting, SessionState::Reconnected),
            (SessionState::Reconnecting, SessionState::Suspended),
            (SessionState::Suspended, SessionState::Reconnecting),
            (SessionState::Suspended, SessionState::Failed),
            (SessionState::Reconnected, SessionState::Connected),
        ];
        for (from, to) in &valid {
            assert!(
                SessionStateMachine::is_valid_transition(*from, *to),
                "expected valid: {:?} -> {:?}",
                from,
                to
            );
        }

        // A selection of invalid transitions
        let invalid = vec![
            (SessionState::Connected, SessionState::Failed),
            (SessionState::Connected, SessionState::Reconnecting),
            (SessionState::Connected, SessionState::Reconnected),
            (SessionState::Connected, SessionState::Suspended),
            (SessionState::Disconnected, SessionState::Connected),
            (SessionState::Disconnected, SessionState::Failed),
            (SessionState::Reconnecting, SessionState::Connected),
            (SessionState::Reconnecting, SessionState::Failed),
            (SessionState::Reconnected, SessionState::Failed),
            (SessionState::Reconnected, SessionState::Disconnected),
            (SessionState::Failed, SessionState::Connected),
            (SessionState::Failed, SessionState::Reconnecting),
        ];
        for (from, to) in &invalid {
            assert!(
                !SessionStateMachine::is_valid_transition(*from, *to),
                "expected invalid: {:?} -> {:?}",
                from,
                to
            );
        }
    }

    #[test]
    fn test_subscribe_receives_events() {
        let (mut sm, _rx) = SessionStateMachine::new(SessionId::new(), SessionState::Connected);

        // Subscribe a second receiver
        let mut rx2 = sm.subscribe();

        sm.transition(SessionState::Unstable, None).unwrap();

        let event = rx2.try_recv().unwrap();
        assert_eq!(event.from_state, SessionState::Connected);
        assert_eq!(event.to_state, SessionState::Unstable);
    }
}
