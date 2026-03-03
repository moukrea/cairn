//! Mesh relay forwarding (spec/09-mesh-networking.md section 9.3).
//!
//! Handles forwarding opaque encrypted bytes between peers. Relay peers
//! cannot read, modify, or forge relayed content. The relay layer operates
//! entirely below the session encryption layer.

use crate::identity::PeerId;
use crate::server::headless::PeerQuota;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};

use super::{MeshConfig, MeshError};

/// Unique identifier for a relay session.
pub type RelaySessionId = u64;

/// A relay session bridging two peers through this node.
#[derive(Debug)]
pub struct RelaySession {
    /// The unique session identifier.
    pub id: RelaySessionId,
    /// The source peer (requesting the relay).
    pub source: PeerId,
    /// The destination peer (being relayed to).
    pub destination: PeerId,
}

/// Manages relay sessions for this peer.
///
/// Enforces `relay_willing` and `relay_capacity` from `MeshConfig`.
/// Each relay session bridges two streams, forwarding opaque bytes between them.
pub struct RelayManager {
    config: MeshConfig,
    sessions: HashMap<RelaySessionId, RelaySession>,
    next_session_id: Arc<AtomicU32>,
}

impl RelayManager {
    /// Create a new relay manager with the given mesh configuration.
    pub fn new(config: MeshConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            next_session_id: Arc::new(AtomicU32::new(1)),
        }
    }

    /// Request to start a new relay session.
    ///
    /// Validates that this peer is willing to relay, has capacity, the
    /// destination is not the source, and the optional bandwidth quota is not exceeded.
    pub fn request_relay(
        &mut self,
        source: PeerId,
        destination: PeerId,
        quota: Option<&PeerQuota>,
    ) -> Result<RelaySessionId, MeshError> {
        if !self.config.mesh_enabled {
            return Err(MeshError::MeshDisabled);
        }

        if !self.config.relay_willing {
            return Err(MeshError::RelayNotWilling);
        }

        let active = self.active_session_count() as u32;
        if active >= self.config.relay_capacity {
            return Err(MeshError::RelayCapacityFull(
                active,
                self.config.relay_capacity,
            ));
        }

        if source == destination {
            return Err(MeshError::RelayConnectionFailed(
                "source and destination are the same peer".to_string(),
            ));
        }

        // Check relay bandwidth quota if provided.
        if let Some(q) = quota {
            // Use active session count as a proxy for current bandwidth pressure.
            // Each active session contributes to relay load.
            let current_bps = self.active_session_count() as u64;
            if !q.check_relay_quota(current_bps) {
                return Err(MeshError::RelayConnectionFailed(
                    "relay bandwidth quota exceeded".to_string(),
                ));
            }
        }

        let id = self.next_session_id.fetch_add(1, Ordering::Relaxed) as RelaySessionId;

        debug!(
            session_id = id,
            source = %source,
            destination = %destination,
            "relay session created"
        );

        self.sessions.insert(
            id,
            RelaySession {
                id,
                source,
                destination,
            },
        );

        Ok(id)
    }

    /// Close a relay session.
    pub fn close_session(&mut self, session_id: RelaySessionId) -> bool {
        if let Some(session) = self.sessions.remove(&session_id) {
            debug!(
                session_id = session_id,
                source = %session.source,
                destination = %session.destination,
                "relay session closed"
            );
            true
        } else {
            warn!(session_id = session_id, "relay session not found");
            false
        }
    }

    /// Get the number of active relay sessions.
    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get a relay session by ID.
    pub fn get_session(&self, session_id: RelaySessionId) -> Option<&RelaySession> {
        self.sessions.get(&session_id)
    }

    /// Get the remaining relay capacity.
    pub fn remaining_capacity(&self) -> u32 {
        self.config
            .relay_capacity
            .saturating_sub(self.active_session_count() as u32)
    }

    /// Check whether this peer is willing to relay.
    pub fn is_willing(&self) -> bool {
        self.config.relay_willing
    }

    /// Update the mesh configuration.
    pub fn update_config(&mut self, config: MeshConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;

    fn make_peer() -> PeerId {
        LocalIdentity::generate().peer_id().clone()
    }

    fn willing_config() -> MeshConfig {
        MeshConfig {
            mesh_enabled: true,
            max_hops: 3,
            relay_willing: true,
            relay_capacity: 10,
        }
    }

    #[test]
    fn test_relay_request_success() {
        let mut mgr = RelayManager::new(willing_config());
        let src = make_peer();
        let dst = make_peer();

        let id = mgr.request_relay(src, dst, None).unwrap();
        assert_eq!(mgr.active_session_count(), 1);
        assert!(mgr.get_session(id).is_some());
    }

    #[test]
    fn test_relay_request_mesh_disabled() {
        let config = MeshConfig {
            mesh_enabled: false,
            ..willing_config()
        };
        let mut mgr = RelayManager::new(config);
        let result = mgr.request_relay(make_peer(), make_peer(), None);
        assert!(matches!(result.unwrap_err(), MeshError::MeshDisabled));
    }

    #[test]
    fn test_relay_request_not_willing() {
        let config = MeshConfig {
            relay_willing: false,
            ..willing_config()
        };
        let mut mgr = RelayManager::new(config);
        let result = mgr.request_relay(make_peer(), make_peer(), None);
        assert!(matches!(result.unwrap_err(), MeshError::RelayNotWilling));
    }

    #[test]
    fn test_relay_capacity_enforced() {
        let config = MeshConfig {
            relay_capacity: 2,
            ..willing_config()
        };
        let mut mgr = RelayManager::new(config);

        mgr.request_relay(make_peer(), make_peer(), None).unwrap();
        mgr.request_relay(make_peer(), make_peer(), None).unwrap();
        let result = mgr.request_relay(make_peer(), make_peer(), None);
        assert!(matches!(
            result.unwrap_err(),
            MeshError::RelayCapacityFull(2, 2)
        ));
    }

    #[test]
    fn test_relay_same_source_and_dest_rejected() {
        let mut mgr = RelayManager::new(willing_config());
        let peer = make_peer();
        let result = mgr.request_relay(peer.clone(), peer, None);
        assert!(matches!(
            result.unwrap_err(),
            MeshError::RelayConnectionFailed(_)
        ));
    }

    #[test]
    fn test_close_session() {
        let mut mgr = RelayManager::new(willing_config());
        let id = mgr.request_relay(make_peer(), make_peer(), None).unwrap();
        assert_eq!(mgr.active_session_count(), 1);

        assert!(mgr.close_session(id));
        assert_eq!(mgr.active_session_count(), 0);
    }

    #[test]
    fn test_close_nonexistent_session() {
        let mut mgr = RelayManager::new(willing_config());
        assert!(!mgr.close_session(999));
    }

    #[test]
    fn test_remaining_capacity() {
        let config = MeshConfig {
            relay_capacity: 5,
            ..willing_config()
        };
        let mut mgr = RelayManager::new(config);
        assert_eq!(mgr.remaining_capacity(), 5);

        mgr.request_relay(make_peer(), make_peer(), None).unwrap();
        assert_eq!(mgr.remaining_capacity(), 4);
    }

    #[test]
    fn test_capacity_restored_after_close() {
        let config = MeshConfig {
            relay_capacity: 2,
            ..willing_config()
        };
        let mut mgr = RelayManager::new(config);

        let id1 = mgr.request_relay(make_peer(), make_peer(), None).unwrap();
        let _id2 = mgr.request_relay(make_peer(), make_peer(), None).unwrap();

        // At capacity
        assert!(mgr.request_relay(make_peer(), make_peer(), None).is_err());

        // Close one, now there's room
        mgr.close_session(id1);
        assert!(mgr.request_relay(make_peer(), make_peer(), None).is_ok());
    }

    #[test]
    fn test_unique_session_ids() {
        let mut mgr = RelayManager::new(willing_config());
        let id1 = mgr.request_relay(make_peer(), make_peer(), None).unwrap();
        let id2 = mgr.request_relay(make_peer(), make_peer(), None).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_session_details() {
        let mut mgr = RelayManager::new(willing_config());
        let src = make_peer();
        let dst = make_peer();
        let id = mgr.request_relay(src.clone(), dst.clone(), None).unwrap();

        let session = mgr.get_session(id).unwrap();
        assert_eq!(session.source, src);
        assert_eq!(session.destination, dst);
    }

    #[test]
    fn test_is_willing() {
        let mgr = RelayManager::new(willing_config());
        assert!(mgr.is_willing());

        let config = MeshConfig {
            relay_willing: false,
            ..willing_config()
        };
        let mgr2 = RelayManager::new(config);
        assert!(!mgr2.is_willing());
    }

    // -- Quota enforcement --

    #[test]
    fn test_relay_quota_allows_within_limit() {
        let mut mgr = RelayManager::new(willing_config());
        let quota = PeerQuota {
            max_relay_bandwidth_bps: Some(5),
            ..PeerQuota::default()
        };
        let result = mgr.request_relay(make_peer(), make_peer(), Some(&quota));
        assert!(result.is_ok());
    }

    #[test]
    fn test_relay_quota_rejects_at_limit() {
        let mut mgr = RelayManager::new(willing_config());
        let quota = PeerQuota {
            max_relay_bandwidth_bps: Some(1),
            ..PeerQuota::default()
        };

        // First session should succeed (0 active < 1 limit... actually check_relay_quota uses <=)
        mgr.request_relay(make_peer(), make_peer(), Some(&quota))
            .unwrap();

        // Second session: 1 active session, quota is max 1 bps, check_relay_quota(1) returns 1 <= 1 = true
        mgr.request_relay(make_peer(), make_peer(), Some(&quota))
            .unwrap();

        // Third session: 2 active sessions, check_relay_quota(2) returns 2 <= 1 = false
        let result = mgr.request_relay(make_peer(), make_peer(), Some(&quota));
        assert!(result.is_err());
        match result.unwrap_err() {
            MeshError::RelayConnectionFailed(msg) => {
                assert!(msg.contains("quota exceeded"));
            }
            other => panic!("expected RelayConnectionFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_relay_no_quota_allows_up_to_capacity() {
        let config = MeshConfig {
            relay_capacity: 3,
            ..willing_config()
        };
        let mut mgr = RelayManager::new(config);

        // Without quota, limited only by capacity
        for _ in 0..3 {
            mgr.request_relay(make_peer(), make_peer(), None).unwrap();
        }
        assert!(mgr.request_relay(make_peer(), make_peer(), None).is_err());
    }

    #[test]
    fn test_relay_unlimited_quota_allows_all() {
        let mut mgr = RelayManager::new(willing_config());
        // None means unlimited for that resource
        let quota = PeerQuota {
            max_relay_bandwidth_bps: None,
            ..PeerQuota::default()
        };

        for _ in 0..5 {
            mgr.request_relay(make_peer(), make_peer(), Some(&quota))
                .unwrap();
        }
    }
}
