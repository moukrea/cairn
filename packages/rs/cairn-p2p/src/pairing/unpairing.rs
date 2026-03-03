use crate::identity::{PeerId, TrustStore};

/// Event emitted when a peer is unpaired (local or remote initiated).
#[derive(Debug, Clone)]
pub enum UnpairingEvent {
    /// Local unpair completed.
    LocalUnpairCompleted { peer_id: PeerId },
    /// Remote peer sent PairRevoke.
    RemotePeerUnpaired { peer_id: PeerId },
}

/// Errors during unpairing operations.
#[derive(Debug, thiserror::Error)]
pub enum UnpairingError {
    #[error("peer not found in trust store: {0}")]
    PeerNotFound(PeerId),
    #[error("failed to remove peer state: {0}")]
    StateRemovalFailed(String),
}

/// Execute the local unpairing protocol for a given peer.
///
/// Steps:
/// 1. Verify the peer exists in the trust store.
/// 2. Remove the peer from the trust store.
/// 3. Return `LocalUnpairCompleted` event for the caller to propagate.
///
/// Note: sending `PairRevoke` and closing sessions is delegated to the
/// session management layer (the caller). This function handles only
/// trust store cleanup and event emission.
pub fn unpair(
    peer_id: &PeerId,
    trust_store: &mut dyn TrustStore,
) -> Result<UnpairingEvent, UnpairingError> {
    if !trust_store.is_paired(peer_id) {
        return Err(UnpairingError::PeerNotFound(peer_id.clone()));
    }

    let removed = trust_store
        .remove_peer(peer_id)
        .map_err(|e| UnpairingError::StateRemovalFailed(e.to_string()))?;

    if !removed {
        return Err(UnpairingError::StateRemovalFailed(
            "peer was present but removal returned false".into(),
        ));
    }

    Ok(UnpairingEvent::LocalUnpairCompleted {
        peer_id: peer_id.clone(),
    })
}

/// Handle an incoming `PairRevoke` message from a remote peer.
///
/// Steps:
/// 1. Remove the peer from the trust store (if present).
/// 2. Return `RemotePeerUnpaired` event.
///
/// If the peer is not in the trust store (e.g., already unpaired), this
/// still returns the event — the caller can decide whether to propagate it.
pub fn handle_pair_revoke(
    peer_id: &PeerId,
    trust_store: &mut dyn TrustStore,
) -> Result<UnpairingEvent, UnpairingError> {
    // Remove if present; ignore "not found" since the peer may have already
    // been removed locally.
    let _ = trust_store.remove_peer(peer_id);

    Ok(UnpairingEvent::RemotePeerUnpaired {
        peer_id: peer_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{InMemoryTrustStore, PairedPeerInfo};
    use ed25519_dalek::SigningKey;

    fn make_peer_info(suffix: u8) -> PairedPeerInfo {
        let seed = [suffix; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let peer_id = PeerId::from_public_key(&verifying_key);
        PairedPeerInfo {
            peer_id,
            public_key: verifying_key,
            paired_at: 1700000000 + u64::from(suffix),
            pairing_mechanism: "test".into(),
            is_verified: true,
        }
    }

    #[test]
    fn unpair_removes_peer_from_trust_store() {
        let mut store = InMemoryTrustStore::new();
        let info = make_peer_info(1);
        let peer_id = info.peer_id.clone();
        store.add_peer(info).unwrap();

        assert!(store.is_paired(&peer_id));

        let event = unpair(&peer_id, &mut store).unwrap();
        match event {
            UnpairingEvent::LocalUnpairCompleted { peer_id: pid } => {
                assert_eq!(pid, peer_id);
            }
            _ => panic!("expected LocalUnpairCompleted"),
        }

        assert!(!store.is_paired(&peer_id));
    }

    #[test]
    fn unpair_unknown_peer_returns_error() {
        let mut store = InMemoryTrustStore::new();
        let info = make_peer_info(1);
        let peer_id = info.peer_id.clone();

        let err = unpair(&peer_id, &mut store).unwrap_err();
        match err {
            UnpairingError::PeerNotFound(pid) => {
                assert_eq!(pid, peer_id);
            }
            _ => panic!("expected PeerNotFound, got: {err}"),
        }
    }

    #[test]
    fn handle_pair_revoke_removes_peer() {
        let mut store = InMemoryTrustStore::new();
        let info = make_peer_info(2);
        let peer_id = info.peer_id.clone();
        store.add_peer(info).unwrap();

        let event = handle_pair_revoke(&peer_id, &mut store).unwrap();
        match event {
            UnpairingEvent::RemotePeerUnpaired { peer_id: pid } => {
                assert_eq!(pid, peer_id);
            }
            _ => panic!("expected RemotePeerUnpaired"),
        }

        assert!(!store.is_paired(&peer_id));
    }

    #[test]
    fn handle_pair_revoke_for_unknown_peer_succeeds() {
        let mut store = InMemoryTrustStore::new();
        let info = make_peer_info(3);
        let peer_id = info.peer_id.clone();

        // Should succeed even if peer not in trust store
        let event = handle_pair_revoke(&peer_id, &mut store).unwrap();
        assert!(matches!(event, UnpairingEvent::RemotePeerUnpaired { .. }));
    }

    #[test]
    fn unpair_does_not_affect_other_peers() {
        let mut store = InMemoryTrustStore::new();
        let info1 = make_peer_info(1);
        let info2 = make_peer_info(2);
        let pid1 = info1.peer_id.clone();
        let pid2 = info2.peer_id.clone();
        store.add_peer(info1).unwrap();
        store.add_peer(info2).unwrap();

        unpair(&pid1, &mut store).unwrap();

        assert!(!store.is_paired(&pid1));
        assert!(store.is_paired(&pid2));
    }

    #[test]
    fn handle_pair_revoke_does_not_affect_other_peers() {
        let mut store = InMemoryTrustStore::new();
        let info1 = make_peer_info(1);
        let info2 = make_peer_info(2);
        let pid1 = info1.peer_id.clone();
        let pid2 = info2.peer_id.clone();
        store.add_peer(info1).unwrap();
        store.add_peer(info2).unwrap();

        handle_pair_revoke(&pid1, &mut store).unwrap();

        assert!(!store.is_paired(&pid1));
        assert!(store.is_paired(&pid2));
    }

    #[test]
    fn error_display() {
        let info = make_peer_info(1);
        let err = UnpairingError::PeerNotFound(info.peer_id);
        assert!(err.to_string().contains("peer not found"));

        let err = UnpairingError::StateRemovalFailed("disk error".into());
        assert!(err.to_string().contains("disk error"));
    }

    #[test]
    fn unpairing_event_debug() {
        let info = make_peer_info(1);
        let event = UnpairingEvent::LocalUnpairCompleted {
            peer_id: info.peer_id.clone(),
        };
        let debug = format!("{event:?}");
        assert!(debug.contains("LocalUnpairCompleted"));

        let event = UnpairingEvent::RemotePeerUnpaired {
            peer_id: info.peer_id,
        };
        let debug = format!("{event:?}");
        assert!(debug.contains("RemotePeerUnpaired"));
    }
}
