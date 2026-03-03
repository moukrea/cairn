use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;

use super::peer_id::{IdentityError, PeerId};

/// Metadata about a paired peer, stored in the trust store after successful pairing.
#[derive(Debug, Clone)]
pub struct PairedPeerInfo {
    pub peer_id: PeerId,
    pub public_key: VerifyingKey,
    pub paired_at: u64,
    pub pairing_mechanism: String,
    pub is_verified: bool,
}

/// Interface for storing and retrieving paired peer information.
///
/// Implementations must be Send + Sync to support concurrent access.
pub trait TrustStore: Send + Sync {
    fn add_peer(&mut self, info: PairedPeerInfo) -> Result<(), IdentityError>;
    fn remove_peer(&mut self, peer_id: &PeerId) -> Result<bool, IdentityError>;
    fn get_peer(&self, peer_id: &PeerId) -> Option<&PairedPeerInfo>;
    fn list_peers(&self) -> Vec<&PairedPeerInfo>;
    fn is_paired(&self, peer_id: &PeerId) -> bool;
}

/// In-memory trust store backed by a HashMap. Suitable for testing and ephemeral use.
#[derive(Debug, Default)]
pub struct InMemoryTrustStore {
    peers: HashMap<PeerId, PairedPeerInfo>,
}

impl InMemoryTrustStore {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

impl TrustStore for InMemoryTrustStore {
    fn add_peer(&mut self, info: PairedPeerInfo) -> Result<(), IdentityError> {
        if self.peers.contains_key(&info.peer_id) {
            return Err(IdentityError::AlreadyPaired(info.peer_id));
        }
        self.peers.insert(info.peer_id.clone(), info);
        Ok(())
    }

    fn remove_peer(&mut self, peer_id: &PeerId) -> Result<bool, IdentityError> {
        Ok(self.peers.remove(peer_id).is_some())
    }

    fn get_peer(&self, peer_id: &PeerId) -> Option<&PairedPeerInfo> {
        self.peers.get(peer_id)
    }

    fn list_peers(&self) -> Vec<&PairedPeerInfo> {
        self.peers.values().collect()
    }

    fn is_paired(&self, peer_id: &PeerId) -> bool {
        self.peers.contains_key(peer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn make_peer_info(suffix: u8) -> PairedPeerInfo {
        // Deterministic keypair from a fixed seed for reproducibility.
        let seed = [suffix; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let peer_id = PeerId::from_public_key(&verifying_key);
        PairedPeerInfo {
            peer_id,
            public_key: verifying_key,
            paired_at: 1700000000 + u64::from(suffix),
            pairing_mechanism: "pin_code".into(),
            is_verified: true,
        }
    }

    #[test]
    fn add_and_get_peer() {
        let mut store = InMemoryTrustStore::new();
        let info = make_peer_info(1);
        let pid = info.peer_id.clone();
        store.add_peer(info).unwrap();
        let retrieved = store.get_peer(&pid).unwrap();
        assert_eq!(retrieved.peer_id, pid);
        assert!(retrieved.is_verified);
    }

    #[test]
    fn add_duplicate_peer_fails() {
        let mut store = InMemoryTrustStore::new();
        let info = make_peer_info(1);
        store.add_peer(info.clone()).unwrap();
        let result = store.add_peer(info);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("already paired"));
    }

    #[test]
    fn remove_existing_peer() {
        let mut store = InMemoryTrustStore::new();
        let info = make_peer_info(1);
        let pid = info.peer_id.clone();
        store.add_peer(info).unwrap();
        let removed = store.remove_peer(&pid).unwrap();
        assert!(removed);
        assert!(!store.is_paired(&pid));
    }

    #[test]
    fn remove_nonexistent_peer_returns_false() {
        let mut store = InMemoryTrustStore::new();
        let info = make_peer_info(1);
        let removed = store.remove_peer(&info.peer_id).unwrap();
        assert!(!removed);
    }

    #[test]
    fn is_paired_check() {
        let mut store = InMemoryTrustStore::new();
        let info = make_peer_info(1);
        let pid = info.peer_id.clone();
        assert!(!store.is_paired(&pid));
        store.add_peer(info).unwrap();
        assert!(store.is_paired(&pid));
    }

    #[test]
    fn list_peers_returns_all() {
        let mut store = InMemoryTrustStore::new();
        store.add_peer(make_peer_info(1)).unwrap();
        store.add_peer(make_peer_info(2)).unwrap();
        store.add_peer(make_peer_info(3)).unwrap();
        assert_eq!(store.list_peers().len(), 3);
    }

    #[test]
    fn len_and_is_empty() {
        let mut store = InMemoryTrustStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        store.add_peer(make_peer_info(1)).unwrap();
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn get_peer_nonexistent_returns_none() {
        let store = InMemoryTrustStore::new();
        let info = make_peer_info(1);
        assert!(store.get_peer(&info.peer_id).is_none());
    }

    #[test]
    fn paired_peer_info_fields() {
        let info = make_peer_info(42);
        assert_eq!(info.paired_at, 1700000042);
        assert_eq!(info.pairing_mechanism, "pin_code");
        assert!(info.is_verified);
    }

    #[test]
    fn trust_store_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryTrustStore>();
    }
}
