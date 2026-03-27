//! Session state persistence for session resumption.
//!
//! Saves enough state after handshake completion so a node can resume the session
//! after restart. Sessions are stored in the KeyStore with key format
//! `session:<remote_libp2p_peer_id>` and an index at `session:_index`.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{CairnError, Result};
use crate::traits::KeyStore;

/// Default session expiry: 24 hours in seconds.
pub const DEFAULT_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// Key prefix for session entries in the keystore.
const SESSION_KEY_PREFIX: &str = "session:";

/// Key for the session index in the keystore.
const SESSION_INDEX_KEY: &str = "session:_index";

/// Serializable representation of a session that can be persisted and restored.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SavedSession {
    /// UUID v7 session identifier (16 bytes).
    pub session_id: [u8; 16],
    /// Remote peer's libp2p PeerId string.
    pub remote_libp2p_peer_id: String,
    /// Exported DoubleRatchet state bytes (from `export_state()`).
    pub ratchet_state: Vec<u8>,
    /// Outbound sequence counter at time of save.
    pub sequence_tx: u64,
    /// Inbound sequence counter at time of save.
    pub sequence_rx: u64,
    /// Ratchet epoch counter.
    pub ratchet_epoch: u32,
    /// Unix timestamp (seconds) when the session was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) of last activity.
    pub last_activity: u64,
    /// Remote peer's known multiaddr strings for re-dialing.
    pub remote_addrs: Vec<String>,
    /// Session expiry duration in seconds (default: 86400 = 24h).
    pub expiry_secs: u64,
}

impl SavedSession {
    /// Check if this session has expired based on its creation time and expiry duration.
    pub fn is_expired(&self) -> bool {
        let now = unix_timestamp_secs();
        now.saturating_sub(self.created_at) > self.expiry_secs
    }
}

/// Get current Unix timestamp in seconds.
fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build the keystore key for a session entry.
fn session_key(remote_peer_id: &str) -> String {
    format!("{SESSION_KEY_PREFIX}{remote_peer_id}")
}

/// Save a session to the keystore and update the index.
pub async fn save_session(keystore: &dyn KeyStore, saved: &SavedSession) -> Result<()> {
    let data = serde_json::to_vec(saved)
        .map_err(|e| CairnError::KeyStore(format!("session serialization failed: {e}")))?;

    let key = session_key(&saved.remote_libp2p_peer_id);
    keystore.store(&key, &data).await?;

    // Update the index
    let mut index = load_index(keystore).await;
    if !index.contains(&saved.remote_libp2p_peer_id) {
        index.push(saved.remote_libp2p_peer_id.clone());
        save_index(keystore, &index).await?;
    }

    Ok(())
}

/// Load a saved session from the keystore by remote peer ID.
///
/// Returns `None` if no session exists or if the session has expired (expired
/// entries are automatically deleted).
pub async fn load_session(
    keystore: &dyn KeyStore,
    remote_peer_id: &str,
) -> Result<Option<SavedSession>> {
    let key = session_key(remote_peer_id);
    if !keystore.exists(&key).await? {
        return Ok(None);
    }

    let data = match keystore.retrieve(&key).await {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };

    let saved: SavedSession = serde_json::from_slice(&data)
        .map_err(|e| CairnError::KeyStore(format!("session deserialization failed: {e}")))?;

    // Check expiry
    if saved.is_expired() {
        delete_session(keystore, remote_peer_id).await?;
        return Ok(None);
    }

    Ok(Some(saved))
}

/// Delete a saved session from the keystore and remove it from the index.
pub async fn delete_session(keystore: &dyn KeyStore, remote_peer_id: &str) -> Result<()> {
    let key = session_key(remote_peer_id);
    keystore.delete(&key).await?;

    // Update the index
    let mut index = load_index(keystore).await;
    index.retain(|id| id != remote_peer_id);
    save_index(keystore, &index).await?;

    Ok(())
}

/// Load all non-expired saved sessions from the keystore.
///
/// Expired sessions are pruned from both the keystore and the index.
pub async fn load_all_sessions(keystore: &dyn KeyStore) -> Result<Vec<SavedSession>> {
    let index = load_index(keystore).await;
    let mut sessions = Vec::new();
    let mut expired = Vec::new();

    for peer_id in &index {
        match load_session(keystore, peer_id).await? {
            Some(saved) => sessions.push(saved),
            None => expired.push(peer_id.clone()),
        }
    }

    // The expired ones were already cleaned up by load_session, but if
    // the index had stale entries that failed to load, clean those too.
    if !expired.is_empty() {
        let mut new_index = load_index(keystore).await;
        new_index.retain(|id| !expired.contains(id));
        save_index(keystore, &new_index).await?;
    }

    Ok(sessions)
}

/// Load the session index from the keystore.
async fn load_index(keystore: &dyn KeyStore) -> Vec<String> {
    match keystore.retrieve(SESSION_INDEX_KEY).await {
        Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Save the session index to the keystore.
async fn save_index(keystore: &dyn KeyStore, index: &[String]) -> Result<()> {
    let data = serde_json::to_vec(index)
        .map_err(|e| CairnError::KeyStore(format!("index serialization failed: {e}")))?;
    keystore.store(SESSION_INDEX_KEY, &data).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keystore::InMemoryKeyStore;

    fn make_saved_session(peer_id: &str) -> SavedSession {
        SavedSession {
            session_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            remote_libp2p_peer_id: peer_id.to_string(),
            ratchet_state: vec![0xAA, 0xBB, 0xCC],
            sequence_tx: 42,
            sequence_rx: 17,
            ratchet_epoch: 2,
            created_at: unix_timestamp_secs(),
            last_activity: unix_timestamp_secs(),
            remote_addrs: vec![
                "/ip4/127.0.0.1/tcp/9000".to_string(),
                "/ip4/127.0.0.1/tcp/9001/ws".to_string(),
            ],
            expiry_secs: DEFAULT_EXPIRY_SECS,
        }
    }

    #[test]
    fn saved_session_serde_roundtrip() {
        let session = make_saved_session("peer-abc");
        let json = serde_json::to_vec(&session).unwrap();
        let decoded: SavedSession = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.session_id, session.session_id);
        assert_eq!(decoded.remote_libp2p_peer_id, session.remote_libp2p_peer_id);
        assert_eq!(decoded.ratchet_state, session.ratchet_state);
        assert_eq!(decoded.sequence_tx, session.sequence_tx);
        assert_eq!(decoded.sequence_rx, session.sequence_rx);
        assert_eq!(decoded.ratchet_epoch, session.ratchet_epoch);
        assert_eq!(decoded.created_at, session.created_at);
        assert_eq!(decoded.remote_addrs, session.remote_addrs);
        assert_eq!(decoded.expiry_secs, session.expiry_secs);
    }

    #[test]
    fn session_not_expired_when_fresh() {
        let session = make_saved_session("peer-abc");
        assert!(!session.is_expired());
    }

    #[test]
    fn session_expired_when_old() {
        let mut session = make_saved_session("peer-abc");
        // Set created_at to 25 hours ago
        session.created_at = unix_timestamp_secs().saturating_sub(25 * 3600);
        assert!(session.is_expired());
    }

    #[test]
    fn session_not_expired_at_boundary() {
        let mut session = make_saved_session("peer-abc");
        // Set created_at to exactly 24 hours ago (should not be expired yet
        // because we check > not >=)
        session.created_at = unix_timestamp_secs().saturating_sub(DEFAULT_EXPIRY_SECS);
        assert!(!session.is_expired());
    }

    #[test]
    fn session_expired_with_zero_expiry() {
        let mut session = make_saved_session("peer-abc");
        session.expiry_secs = 0;
        // created_at is "now" but expiry is 0, so now - created_at (0) > 0 is false
        // This is technically not expired since elapsed is 0
        // But if we wait even 1 second it would be. Let's set created_at 1 second ago.
        session.created_at = unix_timestamp_secs().saturating_sub(1);
        assert!(session.is_expired());
    }

    #[tokio::test]
    async fn save_and_load_session() {
        let store = InMemoryKeyStore::new();
        let session = make_saved_session("peer-abc");

        save_session(&store, &session).await.unwrap();
        let loaded = load_session(&store, "peer-abc").await.unwrap();

        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.session_id, session.session_id);
        assert_eq!(loaded.remote_libp2p_peer_id, "peer-abc");
        assert_eq!(loaded.sequence_tx, 42);
    }

    #[tokio::test]
    async fn load_nonexistent_returns_none() {
        let store = InMemoryKeyStore::new();
        let loaded = load_session(&store, "nonexistent").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn load_expired_session_returns_none_and_deletes() {
        let store = InMemoryKeyStore::new();
        let mut session = make_saved_session("peer-expired");
        session.created_at = unix_timestamp_secs().saturating_sub(25 * 3600);

        save_session(&store, &session).await.unwrap();

        // Load should return None for expired session
        let loaded = load_session(&store, "peer-expired").await.unwrap();
        assert!(loaded.is_none());

        // Should have been deleted from store
        let key = session_key("peer-expired");
        assert!(!store.exists(&key).await.unwrap());

        // Should have been removed from index
        let index = load_index(&store).await;
        assert!(!index.contains(&"peer-expired".to_string()));
    }

    #[tokio::test]
    async fn delete_session_removes_from_store_and_index() {
        let store = InMemoryKeyStore::new();
        let session = make_saved_session("peer-abc");

        save_session(&store, &session).await.unwrap();
        delete_session(&store, "peer-abc").await.unwrap();

        let loaded = load_session(&store, "peer-abc").await.unwrap();
        assert!(loaded.is_none());

        let index = load_index(&store).await;
        assert!(!index.contains(&"peer-abc".to_string()));
    }

    #[tokio::test]
    async fn delete_nonexistent_is_ok() {
        let store = InMemoryKeyStore::new();
        delete_session(&store, "nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn save_multiple_sessions_and_load_all() {
        let store = InMemoryKeyStore::new();
        let s1 = make_saved_session("peer-1");
        let s2 = make_saved_session("peer-2");
        let s3 = make_saved_session("peer-3");

        save_session(&store, &s1).await.unwrap();
        save_session(&store, &s2).await.unwrap();
        save_session(&store, &s3).await.unwrap();

        let all = load_all_sessions(&store).await.unwrap();
        assert_eq!(all.len(), 3);

        let peer_ids: Vec<&str> = all.iter().map(|s| s.remote_libp2p_peer_id.as_str()).collect();
        assert!(peer_ids.contains(&"peer-1"));
        assert!(peer_ids.contains(&"peer-2"));
        assert!(peer_ids.contains(&"peer-3"));
    }

    #[tokio::test]
    async fn load_all_prunes_expired() {
        let store = InMemoryKeyStore::new();
        let s1 = make_saved_session("peer-fresh");
        let mut s2 = make_saved_session("peer-expired");
        s2.created_at = unix_timestamp_secs().saturating_sub(25 * 3600);

        save_session(&store, &s1).await.unwrap();
        save_session(&store, &s2).await.unwrap();

        let all = load_all_sessions(&store).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].remote_libp2p_peer_id, "peer-fresh");
    }

    #[tokio::test]
    async fn index_not_duplicated_on_resave() {
        let store = InMemoryKeyStore::new();
        let session = make_saved_session("peer-abc");

        save_session(&store, &session).await.unwrap();
        save_session(&store, &session).await.unwrap();
        save_session(&store, &session).await.unwrap();

        let index = load_index(&store).await;
        assert_eq!(index.len(), 1);
    }

    #[tokio::test]
    async fn overwrite_session_updates_data() {
        let store = InMemoryKeyStore::new();
        let mut session = make_saved_session("peer-abc");
        session.sequence_tx = 10;

        save_session(&store, &session).await.unwrap();

        session.sequence_tx = 99;
        save_session(&store, &session).await.unwrap();

        let loaded = load_session(&store, "peer-abc").await.unwrap().unwrap();
        assert_eq!(loaded.sequence_tx, 99);
    }
}
