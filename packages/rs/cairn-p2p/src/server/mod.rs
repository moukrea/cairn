pub mod headless;
pub mod management;
pub mod store_forward;

pub use headless::{
    HeadlessPairing, HeadlessPairingError, HeadlessPairingMethod, PeerMetrics, PeerQuota,
    PeerSyncState, PersonalRelayConfig,
};
pub use management::ManagementConfig;
pub use store_forward::{
    DeduplicationTracker, ForwardAck, ForwardDeliver, ForwardPurge, ForwardRequest, MessageQueue,
    RetentionPolicy, StoredMessage, FORWARD_CHANNEL, MAX_SKIP_THRESHOLD,
};

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Server-mode configuration posture (spec 10.2).
///
/// Server mode is not a separate class or protocol -- it is a standard `Node`
/// with adjusted defaults. The `create_server(config)` convenience constructor
/// applies these defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub mesh_enabled: bool,
    pub relay_willing: bool,
    pub relay_capacity: u32,
    pub store_forward_enabled: bool,
    pub store_forward_max_per_peer: u32,
    pub store_forward_max_age: Duration,
    pub store_forward_max_total_size: u64,
    pub session_expiry: Duration,
    pub heartbeat_interval: Duration,
    pub reconnect_max_duration: Option<Duration>,
    pub headless: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            mesh_enabled: true,
            relay_willing: true,
            relay_capacity: 100,
            store_forward_enabled: true,
            store_forward_max_per_peer: 1_000,
            store_forward_max_age: Duration::from_secs(7 * 24 * 3600), // 7 days
            store_forward_max_total_size: 1_073_741_824,               // 1 GB
            session_expiry: Duration::from_secs(7 * 24 * 3600),        // 7 days
            heartbeat_interval: Duration::from_secs(60),
            reconnect_max_duration: None, // indefinite
            headless: true,
        }
    }
}

impl ServerConfig {
    /// Build a `RetentionPolicy` from this server config.
    pub fn retention_policy(&self) -> RetentionPolicy {
        RetentionPolicy {
            max_age: self.store_forward_max_age,
            max_messages: self.store_forward_max_per_peer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_defaults() {
        let cfg = ServerConfig::default();
        assert!(cfg.mesh_enabled);
        assert!(cfg.relay_willing);
        assert_eq!(cfg.relay_capacity, 100);
        assert!(cfg.store_forward_enabled);
        assert_eq!(cfg.store_forward_max_per_peer, 1_000);
        assert_eq!(cfg.store_forward_max_age, Duration::from_secs(604_800));
        assert_eq!(cfg.store_forward_max_total_size, 1_073_741_824);
        assert_eq!(cfg.session_expiry, Duration::from_secs(604_800));
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(60));
        assert!(cfg.reconnect_max_duration.is_none());
        assert!(cfg.headless);
    }

    #[test]
    fn retention_policy_from_server_config() {
        let cfg = ServerConfig::default();
        let policy = cfg.retention_policy();
        assert_eq!(policy.max_age, cfg.store_forward_max_age);
        assert_eq!(policy.max_messages, cfg.store_forward_max_per_peer);
    }

    #[test]
    fn server_config_custom() {
        let cfg = ServerConfig {
            relay_capacity: 500,
            store_forward_max_per_peer: 10_000,
            headless: false,
            ..ServerConfig::default()
        };
        assert_eq!(cfg.relay_capacity, 500);
        assert_eq!(cfg.store_forward_max_per_peer, 10_000);
        assert!(!cfg.headless);
    }

    #[test]
    fn server_config_serde_roundtrip() {
        let cfg = ServerConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: ServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.relay_capacity, cfg.relay_capacity);
        assert_eq!(
            restored.store_forward_max_per_peer,
            cfg.store_forward_max_per_peer
        );
        assert!(restored.headless);
    }
}
