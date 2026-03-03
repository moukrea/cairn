//! Opt-in mesh networking: routing table, multi-hop relay, topology exchange.
//!
//! Mesh networking enables peers to route traffic through intermediate hops when
//! direct connections are not possible. It uses cairn's own application-level relay
//! on standard libp2p streams (NOT Circuit Relay v2) with no duration or data limits.
//!
//! See spec/09-mesh-networking.md.

pub mod relay;
pub mod routing;

pub use relay::{RelayManager, RelaySession, RelaySessionId};
pub use routing::{MeshTopologyUpdate, ReachabilityEntry, Route, RoutingTable};

use serde::{Deserialize, Serialize};

/// Mesh networking configuration (spec 9.4).
///
/// Mesh is opt-in and disabled by default. Server-mode peers override defaults
/// with `mesh_enabled = true`, `relay_willing = true`, `relay_capacity = 100+`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Enable/disable mesh routing. Default: false.
    pub mesh_enabled: bool,
    /// Maximum relay hops allowed for any route. Default: 3.
    pub max_hops: u8,
    /// Whether this peer is willing to relay traffic for others. Default: false.
    pub relay_willing: bool,
    /// Maximum simultaneous relay connections this peer will serve. Default: 10.
    pub relay_capacity: u32,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            mesh_enabled: false,
            max_hops: 3,
            relay_willing: false,
            relay_capacity: 10,
        }
    }
}

impl MeshConfig {
    /// Configuration preset for server-mode peers.
    pub fn server_mode() -> Self {
        Self {
            mesh_enabled: true,
            max_hops: 3,
            relay_willing: true,
            relay_capacity: 100,
        }
    }
}

/// Errors specific to mesh networking operations.
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("mesh routing disabled")]
    MeshDisabled,

    #[error("no route to peer {0}")]
    NoRoute(String),

    #[error("max hops exceeded: {0} > {1}")]
    MaxHopsExceeded(u8, u8),

    #[error("relay capacity full ({0}/{1})")]
    RelayCapacityFull(u32, u32),

    #[error("relay not willing")]
    RelayNotWilling,

    #[error("relay connection failed: {0}")]
    RelayConnectionFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MeshConfig::default();
        assert!(!config.mesh_enabled);
        assert_eq!(config.max_hops, 3);
        assert!(!config.relay_willing);
        assert_eq!(config.relay_capacity, 10);
    }

    #[test]
    fn test_server_mode_config() {
        let config = MeshConfig::server_mode();
        assert!(config.mesh_enabled);
        assert!(config.relay_willing);
        assert_eq!(config.relay_capacity, 100);
        assert_eq!(config.max_hops, 3);
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = MeshConfig {
            mesh_enabled: true,
            max_hops: 5,
            relay_willing: true,
            relay_capacity: 50,
        };
        let json = serde_json::to_string(&config).unwrap();
        let decoded: MeshConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.mesh_enabled, config.mesh_enabled);
        assert_eq!(decoded.max_hops, config.max_hops);
        assert_eq!(decoded.relay_willing, config.relay_willing);
        assert_eq!(decoded.relay_capacity, config.relay_capacity);
    }

    #[test]
    fn test_mesh_error_display() {
        assert_eq!(MeshError::MeshDisabled.to_string(), "mesh routing disabled");
        assert_eq!(
            MeshError::NoRoute("peer-abc".into()).to_string(),
            "no route to peer peer-abc"
        );
        assert_eq!(
            MeshError::MaxHopsExceeded(4, 3).to_string(),
            "max hops exceeded: 4 > 3"
        );
        assert_eq!(
            MeshError::RelayCapacityFull(10, 10).to_string(),
            "relay capacity full (10/10)"
        );
        assert_eq!(MeshError::RelayNotWilling.to_string(), "relay not willing");
        assert_eq!(
            MeshError::RelayConnectionFailed("timeout".into()).to_string(),
            "relay connection failed: timeout"
        );
    }
}
