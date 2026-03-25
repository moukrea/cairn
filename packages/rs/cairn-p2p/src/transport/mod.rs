pub mod fallback;
pub mod nat;
pub mod swarm;

use std::time::Duration;

/// Per-transport enable/disable flags and timeout settings.
///
/// Controls which transports are included in the libp2p swarm construction.
/// Disabled transports are not composed into the transport stack at all.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Enable QUIC v1 (RFC 9000) — priority 1 in the fallback chain.
    pub quic_enabled: bool,
    /// Enable TCP — priority 3 in the fallback chain.
    pub tcp_enabled: bool,
    /// Enable WebSocket over TLS — priority 6 in the fallback chain.
    pub websocket_enabled: bool,
    /// Enable WebTransport over HTTP/3 — priority 7 in the fallback chain.
    /// Note: libp2p-websocket is used for WS; WebTransport is a placeholder
    /// until libp2p Rust gains native webtransport support.
    pub webtransport_enabled: bool,
    /// Per-transport connection timeout.
    pub per_transport_timeout: Duration,
    /// Enable mDNS for LAN peer discovery.
    /// Disable in tests to avoid cross-test interference.
    pub mdns_enabled: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            quic_enabled: true,
            tcp_enabled: true,
            websocket_enabled: true,
            webtransport_enabled: true,
            per_transport_timeout: Duration::from_secs(10),
            mdns_enabled: true,
        }
    }
}

pub use fallback::{
    ConnectionQuality, ConnectionQualityMonitor, DegradationEvent, DegradationReason,
    FallbackChain, FallbackTransportType, MigrationEvent, QualityThresholds, TransportAttempt,
    TransportAttemptResult, TransportMigrator,
};
pub use nat::{NatDetector, NatType, NetworkInfo};
pub use swarm::{build_swarm, SwarmCommandSender, SwarmController, SwarmEvent as CairnSwarmEvent};
