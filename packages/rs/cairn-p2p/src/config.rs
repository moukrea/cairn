use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use crate::error::{CairnError, Result};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Transport protocol in the fallback chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Quic,
    Tcp,
    WsTls,
    WebTransport,
    CircuitRelayV2,
}

/// TURN relay server credentials.
#[derive(Debug, Clone)]
pub struct TurnServer {
    pub url: String,
    pub username: String,
    pub credential: String,
}

/// Reconnection and timeout policy (spec section 2.2).
#[derive(Debug, Clone)]
pub struct ReconnectionPolicy {
    pub connect_timeout: Duration,
    pub transport_timeout: Duration,
    pub reconnect_max_duration: Duration,
    pub reconnect_backoff_initial: Duration,
    pub reconnect_backoff_max: Duration,
    pub reconnect_backoff_factor: f64,
    pub rendezvous_poll_interval: Duration,
    pub session_expiry: Duration,
    pub pairing_payload_expiry: Duration,
}

impl Default for ReconnectionPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            transport_timeout: Duration::from_secs(10),
            reconnect_max_duration: Duration::from_secs(3600),
            reconnect_backoff_initial: Duration::from_secs(1),
            reconnect_backoff_max: Duration::from_secs(60),
            reconnect_backoff_factor: 2.0,
            rendezvous_poll_interval: Duration::from_secs(30),
            session_expiry: Duration::from_secs(86400),
            pairing_payload_expiry: Duration::from_secs(300),
        }
    }
}

/// Mesh routing settings (spec section 1.2).
#[derive(Debug, Clone)]
pub struct MeshSettings {
    pub mesh_enabled: bool,
    pub max_hops: u8,
    pub relay_willing: bool,
    pub relay_capacity: u16,
}

impl Default for MeshSettings {
    fn default() -> Self {
        Self {
            mesh_enabled: false,
            max_hops: 3,
            relay_willing: false,
            relay_capacity: 10,
        }
    }
}

/// Storage backend for keys, identities, and pairing state.
#[derive(Debug, Clone)]
pub enum StorageBackend {
    Filesystem { path: PathBuf },
    InMemory,
    Custom(String),
}

impl Default for StorageBackend {
    fn default() -> Self {
        StorageBackend::Filesystem {
            path: PathBuf::from(".cairn"),
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest (spec section 1.3)
// ---------------------------------------------------------------------------

/// Configuration for opt-in signed manifest fetch.
#[derive(Debug, Clone)]
pub struct ManifestConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub refresh_interval: Duration,
}

/// Embedded Ed25519 public key for verifying infrastructure manifest signatures.
/// Placeholder -- replaced with a real key at release time.
const MANIFEST_VERIFY_KEY: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// JSON structure of the signed infrastructure manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct InfrastructureManifest {
    pub version: u32,
    pub stun_servers: Vec<String>,
    pub tracker_urls: Vec<String>,
    pub bootstrap_nodes: Vec<String>,
    pub signature: String,
}

/// Returns the embedded Ed25519 verifying key for manifest signatures.
pub fn manifest_verify_key() -> [u8; 32] {
    MANIFEST_VERIFY_KEY
}

/// Verify an infrastructure manifest's Ed25519 signature.
///
/// The signature covers the canonical JSON of all fields *except* `signature`.
pub fn verify_manifest(manifest_json: &str) -> Result<InfrastructureManifest> {
    let manifest: InfrastructureManifest = serde_json::from_str(manifest_json)
        .map_err(|e| CairnError::Protocol(format!("invalid manifest JSON: {e}")))?;

    // Reconstruct the signed payload (everything except the signature field).
    let signed_payload = format!(
        r#"{{"version":{},"stun_servers":{},"tracker_urls":{},"bootstrap_nodes":{}}}"#,
        manifest.version,
        serde_json::to_string(&manifest.stun_servers).unwrap_or_default(),
        serde_json::to_string(&manifest.tracker_urls).unwrap_or_default(),
        serde_json::to_string(&manifest.bootstrap_nodes).unwrap_or_default(),
    );

    let sig_bytes = base64_decode(&manifest.signature)?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| CairnError::Crypto(format!("invalid manifest signature bytes: {e}")))?;

    let verifying_key = VerifyingKey::from_bytes(&MANIFEST_VERIFY_KEY)
        .map_err(|e| CairnError::Crypto(format!("invalid embedded manifest verify key: {e}")))?;

    verifying_key
        .verify(signed_payload.as_bytes(), &signature)
        .map_err(|e| CairnError::Crypto(format!("manifest signature verification failed: {e}")))?;

    Ok(manifest)
}

/// Simple base64 decode (standard alphabet, no padding required).
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    // Minimal base64 decoder -- avoids pulling in the `base64` crate just for this.
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => None, // padding
            _ => None,
        }
    }

    let input = input.as_bytes();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let chunks = input.chunks(4);
    for chunk in chunks {
        let mut buf: u32 = 0;
        let mut count = 0u8;
        for &b in chunk {
            if let Some(v) = val(b) {
                buf = (buf << 6) | u32::from(v);
                count += 1;
            } else if b == b'=' {
                buf <<= 6;
            } else {
                return Err(CairnError::Protocol(format!(
                    "invalid base64 character: {}",
                    b as char
                )));
            }
        }
        match count {
            4 => {
                out.push((buf >> 16) as u8);
                out.push((buf >> 8) as u8);
                out.push(buf as u8);
            }
            3 => {
                out.push((buf >> 16) as u8);
                out.push((buf >> 8) as u8);
            }
            2 => {
                out.push((buf >> 16) as u8);
            }
            _ => {}
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// CairnConfig
// ---------------------------------------------------------------------------

/// Top-level configuration object passed at initialization (spec section 1.1).
///
/// Every field has a sensible default, enabling zero-config usage (Tier 0).
#[derive(Debug, Clone)]
pub struct CairnConfig {
    pub stun_servers: Vec<String>,
    pub turn_servers: Vec<TurnServer>,
    pub signaling_servers: Vec<String>,
    pub tracker_urls: Vec<String>,
    pub bootstrap_nodes: Vec<String>,
    pub transport_preferences: Vec<TransportType>,
    pub reconnection_policy: ReconnectionPolicy,
    pub mesh_settings: MeshSettings,
    pub storage_backend: StorageBackend,
    pub server_mode: bool,
    pub manifest_config: Option<ManifestConfig>,
    /// Optional application identifier for discovery namespace isolation.
    /// Different app identifiers produce different rendezvous IDs from the
    /// same pairing secret, preventing cross-app peer collision on public
    /// DHT/tracker networks.
    pub app_identifier: Option<String>,
    /// Customizable PIN format for pairing codes.
    pub pin_format: PinFormat,
    /// Auto-approve all valid pairing requests (useful for kiosk/open scenarios).
    pub auto_approve_pairing: bool,
    /// Optional pairing password for second-layer authentication after PIN verification.
    pub pairing_password: Option<String>,
    /// Optional human-readable message attached to pairing requests.
    pub pairing_message: Option<String>,
    /// Optional explicit listen addresses (multiaddr format).
    /// When set, cairn listens only on these addresses instead of the default
    /// `0.0.0.0` (all interfaces). Useful for skipping unwanted interfaces
    /// (e.g., Docker bridges) that slow down startup.
    /// Example: `["/ip4/192.168.1.10/tcp/0", "/ip4/192.168.1.10/udp/0/quic-v1"]`
    pub listen_addresses: Option<Vec<String>>,
}

/// PIN format configuration.
#[derive(Debug, Clone)]
pub struct PinFormat {
    /// Number of Crockford Base32 characters in the PIN. Default: 8.
    pub length: usize,
    /// Number of characters per group. Default: 4.
    pub group_size: usize,
    /// Separator between groups. Default: "-".
    pub separator: String,
}

impl Default for PinFormat {
    fn default() -> Self {
        Self {
            length: 8,
            group_size: 4,
            separator: "-".into(),
        }
    }
}

/// Default STUN servers (Google, Cloudflare).
fn default_stun_servers() -> Vec<String> {
    vec![
        "stun:stun.l.google.com:19302".into(),
        "stun:stun1.l.google.com:19302".into(),
        "stun:stun.cloudflare.com:3478".into(),
    ]
}

/// Default transport fallback order from spec.
fn default_transport_preferences() -> Vec<TransportType> {
    vec![
        TransportType::Quic,
        TransportType::Tcp,
        TransportType::WsTls,
        TransportType::WebTransport,
        TransportType::CircuitRelayV2,
    ]
}

impl Default for CairnConfig {
    fn default() -> Self {
        Self {
            stun_servers: default_stun_servers(),
            turn_servers: Vec::new(),
            signaling_servers: Vec::new(),
            tracker_urls: Vec::new(),
            bootstrap_nodes: Vec::new(),
            transport_preferences: default_transport_preferences(),
            reconnection_policy: ReconnectionPolicy::default(),
            mesh_settings: MeshSettings::default(),
            storage_backend: StorageBackend::default(),
            server_mode: false,
            manifest_config: None,
            app_identifier: None,
            pin_format: PinFormat::default(),
            auto_approve_pairing: false,
            pairing_password: None,
            pairing_message: None,
            listen_addresses: None,
        }
    }
}

impl CairnConfig {
    /// Tier 0: fully decentralized, zero-config (mDNS + DHT + public STUN).
    pub fn tier0() -> Self {
        Self::default()
    }

    /// Tier 1: add a signaling server and optional TURN relay.
    pub fn tier1(signaling_servers: Vec<String>, turn_servers: Vec<TurnServer>) -> Self {
        Self {
            signaling_servers,
            turn_servers,
            ..Self::default()
        }
    }

    /// Tier 2: self-hosted infrastructure (signaling + TURN + custom trackers + bootstrap).
    pub fn tier2(
        signaling_servers: Vec<String>,
        turn_servers: Vec<TurnServer>,
        tracker_urls: Vec<String>,
        bootstrap_nodes: Vec<String>,
    ) -> Self {
        Self {
            signaling_servers,
            turn_servers,
            tracker_urls,
            bootstrap_nodes,
            ..Self::default()
        }
    }

    /// Tier 3: fully self-hosted with mesh routing enabled.
    pub fn tier3(
        signaling_servers: Vec<String>,
        turn_servers: Vec<TurnServer>,
        tracker_urls: Vec<String>,
        bootstrap_nodes: Vec<String>,
        mesh_settings: MeshSettings,
    ) -> Self {
        Self {
            signaling_servers,
            turn_servers,
            tracker_urls,
            bootstrap_nodes,
            mesh_settings,
            ..Self::default()
        }
    }

    /// Default server-mode config (headless, longer expiry, relay-willing).
    pub fn default_server() -> Self {
        Self {
            server_mode: true,
            reconnection_policy: ReconnectionPolicy {
                session_expiry: Duration::from_secs(86400 * 7), // 7 days
                ..ReconnectionPolicy::default()
            },
            mesh_settings: MeshSettings {
                relay_willing: true,
                ..MeshSettings::default()
            },
            storage_backend: StorageBackend::Filesystem {
                path: PathBuf::from(".cairn-server"),
            },
            ..Self::default()
        }
    }

    /// Validate configuration, returning an error on invalid settings.
    pub fn validate(&self) -> Result<()> {
        // STUN servers must not be empty unless TURN is configured.
        if self.stun_servers.is_empty() && self.turn_servers.is_empty() {
            return Err(CairnError::Protocol(
                "config validation: stun_servers must not be empty unless turn_servers are configured".into(),
            ));
        }

        // Backoff factor must be > 1.0.
        if self.reconnection_policy.reconnect_backoff_factor <= 1.0 {
            return Err(CairnError::Protocol(
                "config validation: reconnect_backoff_factor must be greater than 1.0".into(),
            ));
        }

        // max_hops must be 1..=10.
        if self.mesh_settings.max_hops == 0 || self.mesh_settings.max_hops > 10 {
            return Err(CairnError::Protocol(
                "config validation: max_hops must be between 1 and 10".into(),
            ));
        }

        // Manifest endpoint must be HTTPS if enabled.
        if let Some(ref mc) = self.manifest_config {
            if mc.enabled && !mc.endpoint.starts_with("https://") {
                return Err(CairnError::Protocol(
                    "config validation: manifest endpoint must be an HTTPS URL".into(),
                ));
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Type-safe consuming builder for `CairnConfig`.
#[derive(Debug)]
pub struct CairnConfigBuilder {
    config: CairnConfig,
}

impl CairnConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: CairnConfig::default(),
        }
    }

    pub fn stun_servers(mut self, servers: Vec<String>) -> Self {
        self.config.stun_servers = servers;
        self
    }

    pub fn turn_servers(mut self, servers: Vec<TurnServer>) -> Self {
        self.config.turn_servers = servers;
        self
    }

    pub fn signaling_servers(mut self, servers: Vec<String>) -> Self {
        self.config.signaling_servers = servers;
        self
    }

    pub fn tracker_urls(mut self, urls: Vec<String>) -> Self {
        self.config.tracker_urls = urls;
        self
    }

    pub fn bootstrap_nodes(mut self, nodes: Vec<String>) -> Self {
        self.config.bootstrap_nodes = nodes;
        self
    }

    pub fn transport_preferences(mut self, prefs: Vec<TransportType>) -> Self {
        self.config.transport_preferences = prefs;
        self
    }

    pub fn reconnection_policy(mut self, policy: ReconnectionPolicy) -> Self {
        self.config.reconnection_policy = policy;
        self
    }

    pub fn mesh_settings(mut self, settings: MeshSettings) -> Self {
        self.config.mesh_settings = settings;
        self
    }

    pub fn storage_backend(mut self, backend: StorageBackend) -> Self {
        self.config.storage_backend = backend;
        self
    }

    pub fn server_mode(mut self, enabled: bool) -> Self {
        self.config.server_mode = enabled;
        self
    }

    pub fn listen_addresses(mut self, addrs: Vec<String>) -> Self {
        self.config.listen_addresses = Some(addrs);
        self
    }

    pub fn manifest_config(mut self, config: ManifestConfig) -> Self {
        self.config.manifest_config = Some(config);
        self
    }

    /// Build and validate the configuration.
    pub fn build(self) -> Result<CairnConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for CairnConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Factory functions
// ---------------------------------------------------------------------------

use crate::api::node::ApiNode;

/// Create a cairn node with default (Tier 0) configuration.
///
/// Does NOT start the transport layer. Call `node.start_transport().await`
/// to enable real network connections, or use `create_and_start()` for the
/// async version that starts transport automatically.
pub fn create() -> Result<ApiNode> {
    create_with_config(CairnConfig::default())
}

/// Create a cairn node with the given configuration.
///
/// Does NOT start the transport layer. See `create()` for details.
pub fn create_with_config(config: CairnConfig) -> Result<ApiNode> {
    ApiNode::new(config)
}

/// Create a cairn node with default config AND start the transport layer.
///
/// This is the recommended entry point for applications that need real
/// network connectivity. Returns a node that is ready to pair and connect.
pub async fn create_and_start() -> Result<ApiNode> {
    create_and_start_with_config(CairnConfig::default()).await
}

/// Create a cairn node with the given config AND start the transport layer.
pub async fn create_and_start_with_config(config: CairnConfig) -> Result<ApiNode> {
    let mut node = ApiNode::new(config)?;
    node.start_transport().await?;
    Ok(node)
}

/// Create a cairn server node with default server configuration.
pub fn create_server() -> Result<ApiNode> {
    create_server_with_config(CairnConfig::default_server())
}

/// Create a cairn server node with the given configuration.
pub fn create_server_with_config(mut config: CairnConfig) -> Result<ApiNode> {
    config.server_mode = true;
    ApiNode::new(config)
}

/// Create a cairn server node with transport started.
pub async fn create_server_and_start() -> Result<ApiNode> {
    let mut node = create_server()?;
    node.start_transport().await?;
    Ok(node)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Defaults --

    #[test]
    fn default_config_has_stun_servers() {
        let cfg = CairnConfig::default();
        assert_eq!(cfg.stun_servers.len(), 3);
        assert!(cfg.stun_servers[0].contains("google.com"));
        assert!(cfg.stun_servers[2].contains("cloudflare.com"));
    }

    #[test]
    fn default_config_has_transport_order() {
        let cfg = CairnConfig::default();
        assert_eq!(
            cfg.transport_preferences,
            vec![
                TransportType::Quic,
                TransportType::Tcp,
                TransportType::WsTls,
                TransportType::WebTransport,
                TransportType::CircuitRelayV2,
            ]
        );
    }

    #[test]
    fn default_reconnection_policy_values() {
        let p = ReconnectionPolicy::default();
        assert_eq!(p.connect_timeout, Duration::from_secs(30));
        assert_eq!(p.transport_timeout, Duration::from_secs(10));
        assert_eq!(p.reconnect_max_duration, Duration::from_secs(3600));
        assert_eq!(p.reconnect_backoff_initial, Duration::from_secs(1));
        assert_eq!(p.reconnect_backoff_max, Duration::from_secs(60));
        assert!((p.reconnect_backoff_factor - 2.0).abs() < f64::EPSILON);
        assert_eq!(p.rendezvous_poll_interval, Duration::from_secs(30));
        assert_eq!(p.session_expiry, Duration::from_secs(86400));
        assert_eq!(p.pairing_payload_expiry, Duration::from_secs(300));
    }

    #[test]
    fn default_mesh_settings() {
        let m = MeshSettings::default();
        assert!(!m.mesh_enabled);
        assert_eq!(m.max_hops, 3);
        assert!(!m.relay_willing);
        assert_eq!(m.relay_capacity, 10);
    }

    #[test]
    fn default_config_is_not_server_mode() {
        let cfg = CairnConfig::default();
        assert!(!cfg.server_mode);
    }

    #[test]
    fn default_config_validates() {
        CairnConfig::default().validate().unwrap();
    }

    // -- Tier presets --

    #[test]
    fn tier0_is_default() {
        let t0 = CairnConfig::tier0();
        let def = CairnConfig::default();
        assert_eq!(t0.stun_servers, def.stun_servers);
        assert!(t0.signaling_servers.is_empty());
        assert!(t0.turn_servers.is_empty());
    }

    #[test]
    fn tier1_has_signaling_and_turn() {
        let t1 = CairnConfig::tier1(
            vec!["wss://signal.example.com".into()],
            vec![TurnServer {
                url: "turn:relay.example.com:3478".into(),
                username: "user".into(),
                credential: "pass".into(),
            }],
        );
        assert_eq!(t1.signaling_servers.len(), 1);
        assert_eq!(t1.turn_servers.len(), 1);
        t1.validate().unwrap();
    }

    #[test]
    fn tier2_has_trackers_and_bootstrap() {
        let t2 = CairnConfig::tier2(
            vec!["wss://signal.example.com".into()],
            vec![],
            vec!["udp://tracker.example.com:6969".into()],
            vec!["/ip4/1.2.3.4/tcp/4001".into()],
        );
        assert_eq!(t2.tracker_urls.len(), 1);
        assert_eq!(t2.bootstrap_nodes.len(), 1);
        t2.validate().unwrap();
    }

    #[test]
    fn tier3_has_mesh_settings() {
        let t3 = CairnConfig::tier3(
            vec!["wss://signal.example.com".into()],
            vec![],
            vec![],
            vec![],
            MeshSettings {
                mesh_enabled: true,
                max_hops: 5,
                relay_willing: true,
                relay_capacity: 20,
            },
        );
        assert!(t3.mesh_settings.mesh_enabled);
        assert_eq!(t3.mesh_settings.max_hops, 5);
        t3.validate().unwrap();
    }

    // -- Server mode --

    #[test]
    fn default_server_config() {
        let cfg = CairnConfig::default_server();
        assert!(cfg.server_mode);
        assert!(cfg.mesh_settings.relay_willing);
        assert_eq!(
            cfg.reconnection_policy.session_expiry,
            Duration::from_secs(86400 * 7)
        );
        cfg.validate().unwrap();
    }

    // -- Builder --

    #[test]
    fn builder_defaults_validate() {
        let cfg = CairnConfigBuilder::new().build().unwrap();
        assert_eq!(cfg.stun_servers.len(), 3);
        assert!(!cfg.server_mode);
    }

    #[test]
    fn builder_overrides_stun_and_turn() {
        let cfg = CairnConfigBuilder::new()
            .stun_servers(vec!["stun:custom.example.com:3478".into()])
            .turn_servers(vec![TurnServer {
                url: "turn:relay.example.com:3478".into(),
                username: "u".into(),
                credential: "p".into(),
            }])
            .build()
            .unwrap();
        assert_eq!(cfg.stun_servers.len(), 1);
        assert_eq!(cfg.turn_servers.len(), 1);
    }

    #[test]
    fn builder_server_mode() {
        let cfg = CairnConfigBuilder::new().server_mode(true).build().unwrap();
        assert!(cfg.server_mode);
    }

    #[test]
    fn builder_with_manifest_config() {
        let cfg = CairnConfigBuilder::new()
            .manifest_config(ManifestConfig {
                enabled: true,
                endpoint: "https://manifest.cairn.dev/v1".into(),
                refresh_interval: Duration::from_secs(86400),
            })
            .build()
            .unwrap();
        assert!(cfg.manifest_config.is_some());
        let mc = cfg.manifest_config.unwrap();
        assert!(mc.enabled);
    }

    // -- Validation --

    #[test]
    fn validation_empty_stun_no_turn_fails() {
        let cfg = CairnConfig {
            stun_servers: vec![],
            ..CairnConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("stun_servers"));
    }

    #[test]
    fn validation_empty_stun_with_turn_ok() {
        let cfg = CairnConfig {
            stun_servers: vec![],
            turn_servers: vec![TurnServer {
                url: "turn:relay.example.com:3478".into(),
                username: "u".into(),
                credential: "p".into(),
            }],
            ..CairnConfig::default()
        };
        cfg.validate().unwrap();
    }

    #[test]
    fn validation_backoff_factor_le_one_fails() {
        let cfg = CairnConfig {
            reconnection_policy: ReconnectionPolicy {
                reconnect_backoff_factor: 1.0,
                ..ReconnectionPolicy::default()
            },
            ..CairnConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("backoff_factor"));
    }

    #[test]
    fn validation_max_hops_zero_fails() {
        let cfg = CairnConfig {
            mesh_settings: MeshSettings {
                max_hops: 0,
                ..MeshSettings::default()
            },
            ..CairnConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("max_hops"));
    }

    #[test]
    fn validation_max_hops_eleven_fails() {
        let cfg = CairnConfig {
            mesh_settings: MeshSettings {
                max_hops: 11,
                ..MeshSettings::default()
            },
            ..CairnConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("max_hops"));
    }

    #[test]
    fn validation_manifest_http_fails() {
        let cfg = CairnConfig {
            manifest_config: Some(ManifestConfig {
                enabled: true,
                endpoint: "http://insecure.example.com".into(),
                refresh_interval: Duration::from_secs(86400),
            }),
            ..CairnConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("HTTPS"));
    }

    #[test]
    fn validation_manifest_disabled_http_ok() {
        let cfg = CairnConfig {
            manifest_config: Some(ManifestConfig {
                enabled: false,
                endpoint: "http://whatever".into(),
                refresh_interval: Duration::from_secs(86400),
            }),
            ..CairnConfig::default()
        };
        cfg.validate().unwrap();
    }

    // -- Builder validation failures propagate --

    #[test]
    fn builder_invalid_backoff_factor() {
        let err = CairnConfigBuilder::new()
            .reconnection_policy(ReconnectionPolicy {
                reconnect_backoff_factor: 0.5,
                ..ReconnectionPolicy::default()
            })
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("backoff_factor"));
    }

    // -- Factory functions --

    #[test]
    fn create_returns_node() {
        let node = create().unwrap();
        assert!(!node.config().server_mode);
    }

    #[test]
    fn create_with_config_validates() {
        let bad = CairnConfig {
            stun_servers: vec![],
            ..CairnConfig::default()
        };
        assert!(create_with_config(bad).is_err());
    }

    #[test]
    fn create_server_returns_server_node() {
        let node = create_server().unwrap();
        assert!(node.config().server_mode);
    }

    #[test]
    fn create_server_with_config_forces_server_mode() {
        let cfg = CairnConfig {
            server_mode: false,
            ..Default::default()
        };
        let node = create_server_with_config(cfg).unwrap();
        assert!(node.config().server_mode);
    }

    // -- Manifest signature verification --

    #[test]
    fn verify_manifest_rejects_invalid_json() {
        let result = verify_manifest("not json");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid manifest JSON"));
    }

    #[test]
    fn verify_manifest_rejects_bad_signature() {
        // Valid JSON but garbage signature -- should fail verification.
        let json = r#"{"version":1,"stun_servers":[],"tracker_urls":[],"bootstrap_nodes":[],"signature":"AAAA"}"#;
        let result = verify_manifest(json);
        assert!(result.is_err());
    }

    // -- Base64 decoder --

    #[test]
    fn base64_decode_roundtrip() {
        // "SGVsbG8=" -> "Hello"
        let decoded = base64_decode("SGVsbG8=").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn base64_decode_empty() {
        let decoded = base64_decode("").unwrap();
        assert!(decoded.is_empty());
    }
}
