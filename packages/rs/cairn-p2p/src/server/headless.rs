//! Headless pairing for server-mode peers (spec 10.5).
//!
//! Server-mode peers run without display, keyboard, or camera. This module
//! provides workflows for pairing via four mechanisms:
//!
//! | Mechanism      | Headless Workflow |
//! |----------------|-------------------|
//! | Pre-shared key | Config file or `CAIRN_PSK` env var. |
//! | Pin code       | Server generates pin on CLI/logs; user enters on device. |
//! | Pairing link   | Server outputs `cairn://pair?...` URI on CLI. |
//! | QR code        | Terminal ASCII art + PNG bytes for management API. |
//!
//! SAS verification is excluded — it requires a display for visual comparison.

use std::io::Cursor;
use std::time::{Duration, Instant, SystemTime};

use image::Luma;
use qrcode::render::unicode::Dense1x2;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::identity::PeerId;
use crate::pairing::mechanisms::{
    PairingLinkMechanism, PairingMechanism, PairingPayload, PinCodeMechanism, PskError,
    PskMechanism, QrCodeMechanism,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default validity window for headless pairing payloads (5 minutes).
pub const DEFAULT_VALIDITY_WINDOW: Duration = Duration::from_secs(300);

/// Environment variable name for pre-shared key.
pub const PSK_ENV_VAR: &str = "CAIRN_PSK";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors specific to headless pairing operations.
#[derive(Debug, thiserror::Error)]
pub enum HeadlessPairingError {
    #[error("pairing mechanism error: {0}")]
    MechanismError(String),

    #[error("PSK error: {0}")]
    PskError(#[from] PskError),

    #[error("pairing payload has expired")]
    Expired,

    #[error("QR code generation failed: {0}")]
    QrGenerationFailed(String),

    #[error("PNG encoding failed: {0}")]
    PngEncodingFailed(String),

    #[error("PSK not configured (set {PSK_ENV_VAR} env var or provide via config)")]
    PskNotConfigured,
}

// ---------------------------------------------------------------------------
// HeadlessPairingMethod
// ---------------------------------------------------------------------------

/// A generated headless pairing method with its payload and expiration.
#[derive(Debug, Clone)]
pub enum HeadlessPairingMethod {
    /// PSK loaded from config file or `CAIRN_PSK` env var.
    PreSharedKey {
        /// The raw PSK bytes (validated for minimum entropy).
        psk: Vec<u8>,
    },

    /// Pin code generated and logged/printed.
    PinCode {
        /// The formatted pin code (e.g., `XXXX-XXXX`).
        pin: String,
        /// When this pin code expires.
        expires_at: Instant,
    },

    /// `cairn://pair?...` URI for out-of-band transfer.
    PairingLink {
        /// The full pairing URI.
        uri: String,
        /// When this link expires.
        expires_at: Instant,
    },

    /// QR code in both ASCII art and PNG formats.
    QrCode {
        /// Unicode block-character art for terminal display.
        ascii_art: String,
        /// PNG-encoded image bytes for management API.
        png_bytes: Vec<u8>,
        /// When this QR code expires.
        expires_at: Instant,
    },
}

impl HeadlessPairingMethod {
    /// Check whether this method's payload has expired.
    pub fn is_expired(&self) -> bool {
        match self {
            Self::PreSharedKey { .. } => false, // PSK does not expire
            Self::PinCode { expires_at, .. }
            | Self::PairingLink { expires_at, .. }
            | Self::QrCode { expires_at, .. } => Instant::now() >= *expires_at,
        }
    }
}

// ---------------------------------------------------------------------------
// HeadlessPairing
// ---------------------------------------------------------------------------

/// Headless pairing controller for server-mode peers (spec 10.5).
///
/// Generates pairing payloads using mechanisms that work without a display,
/// keyboard, or camera. All generated payloads expire after `validity_window`
/// (default: 5 minutes) as a defense-in-depth measure.
///
/// SAS verification is excluded — it requires a display for visual comparison.
#[derive(Debug, Clone)]
pub struct HeadlessPairing {
    /// Validity window for pairing payloads (default: 5 minutes).
    pub validity_window: Duration,
}

impl Default for HeadlessPairing {
    fn default() -> Self {
        Self {
            validity_window: DEFAULT_VALIDITY_WINDOW,
        }
    }
}

impl HeadlessPairing {
    /// Create a new headless pairing controller with a custom validity window.
    pub fn new(validity_window: Duration) -> Self {
        Self { validity_window }
    }

    /// Alias for `new` — create with a custom validity window.
    pub fn with_validity_window(validity_window: Duration) -> Self {
        Self::new(validity_window)
    }

    /// Generate a pre-shared key pairing method.
    ///
    /// Loads the PSK from the provided bytes or the `CAIRN_PSK` environment
    /// variable. Validates minimum entropy (128 bits).
    pub fn generate_psk(
        &self,
        psk: Option<&[u8]>,
    ) -> Result<HeadlessPairingMethod, HeadlessPairingError> {
        let psk_bytes = match psk {
            Some(bytes) => bytes.to_vec(),
            None => {
                let env_val = std::env::var(PSK_ENV_VAR)
                    .map_err(|_| HeadlessPairingError::PskNotConfigured)?;
                env_val.into_bytes()
            }
        };

        // Validate entropy
        let mechanism = PskMechanism::new();
        mechanism.validate_entropy(&psk_bytes)?;

        info!("headless pairing: PSK method configured");

        Ok(HeadlessPairingMethod::PreSharedKey { psk: psk_bytes })
    }

    /// Create a pre-shared key pairing method from raw bytes (no validation).
    pub fn from_psk(psk: Vec<u8>) -> HeadlessPairingMethod {
        HeadlessPairingMethod::PreSharedKey { psk }
    }

    /// Generate a pin code pairing method.
    ///
    /// The pin is logged/printed on the server CLI; the user enters it on
    /// their device. The pin expires after `validity_window`.
    pub fn generate_pin(
        &self,
        payload: &PairingPayload,
    ) -> Result<HeadlessPairingMethod, HeadlessPairingError> {
        let mechanism = PinCodeMechanism::with_ttl(self.validity_window);
        let raw = mechanism
            .generate_payload(payload)
            .map_err(|e| HeadlessPairingError::MechanismError(e.to_string()))?;
        let pin = String::from_utf8(raw)
            .map_err(|e| HeadlessPairingError::MechanismError(e.to_string()))?;

        let expires_at = Instant::now() + self.validity_window;

        info!(
            pin = %pin,
            expires_in_secs = self.validity_window.as_secs(),
            "headless pairing: pin code generated — enter this on your device"
        );

        Ok(HeadlessPairingMethod::PinCode { pin, expires_at })
    }

    /// Generate a pairing link method.
    ///
    /// The `cairn://pair?...` URI is output on the server CLI; the user
    /// copies it via SSH, clipboard, or management interface.
    pub fn generate_link(
        &self,
        payload: &PairingPayload,
    ) -> Result<HeadlessPairingMethod, HeadlessPairingError> {
        let mechanism = PairingLinkMechanism::new("cairn", self.validity_window);
        let raw = mechanism
            .generate_payload(payload)
            .map_err(|e| HeadlessPairingError::MechanismError(e.to_string()))?;
        let uri = String::from_utf8(raw)
            .map_err(|e| HeadlessPairingError::MechanismError(e.to_string()))?;

        let expires_at = Instant::now() + self.validity_window;

        info!(
            uri = %uri,
            expires_in_secs = self.validity_window.as_secs(),
            "headless pairing: pairing link generated — copy to your device"
        );

        Ok(HeadlessPairingMethod::PairingLink { uri, expires_at })
    }

    /// Generate a QR code pairing method.
    ///
    /// Produces both Unicode block-character art for terminal display and
    /// PNG bytes for the management HTTP endpoint.
    pub fn generate_qr(
        &self,
        payload: &PairingPayload,
    ) -> Result<HeadlessPairingMethod, HeadlessPairingError> {
        let mechanism = QrCodeMechanism::with_ttl(self.validity_window);

        // Generate CBOR payload through the mechanism
        let raw = mechanism
            .generate_payload(payload)
            .map_err(|e| HeadlessPairingError::MechanismError(e.to_string()))?;

        let ascii_art = qr_to_ascii(&raw)?;
        let png_bytes = qr_to_png(&raw)?;

        let expires_at = Instant::now() + self.validity_window;

        info!(
            expires_in_secs = self.validity_window.as_secs(),
            png_size_bytes = png_bytes.len(),
            "headless pairing: QR code generated — scan with your device"
        );

        Ok(HeadlessPairingMethod::QrCode {
            ascii_art,
            png_bytes,
            expires_at,
        })
    }

    /// Validate an incoming pairing payload against the validity window.
    ///
    /// Returns `Ok(())` if the payload is still valid, `Err` if expired.
    pub fn validate_payload(&self, payload: &PairingPayload) -> Result<(), HeadlessPairingError> {
        let now_unix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if payload.is_expired(now_unix) {
            warn!("headless pairing: rejected expired pairing payload");
            return Err(HeadlessPairingError::Expired);
        }

        Ok(())
    }

    /// Check whether SAS verification is available in headless mode.
    ///
    /// Always returns `false` — SAS requires a display for visual comparison.
    pub fn sas_available(&self) -> bool {
        false
    }

    /// List the mechanisms supported in headless mode.
    pub fn supported_mechanisms(&self) -> Vec<&'static str> {
        vec!["psk", "pin", "link", "qr"]
    }
}

// ---------------------------------------------------------------------------
// QR rendering helpers
// ---------------------------------------------------------------------------

/// Render QR code data as Unicode block-character art for terminal display.
fn qr_to_ascii(data: &[u8]) -> Result<String, HeadlessPairingError> {
    let code = qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::M)
        .map_err(|e| HeadlessPairingError::QrGenerationFailed(e.to_string()))?;

    Ok(code.render::<Dense1x2>().quiet_zone(true).build())
}

/// Render QR code data as a PNG image, returning the encoded bytes.
fn qr_to_png(data: &[u8]) -> Result<Vec<u8>, HeadlessPairingError> {
    let code = qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::M)
        .map_err(|e| HeadlessPairingError::QrGenerationFailed(e.to_string()))?;

    let image_buf = code
        .render::<Luma<u8>>()
        .quiet_zone(true)
        .min_dimensions(256, 256)
        .build();

    let mut png_bytes: Vec<u8> = Vec::new();
    image_buf
        .write_to(&mut Cursor::new(&mut png_bytes), image::ImageFormat::Png)
        .map_err(|e| HeadlessPairingError::PngEncodingFailed(e.to_string()))?;

    Ok(png_bytes)
}

// ---------------------------------------------------------------------------
// PersonalRelayConfig (spec 10.4)
// ---------------------------------------------------------------------------

/// Personal relay configuration for server-mode peers.
///
/// A server-mode peer with a public IP relays traffic between paired peers
/// who cannot connect directly. This leverages the mesh relay mechanism
/// with the server as the natural relay hub.
///
/// Key difference from companion TURN relay: the personal relay **only serves
/// paired peers**, limiting abuse surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalRelayConfig {
    /// Whether the server is willing to relay traffic.
    pub relay_willing: bool,

    /// Maximum number of concurrent relay sessions.
    pub relay_capacity: u32,

    /// Set of peer IDs allowed to use this relay (paired peers only).
    /// If empty, all paired peers are allowed.
    pub allowed_peers: Vec<PeerId>,
}

impl Default for PersonalRelayConfig {
    fn default() -> Self {
        Self {
            relay_willing: true,
            relay_capacity: 100,
            allowed_peers: Vec::new(),
        }
    }
}

impl PersonalRelayConfig {
    /// Check whether a peer is allowed to use this relay.
    ///
    /// If `allowed_peers` is empty, all peers are allowed (the caller
    /// should still verify that the peer is paired).
    pub fn is_peer_allowed(&self, peer_id: &PeerId) -> bool {
        if self.allowed_peers.is_empty() {
            return true; // Caller verifies pairing
        }
        self.allowed_peers.contains(peer_id)
    }
}

// ---------------------------------------------------------------------------
// Multi-device sync (spec 10.6)
// ---------------------------------------------------------------------------

/// Per-peer synchronization state tracked by the server node.
///
/// Used for multi-device sync: the server tracks what each peer has seen
/// so that when a device reconnects, it receives everything it missed.
///
/// ```text
/// Phone <--> Server Node <--> Laptop
///                 |
///              Tablet
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSyncState {
    /// The peer being tracked.
    pub peer_id: PeerId,

    /// The last sequence number this peer has acknowledged.
    pub last_seen_sequence: u64,

    /// Number of messages pending delivery to this peer.
    pub pending_deliveries: u32,

    /// When this peer was last connected (None if never seen).
    pub last_connected: Option<SystemTime>,
}

impl PeerSyncState {
    /// Create a new sync state for a peer with no history.
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            last_seen_sequence: 0,
            pending_deliveries: 0,
            last_connected: None,
        }
    }

    /// Record that the peer has connected.
    pub fn mark_connected(&mut self) {
        self.last_connected = Some(SystemTime::now());
    }

    /// Update the last-seen sequence number after delivering messages.
    ///
    /// Decrements pending deliveries by the number of messages delivered
    /// (i.e., the gap between the old and new sequence numbers).
    pub fn advance_sequence(&mut self, seq: u64) {
        if seq > self.last_seen_sequence {
            let delivered = (seq - self.last_seen_sequence) as u32;
            self.last_seen_sequence = seq;
            self.pending_deliveries = self.pending_deliveries.saturating_sub(delivered);
        }
    }

    /// Increment the pending delivery count by one.
    pub fn enqueue_delivery(&mut self) {
        self.pending_deliveries = self.pending_deliveries.saturating_add(1);
    }

    /// Increment the pending delivery count by a given amount.
    pub fn add_pending(&mut self, count: u32) {
        self.pending_deliveries = self.pending_deliveries.saturating_add(count);
    }

    /// Decrement the pending delivery count after successful delivery.
    pub fn acknowledge_delivery(&mut self, count: u32) {
        self.pending_deliveries = self.pending_deliveries.saturating_sub(count);
    }
}

// ---------------------------------------------------------------------------
// Resource accounting (spec 10.7)
// ---------------------------------------------------------------------------

/// Per-peer resource metrics tracked by the server.
///
/// Exposed via the management API and structured tracing events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerMetrics {
    /// The peer being tracked.
    pub peer_id: PeerId,

    /// Total bytes relayed for this peer.
    pub bytes_relayed: u64,

    /// Total bytes stored (in store-and-forward queue) for this peer.
    pub bytes_stored: u64,
}

impl PeerMetrics {
    /// Create new zero-value metrics for a peer.
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            bytes_relayed: 0,
            bytes_stored: 0,
        }
    }

    /// Record bytes relayed for this peer.
    pub fn record_relay(&mut self, bytes: u64) {
        self.bytes_relayed = self.bytes_relayed.saturating_add(bytes);
        tracing::debug!(
            peer_id = %self.peer_id,
            bytes_relayed = self.bytes_relayed,
            "relay bytes recorded"
        );
    }

    /// Record bytes stored for this peer.
    pub fn record_store(&mut self, bytes: u64) {
        self.bytes_stored = self.bytes_stored.saturating_add(bytes);
        tracing::debug!(
            peer_id = %self.peer_id,
            bytes_stored = self.bytes_stored,
            "store bytes recorded"
        );
    }

    /// Decrease stored bytes after delivery/purge.
    pub fn release_stored(&mut self, bytes: u64) {
        self.bytes_stored = self.bytes_stored.saturating_sub(bytes);
    }
}

/// Per-peer resource quotas. Configurable, disabled by default.
///
/// When a quota is `None`, that resource is unlimited.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerQuota {
    /// Maximum stored messages in the store-and-forward queue.
    pub max_stored_messages: Option<u32>,

    /// Maximum relay bandwidth in bytes per second.
    pub max_relay_bandwidth_bps: Option<u64>,
}

impl PeerQuota {
    /// Check whether the stored message count is within quota.
    pub fn check_store_quota(&self, current_messages: u32) -> bool {
        match self.max_stored_messages {
            Some(max) => current_messages < max,
            None => true,
        }
    }

    /// Check whether the relay bandwidth is within quota.
    pub fn check_relay_quota(&self, current_bps: u64) -> bool {
        match self.max_relay_bandwidth_bps {
            Some(max) => current_bps <= max,
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;
    use crate::pairing::mechanisms::ConnectionHint;

    fn test_peer_id() -> PeerId {
        LocalIdentity::generate().peer_id().clone()
    }

    fn make_peer(seed: u8) -> PeerId {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        PeerId::from_public_key(&key.verifying_key())
    }

    fn test_payload() -> PairingPayload {
        PairingPayload {
            peer_id: test_peer_id(),
            nonce: [0u8; 16],
            pake_credential: vec![0u8; 32],
            connection_hints: None,
            created_at: 1000,
            expires_at: 1300,
        }
    }

    fn make_payload(expires_at: u64) -> PairingPayload {
        PairingPayload {
            peer_id: test_peer_id(),
            nonce: [0x42; 16],
            pake_credential: vec![0xAB; 32],
            connection_hints: Some(vec![ConnectionHint {
                hint_type: "rendezvous".into(),
                value: "relay.example.com:9090".into(),
            }]),
            created_at: 1700000000,
            expires_at,
        }
    }

    // -- HeadlessPairing defaults --

    #[test]
    fn headless_pairing_default_validity() {
        let hp = HeadlessPairing::default();
        assert_eq!(hp.validity_window, DEFAULT_VALIDITY_WINDOW);
    }

    #[test]
    fn custom_validity_window() {
        let hp = HeadlessPairing::with_validity_window(Duration::from_secs(60));
        assert_eq!(hp.validity_window, Duration::from_secs(60));
    }

    #[test]
    fn new_and_with_validity_window_equivalent() {
        let a = HeadlessPairing::new(Duration::from_secs(120));
        let b = HeadlessPairing::with_validity_window(Duration::from_secs(120));
        assert_eq!(a.validity_window, b.validity_window);
    }

    #[test]
    fn sas_not_available_in_headless_mode() {
        let hp = HeadlessPairing::default();
        assert!(!hp.sas_available());
    }

    #[test]
    fn supported_mechanisms_list() {
        let hp = HeadlessPairing::default();
        let mechs = hp.supported_mechanisms();
        assert_eq!(mechs.len(), 4);
        assert!(mechs.contains(&"psk"));
        assert!(mechs.contains(&"pin"));
        assert!(mechs.contains(&"link"));
        assert!(mechs.contains(&"qr"));
        // SAS should NOT be in the list
        assert!(!mechs.contains(&"sas"));
    }

    // -- PSK --

    #[test]
    fn generate_psk_with_valid_key() {
        let hp = HeadlessPairing::default();
        let key = vec![0xAB; 16]; // 128 bits
        let method = hp.generate_psk(Some(&key)).unwrap();
        match method {
            HeadlessPairingMethod::PreSharedKey { psk } => {
                assert_eq!(psk, key);
            }
            _ => panic!("expected PreSharedKey variant"),
        }
    }

    #[test]
    fn generate_psk_rejects_short_key() {
        let hp = HeadlessPairing::default();
        let key = vec![0xAB; 8]; // 64 bits < 128 bits
        let result = hp.generate_psk(Some(&key));
        assert!(result.is_err());
    }

    #[test]
    fn generate_psk_from_env_var() {
        let hp = HeadlessPairing::default();
        let key = "A_VERY_LONG_SECRET_KEY_FOR_TESTING_PSK";
        // SAFETY: test is single-threaded for this specific env var
        unsafe { std::env::set_var(PSK_ENV_VAR, key) };
        let method = hp.generate_psk(None).unwrap();
        unsafe { std::env::remove_var(PSK_ENV_VAR) };
        match method {
            HeadlessPairingMethod::PreSharedKey { psk } => {
                assert_eq!(psk, key.as_bytes());
            }
            _ => panic!("expected PreSharedKey variant"),
        }
    }

    #[test]
    fn generate_psk_env_var_not_set() {
        let hp = HeadlessPairing::default();
        // SAFETY: test is single-threaded for this specific env var
        unsafe { std::env::remove_var(PSK_ENV_VAR) };
        let result = hp.generate_psk(None);
        assert!(matches!(
            result,
            Err(HeadlessPairingError::PskNotConfigured)
        ));
    }

    #[test]
    fn from_psk_creates_psk_variant() {
        let method = HeadlessPairing::from_psk(vec![0u8; 32]);
        match method {
            HeadlessPairingMethod::PreSharedKey { psk } => {
                assert_eq!(psk.len(), 32);
            }
            _ => panic!("expected PreSharedKey variant"),
        }
    }

    #[test]
    fn psk_never_expires() {
        let method = HeadlessPairing::from_psk(vec![0u8; 32]);
        assert!(!method.is_expired());
    }

    // -- Pin code --

    #[test]
    fn generate_pin_returns_formatted_pin() {
        let hp = HeadlessPairing::default();
        let method = hp.generate_pin(&test_payload()).unwrap();
        match method {
            HeadlessPairingMethod::PinCode { pin, .. } => {
                assert_eq!(pin.len(), 9); // XXXX-XXXX
                assert_eq!(pin.as_bytes()[4], b'-');
            }
            _ => panic!("expected PinCode"),
        }
    }

    #[test]
    fn pin_not_expired_immediately() {
        let hp = HeadlessPairing::default();
        let method = hp.generate_pin(&test_payload()).unwrap();
        assert!(!method.is_expired());
    }

    // -- Pairing link --

    #[test]
    fn generate_link_returns_cairn_uri() {
        let hp = HeadlessPairing::default();
        let method = hp.generate_link(&test_payload()).unwrap();
        match method {
            HeadlessPairingMethod::PairingLink { uri, .. } => {
                assert!(uri.starts_with("cairn://pair?"));
                assert!(uri.contains("pid="));
                assert!(uri.contains("nonce="));
                assert!(uri.contains("pake="));
            }
            _ => panic!("expected PairingLink"),
        }
    }

    #[test]
    fn link_not_expired_immediately() {
        let hp = HeadlessPairing::default();
        let method = hp.generate_link(&test_payload()).unwrap();
        assert!(!method.is_expired());
    }

    // -- QR code --

    #[test]
    fn generate_qr_returns_ascii_and_png() {
        let hp = HeadlessPairing::default();
        let method = hp.generate_qr(&test_payload()).unwrap();
        match method {
            HeadlessPairingMethod::QrCode {
                ascii_art,
                png_bytes,
                ..
            } => {
                assert!(!ascii_art.is_empty());
                // PNG magic bytes
                assert!(png_bytes.len() > 8);
                assert_eq!(&png_bytes[1..4], b"PNG");
            }
            _ => panic!("expected QrCode"),
        }
    }

    #[test]
    fn qr_not_expired_immediately() {
        let hp = HeadlessPairing::default();
        let method = hp.generate_qr(&test_payload()).unwrap();
        assert!(!method.is_expired());
    }

    #[test]
    fn qr_png_has_reasonable_size() {
        let hp = HeadlessPairing::default();
        let method = hp.generate_qr(&test_payload()).unwrap();
        if let HeadlessPairingMethod::QrCode { png_bytes, .. } = method {
            // PNG should be non-trivial for a 256x256+ image
            assert!(png_bytes.len() > 100);
        }
    }

    // -- Payload validation --

    #[test]
    fn validate_payload_accepts_valid() {
        let hp = HeadlessPairing::default();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let payload = make_payload(now + 300);
        assert!(hp.validate_payload(&payload).is_ok());
    }

    #[test]
    fn validate_payload_rejects_expired() {
        let hp = HeadlessPairing::default();
        let payload = make_payload(1000); // expired long ago
        assert!(matches!(
            hp.validate_payload(&payload),
            Err(HeadlessPairingError::Expired)
        ));
    }

    // -- PersonalRelayConfig --

    #[test]
    fn relay_config_defaults() {
        let cfg = PersonalRelayConfig::default();
        assert!(cfg.relay_willing);
        assert_eq!(cfg.relay_capacity, 100);
        assert!(cfg.allowed_peers.is_empty());
    }

    #[test]
    fn relay_allows_all_peers_when_list_empty() {
        let cfg = PersonalRelayConfig::default();
        let peer = make_peer(1);
        assert!(cfg.is_peer_allowed(&peer));
    }

    #[test]
    fn relay_restricts_to_allowed_peers() {
        let peer_a = make_peer(1);
        let peer_b = make_peer(2);
        let peer_c = make_peer(3);
        let cfg = PersonalRelayConfig {
            relay_willing: true,
            relay_capacity: 10,
            allowed_peers: vec![peer_a.clone(), peer_b.clone()],
        };
        assert!(cfg.is_peer_allowed(&peer_a));
        assert!(cfg.is_peer_allowed(&peer_b));
        assert!(!cfg.is_peer_allowed(&peer_c));
    }

    #[test]
    fn relay_config_serde_roundtrip() {
        let cfg = PersonalRelayConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: PersonalRelayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.relay_willing, cfg.relay_willing);
        assert_eq!(restored.relay_capacity, cfg.relay_capacity);
    }

    // -- PeerSyncState --

    #[test]
    fn peer_sync_state_new_is_zeroed() {
        let peer = make_peer(1);
        let state = PeerSyncState::new(peer.clone());
        assert_eq!(state.peer_id, peer);
        assert_eq!(state.last_seen_sequence, 0);
        assert_eq!(state.pending_deliveries, 0);
        assert!(state.last_connected.is_none());
    }

    #[test]
    fn peer_sync_state_lifecycle() {
        let mut state = PeerSyncState::new(test_peer_id());
        assert_eq!(state.pending_deliveries, 0);
        assert!(state.last_connected.is_none());

        state.mark_connected();
        assert!(state.last_connected.is_some());

        state.enqueue_delivery();
        state.enqueue_delivery();
        state.enqueue_delivery();
        assert_eq!(state.pending_deliveries, 3);

        state.advance_sequence(2);
        assert_eq!(state.last_seen_sequence, 2);
        assert_eq!(state.pending_deliveries, 1);
    }

    #[test]
    fn peer_sync_state_advance_does_not_go_backwards() {
        let mut state = PeerSyncState::new(make_peer(1));
        state.advance_sequence(42);
        assert_eq!(state.last_seen_sequence, 42);
        // Should not go backwards
        state.advance_sequence(10);
        assert_eq!(state.last_seen_sequence, 42);
    }

    #[test]
    fn peer_sync_state_add_pending_and_acknowledge() {
        let mut state = PeerSyncState::new(make_peer(1));
        state.add_pending(5);
        assert_eq!(state.pending_deliveries, 5);
        state.acknowledge_delivery(3);
        assert_eq!(state.pending_deliveries, 2);
        // Cannot go below zero
        state.acknowledge_delivery(10);
        assert_eq!(state.pending_deliveries, 0);
    }

    #[test]
    fn peer_sync_state_pending_saturates() {
        let mut state = PeerSyncState::new(make_peer(1));
        state.add_pending(u32::MAX);
        state.add_pending(1);
        assert_eq!(state.pending_deliveries, u32::MAX);
    }

    #[test]
    fn peer_sync_state_enqueue_saturates() {
        let mut state = PeerSyncState::new(make_peer(1));
        state.pending_deliveries = u32::MAX;
        state.enqueue_delivery();
        assert_eq!(state.pending_deliveries, u32::MAX);
    }

    #[test]
    fn peer_sync_serde_roundtrip() {
        let mut state = PeerSyncState::new(test_peer_id());
        state.advance_sequence(100);
        state.add_pending(5);
        state.mark_connected();

        let json = serde_json::to_string(&state).unwrap();
        let restored: PeerSyncState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.last_seen_sequence, 100);
        assert!(restored.last_connected.is_some());
    }

    // -- PeerMetrics --

    #[test]
    fn peer_metrics_new_is_zeroed() {
        let peer = make_peer(1);
        let metrics = PeerMetrics::new(peer.clone());
        assert_eq!(metrics.peer_id, peer);
        assert_eq!(metrics.bytes_relayed, 0);
        assert_eq!(metrics.bytes_stored, 0);
    }

    #[test]
    fn peer_metrics_accounting() {
        let mut m = PeerMetrics::new(test_peer_id());
        m.record_relay(1024);
        m.record_store(512);
        assert_eq!(m.bytes_relayed, 1024);
        assert_eq!(m.bytes_stored, 512);
        m.record_relay(u64::MAX);
        assert_eq!(m.bytes_relayed, u64::MAX);
    }

    #[test]
    fn peer_metrics_release_stored() {
        let mut m = PeerMetrics::new(make_peer(1));
        m.record_store(2048);
        m.release_stored(1024);
        assert_eq!(m.bytes_stored, 1024);
        // Cannot go below zero
        m.release_stored(5000);
        assert_eq!(m.bytes_stored, 0);
    }

    #[test]
    fn peer_metrics_serde_roundtrip() {
        let mut m = PeerMetrics::new(make_peer(1));
        m.record_relay(1000);
        m.record_store(2048);

        let json = serde_json::to_string(&m).unwrap();
        let restored: PeerMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.bytes_relayed, 1000);
        assert_eq!(restored.bytes_stored, 2048);
    }

    // -- PeerQuota --

    #[test]
    fn peer_quota_default_disabled() {
        let q = PeerQuota::default();
        assert!(q.max_stored_messages.is_none());
        assert!(q.max_relay_bandwidth_bps.is_none());
    }

    #[test]
    fn quota_check_store_unlimited() {
        let quota = PeerQuota::default();
        assert!(quota.check_store_quota(1_000_000));
    }

    #[test]
    fn quota_check_store_within_limit() {
        let quota = PeerQuota {
            max_stored_messages: Some(100),
            ..PeerQuota::default()
        };
        assert!(quota.check_store_quota(99));
        assert!(!quota.check_store_quota(100));
        assert!(!quota.check_store_quota(101));
    }

    #[test]
    fn quota_check_relay_unlimited() {
        let quota = PeerQuota::default();
        assert!(quota.check_relay_quota(u64::MAX));
    }

    #[test]
    fn quota_check_relay_within_limit() {
        let quota = PeerQuota {
            max_relay_bandwidth_bps: Some(1_000_000),
            ..PeerQuota::default()
        };
        assert!(quota.check_relay_quota(999_999));
        assert!(quota.check_relay_quota(1_000_000));
        assert!(!quota.check_relay_quota(1_000_001));
    }

    #[test]
    fn quota_serde_roundtrip() {
        let quota = PeerQuota {
            max_stored_messages: Some(500),
            max_relay_bandwidth_bps: Some(1_000_000),
        };
        let json = serde_json::to_string(&quota).unwrap();
        let restored: PeerQuota = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.max_stored_messages, Some(500));
        assert_eq!(restored.max_relay_bandwidth_bps, Some(1_000_000));
    }

    // -- Error display --

    #[test]
    fn error_display_mechanism() {
        let e = HeadlessPairingError::MechanismError("test".into());
        assert!(e.to_string().contains("test"));
    }

    #[test]
    fn error_display_psk_not_configured() {
        let e = HeadlessPairingError::PskNotConfigured;
        assert!(e.to_string().contains("CAIRN_PSK"));
    }

    #[test]
    fn error_display_expired() {
        let e = HeadlessPairingError::Expired;
        assert!(e.to_string().contains("expired"));
    }

    #[test]
    fn error_display_qr_generation_failed() {
        let e = HeadlessPairingError::QrGenerationFailed("bad data".into());
        assert!(e.to_string().contains("bad data"));
    }

    #[test]
    fn error_display_png_encoding_failed() {
        let e = HeadlessPairingError::PngEncodingFailed("codec error".into());
        assert!(e.to_string().contains("codec error"));
    }
}
