//! Server-mode management API (spec 10.5, 10.7).
//!
//! Opt-in REST/JSON HTTP API for server-mode peers. Bound to `127.0.0.1:9090`
//! by default with bearer token authentication. Exposes paired peers list,
//! queue depths, relay stats, connection health, and pairing QR generation.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::identity::PeerId;
use crate::pairing::mechanisms::PairingPayload;
use crate::server::headless::HeadlessPairing;
use crate::server::store_forward::MessageQueue;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Management API configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementConfig {
    /// Whether the management API is enabled.
    pub enabled: bool,
    /// Bind address. Default: `127.0.0.1`.
    pub bind_address: IpAddr,
    /// Port. Default: `9090`.
    pub port: u16,
    /// Bearer token for authentication.
    pub auth_token: String,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port: 9090,
            auth_token: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// Information about a paired peer, used by the management API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub name: String,
    pub connected: bool,
    pub last_seen: Option<String>,
}

/// Per-peer relay statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRelayStats {
    pub peer_id: PeerId,
    pub bytes_relayed: u64,
    pub active_streams: u32,
}

/// Relay statistics overview.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayStats {
    pub active_connections: u32,
    pub per_peer: Vec<PeerRelayStats>,
}

/// Shared state accessible by all management API handlers.
pub struct ManagementState {
    /// Bearer token (stored for constant-time comparison).
    pub auth_token: Vec<u8>,
    /// Paired peers information.
    pub peers: RwLock<Vec<PeerInfo>>,
    /// Store-and-forward message queues.
    pub message_queue: RwLock<MessageQueue>,
    /// Relay statistics.
    pub relay_stats: RwLock<RelayStats>,
    /// Server start time for uptime calculation.
    pub started_at: Instant,
    /// Headless pairing controller for QR code generation.
    pub headless_pairing: Option<HeadlessPairing>,
    /// Local node's peer ID for pairing payload generation.
    pub local_peer_id: Option<PeerId>,
}

impl ManagementState {
    /// Create a new management state with the given auth token.
    pub fn new(auth_token: String) -> Self {
        Self {
            auth_token: auth_token.into_bytes(),
            peers: RwLock::new(Vec::new()),
            message_queue: RwLock::new(MessageQueue::new()),
            relay_stats: RwLock::new(RelayStats::default()),
            started_at: Instant::now(),
            headless_pairing: None,
            local_peer_id: None,
        }
    }

    /// Create a management state configured for pairing QR code generation.
    pub fn with_pairing(auth_token: String, peer_id: PeerId, headless: HeadlessPairing) -> Self {
        Self {
            auth_token: auth_token.into_bytes(),
            peers: RwLock::new(Vec::new()),
            message_queue: RwLock::new(MessageQueue::new()),
            relay_stats: RwLock::new(RelayStats::default()),
            started_at: Instant::now(),
            headless_pairing: Some(headless),
            local_peer_id: Some(peer_id),
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Management API errors.
#[derive(Debug, thiserror::Error)]
pub enum ManagementError {
    #[error("failed to bind management API: {0}")]
    BindError(#[from] std::io::Error),

    #[error("management API auth token is empty")]
    EmptyToken,
}

// ---------------------------------------------------------------------------
// Bearer token authentication middleware
// ---------------------------------------------------------------------------

/// Axum middleware that validates `Authorization: Bearer <token>` headers
/// using constant-time comparison to prevent timing attacks.
async fn auth_middleware(
    State(state): State<Arc<ManagementState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match token {
        Some(provided) => {
            let provided_bytes = provided.as_bytes();
            let expected_bytes = &state.auth_token;

            // Constant-time comparison: first check lengths, then compare bytes.
            // Both checks use constant-time operations.
            let len_eq = (provided_bytes.len() as u64).ct_eq(&(expected_bytes.len() as u64));
            let bytes_eq = if provided_bytes.len() == expected_bytes.len() {
                provided_bytes.ct_eq(expected_bytes)
            } else {
                // Compare against expected to avoid timing leak on length mismatch.
                // The result will be discarded due to len_eq being false.
                expected_bytes.ct_eq(expected_bytes) // always true, but constant-time
            };

            if (len_eq & bytes_eq).into() {
                Ok(next.run(req).await)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct PeersResponse {
    peers: Vec<PeerInfo>,
}

#[derive(Serialize)]
struct QueueInfo {
    peer_id: PeerId,
    pending_messages: usize,
    oldest_message_age_secs: Option<u64>,
    total_bytes: usize,
}

#[derive(Serialize)]
struct QueuesResponse {
    queues: Vec<QueueInfo>,
}

#[derive(Serialize)]
struct RelayStatsResponse {
    relay: RelayStats,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    uptime_secs: u64,
    connected_peers: usize,
    total_peers: usize,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /peers` -- Returns list of paired peers with connection status.
async fn get_peers(State(state): State<Arc<ManagementState>>) -> Json<PeersResponse> {
    let peers = state.peers.read().await;
    Json(PeersResponse {
        peers: peers.clone(),
    })
}

/// `GET /queues` -- Returns per-peer store-and-forward queue depths.
async fn get_queues(State(state): State<Arc<ManagementState>>) -> Json<QueuesResponse> {
    let mq = state.message_queue.read().await;
    let stats = mq.queue_stats();
    let queues = stats
        .into_iter()
        .map(
            |(peer_id, pending_messages, oldest_message_age_secs, total_bytes)| QueueInfo {
                peer_id,
                pending_messages,
                oldest_message_age_secs,
                total_bytes,
            },
        )
        .collect();
    Json(QueuesResponse { queues })
}

/// `GET /relay/stats` -- Returns per-peer relay statistics.
async fn get_relay_stats(State(state): State<Arc<ManagementState>>) -> Json<RelayStatsResponse> {
    let relay = state.relay_stats.read().await;
    Json(RelayStatsResponse {
        relay: relay.clone(),
    })
}

/// `GET /health` -- Returns connection health and uptime.
async fn get_health(State(state): State<Arc<ManagementState>>) -> Json<HealthResponse> {
    let peers = state.peers.read().await;
    let total_peers = peers.len();
    let connected_peers = peers.iter().filter(|p| p.connected).count();
    let uptime = state.started_at.elapsed().as_secs();

    let status = if connected_peers > 0 {
        "healthy"
    } else {
        "degraded"
    };

    Json(HealthResponse {
        status: status.to_string(),
        uptime_secs: uptime,
        connected_peers,
        total_peers,
    })
}

/// `GET /pairing/qr` -- Returns a pairing QR code as PNG image.
///
/// The QR code encodes a `cairn://pair?...` URI with a 5-minute validity
/// window. Returns `Content-Type: image/png` on success, or a 503 JSON
/// error if the identity or headless pairing is not configured.
async fn get_pairing_qr(State(state): State<Arc<ManagementState>>) -> Response {
    let (headless, peer_id) = match (&state.headless_pairing, &state.local_peer_id) {
        (Some(h), Some(p)) => (h, p),
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "pairing QR generation not available (identity not initialized)"
                })),
            )
                .into_response();
        }
    };

    // Generate a fresh pairing payload with random nonce and PAKE credential.
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let mut pake_credential = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut pake_credential);

    let payload = PairingPayload {
        peer_id: peer_id.clone(),
        nonce,
        pake_credential,
        connection_hints: None,
        created_at: now_unix,
        expires_at: now_unix + headless.validity_window.as_secs(),
    };

    match headless.generate_qr(&payload) {
        Ok(crate::server::headless::HeadlessPairingMethod::QrCode { png_bytes, .. }) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "image/png")],
            png_bytes,
        )
            .into_response(),
        Ok(_) => {
            // Should not happen, but handle gracefully.
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "unexpected pairing method returned"
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "QR code generation failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": format!("QR code generation failed: {e}")
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the management API router with authentication middleware.
pub fn management_router(state: Arc<ManagementState>) -> Router {
    Router::new()
        .route("/peers", get(get_peers))
        .route("/queues", get(get_queues))
        .route("/relay/stats", get(get_relay_stats))
        .route("/health", get(get_health))
        .route("/pairing/qr", get(get_pairing_qr))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

/// Start the management API HTTP server.
///
/// This function binds to the configured address and port, emits a warning
/// if the bind address is non-loopback, and serves requests until the
/// provided shutdown signal resolves.
///
/// # Errors
///
/// Returns `ManagementError::EmptyToken` if the auth token is empty.
/// Returns `ManagementError::BindError` if the TCP listener cannot bind.
pub async fn start_management_server(
    config: &ManagementConfig,
    state: Arc<ManagementState>,
    shutdown: tokio::sync::watch::Receiver<()>,
) -> Result<(), ManagementError> {
    if config.auth_token.is_empty() {
        return Err(ManagementError::EmptyToken);
    }

    // Warn if bound to non-loopback interface.
    if !config.bind_address.is_loopback() {
        tracing::warn!(
            "Management API exposed on non-loopback interface {} without TLS. This is insecure.",
            config.bind_address
        );
    }

    let addr = std::net::SocketAddr::new(config.bind_address, config.port);
    let listener = TcpListener::bind(addr).await?;

    tracing::info!("Management API listening on {}", addr);

    let router = management_router(state);

    // Serve with graceful shutdown.
    let mut shutdown = shutdown;
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    fn test_state() -> Arc<ManagementState> {
        Arc::new(ManagementState::new("test-secret-token".to_string()))
    }

    fn auth_header(token: &str) -> String {
        format!("Bearer {}", token)
    }

    fn test_peer_id(seed: u8) -> PeerId {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[seed; 32]);
        PeerId::from_public_key(&key.verifying_key())
    }

    // -- ManagementConfig --

    #[test]
    fn config_defaults() {
        let cfg = ManagementConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.bind_address.is_loopback());
        assert_eq!(cfg.port, 9090);
        assert!(cfg.auth_token.is_empty());
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = ManagementConfig {
            enabled: true,
            bind_address: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            port: 8080,
            auth_token: "my-token".to_string(),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: ManagementConfig = serde_json::from_str(&json).unwrap();
        assert!(restored.enabled);
        assert_eq!(restored.port, 8080);
        assert_eq!(restored.auth_token, "my-token");
    }

    // -- Authentication middleware --

    #[tokio::test]
    async fn auth_rejects_missing_token() {
        let state = test_state();
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_rejects_wrong_token() {
        let state = test_state();
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/health")
            .header(header::AUTHORIZATION, auth_header("wrong-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_rejects_wrong_length_token() {
        let state = test_state();
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/health")
            .header(header::AUTHORIZATION, auth_header("short"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_accepts_correct_token() {
        let state = test_state();
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/health")
            .header(header::AUTHORIZATION, auth_header("test-secret-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_rejects_malformed_header() {
        let state = test_state();
        let app = management_router(state);

        // No "Bearer " prefix
        let req = HttpRequest::builder()
            .uri("/health")
            .header(header::AUTHORIZATION, "test-secret-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // -- GET /health --

    #[tokio::test]
    async fn health_endpoint_returns_json() {
        let state = test_state();
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/health")
            .header(header::AUTHORIZATION, auth_header("test-secret-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("status").is_some());
        assert!(json.get("uptime_secs").is_some());
        assert!(json.get("connected_peers").is_some());
        assert!(json.get("total_peers").is_some());
    }

    #[tokio::test]
    async fn health_reports_degraded_with_no_peers() {
        let state = test_state();
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/health")
            .header(header::AUTHORIZATION, auth_header("test-secret-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "degraded");
        assert_eq!(json["connected_peers"], 0);
        assert_eq!(json["total_peers"], 0);
    }

    #[tokio::test]
    async fn health_reports_healthy_with_connected_peer() {
        let state = test_state();
        {
            let mut peers = state.peers.write().await;
            peers.push(PeerInfo {
                peer_id: test_peer_id(1),
                name: "test-peer".to_string(),
                connected: true,
                last_seen: Some("2026-03-01T12:00:00Z".to_string()),
            });
        }
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/health")
            .header(header::AUTHORIZATION, auth_header("test-secret-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["connected_peers"], 1);
        assert_eq!(json["total_peers"], 1);
    }

    // -- GET /peers --

    #[tokio::test]
    async fn peers_endpoint_returns_empty_list() {
        let state = test_state();
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/peers")
            .header(header::AUTHORIZATION, auth_header("test-secret-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["peers"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn peers_endpoint_returns_peer_list() {
        let state = test_state();
        {
            let mut peers = state.peers.write().await;
            peers.push(PeerInfo {
                peer_id: test_peer_id(1),
                name: "alpha".to_string(),
                connected: true,
                last_seen: Some("2026-03-01T12:00:00Z".to_string()),
            });
            peers.push(PeerInfo {
                peer_id: test_peer_id(2),
                name: "beta".to_string(),
                connected: false,
                last_seen: None,
            });
        }
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/peers")
            .header(header::AUTHORIZATION, auth_header("test-secret-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let peers = json["peers"].as_array().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0]["name"], "alpha");
        assert!(peers[0]["connected"].as_bool().unwrap());
        assert_eq!(peers[1]["name"], "beta");
        assert!(!peers[1]["connected"].as_bool().unwrap());
    }

    // -- GET /queues --

    #[tokio::test]
    async fn queues_endpoint_returns_empty() {
        let state = test_state();
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/queues")
            .header(header::AUTHORIZATION, auth_header("test-secret-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["queues"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn queues_endpoint_returns_queue_depths() {
        use std::collections::HashSet;
        use uuid::Uuid;

        let state = test_state();
        let sender = test_peer_id(1);
        let recipient = test_peer_id(2);
        let mut paired: HashSet<PeerId> = HashSet::new();
        paired.insert(sender.clone());
        paired.insert(recipient.clone());

        {
            let mut mq = state.message_queue.write().await;
            let fwd_req = crate::server::store_forward::ForwardRequest {
                msg_id: Uuid::now_v7(),
                recipient: recipient.clone(),
                encrypted_payload: vec![0xAB; 100],
                sequence_number: 1,
            };
            mq.enqueue(&fwd_req, &sender, &paired, None);
        }

        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/queues")
            .header(header::AUTHORIZATION, auth_header("test-secret-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let queues = json["queues"].as_array().unwrap();
        assert_eq!(queues.len(), 1);
        assert_eq!(queues[0]["pending_messages"], 1);
        assert_eq!(queues[0]["total_bytes"], 100);
    }

    // -- GET /relay/stats --

    #[tokio::test]
    async fn relay_stats_endpoint_returns_defaults() {
        let state = test_state();
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/relay/stats")
            .header(header::AUTHORIZATION, auth_header("test-secret-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["relay"]["active_connections"], 0);
        assert_eq!(json["relay"]["per_peer"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn relay_stats_endpoint_with_data() {
        let state = test_state();
        {
            let mut relay = state.relay_stats.write().await;
            relay.active_connections = 2;
            relay.per_peer.push(PeerRelayStats {
                peer_id: test_peer_id(1),
                bytes_relayed: 1_048_576,
                active_streams: 1,
            });
        }
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/relay/stats")
            .header(header::AUTHORIZATION, auth_header("test-secret-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["relay"]["active_connections"], 2);
        let per_peer = json["relay"]["per_peer"].as_array().unwrap();
        assert_eq!(per_peer.len(), 1);
        assert_eq!(per_peer[0]["bytes_relayed"], 1_048_576);
        assert_eq!(per_peer[0]["active_streams"], 1);
    }

    // -- GET /pairing/qr --

    #[tokio::test]
    async fn pairing_qr_returns_service_unavailable_without_identity() {
        let state = test_state();
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/pairing/qr")
            .header(header::AUTHORIZATION, auth_header("test-secret-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn pairing_qr_returns_png_when_configured() {
        use crate::identity::LocalIdentity;
        use crate::server::headless::HeadlessPairing;

        let identity = LocalIdentity::generate();
        let state = Arc::new(ManagementState::with_pairing(
            "test-secret-token".to_string(),
            identity.peer_id().clone(),
            HeadlessPairing::default(),
        ));
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/pairing/qr")
            .header(header::AUTHORIZATION, auth_header("test-secret-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/png"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        // Verify PNG magic bytes: 0x89 P N G
        assert!(body.len() > 8);
        assert_eq!(body[0], 0x89);
        assert_eq!(&body[1..4], b"PNG");
    }

    // -- Non-loopback detection --

    #[test]
    fn non_loopback_detection() {
        let loopback = ManagementConfig {
            bind_address: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            ..ManagementConfig::default()
        };
        assert!(loopback.bind_address.is_loopback());

        let external = ManagementConfig {
            bind_address: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            ..ManagementConfig::default()
        };
        assert!(!external.bind_address.is_loopback());
    }

    // -- Start server (token validation) --

    #[tokio::test]
    async fn start_server_rejects_empty_token() {
        let config = ManagementConfig {
            enabled: true,
            auth_token: String::new(),
            ..ManagementConfig::default()
        };
        let state = Arc::new(ManagementState::new(String::new()));
        let (_tx, rx) = tokio::sync::watch::channel(());

        let result = start_management_server(&config, state, rx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ManagementError::EmptyToken));
    }

    // -- Server integration (router-level) --

    #[tokio::test]
    async fn management_server_router_responds() {
        let state = Arc::new(ManagementState::new("integration-test-token".to_string()));
        let app = management_router(state);

        let req = HttpRequest::builder()
            .uri("/health")
            .header(header::AUTHORIZATION, auth_header("integration-test-token"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
