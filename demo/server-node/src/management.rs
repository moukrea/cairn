//! Management API HTTP server for the personal server node.
//!
//! Wraps cairn-p2p's management module with server-node-specific endpoints
//! and environment-based configuration.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::{header, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::Rng;
use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use crate::config::ServerConfig;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// A pending pairing PIN with expiration.
#[derive(Debug, Clone)]
struct PendingPin {
    pin: String,
    created_at: Instant,
    expires_in_secs: u64,
}

/// A pending pairing link with expiration.
#[derive(Debug, Clone)]
struct PendingLink {
    uri: String,
    created_at: Instant,
    expires_in_secs: u64,
}

/// Shared application state for the management API.
pub struct AppState {
    /// Bearer token for authentication
    pub auth_token: Vec<u8>,
    /// Server configuration
    pub config: ServerConfig,
    /// Server start time
    pub started_at: std::time::Instant,
    /// Connected peers
    pub peers: RwLock<Vec<PeerEntry>>,
    /// Queue statistics
    pub queue_stats: RwLock<Vec<QueueEntry>>,
    /// Relay statistics
    pub relay_stats: RwLock<RelayStatsData>,
    /// Pending pairing PINs (keyed by PIN string)
    pub pending_pins: RwLock<HashMap<String, PendingPin>>,
    /// Pending pairing links (keyed by nonce)
    pub pending_links: RwLock<HashMap<String, PendingLink>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerEntry {
    pub peer_id: String,
    pub name: String,
    pub connected: bool,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueueEntry {
    pub peer_id: String,
    pub pending_messages: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RelayStatsData {
    pub active_connections: u32,
    pub bytes_relayed: u64,
    pub per_peer: Vec<PeerRelayEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerRelayEntry {
    pub peer_id: String,
    pub bytes_relayed: u64,
    pub active_streams: u32,
}

/// Default PIN expiration time (5 minutes).
const PIN_EXPIRES_SECS: u64 = 300;

/// Default pairing link expiration time (5 minutes).
const LINK_EXPIRES_SECS: u64 = 300;

impl AppState {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            auth_token: config.mgmt_token.clone().into_bytes(),
            config,
            started_at: std::time::Instant::now(),
            peers: RwLock::new(Vec::new()),
            queue_stats: RwLock::new(Vec::new()),
            relay_stats: RwLock::new(RelayStatsData::default()),
            pending_pins: RwLock::new(HashMap::new()),
            pending_links: RwLock::new(HashMap::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Pairing helpers
// ---------------------------------------------------------------------------

/// Generate a random 8-digit PIN formatted as XXXX-XXXX.
fn generate_pin() -> String {
    let mut rng = rand::thread_rng();
    let first: u32 = rng.gen_range(0..10000);
    let second: u32 = rng.gen_range(0..10000);
    format!("{:04}-{:04}", first, second)
}

/// Generate a random hex nonce for pairing links.
fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    hex::encode(&bytes)
}

/// Simple hex encoding (avoids adding the `hex` crate).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Build a cairn:// pairing link URI.
///
/// Format: cairn://pair/<nonce>?signal=<signal_server>&host=<hostname>
/// The nonce is a random 32-hex-char string that identifies this pairing session.
fn build_pairing_link(config: &ServerConfig, nonce: &str) -> String {
    let mut uri = format!("cairn://pair/{nonce}");
    let mut has_query = false;

    // Append signal server if configured
    if !config.signal_servers.is_empty() {
        uri.push_str("?signal=");
        uri.push_str(&config.signal_servers[0]);
        has_query = true;
    }

    // Append hostname from the data dir or environment
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("CAIRN_HOSTNAME"))
        .unwrap_or_else(|_| "cairn-server".to_string());
    let sep = if has_query { "&" } else { "?" };
    uri.push_str(&format!("{sep}host={hostname}"));

    uri
}

// ---------------------------------------------------------------------------
// Bearer token authentication middleware
// ---------------------------------------------------------------------------

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
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

            let len_eq = (provided_bytes.len() as u64).ct_eq(&(expected_bytes.len() as u64));
            let bytes_eq = if provided_bytes.len() == expected_bytes.len() {
                provided_bytes.ct_eq(expected_bytes)
            } else {
                expected_bytes.ct_eq(expected_bytes)
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
    peers: Vec<PeerEntry>,
}

#[derive(Serialize)]
struct QueueResponse {
    queues: Vec<QueueEntry>,
    total_storage_bytes: u64,
}

#[derive(Serialize)]
struct RelayStatsResponse {
    relay: RelayStatsData,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    uptime_secs: u64,
    connected_peers: usize,
    total_peers: usize,
    storage_used_bytes: u64,
    forward_enabled: bool,
}

#[derive(Serialize)]
struct PairingPinResponse {
    pin: String,
    expires_in_secs: u64,
}

#[derive(Serialize)]
struct PairingLinkResponse {
    uri: String,
    expires_in_secs: u64,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /peers — list paired peers with connection status and last seen time.
async fn get_peers(State(state): State<Arc<AppState>>) -> Json<PeersResponse> {
    let peers = state.peers.read().await;
    Json(PeersResponse { peers: peers.clone() })
}

/// POST /peers/:id/unpair — unpair a specific peer.
async fn unpair_peer(
    State(state): State<Arc<AppState>>,
    Path(peer_id): Path<String>,
) -> impl IntoResponse {
    let mut peers = state.peers.write().await;
    let before = peers.len();
    peers.retain(|p| p.peer_id != peer_id);
    if peers.len() < before {
        (StatusCode::OK, Json(serde_json::json!({"status": "unpaired"})))
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "peer not found"})))
    }
}

/// GET /queue — queue sizes per peer and total storage used.
async fn get_queue(State(state): State<Arc<AppState>>) -> Json<QueueResponse> {
    let queues = state.queue_stats.read().await;
    let total: u64 = queues.iter().map(|q| q.total_bytes).sum();
    Json(QueueResponse {
        queues: queues.clone(),
        total_storage_bytes: total,
    })
}

/// GET /queue/:peer_id — message queue for a specific peer.
async fn get_peer_queue(
    State(state): State<Arc<AppState>>,
    Path(peer_id): Path<String>,
) -> impl IntoResponse {
    let queues = state.queue_stats.read().await;
    match queues.iter().find(|q| q.peer_id == peer_id) {
        Some(entry) => (StatusCode::OK, Json(serde_json::to_value(entry).unwrap())),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "peer not found"}))),
    }
}

/// POST /queue/:peer_id/purge — purge queued messages for a peer.
async fn purge_peer_queue(
    State(state): State<Arc<AppState>>,
    Path(peer_id): Path<String>,
) -> impl IntoResponse {
    let mut queues = state.queue_stats.write().await;
    if let Some(entry) = queues.iter_mut().find(|q| q.peer_id == peer_id) {
        let purged = entry.pending_messages;
        entry.pending_messages = 0;
        entry.total_bytes = 0;
        (StatusCode::OK, Json(serde_json::json!({"purged": purged})))
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "peer not found"})))
    }
}

/// GET /relay/stats — active relay connections and bytes relayed per peer.
async fn get_relay_stats(State(state): State<Arc<AppState>>) -> Json<RelayStatsResponse> {
    let relay = state.relay_stats.read().await;
    Json(RelayStatsResponse { relay: relay.clone() })
}

/// GET /health — server health: uptime, peer count, storage usage.
async fn get_health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let peers = state.peers.read().await;
    let queues = state.queue_stats.read().await;
    let total_storage: u64 = queues.iter().map(|q| q.total_bytes).sum();
    let connected = peers.iter().filter(|p| p.connected).count();

    let status = if connected > 0 { "healthy" } else { "idle" };

    Json(HealthResponse {
        status: status.to_string(),
        uptime_secs: state.started_at.elapsed().as_secs(),
        connected_peers: connected,
        total_peers: peers.len(),
        storage_used_bytes: total_storage,
        forward_enabled: state.config.forward_enabled,
    })
}

/// POST /pairing/pin — generate a new pin code for headless pairing.
async fn create_pairing_pin(
    State(state): State<Arc<AppState>>,
) -> Json<PairingPinResponse> {
    let pin = generate_pin();

    // Store the pending PIN
    let pending = PendingPin {
        pin: pin.clone(),
        created_at: Instant::now(),
        expires_in_secs: PIN_EXPIRES_SECS,
    };

    {
        let mut pins = state.pending_pins.write().await;
        // Purge expired PINs first
        pins.retain(|_, p| p.created_at.elapsed().as_secs() < p.expires_in_secs);
        pins.insert(pin.clone(), pending);
    }

    Json(PairingPinResponse {
        pin,
        expires_in_secs: PIN_EXPIRES_SECS,
    })
}

/// GET /pairing/qr — return a QR-encodable pairing link.
///
/// Returns the pairing link as a string that can be rendered into a QR code
/// by the client. Does not generate an actual QR image server-side.
async fn get_pairing_qr(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let nonce = generate_nonce();
    let uri = build_pairing_link(&state.config, &nonce);

    // Store as a pending link so it can be validated when the peer connects
    let pending = PendingLink {
        uri: uri.clone(),
        created_at: Instant::now(),
        expires_in_secs: LINK_EXPIRES_SECS,
    };

    {
        let mut links = state.pending_links.write().await;
        links.retain(|_, l| l.created_at.elapsed().as_secs() < l.expires_in_secs);
        links.insert(nonce, pending);
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "qr_data": uri,
            "expires_in_secs": LINK_EXPIRES_SECS,
        })),
    )
}

/// POST /pairing/link — generate a pairing link URI.
async fn create_pairing_link(
    State(state): State<Arc<AppState>>,
) -> Json<PairingLinkResponse> {
    let nonce = generate_nonce();
    let uri = build_pairing_link(&state.config, &nonce);

    // Store as a pending link
    let pending = PendingLink {
        uri: uri.clone(),
        created_at: Instant::now(),
        expires_in_secs: LINK_EXPIRES_SECS,
    };

    {
        let mut links = state.pending_links.write().await;
        links.retain(|_, l| l.created_at.elapsed().as_secs() < l.expires_in_secs);
        links.insert(nonce, pending);
    }

    Json(PairingLinkResponse {
        uri,
        expires_in_secs: LINK_EXPIRES_SECS,
    })
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the management API router with authentication middleware.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/peers", get(get_peers))
        .route("/peers/{id}/unpair", post(unpair_peer))
        .route("/queue", get(get_queue))
        .route("/queue/{peer_id}", get(get_peer_queue))
        .route("/queue/{peer_id}/purge", post(purge_peer_queue))
        .route("/relay/stats", get(get_relay_stats))
        .route("/health", get(get_health))
        .route("/pairing/pin", post(create_pairing_pin))
        .route("/pairing/qr", get(get_pairing_qr))
        .route("/pairing/link", post(create_pairing_link))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

/// Start the management API HTTP server.
pub async fn start_server(
    config: &ServerConfig,
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !config.mgmt_enabled {
        eprintln!("Management API disabled");
        return Ok(());
    }

    if config.mgmt_token.is_empty() {
        return Err("CAIRN_MGMT_TOKEN must be set when management API is enabled".into());
    }

    if !config.mgmt_bind.is_loopback() {
        eprintln!(
            "WARNING: Management API exposed on non-loopback interface {} without TLS",
            config.mgmt_bind
        );
    }

    let addr = std::net::SocketAddr::new(config.mgmt_bind, config.mgmt_port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("Management API listening on {}", addr);

    let router = build_router(state);
    axum::serve(listener, router).await?;

    Ok(())
}
