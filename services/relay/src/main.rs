//! cairn-relay: TURN relay server implementing RFC 8656.
//!
//! Provides NAT traversal relay for cairn peers that cannot establish direct connections.

mod credentials;
mod relay;
#[allow(dead_code)] // Protocol constants defined for completeness per RFC 8489/8656.
mod stun;

use crate::credentials::{CredentialStore, DynamicCredential};
use crate::relay::RelayState;
use axum::{
    extract::Query,
    extract::Request,
    extract::State,
    http::StatusCode,
    middleware,
    middleware::Next,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

/// cairn-relay: TURN relay server (RFC 8656)
#[derive(Parser, Debug)]
#[command(name = "cairn-relay", about = "TURN relay server for cairn")]
struct Args {
    /// Listen address for TURN UDP
    #[arg(long, env = "CAIRN_RELAY_LISTEN_ADDR", default_value = "0.0.0.0:3478")]
    listen_addr: SocketAddr,

    /// Relay port range (format: start-end)
    #[arg(long, env = "CAIRN_RELAY_PORT_RANGE", default_value = "49152-65535")]
    port_range: String,

    /// Static credentials (format: username:password, can be repeated)
    #[arg(long, env = "CAIRN_RELAY_CREDENTIALS")]
    credentials: Option<String>,

    /// Shared secret for REST API dynamic credential provisioning
    #[arg(long, env = "CAIRN_RELAY_REST_SECRET")]
    rest_secret: Option<String>,

    /// TLS certificate path (for port 443 listener)
    #[arg(long, env = "CAIRN_RELAY_TLS_CERT")]
    tls_cert: Option<String>,

    /// TLS key path (for port 443 listener)
    #[arg(long, env = "CAIRN_RELAY_TLS_KEY")]
    tls_key: Option<String>,

    /// TLS listen address
    #[arg(long, env = "CAIRN_RELAY_TLS_ADDR", default_value = "0.0.0.0:443")]
    tls_addr: SocketAddr,

    /// REST API listen address
    #[arg(long, env = "CAIRN_RELAY_API_ADDR", default_value = "127.0.0.1:8080")]
    api_addr: SocketAddr,

    /// TURN realm
    #[arg(long, env = "CAIRN_RELAY_REALM", default_value = "cairn")]
    realm: String,

    /// TURN URI advertised in REST API responses
    #[arg(long, env = "CAIRN_RELAY_URI")]
    turn_uri: Option<String>,
}

fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "invalid port range format: {s} (expected start-end)"
        ));
    }
    let start: u16 = parts[0]
        .parse()
        .map_err(|_| format!("invalid start port: {}", parts[0]))?;
    let end: u16 = parts[1]
        .parse()
        .map_err(|_| format!("invalid end port: {}", parts[1]))?;
    if start >= end {
        return Err(format!(
            "start port must be less than end port: {start}-{end}"
        ));
    }
    Ok((start, end))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let port_range =
        parse_port_range(&args.port_range).map_err(Box::<dyn std::error::Error>::from)?;

    info!(
        listen = %args.listen_addr,
        port_range = %args.port_range,
        realm = %args.realm,
        "starting cairn-relay"
    );

    // Set up credential store
    let mut cred_store = CredentialStore::new(args.realm.clone());

    if let Some(ref creds) = args.credentials {
        for cred in creds.split(',') {
            cred_store.add_static_credential(cred.trim());
            info!("added static credential");
        }
    }

    if let Some(ref secret) = args.rest_secret {
        cred_store.set_rest_secret(secret.clone());
        info!("REST API dynamic credential provisioning enabled");
    }

    // Bind the main TURN UDP socket
    let server_socket = Arc::new(
        UdpSocket::bind(args.listen_addr)
            .await
            .map_err(|e| format!("failed to bind UDP socket on {}: {e}", args.listen_addr))?,
    );
    info!(addr = %args.listen_addr, "TURN UDP listener started");

    let relay_bind_addr = args.listen_addr.ip();
    let state = Arc::new(RelayState::new(
        cred_store.clone(),
        relay_bind_addr,
        port_range,
        server_socket.clone(),
    ));

    // Start the allocation expiry task
    let expiry_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            expiry_state.expire_allocations().await;
        }
    });

    // Start REST API if credentials support it
    let api_addr = args.api_addr;
    let turn_uri = args
        .turn_uri
        .unwrap_or_else(|| format!("turn:{}:{}", args.listen_addr.ip(), args.listen_addr.port()));
    let rest_enabled = cred_store.has_rest_api();

    if rest_enabled {
        let app_state = ApiState {
            credentials: cred_store.clone(),
            turn_uris: vec![turn_uri],
            rest_secret: args.rest_secret.clone().unwrap_or_default(),
        };
        tokio::spawn(async move {
            if let Err(e) = run_rest_api(api_addr, app_state).await {
                error!(error = %e, "REST API failed");
            }
        });
        info!(addr = %api_addr, "REST API started");
    }

    // Start TLS listener if configured
    if let (Some(cert_path), Some(key_path)) = (args.tls_cert, args.tls_key) {
        let tls_state = Arc::clone(&state);
        let tls_addr = args.tls_addr;
        tokio::spawn(async move {
            if let Err(e) = run_tls_listener(tls_addr, &cert_path, &key_path, tls_state).await {
                error!(error = %e, "TLS listener failed");
            }
        });
    }

    // Main TURN UDP loop with SIGINT + SIGTERM handling
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| format!("failed to register SIGTERM handler: {e}"))?;

    let mut buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            result = server_socket.recv_from(&mut buf) => {
                let (len, client_addr) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, "UDP recv error");
                        continue;
                    }
                };

                let data = &buf[..len];

                // Check if this is ChannelData (first two bits are 01, i.e. channel >= 0x4000)
                if stun::is_channel_data(data) {
                    if let Some((channel, payload)) = stun::parse_channel_data(data) {
                        state.handle_channel_data(channel, payload, client_addr).await;
                    }
                    continue;
                }

                // Parse as STUN message
                let msg = match stun::Message::decode(data) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(client = %client_addr, error = %e, "invalid STUN message");
                        continue;
                    }
                };

                if let Some(response) = state.handle_stun_message(&msg, data, client_addr).await {
                    if let Err(e) = server_socket.send_to(&response, client_addr).await {
                        warn!(client = %client_addr, error = %e, "failed to send response");
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received SIGINT, stopping");
                break;
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM, stopping");
                break;
            }
        }
    }

    // Graceful shutdown: stop accepting new allocations, let existing ones expire
    info!("shutting down, waiting for allocations to expire");
    let allocs = state.allocations.read().await;
    if allocs.is_empty() {
        info!("no active allocations, exiting");
    } else {
        info!(count = allocs.len(), "active allocations will be dropped");
    }

    Ok(())
}

// --- REST API for dynamic credential provisioning ---

#[derive(Clone)]
struct ApiState {
    credentials: CredentialStore,
    turn_uris: Vec<String>,
    rest_secret: String,
}

#[derive(serde::Deserialize)]
struct CredentialQuery {
    ttl: Option<u64>,
}

/// Bearer token authentication middleware.
///
/// Validates the `Authorization: Bearer <token>` header against the configured
/// `rest_secret`. Uses constant-time comparison to prevent timing attacks.
async fn bearer_auth(State(state): State<ApiState>, request: Request, next: Next) -> Response {
    let auth_header = request.headers().get(axum::http::header::AUTHORIZATION);

    let token = match auth_header.and_then(|v| v.to_str().ok()) {
        Some(value) if value.starts_with("Bearer ") => &value[7..],
        Some(_) => return StatusCode::UNAUTHORIZED.into_response(),
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let expected = state.rest_secret.as_bytes();
    let provided = token.as_bytes();

    if expected.len() != provided.len() || expected.ct_eq(provided).unwrap_u8() != 1 {
        return StatusCode::FORBIDDEN.into_response();
    }

    next.run(request).await
}

async fn get_credentials(
    State(state): State<ApiState>,
    Query(query): Query<CredentialQuery>,
) -> Result<Json<DynamicCredential>, StatusCode> {
    let ttl = query.ttl.unwrap_or(3600);

    state
        .credentials
        .generate_dynamic_credential(ttl, &state.turn_uris)
        .map(Json)
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)
}

async fn run_rest_api(
    addr: SocketAddr,
    state: ApiState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/credentials", get(get_credentials))
        .route_layer(middleware::from_fn_with_state(state.clone(), bearer_auth))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request as HttpRequest};
    use tower::ServiceExt;

    fn test_app() -> Router {
        let mut cred_store = CredentialStore::new("cairn".to_string());
        cred_store.set_rest_secret("test-secret-123".to_string());

        let state = ApiState {
            credentials: cred_store,
            turn_uris: vec!["turn:relay.test:3478".to_string()],
            rest_secret: "test-secret-123".to_string(),
        };

        Router::new()
            .route("/credentials", get(get_credentials))
            .route_layer(middleware::from_fn_with_state(state.clone(), bearer_auth))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_no_auth_header_returns_401() {
        let app = test_app();
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/credentials")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_wrong_bearer_token_returns_403() {
        let app = test_app();
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/credentials")
                    .header(header::AUTHORIZATION, "Bearer wrong-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_correct_bearer_token_returns_200() {
        let app = test_app();
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/credentials")
                    .header(header::AUTHORIZATION, "Bearer test-secret-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_non_bearer_auth_returns_401() {
        let app = test_app();
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/credentials")
                    .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_empty_bearer_token_returns_403() {
        let app = test_app();
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/credentials")
                    .header(header::AUTHORIZATION, "Bearer ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_credentials_response_has_correct_fields() {
        let app = test_app();
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/credentials?ttl=600")
                    .header(header::AUTHORIZATION, "Bearer test-secret-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let cred: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(cred.get("username").is_some());
        assert!(cred.get("password").is_some());
        assert_eq!(cred["ttl"], 600);
        assert!(cred["uris"].is_array());
    }
}

// --- TLS listener for WebSocket-over-TLS escape hatch ---

async fn run_tls_listener(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    state: Arc<RelayState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rustls::ServerConfig;
    use std::io::BufReader;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsAcceptor;

    // Load TLS certificate and key
    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| format!("failed to open TLS cert {cert_path}: {e}"))?;
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| format!("failed to open TLS key {key_path}: {e}"))?;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(cert_file))
            .filter_map(|r| r.ok())
            .collect();

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| format!("failed to parse TLS key: {e}"))?
        .ok_or("no private key found in key file")?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config error: {e}"))?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(addr = %addr, "TLS listener started");

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "TLS accept error");
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            let mut tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(peer = %peer_addr, error = %e, "TLS handshake failed");
                    return;
                }
            };

            // Read TURN messages over TLS/TCP.
            // TCP framing: each STUN message is preceded by a 2-byte length prefix (RFC 6062).
            let mut len_buf = [0u8; 2];
            while tls_stream.read_exact(&mut len_buf).await.is_ok() {
                let msg_len = u16::from_be_bytes(len_buf) as usize;
                if msg_len == 0 || msg_len > 65535 {
                    break;
                }

                let mut msg_buf = vec![0u8; msg_len];
                if tls_stream.read_exact(&mut msg_buf).await.is_err() {
                    break;
                }

                // Check for ChannelData
                if stun::is_channel_data(&msg_buf) {
                    if let Some((channel, payload)) = stun::parse_channel_data(&msg_buf) {
                        state.handle_channel_data(channel, payload, peer_addr).await;
                    }
                    continue;
                }

                let msg = match stun::Message::decode(&msg_buf) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                if let Some(response) = state.handle_stun_message(&msg, &msg_buf, peer_addr).await {
                    let resp_len = (response.len() as u16).to_be_bytes();
                    if tls_stream.write_all(&resp_len).await.is_err() {
                        break;
                    }
                    if tls_stream.write_all(&response).await.is_err() {
                        break;
                    }
                }
            }
        });
    }
}
