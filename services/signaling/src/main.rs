mod auth;
mod server;

use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

/// cairn signaling server -- lightweight WebSocket message router
/// for real-time peer discovery and handshake relay.
#[derive(Parser, Debug)]
#[command(name = "cairn-signal", version)]
struct Args {
    /// Listen address (host:port).
    #[arg(long, env = "CAIRN_SIGNAL_LISTEN_ADDR", default_value = "0.0.0.0:443")]
    listen_addr: SocketAddr,

    /// Path to TLS certificate chain (PEM). If omitted, runs in plaintext mode.
    #[arg(long, env = "CAIRN_SIGNAL_TLS_CERT")]
    tls_cert: Option<String>,

    /// Path to TLS private key (PEM). Required if --tls-cert is set.
    #[arg(long, env = "CAIRN_SIGNAL_TLS_KEY")]
    tls_key: Option<String>,

    /// Bearer token for authentication. If omitted, all connections are allowed.
    #[arg(long, env = "CAIRN_SIGNAL_AUTH_TOKEN")]
    auth_token: Option<String>,
}

fn load_tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| format!("failed to open TLS cert file '{cert_path}': {e}"))?;
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| format!("failed to open TLS key file '{key_path}': {e}"))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse TLS certs: {e}"))?;

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| format!("failed to parse TLS key: {e}"))?
        .ok_or("no private key found in TLS key file")?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config error: {e}"))?;

    Ok(Arc::new(config))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // Load TLS config if cert/key paths are provided.
    let tls_config = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => match load_tls_config(cert, key) {
            Ok(config) => Some(config),
            Err(e) => {
                tracing::error!("TLS configuration failed: {e}");
                std::process::exit(1);
            }
        },
        (Some(_), None) | (None, Some(_)) => {
            tracing::error!("both --tls-cert and --tls-key must be set together");
            std::process::exit(1);
        }
        (None, None) => None,
    };

    let config = server::ServerConfig {
        listen_addr: args.listen_addr,
        tls_config,
        auth_token: args.auth_token,
    };

    // Shutdown signal: SIGTERM or SIGINT.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {}
                _ = sigterm.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
        }
        tracing::info!("received shutdown signal");
        let _ = shutdown_tx.send(true);
    });

    if let Err(e) = server::run(config, shutdown_rx).await {
        tracing::error!("server error: {e}");
        std::process::exit(1);
    }
}
