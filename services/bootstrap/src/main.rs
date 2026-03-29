//! cairn-bootstrap: lightweight Kademlia DHT bootstrap node.
//!
//! Runs a cairn-p2p node that listens on TCP, QUIC, and WebSocket,
//! participates in the Kademlia DHT, and acts as a bootstrap peer for
//! both native (TCP/QUIC) and browser (WSS) clients.
//!
//! This bridges the TCP↔WSS DHT overlay gap: provider records published
//! by native hosts become discoverable by browser clients through this node.

use clap::Parser;
use tracing::{info, warn};

/// cairn-bootstrap: Kademlia DHT bootstrap node
#[derive(Parser, Debug)]
#[command(name = "cairn-bootstrap", about = "DHT bootstrap node for cairn P2P")]
struct Args {
    /// TCP listen address
    #[arg(long, env = "CAIRN_BOOTSTRAP_TCP", default_value = "0.0.0.0:4001")]
    tcp_addr: String,

    /// QUIC (UDP) listen address
    #[arg(long, env = "CAIRN_BOOTSTRAP_QUIC", default_value = "0.0.0.0:4001")]
    quic_addr: String,

    /// WebSocket listen address
    #[arg(long, env = "CAIRN_BOOTSTRAP_WS", default_value = "0.0.0.0:4002")]
    ws_addr: String,

    /// Data directory for identity persistence
    #[arg(long, env = "CAIRN_BOOTSTRAP_DATA", default_value = ".cairn-bootstrap")]
    data_dir: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.parse().unwrap_or_default()),
        )
        .init();

    info!("cairn-bootstrap starting...");

    let mut config = cairn_p2p::CairnConfig::default();
    config.server_mode = true;
    config.storage_backend = cairn_p2p::StorageBackend::Filesystem {
        path: std::path::PathBuf::from(&args.data_dir),
    };

    // Listen on explicit addresses for all three transports.
    config.listen_addresses = Some(vec![
        format!("/ip4/{}/tcp/{}", parse_host(&args.tcp_addr), parse_port(&args.tcp_addr)),
        format!("/ip4/{}/udp/{}/quic-v1", parse_host(&args.quic_addr), parse_port(&args.quic_addr)),
        format!("/ip4/{}/tcp/{}/ws", parse_host(&args.ws_addr), parse_port(&args.ws_addr)),
    ]);

    let node = match cairn_p2p::create_and_start_with_config(config).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Failed to start cairn node: {e}");
            std::process::exit(1);
        }
    };

    let addrs = node.listen_addresses().await;
    let peer_id = node
        .libp2p_peer_id()
        .map(|p| p.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    info!("PeerId: {peer_id}");
    info!("Listening on {} addresses:", addrs.len());
    for addr in &addrs {
        info!("  {addr}/p2p/{peer_id}");
    }
    info!("Bootstrap node ready — Ctrl+C to stop");

    // Run forever, processing DHT queries.
    loop {
        match node.recv_event().await {
            Some(cairn_p2p::Event::StateChanged { peer_id, state }) => {
                tracing::debug!("Peer {peer_id}: {state:?}");
            }
            Some(cairn_p2p::Event::Error { error }) => {
                tracing::trace!("Transport error: {error}");
            }
            Some(_) => {}
            None => {
                warn!("Event channel closed, shutting down");
                break;
            }
        }
    }
}

fn parse_host(addr: &str) -> &str {
    addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("0.0.0.0")
}

fn parse_port(addr: &str) -> &str {
    addr.rsplit_once(':').map(|(_, p)| p).unwrap_or("4001")
}
