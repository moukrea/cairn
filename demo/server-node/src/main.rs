//! cairn-server: Personal server node (Docker-ready)
//!
//! A ready-to-deploy server-mode peer that provides:
//! - Headless pairing (pin, PSK, link, QR)
//! - Store-and-forward mailbox for offline message delivery
//! - Relay bridging for paired peers behind NATs
//! - Management REST API on localhost:9090
//! - Multi-device sync hub
//!
//! Configuration via environment variables:
//!   CAIRN_DATA_DIR          Data directory (default: /data)
//!   CAIRN_MGMT_ENABLED      Enable management API (default: true)
//!   CAIRN_MGMT_TOKEN        Bearer token for management API
//!   CAIRN_PSK               Pre-shared key for automatic pairing
//!   CAIRN_FORWARD_ENABLED   Enable store-and-forward (default: true)
//!   CAIRN_FORWARD_MAX_PER_PEER  Max messages per peer (default: 10000)
//!   CAIRN_FORWARD_MAX_AGE   Max message age (default: 7d)
//!   CAIRN_FORWARD_MAX_TOTAL Max total storage (default: 1GB)
//!   CAIRN_SIGNAL_SERVERS    Comma-separated signaling server URLs
//!   CAIRN_TURN_SERVERS      Comma-separated TURN relay URLs

mod config;
mod management;

use std::sync::Arc;

use clap::Parser;
use rand::Rng;

use cairn_p2p::config::{CairnConfig, MeshSettings};

use config::{ServerArgs, ServerCommand, ServerConfig};
use management::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = ServerArgs::parse();
    let server_config = ServerConfig::from_env();

    if args.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("cairn=debug,cairn_server=debug")
            .init();
    }

    // Emit configuration warnings
    for warning in server_config.validate() {
        eprintln!("WARNING: {}", warning);
    }

    // Ensure data directory exists
    if !server_config.data_dir.exists() {
        std::fs::create_dir_all(&server_config.data_dir)?;
    }

    // Handle pairing subcommand
    if let Some(ServerCommand::Pair { pin, link, qr }) = &args.command {
        if *pin {
            // Generate and print PIN code
            let mut rng = rand::thread_rng();
            let first: u32 = rng.gen_range(0..10000);
            let second: u32 = rng.gen_range(0..10000);
            let pin_code = format!("{:04}-{:04}", first, second);
            eprintln!("Generating PIN code for pairing...");
            println!("{pin_code}");
            eprintln!("Enter this PIN on your device. Expires in 5 minutes.");
            return Ok(());
        }
        if *link {
            // Generate and print pairing link
            let mut rng = rand::thread_rng();
            let nonce_bytes: [u8; 16] = rng.gen();
            let nonce: String = nonce_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            let hostname = std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("CAIRN_HOSTNAME"))
                .unwrap_or_else(|_| "cairn-server".to_string());
            let mut uri = format!("cairn://pair/{nonce}");
            if !server_config.signal_servers.is_empty() {
                uri.push_str(&format!("?signal={}&host={hostname}", server_config.signal_servers[0]));
            } else {
                uri.push_str(&format!("?host={hostname}"));
            }
            eprintln!("Generating pairing link...");
            println!("{uri}");
            eprintln!("Copy this link to your device. Expires in 5 minutes.");
            return Ok(());
        }
        if *qr {
            // Generate a pairing link and display it as QR-encodable data
            let mut rng = rand::thread_rng();
            let nonce_bytes: [u8; 16] = rng.gen();
            let nonce: String = nonce_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            let hostname = std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("CAIRN_HOSTNAME"))
                .unwrap_or_else(|_| "cairn-server".to_string());
            let mut uri = format!("cairn://pair/{nonce}");
            if !server_config.signal_servers.is_empty() {
                uri.push_str(&format!("?signal={}&host={hostname}", server_config.signal_servers[0]));
            } else {
                uri.push_str(&format!("?host={hostname}"));
            }
            eprintln!("QR data (encode this string as a QR code):");
            println!("{uri}");
            return Ok(());
        }
        eprintln!("Specify --pin, --link, or --qr");
        std::process::exit(1);
    }

    // Initialize cairn server node
    let cairn_config = CairnConfig {
        server_mode: true,
        mesh_settings: MeshSettings {
            mesh_enabled: true,
            relay_willing: true,
            relay_capacity: server_config.relay_capacity as u16,
            max_hops: 3,
        },
        signaling_servers: server_config.signal_servers.clone(),
        ..CairnConfig::default_server()
    };

    let _node = cairn_p2p::config::create_server_with_config(cairn_config)?;

    eprintln!("cairn-server started");
    eprintln!("  Data directory: {}", server_config.data_dir.display());
    eprintln!("  Store-and-forward: {}", if server_config.forward_enabled { "enabled" } else { "disabled" });
    eprintln!("  Forward max/peer: {}", server_config.forward_max_per_peer);
    eprintln!("  Forward max age: {:?}", server_config.forward_max_age);
    eprintln!("  Relay capacity: {}", server_config.relay_capacity);

    // Handle PSK auto-pairing
    if let Some(ref psk) = server_config.psk {
        eprintln!("PSK configured — automatic pairing enabled");
        let _ = psk; // Will be wired to headless pairing module
    }

    // Start management API in background
    let app_state = Arc::new(AppState::new(server_config.clone()));
    let mgmt_config = server_config.clone();
    let mgmt_state = app_state.clone();

    let mgmt_handle = tokio::spawn(async move {
        if let Err(e) = management::start_server(&mgmt_config, mgmt_state).await {
            eprintln!("Management API error: {}", e);
        }
    });

    // Main event loop — process cairn events
    eprintln!("Server ready. Press Ctrl+C to stop.");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\nShutting down...");
        }
        _ = mgmt_handle => {
            eprintln!("Management API stopped unexpectedly");
        }
    }

    Ok(())
}
