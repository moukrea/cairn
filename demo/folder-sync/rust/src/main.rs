//! cairn-folder-sync: P2P folder synchronization demo (Rust)
//!
//! Usage:
//!   cairn-folder-sync --dir ./sync-folder --pair-qr
//!   cairn-folder-sync --dir ./sync-folder --pair-pin
//!   cairn-folder-sync --dir ./sync-folder --pair-link
//!   cairn-folder-sync --dir ./sync-folder --enter-pin XXXX-XXXX
//!   cairn-folder-sync --dir ./sync-folder --from-link <uri>
//!   cairn-folder-sync --dir ./sync-folder --server-hub
//!   cairn-folder-sync --verbose

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use clap::Parser;

mod sync;
use sync::{ChunkTransfer, ConflictResolver, DeltaSync, FileMeta, SyncState};

use cairn_p2p::config::{CairnConfig, MeshSettings};
use cairn_p2p::error::CairnError;

#[derive(Parser, Debug)]
#[command(name = "cairn-folder-sync", about = "P2P folder synchronization demo")]
struct Args {
    /// Directory to synchronize
    #[arg(long)]
    dir: PathBuf,

    /// Display QR code for pairing (initiator)
    #[arg(long)]
    pair_qr: bool,

    /// Display PIN code for pairing (initiator)
    #[arg(long)]
    pair_pin: bool,

    /// Display pairing link URI (initiator)
    #[arg(long)]
    pair_link: bool,

    /// Enter PIN code (responder)
    #[arg(long)]
    enter_pin: Option<String>,

    /// Accept pairing link (responder)
    #[arg(long)]
    from_link: Option<String>,

    /// Run as server-mode sync hub
    #[arg(long)]
    server_hub: bool,

    /// Enable mesh routing for multi-device sync
    #[arg(long)]
    mesh: bool,

    /// Enable verbose/structured logging
    #[arg(long)]
    verbose: bool,
}

fn display_error(err: &CairnError) {
    eprintln!("Error: {}", err);
    let msg = err.to_string();
    if msg.contains("TransportExhausted") {
        eprintln!("Hint: Both peers may be behind symmetric NATs. Deploy a TURN relay.");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("cairn=debug,cairn_folder_sync=debug")
            .init();
    }

    // Validate sync directory
    if !args.dir.exists() {
        std::fs::create_dir_all(&args.dir)?;
        eprintln!("Created sync directory: {}", args.dir.display());
    }
    let sync_dir = args.dir.canonicalize()?;

    // Initialize cairn node with mesh support if requested
    let config = if args.server_hub {
        CairnConfig::default_server()
    } else {
        let mut cfg = CairnConfig::default();
        if args.mesh {
            cfg.mesh_settings = MeshSettings {
                mesh_enabled: true,
                max_hops: 3,
                relay_willing: true,
                relay_capacity: 10,
            };
        }
        cfg
    };

    let node = if args.server_hub {
        cairn_p2p::config::create_server_with_config(config)?
    } else {
        cairn_p2p::config::create_with_config(config)?
    };

    eprintln!("cairn-folder-sync started. Watching: {}", sync_dir.display());

    // Handle pairing
    let mechanism = if args.pair_qr {
        eprintln!("Generating QR code for pairing...");
        Some("qr")
    } else if args.pair_pin {
        eprintln!("Generating PIN code...");
        let data = node.pair_generate_pin().await?;
        eprintln!("PIN: {}", data.pin);
        Some("pin")
    } else if args.pair_link {
        eprintln!("Generating pairing link...");
        let data = node.pair_generate_link().await?;
        eprintln!("Link: {}", data.uri);
        Some("link")
    } else if args.enter_pin.is_some() {
        Some("pin")
    } else if args.from_link.is_some() {
        Some("link")
    } else {
        eprintln!("No pairing method. Use --pair-qr, --pair-pin, or --pair-link");
        None
    };

    if mechanism.is_none() {
        std::process::exit(1);
    }

    // Connect to peer
    let peer_id = if let Some(pin) = &args.enter_pin {
        node.pair_enter_pin(pin).await?
    } else if let Some(uri) = &args.from_link {
        node.pair_from_link(uri).await?
    } else {
        // For initiator modes, wait for pairing completion via events
        loop {
            if let Some(event) = node.recv_event().await {
                match event {
                    cairn_p2p::api::events::Event::PairingCompleted { peer_id } => {
                        break peer_id.into();
                    }
                    cairn_p2p::api::events::Event::PairingFailed { error, .. } => {
                        eprintln!("Pairing failed: {}", error);
                        std::process::exit(1);
                    }
                    _ => continue,
                }
            }
        }
    };

    eprintln!("Paired with: {}", peer_id);

    let session = node.connect(&peer_id.to_string()).await?;
    let sync_channel = session.open_channel("sync").await?;
    eprintln!("Sync session established.");

    // Initialize sync state
    let mut sync_state = SyncState::new(sync_dir.clone());
    let chunker = ChunkTransfer::new(65536); // 64 KB chunks
    let conflict_resolver = ConflictResolver::new();
    let delta_sync = DeltaSync::new();

    // Initial scan
    let local_files = sync_state.scan_directory()?;
    eprintln!("Found {} files to sync", local_files.len());

    // Send file metadata to peer
    for meta in &local_files {
        let meta_bytes = serde_json::to_vec(meta)?;
        session.send(&sync_channel, &meta_bytes).await?;
    }

    // Main sync loop — listen for incoming events
    eprintln!("Watching for changes... (Ctrl+C to stop)");

    loop {
        let event = node.recv_event().await;
        match event {
            Some(cairn_p2p::api::events::Event::MessageReceived { channel, data, .. }) => {
                if channel == "sync" {
                    handle_sync_message(
                        &data,
                        &sync_dir,
                        &session,
                        &sync_channel,
                        &chunker,
                        &conflict_resolver,
                        &delta_sync,
                        &mut sync_state,
                    )
                    .await?;
                }
            }
            Some(cairn_p2p::api::events::Event::StateChanged { state, .. }) => {
                eprintln!("--- Connection state: {} ---", state);
            }
            None => break,
            _ => {}
        }
    }

    session.close().await?;
    Ok(())
}

async fn handle_sync_message(
    data: &[u8],
    sync_dir: &Path,
    session: &cairn_p2p::api::node::ApiSession,
    sync_channel: &cairn_p2p::api::node::ApiChannel,
    chunker: &ChunkTransfer,
    conflict_resolver: &ConflictResolver,
    delta_sync: &DeltaSync,
    sync_state: &mut SyncState,
) -> Result<(), Box<dyn std::error::Error>> {
    // Try to parse as file metadata
    if let Ok(meta) = serde_json::from_slice::<FileMeta>(data) {
        eprintln!("[sync] Received metadata: {} ({} bytes)", meta.path, meta.size);

        // Check for conflicts
        if let Some(local_meta) = sync_state.get_file_meta(&meta.path) {
            if local_meta.hash != meta.hash && local_meta.modified != meta.modified {
                // Conflict detected
                let conflict_path = conflict_resolver.resolve_path(
                    sync_dir,
                    &meta.path,
                    &meta.peer_id_prefix,
                    meta.modified,
                );
                eprintln!("[conflict] {} — preserved as {}", meta.path, conflict_path.display());
            }
        }

        // Request file data via chunk protocol
        let request = serde_json::json!({
            "type": "chunk_request",
            "file_path": meta.path,
            "file_hash": meta.hash,
            "from_chunk": sync_state.last_received_chunk(&meta.path),
        });
        session
            .send(sync_channel, &serde_json::to_vec(&request)?)
            .await?;
    }

    // Try to parse as chunk data
    if let Ok(chunk) = serde_json::from_slice::<sync::ChunkData>(data) {
        let dest = sync_dir.join(&chunk.file_path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }

        chunker.write_chunk(&dest, &chunk)?;
        sync_state.record_chunk(&chunk.file_path, chunk.chunk_index);

        if chunk.chunk_index + 1 == chunk.chunk_count {
            eprintln!("[sync] Completed: {}", chunk.file_path);
            sync_state.mark_complete(&chunk.file_path, &chunk.file_hash);

            // Send ack
            let ack = serde_json::json!({
                "type": "chunk_ack",
                "file_path": chunk.file_path,
                "file_hash": chunk.file_hash,
            });
            session
                .send(sync_channel, &serde_json::to_vec(&ack)?)
                .await?;
        }
    }

    Ok(())
}
