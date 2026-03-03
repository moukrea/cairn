//! cairn-chat: P2P messaging demo (Rust)
//!
//! Usage:
//!   cairn-chat --pair-qr                    Display QR code for pairing
//!   cairn-chat --pair-pin                   Display PIN code for pairing
//!   cairn-chat --pair-link                  Display pairing link URI
//!   cairn-chat --scan-qr <data>            Scan QR code data
//!   cairn-chat --enter-pin XXXX-XXXX       Enter PIN code
//!   cairn-chat --from-link <uri>           Accept pairing link
//!   cairn-chat --server-mode --pair-pin    Start as server node
//!   cairn-chat --send "msg" --peer <id> --forward   Forward to offline peer
//!   cairn-chat --verbose                   Enable structured logging

use cairn_p2p::api::{Node, NodeEvent};
use cairn_p2p::config::CairnConfig;
use cairn_p2p::error::CairnError;
use cairn_p2p::pairing::mechanisms::PairingMechanism;

use clap::Parser;
use std::io::{self, BufRead, Write};

#[derive(Parser, Debug)]
#[command(name = "cairn-chat", about = "P2P messaging demo")]
struct Args {
    /// Display QR code for pairing (initiator)
    #[arg(long)]
    pair_qr: bool,

    /// Display PIN code for pairing (initiator)
    #[arg(long)]
    pair_pin: bool,

    /// Display pairing link URI (initiator)
    #[arg(long)]
    pair_link: bool,

    /// Scan QR code data (responder)
    #[arg(long)]
    scan_qr: Option<String>,

    /// Enter PIN code (responder)
    #[arg(long)]
    enter_pin: Option<String>,

    /// Accept pairing link (responder)
    #[arg(long)]
    from_link: Option<String>,

    /// Run as server-mode peer
    #[arg(long)]
    server_mode: bool,

    /// Send a message (non-interactive)
    #[arg(long)]
    send: Option<String>,

    /// Target peer ID for --send
    #[arg(long)]
    peer: Option<String>,

    /// Forward via server-mode peer
    #[arg(long)]
    forward: bool,

    /// Signaling server URL
    #[arg(long)]
    signal: Option<String>,

    /// TURN relay URL
    #[arg(long)]
    turn: Option<String>,

    /// Enable verbose/structured logging
    #[arg(long)]
    verbose: bool,
}

fn display_prompt(peer_status: &str) {
    print!("[{}] peer> ", peer_status);
    io::stdout().flush().unwrap_or(());
}

fn display_message(sender: &str, text: &str, queued: bool) {
    if queued {
        println!("\r[queued] {}: {}", sender, text);
    } else {
        println!("\r{}: {}", sender, text);
    }
}

fn display_state_change(state: &str) {
    eprintln!("--- Connection state: {} ---", state);
}

fn display_error(err: &CairnError) {
    match err {
        _ => {
            eprintln!("Error: {}", err);
            eprintln!("Hint: If both peers are behind symmetric NATs, deploy a TURN relay.");
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("cairn=debug,cairn_chat=debug")
            .init();
    }

    // Initialize cairn node
    let config = CairnConfig::default();
    let node = if args.server_mode {
        cairn_p2p::api::node::create_server(config.into())?
    } else {
        cairn_p2p::api::node::create(config)?
    };

    node.start().await?;
    eprintln!("cairn-chat started. Peer ID: {}", node.peer_id());

    // Handle pairing
    let mechanism = if args.pair_qr {
        eprintln!("Generating QR code for pairing...");
        Some(PairingMechanism::QrCode)
    } else if args.pair_pin {
        eprintln!("Generating PIN code...");
        Some(PairingMechanism::PinCode)
    } else if args.pair_link {
        eprintln!("Generating pairing link...");
        Some(PairingMechanism::PairingLink)
    } else if args.scan_qr.is_some() {
        Some(PairingMechanism::QrCode)
    } else if args.enter_pin.is_some() {
        Some(PairingMechanism::PinCode)
    } else if args.from_link.is_some() {
        Some(PairingMechanism::PairingLink)
    } else {
        eprintln!("No pairing method specified. Use --pair-qr, --pair-pin, or --pair-link");
        None
    };

    if let Some(mech) = mechanism {
        let peer_id = node.pair(mech).await?;
        eprintln!("Paired with: {}", peer_id);

        // Establish session
        let session = node.connect(&peer_id).await?;
        eprintln!("Session established.");

        // Open chat and presence channels
        session.send("chat", b"").await?; // ChannelInit

        // Subscribe to events
        let mut events = node.subscribe();

        // Non-interactive send mode
        if let Some(msg) = &args.send {
            session.send("chat", msg.as_bytes()).await?;
            eprintln!("[sent] {}", msg);
            session.close().await?;
            return Ok(());
        }

        // Interactive chat loop
        let stdin = io::stdin();
        let mut peer_status = "online".to_string();

        display_prompt(&peer_status);

        let reader = stdin.lock();
        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                display_prompt(&peer_status);
                continue;
            }

            if line == "/quit" || line == "/exit" {
                break;
            }

            if line == "/status" {
                eprintln!("Peer: {} | Connected: {}", peer_id, session.is_connected());
                display_prompt(&peer_status);
                continue;
            }

            // Send typing indicator then message
            session.send("presence", b"typing").await.ok();
            session.send("chat", line.as_bytes()).await?;
            display_prompt(&peer_status);
        }

        session.close().await?;
    }

    node.stop().await?;
    Ok(())
}
