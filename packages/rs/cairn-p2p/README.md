# cairn-p2p

Rust reference implementation of the cairn P2P connectivity library.

## Installation

```toml
[dependencies]
cairn-p2p = "0.1"
```

Or via cargo:

```bash
cargo add cairn-p2p
```

## Requirements

- Rust 1.75+
- Async runtime: tokio

## Quick Start

```rust
use cairn_p2p::CairnNode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let node = CairnNode::builder().build().await?;
    let peer = node.pair_with_pin("123456").await?;
    peer.send(b"hello").await?;
    Ok(())
}
```

## API Overview

- `CairnNode` -- Main entry point, manages identity, sessions, and discovery
- `Session` -- Persistent encrypted session with a peer
- `PeerIdentity` -- Ed25519 identity keypair with Peer ID derivation
- `CairnConfig` -- Configuration with tier presets (tier0, tier1, tier2)

## Key Dependencies

- `libp2p` -- Transport, NAT traversal, DHT discovery
- `ed25519-dalek` -- Identity keypairs
- `chacha20poly1305` / `aes-gcm` -- AEAD encryption
- `spake2` -- Password-authenticated key exchange for pairing
- `tokio` -- Async runtime

## License

Licensed under the [MIT License](../../../LICENSE).
