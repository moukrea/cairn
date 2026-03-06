<p align="center">
  <img src="cairn.png" alt="cairn" width="450">
</p>

<p align="center">
  <strong>A universal peer-to-peer connectivity library with end-to-end encryption, available natively in five languages with full inter-compatibility.</strong>
</p>

---

## Documentation

Full documentation is available at [moukrea.github.io/cairn](https://moukrea.github.io/cairn/).

## What is cairn?

cairn eliminates the recurring effort of implementing P2P communication infrastructure. Instead of rebuilding signaling, NAT traversal, relay fallback, encryption, and peer discovery for every new project, you install cairn and get a working encrypted P2P channel in minutes -- no server infrastructure required.

Any language combination works seamlessly: a Rust peer connects to a PHP peer, a Go peer to a TypeScript peer. All implementations share the same wire protocol, cryptographic primitives, and pairing system.

cairn is secure by default -- end-to-end encryption via Noise XX + Double Ratchet, verified pairing via SPAKE2, and forward secrecy are always on with no opt-in required.

## Architecture

cairn is organized in distinct layers:

| Layer | Responsibility |
|-------|---------------|
| **Transport** | Raw connectivity: UDP, TCP, WebSocket, QUIC |
| **NAT Traversal** | Hole punching, STUN/TURN, relay fallback |
| **Security** | Noise XX handshake, SPAKE2 PAKE, Double Ratchet sessions |
| **Session** | Persistent sessions surviving transport churn and reconnection |
| **Discovery** | Peer finding via mDNS, DHT, BitTorrent trackers, signaling |
| **Mesh** | Optional multi-hop routing through trusted peers |
| **API** | Idiomatic per-language developer interface |

## Language Implementations

| Language | Package | Install |
|----------|---------|---------|
| Rust | `packages/rs/cairn-p2p` | `cargo add cairn-p2p` |
| TypeScript | `packages/ts/cairn-p2p` | `npm install cairn-p2p` |
| Go | `packages/go/cairn-p2p` | `go get github.com/moukrea/cairn/packages/go/cairn-p2p` |
| Python | `packages/py/cairn-p2p` | `pip install cairn-p2p` |
| PHP | `packages/php/cairn-p2p` | `composer require moukrea/cairn-p2p` |

All five implementations are wire-compatible and can communicate with each other.

## Infrastructure Tiers

cairn uses a progressive infrastructure model. Start with zero configuration, then optionally add components as your needs grow.

### Tier 0 -- Zero-Config (Default)

Install and use. Leverages public STUN servers, libp2p DHT, BitTorrent trackers, and mDNS for LAN discovery. Covers most home network and cloud server scenarios.

### Tier 1 -- Signaling & Relay

Deploy cairn's companion signaling server and/or TURN relay (single Docker container each). Adds symmetric NAT traversal, corporate firewall penetration, and sub-second peer discovery.

```bash
docker run cairn/signaling
docker run cairn/relay
```

### Tier 2 -- Server-Mode Peer

Run a cairn peer in always-on server mode. Adds offline message delivery (store-and-forward), personal relay, and multi-device sync.

## Quick Start

### Rust

```rust
use cairn_p2p::CairnNode;

let node = CairnNode::builder().build().await?;
let peer = node.pair_with_pin("123456").await?;
peer.send(b"hello from rust").await?;
```

### TypeScript

```typescript
import { CairnNode } from 'cairn-p2p';

const node = await CairnNode.create();
const peer = await node.pairWithPin('123456');
await peer.send(Buffer.from('hello from typescript'));
```

### Go

```go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

node, _ := cairn.NewNode(cairn.DefaultConfig())
peer, _ := node.PairWithPIN("123456")
peer.Send([]byte("hello from go"))
```

### Python

```python
from cairn import CairnNode

node = await CairnNode.create()
peer = await node.pair_with_pin("123456")
await peer.send(b"hello from python")
```

### PHP

```php
use Cairn\CairnNode;

$node = CairnNode::create($loop);
$peer = $node->pairWithPin('123456');
$peer->send('hello from php');
```

## Project Structure

```
packages/
  rs/cairn-p2p/     Rust reference implementation
  ts/cairn-p2p/     TypeScript implementation
  go/cairn-p2p/     Go implementation
  py/cairn-p2p/     Python implementation
  php/cairn-p2p/    PHP implementation
services/
  signaling/        WebSocket signaling server (Rust)
  relay/            TURN relay server (Rust)
demo/
  messaging/        Cross-language chat demo
  folder-sync/      File synchronization demo
  server-node/      Always-on server peer demo
conformance/        Cross-language conformance test suite
docs/               Design documents and specifications
```

## Documentation

- [Design Document](docs/design-doc.md) -- Architecture and protocol design
- [Product Requirements](docs/PRD.md) -- Requirements and feature summary
- [Technical Specification](docs/technical-specification.md) -- API and protocol details

## License

Licensed under the [MIT License](LICENSE).
