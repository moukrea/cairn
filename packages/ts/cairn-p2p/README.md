# cairn-p2p

TypeScript implementation of the cairn P2P connectivity library.

## Installation

```bash
npm install cairn-p2p
```

## Requirements

- Node.js 18+ or modern browser
- TypeScript 5.5+ (for development)

## Quick Start

```typescript
import { CairnNode } from 'cairn-p2p';

const node = await CairnNode.create();
const peer = await node.pairWithPin('123456');
await peer.send(Buffer.from('hello'));
```

## API Overview

- `CairnNode` -- Main entry point, manages identity, sessions, and discovery
- `Session` -- Persistent encrypted session with a peer
- `PeerIdentity` -- Ed25519 identity with Peer ID derivation
- `CairnConfig` -- Configuration with tier presets

## Key Dependencies

- `libp2p` -- Transport, NAT traversal, DHT discovery
- `@noble/curves` / `@noble/hashes` -- Cryptographic primitives
- `@noble/ciphers` -- AEAD encryption
- `cborg` -- CBOR wire protocol encoding
- `eventemitter3` -- Event-driven API

## License

Licensed under the [MIT License](../../../LICENSE).
