# cairn-p2p

Python implementation of the cairn P2P connectivity library.

## Installation

```bash
pip install cairn-p2p
```

## Requirements

- Python 3.11+

## Quick Start

```python
import asyncio
from cairn import CairnNode

async def main():
    node = await CairnNode.create()
    peer = await node.pair_with_pin("123456")
    await peer.send(b"hello")

asyncio.run(main())
```

## API Overview

- `CairnNode` -- Main entry point, manages identity, sessions, and discovery
- `Session` -- Persistent encrypted session with a peer
- `PeerIdentity` -- Ed25519 identity with Peer ID derivation
- `CairnConfig` -- Configuration with tier presets

## Key Dependencies

- `cryptography` -- AEAD encryption, key derivation
- `spake2` -- Password-authenticated key exchange for pairing
- `cbor2` -- CBOR wire protocol encoding
- `websockets` -- WebSocket transport
- `httpx` -- HTTP client for signaling

## Optional Dependencies

- `libp2p` -- libp2p transport integration
- `zeroconf` -- mDNS LAN discovery
- `kademlia` -- DHT discovery

## License

Licensed under the [MIT License](../../../LICENSE).
