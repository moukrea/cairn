# cairn-p2p

Go implementation of the cairn P2P connectivity library.

## Installation

```bash
go get github.com/moukrea/cairn/packages/go/cairn-p2p
```

## Requirements

- Go 1.24+

## Quick Start

```go
package main

import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

func main() {
    node, _ := cairn.NewNode(cairn.DefaultConfig())
    peer, _ := node.PairWithPIN("123456")
    peer.Send([]byte("hello"))
}
```

## API Overview

- `Node` -- Main entry point, manages identity, sessions, and discovery
- `Session` -- Persistent encrypted session with a peer
- `PeerIdentity` -- Ed25519 identity with Peer ID derivation
- `CairnConfig` -- Configuration with tier presets

## Key Dependencies

- `filippo.io/edwards25519` -- Ed25519 operations
- `github.com/fxamacker/cbor/v2` -- CBOR wire protocol encoding
- `golang.org/x/crypto` -- Cryptographic primitives (ChaCha20-Poly1305, HKDF, Argon2)
- `github.com/stretchr/testify` -- Testing (dev)

## License

Licensed under the [MIT License](../../../LICENSE).
