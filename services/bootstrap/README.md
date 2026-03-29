# cairn-bootstrap

Lightweight Kademlia DHT bootstrap node for cairn P2P.

Bridges the TCP/QUIC and WebSocket DHT overlay gap by listening on all three transports and participating in the Kademlia DHT. Provider records published by native hosts (TCP/QUIC) become discoverable by browser clients (WSS) through this node.

## Usage

```bash
cairn-bootstrap \
  --tcp-addr 0.0.0.0:4001 \
  --quic-addr 0.0.0.0:4001 \
  --ws-addr 0.0.0.0:4002 \
  --data-dir /var/lib/cairn-bootstrap \
  --bootstrap-peers "/dns/sv15.bootstrap.libp2p.io/tcp/4001/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"
```

## Docker

```bash
docker build -t cairn-bootstrap -f services/bootstrap/Dockerfile .
docker run -p 4001:4001/tcp -p 4001:4001/udp -p 4002:4002/tcp cairn-bootstrap
```

## Configuration

All options can be set via CLI flags or environment variables:

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--tcp-addr` | `CAIRN_BOOTSTRAP_TCP` | `0.0.0.0:4001` | TCP listen address |
| `--quic-addr` | `CAIRN_BOOTSTRAP_QUIC` | `0.0.0.0:4001` | QUIC (UDP) listen address |
| `--ws-addr` | `CAIRN_BOOTSTRAP_WS` | `0.0.0.0:4002` | WebSocket listen address |
| `--data-dir` | `CAIRN_BOOTSTRAP_DATA` | `.cairn-bootstrap` | Data directory for identity |
| `--bootstrap-peers` | `CAIRN_BOOTSTRAP_PEERS` | (IPFS defaults) | Additional bootstrap peers (comma-separated multiaddrs) |
| `--log-level` | `RUST_LOG` | `info` | Log level |

## How it works

1. Starts a cairn-p2p node with Ed25519 identity
2. Listens on TCP (port 4001), QUIC (port 4001), and WebSocket (port 4002)
3. Joins the Kademlia DHT via IPFS bootstrap nodes (or custom `--bootstrap-peers`)
4. Native hosts publish provider records via TCP/QUIC
5. Browser clients query via WebSocket and find those same records
6. PeerId is printed at startup for use as a bootstrap address
