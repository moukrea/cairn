---
sidebar_position: 4
title: "Server Node"
---

# Server Node

A server-mode peer is an always-on cairn node that extends the network with store-and-forward messaging, traffic relaying, and multi-device synchronization.

## What a Server-Mode Peer Enables

- **Store-and-forward mailbox**: Messages sent to offline peers are held on the server and delivered when they reconnect. No messages are lost due to temporary disconnections.
- **Personal relay**: The server relays traffic between peers that cannot connect directly (e.g., both behind symmetric NATs), without relying on a public TURN server.
- **Multi-device sync hub**: The server acts as a central sync point for all paired devices, enabling automatic synchronization across laptops, phones, and desktops.

## Docker Deployment

```bash
docker run -d \
  -v cairn-data:/data \
  -e CAIRN_MGMT_TOKEN=your-secret-token \
  -p 9090:9090 \
  ghcr.io/moukrea/cairn-server
```

## Configuration Reference

All configuration is via environment variables:

| Variable                    | Default  | Description                              |
|-----------------------------|----------|------------------------------------------|
| `CAIRN_DATA_DIR`            | `/data`  | Persistent data directory                |
| `CAIRN_MGMT_ENABLED`       | `true`   | Enable management REST API               |
| `CAIRN_MGMT_TOKEN`         | --       | Bearer token for management API auth     |
| `CAIRN_PSK`                | --       | Pre-shared key for automatic pairing     |
| `CAIRN_FORWARD_ENABLED`    | `true`   | Enable store-and-forward mailbox         |
| `CAIRN_FORWARD_MAX_PER_PEER`| `10000` | Max queued messages per peer             |
| `CAIRN_FORWARD_MAX_AGE`    | `7d`     | Max message retention period             |
| `CAIRN_FORWARD_MAX_TOTAL`  | `1GB`    | Max total mailbox storage                |
| `CAIRN_SIGNAL_SERVERS`     | --       | Comma-separated signaling server URLs    |
| `CAIRN_TURN_SERVERS`       | --       | Comma-separated TURN relay URLs          |

## Management REST API

The management API runs on port `9090` when `CAIRN_MGMT_ENABLED=true`. All endpoints require a `Bearer` token set via `CAIRN_MGMT_TOKEN`.

### Health Check

```bash
curl http://localhost:9090/health
```

Returns `200 OK` with server status.

### List Paired Peers

```bash
curl -H "Authorization: Bearer your-secret-token" \
  http://localhost:9090/peers
```

Returns a JSON array of paired peer IDs and their connection status.

### Approve a Pairing Request

```bash
curl -X POST \
  -H "Authorization: Bearer your-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"peer_id": "5Hb7..."}' \
  http://localhost:9090/peers/approve
```

## Headless Pairing

Server nodes typically run unattended, so interactive pairing is impractical.

### Pre-Shared Key (PSK)

Set `CAIRN_PSK` and clients can pair automatically without interactive PIN exchange:

```bash
# Server
docker run -e CAIRN_PSK=my-shared-key ghcr.io/moukrea/cairn-server

# Client connects using the same PSK
```

### Command-Line Pairing

Generate a PIN or link from the server command line:

```bash
# Generate a pairing PIN
cairn-server pair --pin

# Generate a pairing link
cairn-server pair --link
```

## Integration with Signaling + Relay

For a complete Tier 2 deployment, run the server node alongside signaling and relay services. Use the Docker Compose file at `demo/server-node/docker-compose.yml`:

```yaml
services:
  signaling:
    image: ghcr.io/moukrea/cairn-signal:latest
    environment:
      CAIRN_SIGNAL_LISTEN_ADDR: "0.0.0.0:8443"

  relay:
    image: ghcr.io/moukrea/cairn-relay:latest
    environment:
      CAIRN_RELAY_LISTEN_ADDR: "0.0.0.0:3478"

  server:
    build:
      context: ../../
      dockerfile: demo/server-node/Dockerfile
    environment:
      CAIRN_SIGNAL_SERVERS: "ws://signaling:8443"
      CAIRN_TURN_SERVERS: "turn:relay:3478"
      CAIRN_MGMT_ENABLED: "true"
    ports:
      - "9090:9090"
    volumes:
      - server-data:/data

volumes:
  server-data:
```

Start the full stack:

```bash
docker compose up -d
```

The server automatically connects to the signaling server for peer discovery and uses the relay as a fallback transport.
