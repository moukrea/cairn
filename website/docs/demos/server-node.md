---
sidebar_position: 3
title: "Server Node Demo"
---

# Server Node Demo

## What the Demo Does

An always-on server peer that provides:

- **Store-and-forward**: Messages sent to offline peers are queued and delivered when they reconnect.
- **Personal relay**: Relays traffic between peers that cannot connect directly.
- **Multi-device sync**: Acts as a central hub for synchronizing data across all paired devices.

The server exposes a management REST API for monitoring and administration.

## Running with Docker

```bash
docker run -d \
  -v cairn-data:/data \
  -e CAIRN_MGMT_TOKEN=your-secret-token \
  -p 9090:9090 \
  ghcr.io/moukrea/cairn-server
```

Expected output:

```
cairn-server started
  Data directory: /data
  Store-and-forward: enabled
  Forward max/peer: 10000
  Forward max age: 7d
  Relay capacity: 50
Server ready. Press Ctrl+C to stop.
```

## Docker Compose -- Full Tier 2 Stack

Run the server alongside signaling and relay for a complete infrastructure deployment. Use the compose file at `demo/server-node/docker-compose.yml`:

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

Start the stack:

```bash
cd demo/server-node
docker compose up -d
```

## Management API Examples

The management API runs on port `9090`. Authenticate with the bearer token set via `CAIRN_MGMT_TOKEN`.

### Health Check

```bash
curl http://localhost:9090/health
```

Returns server status and uptime.

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

Approves a pending pairing request from the specified peer.
