# Server Node Demo

Docker-ready always-on server peer providing headless pairing, store-and-forward mailbox, relay bridging, and a management REST API.

## Features Exercised

- Server-mode cairn node (always-on, no GUI)
- Headless pairing (PIN, PSK, link, QR)
- Store-and-forward mailbox for offline message delivery
- Relay bridging for peers behind NATs
- Management REST API (localhost:9090)
- Multi-device sync hub with mesh routing
- Environment-variable-driven configuration

## Prerequisites

- Rust 1.75+
- `cargo` build tool

## Build

```bash
cargo build --release
```

## Configuration

All configuration is via environment variables:

| Variable                   | Default  | Description                              |
|----------------------------|----------|------------------------------------------|
| `CAIRN_DATA_DIR`           | `/data`  | Persistent data directory                |
| `CAIRN_MGMT_ENABLED`       | `true`   | Enable management REST API               |
| `CAIRN_MGMT_TOKEN`         | --       | Bearer token for management API auth     |
| `CAIRN_PSK`                | --       | Pre-shared key for automatic pairing     |
| `CAIRN_FORWARD_ENABLED`    | `true`   | Enable store-and-forward mailbox         |
| `CAIRN_FORWARD_MAX_PER_PEER`| `10000` | Max queued messages per peer             |
| `CAIRN_FORWARD_MAX_AGE`    | `7d`     | Max message retention period             |
| `CAIRN_FORWARD_MAX_TOTAL`  | `1GB`    | Max total mailbox storage                |
| `CAIRN_SIGNAL_SERVERS`     | --       | Comma-separated signaling server URLs    |
| `CAIRN_TURN_SERVERS`       | --       | Comma-separated TURN relay URLs          |

## Run

```bash
# Start the server node
CAIRN_DATA_DIR=./data CAIRN_MGMT_TOKEN=secret ./target/release/cairn-server

# With PSK for automatic pairing
CAIRN_PSK=my-shared-key ./target/release/cairn-server

# Generate a pairing PIN
./target/release/cairn-server pair --pin

# Generate a pairing link
./target/release/cairn-server pair --link
```

### Docker

```dockerfile
FROM rust:1.75 AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p cairn-server

FROM debian:bookworm-slim
COPY --from=builder /build/target/release/cairn-server /usr/local/bin/
VOLUME /data
ENV CAIRN_DATA_DIR=/data
EXPOSE 9090
CMD ["cairn-server"]
```

```bash
docker build -t cairn-server .
docker run -d -v cairn-data:/data -e CAIRN_MGMT_TOKEN=secret -p 9090:9090 cairn-server
```

## Expected Output

```
cairn-server started
  Data directory: ./data
  Store-and-forward: enabled
  Forward max/peer: 10000
  Forward max age: 7d
  Relay capacity: 50
Server ready. Press Ctrl+C to stop.
```

## Known Limitations

- Management REST API endpoints are scaffolded but pairing endpoints return placeholder data
- QR code generation requires full pairing integration (not yet wired)
- PSK auto-pairing is configured but the headless pairing module is not fully wired
