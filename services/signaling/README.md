# cairn Signaling Server

Lightweight WebSocket message router for real-time peer discovery and handshake relay. Peers connect via WebSocket, and the server forwards CBOR-encoded signaling messages between them to facilitate NAT traversal and session establishment.

## Prerequisites

- Rust 1.75+ (workspace edition)
- Part of the cairn Cargo workspace

## Build

```bash
# From the repository root
cargo build --release -p cairn-signal
```

The binary is produced at `target/release/cairn-signal`.

## Configuration

All options can be set via CLI flags or environment variables.

| Flag             | Env Variable                | Default         | Description                                      |
|------------------|-----------------------------|-----------------|--------------------------------------------------|
| `--listen-addr`  | `CAIRN_SIGNAL_LISTEN_ADDR`  | `0.0.0.0:443`  | Listen address (host:port)                       |
| `--tls-cert`     | `CAIRN_SIGNAL_TLS_CERT`     | --              | Path to TLS certificate chain (PEM)              |
| `--tls-key`      | `CAIRN_SIGNAL_TLS_KEY`      | --              | Path to TLS private key (PEM)                    |
| `--auth-token`   | `CAIRN_SIGNAL_AUTH_TOKEN`   | --              | Bearer token for client authentication           |

Both `--tls-cert` and `--tls-key` must be provided together. If omitted, the server runs in plaintext WebSocket mode.

If `--auth-token` is omitted, all connections are accepted without authentication.

## Deployment

### Bare metal

```bash
# Plaintext (development)
cairn-signal --listen-addr 0.0.0.0:8080

# With TLS and authentication (production)
cairn-signal \
  --listen-addr 0.0.0.0:443 \
  --tls-cert /etc/cairn/cert.pem \
  --tls-key /etc/cairn/key.pem \
  --auth-token "your-secret-token"
```

### Docker

```dockerfile
FROM rust:1.75 AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p cairn-signal

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/cairn-signal /usr/local/bin/
EXPOSE 443
CMD ["cairn-signal"]
```

```bash
docker build -t cairn-signal .
docker run -d \
  -p 443:443 \
  -e CAIRN_SIGNAL_TLS_CERT=/certs/cert.pem \
  -e CAIRN_SIGNAL_TLS_KEY=/certs/key.pem \
  -e CAIRN_SIGNAL_AUTH_TOKEN=secret \
  -v /path/to/certs:/certs:ro \
  cairn-signal
```

## Security

- **TLS**: Provide PEM certificate and key files for encrypted WebSocket connections (wss://).
- **Authentication**: Set an auth token to require `Authorization: Bearer <token>` on all WebSocket upgrade requests. Without it, the server is open to all clients.
- **No state persistence**: The signaling server is stateless -- it routes messages in memory only. No data is written to disk.

## Logging

Uses the `tracing` crate with `tracing-subscriber`. Control log levels via the `RUST_LOG` environment variable:

```bash
# Default: info level
RUST_LOG=info cairn-signal

# Debug level for cairn modules
RUST_LOG=cairn_signal=debug cairn-signal

# Trace all components
RUST_LOG=trace cairn-signal
```

## Graceful Shutdown

The server handles `SIGINT` (Ctrl+C) and `SIGTERM` for graceful shutdown. Active WebSocket connections are closed before the process exits.

## License

Licensed under the [MIT License](../../LICENSE).
