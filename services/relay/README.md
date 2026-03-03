# cairn TURN Relay

TURN relay server implementing RFC 8656 for NAT traversal. Provides media relay for cairn peers that cannot establish direct connections due to symmetric NATs or restrictive firewalls.

## Prerequisites

- Rust 1.75+ (workspace edition)
- Part of the cairn Cargo workspace

## Build

```bash
# From the repository root
cargo build --release -p cairn-relay
```

The binary is produced at `target/release/cairn-relay`.

## Configuration

All options can be set via CLI flags or environment variables.

| Flag              | Env Variable                | Default            | Description                                          |
|-------------------|-----------------------------|--------------------|------------------------------------------------------|
| `--listen-addr`   | `CAIRN_RELAY_LISTEN_ADDR`   | `0.0.0.0:3478`    | TURN UDP listen address                              |
| `--port-range`    | `CAIRN_RELAY_PORT_RANGE`    | `49152-65535`      | Relay port range (format: start-end)                 |
| `--credentials`   | `CAIRN_RELAY_CREDENTIALS`   | --                 | Static credentials (format: user:pass, comma-separated) |
| `--rest-secret`   | `CAIRN_RELAY_REST_SECRET`   | --                 | Shared secret for REST API credential provisioning   |
| `--tls-cert`      | `CAIRN_RELAY_TLS_CERT`      | --                 | TLS certificate path (for TURN-over-TLS)             |
| `--tls-key`       | `CAIRN_RELAY_TLS_KEY`       | --                 | TLS private key path                                 |
| `--tls-addr`      | `CAIRN_RELAY_TLS_ADDR`      | `0.0.0.0:443`     | TLS listen address                                   |
| `--api-addr`      | `CAIRN_RELAY_API_ADDR`      | `127.0.0.1:8080`  | REST API listen address                              |
| `--realm`         | `CAIRN_RELAY_REALM`         | `cairn`            | TURN realm                                           |
| `--turn-uri`      | `CAIRN_RELAY_URI`           | auto-generated     | TURN URI advertised in REST API responses            |

## Deployment

### Bare metal

```bash
# With static credentials
cairn-relay --credentials "user1:pass1,user2:pass2"

# With REST API for dynamic credential provisioning
cairn-relay \
  --rest-secret "api-shared-secret" \
  --api-addr 127.0.0.1:8080

# Full production setup with TLS
cairn-relay \
  --listen-addr 0.0.0.0:3478 \
  --tls-cert /etc/cairn/cert.pem \
  --tls-key /etc/cairn/key.pem \
  --rest-secret "api-shared-secret" \
  --turn-uri "turn:relay.example.com:3478"
```

### Docker

```dockerfile
FROM rust:1.75 AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p cairn-relay

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/cairn-relay /usr/local/bin/
EXPOSE 3478/udp 443 8080
CMD ["cairn-relay"]
```

```bash
docker build -t cairn-relay .
docker run -d \
  -p 3478:3478/udp \
  -p 443:443 \
  -p 8080:8080 \
  -e CAIRN_RELAY_REST_SECRET=secret \
  -e CAIRN_RELAY_TLS_CERT=/certs/cert.pem \
  -e CAIRN_RELAY_TLS_KEY=/certs/key.pem \
  -v /path/to/certs:/certs:ro \
  cairn-relay
```

## REST API

When `--rest-secret` is configured, the relay exposes a REST API for dynamic TURN credential provisioning.

### `GET /credentials`

Returns temporary TURN credentials. Requires `Authorization: Bearer <rest-secret>`.

**Query parameters:**

| Parameter | Default | Description                  |
|-----------|---------|------------------------------|
| `ttl`     | `3600`  | Credential lifetime (seconds)|

**Example:**

```bash
curl -H "Authorization: Bearer api-shared-secret" \
  "http://127.0.0.1:8080/credentials?ttl=600"
```

**Response:**

```json
{
  "username": "1709312345:cairn-temp",
  "password": "base64-hmac-credential",
  "ttl": 600,
  "uris": ["turn:relay.example.com:3478"]
}
```

## Security

- **Credential authentication**: All TURN allocations require valid credentials (static or dynamic).
- **REST API authentication**: The `/credentials` endpoint requires Bearer token authentication using constant-time comparison to prevent timing attacks.
- **TLS**: Provide certificate and key files for TURN-over-TLS on port 443 (RFC 6062 TCP framing with 2-byte length prefix).
- **Allocation expiry**: Stale allocations are automatically cleaned up every 30 seconds.

## Logging

Uses the `tracing` crate with `tracing-subscriber`. Control log levels via the `RUST_LOG` environment variable:

```bash
# Default: info level
RUST_LOG=info cairn-relay

# Debug level
RUST_LOG=cairn_relay=debug cairn-relay

# Trace all components
RUST_LOG=trace cairn-relay
```

## Graceful Shutdown

The relay handles `SIGINT` (Ctrl+C) and `SIGTERM`. On shutdown, it stops accepting new allocations and reports the count of active allocations that will be dropped.

## License

Licensed under the [MIT License](../../LICENSE).
