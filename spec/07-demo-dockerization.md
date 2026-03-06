# 07 — Demo Dockerization

## Cross-References

- **Depends on: `08-demo-folder-sync-expansion.md`** — The folder-sync Go/Python/PHP implementations must exist before their Dockerfiles can be built.
- **Depends on: `09-cicd-workflows.md`** — Demo Docker images are published via the tag-release CI/CD workflow.

---

## 1. Docker Image Naming Convention

All images are published to `ghcr.io` under the `moukrea` namespace.

| Demo | Image | Tag Pattern |
|------|-------|------------|
| messaging (Rust) | `ghcr.io/moukrea/cairn-demo-messaging-rust` | `latest`, `{version}` |
| messaging (TypeScript) | `ghcr.io/moukrea/cairn-demo-messaging-ts` | `latest`, `{version}` |
| messaging (Go) | `ghcr.io/moukrea/cairn-demo-messaging-go` | `latest`, `{version}` |
| messaging (Python) | `ghcr.io/moukrea/cairn-demo-messaging-py` | `latest`, `{version}` |
| messaging (PHP) | `ghcr.io/moukrea/cairn-demo-messaging-php` | `latest`, `{version}` |
| folder-sync (Rust) | `ghcr.io/moukrea/cairn-demo-folder-sync-rust` | `latest`, `{version}` |
| folder-sync (TypeScript) | `ghcr.io/moukrea/cairn-demo-folder-sync-ts` | `latest`, `{version}` |
| folder-sync (Go) | `ghcr.io/moukrea/cairn-demo-folder-sync-go` | `latest`, `{version}` |
| folder-sync (Python) | `ghcr.io/moukrea/cairn-demo-folder-sync-py` | `latest`, `{version}` |
| folder-sync (PHP) | `ghcr.io/moukrea/cairn-demo-folder-sync-php` | `latest`, `{version}` |
| server-node | `ghcr.io/moukrea/cairn-server` | `latest`, `{version}` |

Authentication: `GITHUB_TOKEN` from the workflow (already configured for existing service images).

---

## 2. Directory Structure

```
demo/
├── messaging/
│   ├── Dockerfile.rust
│   ├── Dockerfile.typescript
│   ├── Dockerfile.go
│   ├── Dockerfile.python
│   ├── Dockerfile.php
│   └── docker-compose.yml        # Run two peers locally
├── folder-sync/
│   ├── go/                       # NEW — Go implementation
│   ├── python/                   # NEW — Python implementation
│   ├── php/                      # NEW — PHP implementation
│   ├── Dockerfile.rust
│   ├── Dockerfile.typescript
│   ├── Dockerfile.go
│   ├── Dockerfile.python
│   ├── Dockerfile.php
│   └── docker-compose.yml
└── server-node/
    ├── Dockerfile                # Already exists
    └── docker-compose.yml        # NEW — with relay & signaling
```

---

## 3. Dockerfile Patterns

### 3.1 Compiled Languages (Rust, Go)

```dockerfile
# Builder stage
FROM {lang-image} AS builder
WORKDIR /build
COPY . .
RUN {build-command}

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/{binary} /usr/local/bin/
ENTRYPOINT ["{binary}"]
```

### 3.2 Interpreted Languages (TypeScript, Python, PHP)

```dockerfile
FROM {lang-image}
WORKDIR /app
COPY {dependency-file} .
RUN {install-command}
COPY . .
ENTRYPOINT ["{runtime}", "{entry-point}"]
```

### 3.3 Requirements for ALL Demo Dockerfiles

- Use multi-stage builds for compiled languages
- Include `ca-certificates` for TLS
- Set `ENTRYPOINT` to the demo binary/script
- Support `--signal` and `--turn` flags for optional server configuration
- Use `-it` compatible entrypoints (interactive terminal demos)
- **Must NOT run as root in the final stage**
- **Must NOT embed secrets or credentials**

---

## 4. Docker Compose Files

### 4.1 `demo/messaging/docker-compose.yml`

```yaml
services:
  peer-a:
    build:
      context: ../../
      dockerfile: demo/messaging/Dockerfile.rust
    stdin_open: true
    tty: true
    command: ["--pair-pin"]
    networks: [cairn]

  peer-b:
    build:
      context: ../../
      dockerfile: demo/messaging/Dockerfile.rust
    stdin_open: true
    tty: true
    # User enters PIN from peer-a
    networks: [cairn]

  # Optional infrastructure
  signaling:
    image: ghcr.io/moukrea/cairn-signal:latest
    networks: [cairn]
    profiles: ["infra"]

  relay:
    image: ghcr.io/moukrea/cairn-relay:latest
    networks: [cairn]
    profiles: ["infra"]

networks:
  cairn:
```

**Usage:**

```bash
# Basic (Tier 0)
docker compose up peer-a peer-b

# With infrastructure (Tier 1)
docker compose --profile infra up
```

### 4.2 `demo/folder-sync/docker-compose.yml`

```yaml
services:
  peer-a:
    build:
      context: ../../
      dockerfile: demo/folder-sync/Dockerfile.rust
    volumes:
      - ./sync-a:/sync
    command: ["--dir", "/sync", "--pair-pin"]

  peer-b:
    build:
      context: ../../
      dockerfile: demo/folder-sync/Dockerfile.rust
    volumes:
      - ./sync-b:/sync
    command: ["--dir", "/sync"]
```

### 4.3 `demo/server-node/docker-compose.yml`

Full Tier 2 stack:

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

---

## 5. Build Commands

All demo images are built from the repository root:

```bash
# Build from repo root
docker build -f demo/messaging/Dockerfile.rust -t cairn-demo-messaging-rust .
docker build -f demo/folder-sync/Dockerfile.go -t cairn-demo-folder-sync-go .

# Run interactively
docker run -it cairn-demo-messaging-rust --pair-pin
```

---

## 6. Target Platforms

All demo Docker images must be built for:

- `linux/amd64`
- `linux/arm64`

---

## 7. Testing Requirements

- Docker images must build successfully
- Docker Compose files must start without errors
- Smoke test: each Docker image starts and prints help/usage when run with `--help`

---

## 8. Security Requirements

- Demo Dockerfiles must not run as root in the final stage
- Demo Docker images must not embed secrets or credentials
- Include only `ca-certificates` and minimal runtime dependencies in final images
