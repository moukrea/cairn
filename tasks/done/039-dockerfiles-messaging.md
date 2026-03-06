# Task 039: Demo Dockerfiles -- Messaging

## Status
done

## Dependencies
- None

## Spec References
- spec/07-demo-dockerization.md

## Scope
Create all 5 Dockerfiles for the messaging demo: Rust, TypeScript, Go, Python, and PHP. Each Dockerfile builds its respective messaging demo and produces an image suitable for interactive terminal use.

## Acceptance Criteria
- [ ] `demo/messaging/Dockerfile.rust` uses multi-stage build with `debian:bookworm-slim` runtime, includes `ca-certificates`, does not run as root
- [ ] `demo/messaging/Dockerfile.typescript` uses Node.js base image, installs deps, does not run as root
- [ ] `demo/messaging/Dockerfile.go` uses multi-stage build with `debian:bookworm-slim` runtime, includes `ca-certificates`, does not run as root
- [ ] `demo/messaging/Dockerfile.python` uses Python base image, installs deps, does not run as root
- [ ] `demo/messaging/Dockerfile.php` uses PHP base image, installs deps, does not run as root
- [ ] All Dockerfiles set ENTRYPOINT to the demo binary/script and support `--signal` and `--turn` flags
- [ ] All images build successfully from repo root: `docker build -f demo/messaging/Dockerfile.{lang} .`

## Implementation Notes
All images are built from the repository root (context = `.`).

**Compiled languages (Rust, Go)** -- multi-stage pattern:
```dockerfile
# Builder stage
FROM {lang-image} AS builder
WORKDIR /build
COPY . .
RUN {build-command}

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/false cairn
USER cairn
COPY --from=builder /build/{binary} /usr/local/bin/
ENTRYPOINT ["{binary}"]
```

**Interpreted languages (TypeScript, Python, PHP)** -- single-stage pattern:
```dockerfile
FROM {lang-image}
WORKDIR /app
COPY {dependency-file} .
RUN {install-command}
COPY . .
RUN useradd -r -s /bin/false cairn || adduser -D cairn
USER cairn
ENTRYPOINT ["{runtime}", "{entry-point}"]
```

Requirements for ALL Dockerfiles:
- Must NOT run as root in the final stage (add a non-root user)
- Must NOT embed secrets or credentials
- Include `ca-certificates` for TLS (compiled languages)
- Set ENTRYPOINT to the demo binary/script
- Support `-it` compatible entrypoints (interactive terminal demos)
- Target platforms: `linux/amd64`, `linux/arm64`

Image naming: `ghcr.io/moukrea/cairn-demo-messaging-{lang}` (rust, ts, go, py, php)

## Files to Create or Modify
- `demo/messaging/Dockerfile.rust` (new)
- `demo/messaging/Dockerfile.typescript` (new)
- `demo/messaging/Dockerfile.go` (new)
- `demo/messaging/Dockerfile.python` (new)
- `demo/messaging/Dockerfile.php` (new -- but only this file, not the demo code)

## Verification Commands
- `docker build -f demo/messaging/Dockerfile.rust -t cairn-demo-messaging-rust .`
- `docker build -f demo/messaging/Dockerfile.typescript -t cairn-demo-messaging-ts .`
- `docker build -f demo/messaging/Dockerfile.go -t cairn-demo-messaging-go .`
- `docker build -f demo/messaging/Dockerfile.python -t cairn-demo-messaging-py .`
- `docker build -f demo/messaging/Dockerfile.php -t cairn-demo-messaging-php .`
