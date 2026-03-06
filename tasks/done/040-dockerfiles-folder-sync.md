# Task 040: Demo Dockerfiles -- Folder Sync

## Status
done

## Dependencies
- 036-folder-sync-go (Go implementation must exist for its Dockerfile)
- 037-folder-sync-python (Python implementation must exist for its Dockerfile)
- 038-folder-sync-php (PHP implementation must exist for its Dockerfile)

## Spec References
- spec/07-demo-dockerization.md

## Scope
Create all 5 Dockerfiles for the folder-sync demo: Rust, TypeScript, Go, Python, and PHP. Each Dockerfile builds its respective folder-sync demo and produces an image suitable for volume-mounted directory syncing.

## Acceptance Criteria
- [ ] `demo/folder-sync/Dockerfile.rust` uses multi-stage build with `debian:bookworm-slim` runtime, includes `ca-certificates`, does not run as root
- [ ] `demo/folder-sync/Dockerfile.typescript` uses Node.js base image, installs deps, does not run as root
- [ ] `demo/folder-sync/Dockerfile.go` uses multi-stage build with `debian:bookworm-slim` runtime, includes `ca-certificates`, does not run as root
- [ ] `demo/folder-sync/Dockerfile.python` uses Python base image, installs deps, does not run as root
- [ ] `demo/folder-sync/Dockerfile.php` uses PHP base image, installs deps, does not run as root
- [ ] All Dockerfiles set ENTRYPOINT to the demo binary/script and support `--dir`, `--signal`, and `--turn` flags
- [ ] All images build successfully from repo root: `docker build -f demo/folder-sync/Dockerfile.{lang} .`

## Implementation Notes
All images are built from the repository root (context = `.`).

Follow the same Dockerfile patterns as task 039 (messaging Dockerfiles) but pointing to the folder-sync demo source code.

**Compiled languages (Rust, Go)** -- multi-stage pattern:
```dockerfile
FROM {lang-image} AS builder
WORKDIR /build
COPY . .
RUN {build-command}

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

Requirements:
- Must NOT run as root in the final stage
- Must NOT embed secrets or credentials
- Include `ca-certificates` for TLS (compiled languages)
- Target platforms: `linux/amd64`, `linux/arm64`

Image naming: `ghcr.io/moukrea/cairn-demo-folder-sync-{lang}` (rust, ts, go, py, php)

## Files to Create or Modify
- `demo/folder-sync/Dockerfile.rust` (new)
- `demo/folder-sync/Dockerfile.typescript` (new)
- `demo/folder-sync/Dockerfile.go` (new)
- `demo/folder-sync/Dockerfile.python` (new)
- `demo/folder-sync/Dockerfile.php` (new)

## Verification Commands
- `docker build -f demo/folder-sync/Dockerfile.rust -t cairn-demo-folder-sync-rust .`
- `docker build -f demo/folder-sync/Dockerfile.typescript -t cairn-demo-folder-sync-ts .`
- `docker build -f demo/folder-sync/Dockerfile.go -t cairn-demo-folder-sync-go .`
- `docker build -f demo/folder-sync/Dockerfile.python -t cairn-demo-folder-sync-py .`
- `docker build -f demo/folder-sync/Dockerfile.php -t cairn-demo-folder-sync-php .`
