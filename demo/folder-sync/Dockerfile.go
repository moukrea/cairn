# cairn-folder-sync: P2P folder sync demo (Go)
# Build from repo root: docker build -f demo/folder-sync/Dockerfile.go -t cairn-demo-folder-sync-go .

# --- Builder stage ---
FROM golang:1.24-bookworm AS builder
WORKDIR /build
COPY . .
WORKDIR /build/demo/folder-sync/go
RUN go build -o cairn-folder-sync .

# --- Runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/false cairn
USER cairn
COPY --from=builder /build/demo/folder-sync/go/cairn-folder-sync /usr/local/bin/cairn-folder-sync
ENTRYPOINT ["cairn-folder-sync"]
