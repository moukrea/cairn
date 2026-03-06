# cairn-chat: P2P messaging demo (Go)
# Build from repo root: docker build -f demo/messaging/Dockerfile.go -t cairn-demo-messaging-go .

# --- Builder stage ---
FROM golang:1.24-bookworm AS builder
WORKDIR /build
COPY . .
WORKDIR /build/demo/messaging/go
RUN go build -o cairn-chat .

# --- Runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/false cairn
USER cairn
COPY --from=builder /build/demo/messaging/go/cairn-chat /usr/local/bin/cairn-chat
ENTRYPOINT ["cairn-chat"]
