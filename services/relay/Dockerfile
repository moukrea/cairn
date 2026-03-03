# Multi-stage build for cairn-relay (TURN relay server)
# Build from repo root: docker build -f services/relay/Dockerfile -t cairn-relay .

FROM rust:1-bookworm AS builder
WORKDIR /build

# Copy workspace-level files
COPY Cargo.toml Cargo.lock ./

# Copy all workspace members required for resolution
COPY packages/rs/cairn-p2p/ packages/rs/cairn-p2p/
COPY services/signaling/ services/signaling/
COPY services/relay/ services/relay/
COPY conformance/runners/rust-runner/ conformance/runners/rust-runner/

# Build only the relay server in release mode
RUN cargo build --release -p cairn-relay && \
    strip target/release/cairn-relay

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /build/target/release/cairn-relay /usr/local/bin/

# TURN UDP, TLS, REST API
EXPOSE 3478/udp 443 8080

ENTRYPOINT ["cairn-relay"]
