# Multi-stage build for cairn-signal (WebSocket signaling server)
# Build from repo root: docker build -f services/signaling/Dockerfile -t cairn-signal .

FROM rust:1-bookworm AS builder
WORKDIR /build

# Copy workspace-level files
COPY Cargo.toml Cargo.lock ./

# Copy all workspace members required for resolution
COPY packages/rs/cairn-p2p/ packages/rs/cairn-p2p/
COPY services/signaling/ services/signaling/
COPY services/relay/ services/relay/
COPY conformance/runners/rust-runner/ conformance/runners/rust-runner/

# Build only the signaling server in release mode
RUN cargo build --release -p cairn-signal && \
    strip target/release/cairn-signal

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /build/target/release/cairn-signal /usr/local/bin/

EXPOSE 443 8443

ENTRYPOINT ["cairn-signal"]
