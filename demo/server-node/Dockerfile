FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --bin cairn-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/cairn-server /usr/local/bin/
VOLUME /data
ENV CAIRN_DATA_DIR=/data
ENV CAIRN_MGMT_ENABLED=true
ENV CAIRN_MGMT_TOKEN=""
EXPOSE 9090
ENTRYPOINT ["cairn-server"]
