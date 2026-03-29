FROM rust:1.82 AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p cairn-bootstrap

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/cairn-bootstrap /usr/local/bin/
EXPOSE 4001/tcp 4001/udp 4002/tcp
ENTRYPOINT ["cairn-bootstrap"]
