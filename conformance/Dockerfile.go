FROM golang:1.22-bookworm AS builder

WORKDIR /build

# Copy cairn-p2p source
COPY packages/go/cairn-p2p/ ./packages/go/cairn-p2p/

# Copy the conformance runner source
COPY conformance/runners/go-runner/ ./conformance/runners/go-runner/

# The runner's go.mod uses: replace github.com/moukrea/cairn/packages/go/cairn-p2p => ../../../packages/go/cairn-p2p
# This path is correct relative to the runner directory within the build context.

# Download dependencies and build the runner binary
RUN cd conformance/runners/go-runner && go mod download && \
    CGO_ENABLED=0 go build -o /usr/local/bin/cairn-conformance-runner .

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iptables ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled runner binary and network shaper
COPY --from=builder /usr/local/bin/cairn-conformance-runner /usr/local/bin/cairn-conformance-runner
COPY conformance/network-shaper.sh /usr/local/bin/network-shaper

RUN chmod +x /usr/local/bin/network-shaper /usr/local/bin/cairn-conformance-runner

WORKDIR /conformance
COPY conformance/tests/ tests/
COPY conformance/fixtures/ fixtures/
COPY conformance/vectors/ vectors/

ENTRYPOINT ["cairn-conformance-runner"]
