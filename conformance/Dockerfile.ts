FROM node:22-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files for dependency caching
COPY packages/ts/cairn-p2p/package.json packages/ts/cairn-p2p/package-lock.json ./
RUN npm ci --production

# Install js-yaml for the conformance runner (YAML scenario parsing)
RUN npm install js-yaml@4

# Copy the TypeScript source and build
COPY packages/ts/cairn-p2p/ ./
RUN npm run build 2>/dev/null || true

# Copy the conformance runner and network shaper
COPY conformance/network-shaper.sh /usr/local/bin/network-shaper
COPY conformance/runners/ts-runner.js /usr/local/bin/cairn-conformance-runner.js

RUN printf '#!/bin/sh\nexec node /usr/local/bin/cairn-conformance-runner.js "$@"\n' > /usr/local/bin/cairn-conformance-runner && \
    chmod +x /usr/local/bin/network-shaper /usr/local/bin/cairn-conformance-runner

WORKDIR /conformance
COPY conformance/tests/ tests/
COPY conformance/fixtures/ fixtures/
COPY conformance/vectors/ vectors/

ENTRYPOINT ["node", "/usr/local/bin/cairn-conformance-runner.js"]
