FROM python:3.13-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files for dependency caching
COPY packages/py/cairn-p2p/pyproject.toml ./
RUN pip install --no-cache-dir . 2>/dev/null || pip install --no-cache-dir cbor2 cryptography spake2 pyyaml

# Copy the Python source
COPY packages/py/cairn-p2p/ ./
RUN pip install --no-cache-dir -e . 2>/dev/null || true

# Copy the conformance runner and network shaper
COPY conformance/network-shaper.sh /usr/local/bin/network-shaper
COPY conformance/runners/py_conformance.py /usr/local/bin/cairn-conformance-runner.py

RUN printf '#!/bin/sh\nexec python /usr/local/bin/cairn-conformance-runner.py "$@"\n' > /usr/local/bin/cairn-conformance-runner && \
    chmod +x /usr/local/bin/network-shaper /usr/local/bin/cairn-conformance-runner

WORKDIR /conformance
COPY conformance/tests/ tests/
COPY conformance/fixtures/ fixtures/
COPY conformance/vectors/ vectors/

ENTRYPOINT ["python", "/usr/local/bin/cairn-conformance-runner.py"]
