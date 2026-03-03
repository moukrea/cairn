# Conformance Testing

Cross-language interoperability test suite for cairn. Validates that all 5 language implementations (Rust, TypeScript, Go, Python, PHP) produce wire-compatible output, agree on cryptographic results, and interoperate correctly across every language pair.

## Overview

cairn supports 5 languages that must communicate seamlessly over the wire. The conformance suite runs every test scenario across all 10 unique language pairs (5 choose 2), verifying:

- **Wire protocol compliance** -- CBOR encoding/decoding produces identical bytes
- **Cryptographic compatibility** -- AEAD, HKDF, SPAKE2, double ratchet agree on outputs
- **Pairing interop** -- PIN, QR, link, PSK pairing completes across any two languages
- **Session lifecycle** -- establish, heartbeat, resume, reestablish work cross-language
- **Transport fallback** -- fallback chains, migration, and exhaustion handling
- **Mesh routing** -- multi-hop relay across heterogeneous peers
- **Store-and-forward** -- offline delivery via server-mode peers

## Quick Start

```bash
cd conformance

# Build all language containers
docker compose build

# Run the full Tier 0 suite (peer-only, no infrastructure)
docker compose --profile tier0 up
```

## Running Tests

### Full suite (all tiers)

```bash
docker compose run tests
```

### By tier

```bash
# Tier 0: peer-only (pairing, session, data, wire, crypto)
docker compose --profile tier0 up

# Tier 1: + signaling server + TURN relay (adds transport tests)
docker compose --profile tier1 up

# Tier 2: + server-mode peer (adds forward/store-and-forward tests)
docker compose --profile tier2 up
```

### By language pair

```bash
docker compose run tests --pair rust-ts
docker compose run tests --pair go-php
```

### By category

```bash
docker compose run tests --category pairing
docker compose run tests --category crypto
docker compose run tests --category wire
```

### By specific scenario

```bash
docker compose run tests --scenario pair-pin-rust-ts
```

### Combined filters

```bash
docker compose run tests --tier 1 --pair rust-go --category transport
```

### Environment variables

| Variable              | Default             | Description                     |
|-----------------------|---------------------|---------------------------------|
| `CAIRN_TEST_TIMEOUT`  | `60`                | Per-scenario timeout (seconds)  |
| `CAIRN_TEST_TIER`     | `0`                 | Default tier if not specified    |
| `CAIRN_ARTIFACTS_DIR` | `/results/artifacts`| Directory for failure artifacts |
| `CAIRN_RESULTS_DIR`   | `/results`          | Directory for results output    |

## Directory Structure

```
conformance/
  docker-compose.yml       Orchestration: language containers, infra, test runner
  run-tests.sh             Test runner script (generates results matrix)
  network-shaper.sh        tc/netem wrapper for simulating network conditions
  tests/
    scenario-schema.yml    YAML schema documentation for test scenarios
    pairing/               Pairing interop scenarios (PIN, QR, link, PSK, SAS)
    session/               Session lifecycle scenarios
    data/                  Data transfer and channel multiplexing
    wire/                  CBOR wire protocol encoding/decoding
    crypto/                Cryptographic primitive verification
    transport/             Transport fallback and migration (Tier 1+)
    mesh/                  Mesh routing scenarios
    forward/               Store-and-forward scenarios (Tier 2)
  fixtures/                Shared test fixtures (keypairs, CBOR samples, pairing vectors)
  vectors/                 Deterministic test vectors (CBOR, crypto, pairing, protocol)
  runners/                 Per-language runner scripts
    rust-runner.sh
    ts-runner.js
    go-runner.sh
    py_conformance.py
    php-runner.php
  Dockerfile.rust          Rust language container
  Dockerfile.ts            TypeScript language container
  Dockerfile.go            Go language container
  Dockerfile.py            Python language container
  Dockerfile.php           PHP language container
```

## Test Scenario Format

Scenarios are defined in YAML files under `tests/<category>/`. Each file contains a `scenarios` list. Example:

```yaml
scenarios:
  - scenario: pair-pin-rust-ts
    description: PIN code pairing between Rust and TypeScript
    tier: 0
    category: pairing
    participants:
      - { role: initiator, lang: rust }
      - { role: responder, lang: ts }
    network: { nat_profile: open }
    actions:
      - type: pair
        actor: initiator
        params: { mechanism: pin, flow: initiation }
      - type: pair
        actor: responder
        params: { mechanism: pin, flow: initiation, pin_source: initiator }
    expected:
      - { type: status, actor: initiator, params: { pairing: complete } }
      - { type: status, actor: responder, params: { pairing: complete } }
      - { type: crypto_match, params: { description: "SPAKE2 shared secret matches" } }
    timeout_ms: 30000
    budget_ms: 30000
```

### Schema fields

| Field          | Description                                                    |
|----------------|----------------------------------------------------------------|
| `scenario`     | Unique identifier (matches filename without extension)         |
| `description`  | Human-readable description                                     |
| `tier`         | Required infrastructure tier (0, 1, or 2)                      |
| `category`     | Test category (pairing, session, data, wire, crypto, transport, mesh, forward) |
| `participants` | List of `{role, lang}` -- role is initiator/responder/relay/server |
| `network`      | Network conditions: `nat_profile`, `netem` (delay, jitter, loss), `disconnect` |
| `actions`      | Ordered list of actions: pair, establish_session, send_data, verify_cbor, etc. |
| `expected`     | Expected outcomes: status, message_received, cbor_match, crypto_match, etc. |
| `timeout_ms`   | Maximum scenario duration                                      |
| `budget_ms`    | Performance budget from spec                                   |

## Tiers

| Tier | Infrastructure           | Categories Enabled                                  |
|------|--------------------------|-----------------------------------------------------|
| 0    | Language containers only | pairing, session, data, wire, crypto                |
| 1    | + signaling + TURN relay | + transport                                         |
| 2    | + server-mode peer       | + forward                                           |

The `transport` category requires Tier 1 (signaling server and TURN relay must be running). The `forward` category requires Tier 2 (server-mode peer for store-and-forward).

## Writing a Runner for a New Language

Each language needs a runner script that:

1. Reads scenario names from stdin (one per line)
2. Locates the scenario YAML file in `/conformance/tests/`
3. Executes the scenario actions using the language's cairn implementation
4. Outputs one JSON-lines result per scenario to stdout

Result format:

```json
{"scenario":"pair-pin-rust-ts","status":"pass","duration_ms":1234,"diagnostics":{}}
```

Place the runner at `runners/<lang>-runner.<ext>` and reference it from the language's Dockerfile as the `ENTRYPOINT` under the name `cairn-conformance-runner`.

## Adding Test Scenarios

1. Create a YAML file in the appropriate `tests/<category>/` directory
2. Follow the schema documented in `tests/scenario-schema.yml`
3. Each scenario needs a unique `scenario` identifier
4. Set the correct `tier` -- 0 for peer-only, 1 for infra-dependent, 2 for server-dependent
5. Define `participants` with roles and language filters
6. List `actions` in execution order and `expected` outcomes
7. Set `timeout_ms` and `budget_ms` per the spec performance budgets

### Performance budgets

| Category  | Budget  |
|-----------|---------|
| wire      | 2s      |
| crypto    | 2s      |
| data      | 5s      |
| session   | 10s     |
| mesh      | 20s     |
| pairing   | 30s     |
| transport | 30s     |
| forward   | 30s     |

## Results

Test results are written to the shared `results` volume:

- `results.jsonl` -- one JSON line per scenario pair result
- `summary.json` -- aggregate pass/fail/skip counts
- `artifacts/<scenario>/<pair>/` -- failure artifacts (result JSON, container logs, network state)

## License

Licensed under the [MIT License](../LICENSE).
