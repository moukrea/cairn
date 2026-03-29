# Cairn Cross-Language Feature Parity Audit

**Date:** 2026-03-29
**Reference implementation:** Rust (`packages/rs/cairn-p2p`)
**Implementations audited:** Rust (RS), Go (GO), TypeScript server+browser (TS), Python (PY), PHP (PHP)

---

## Legend

| Symbol | Meaning |
|--------|---------|
| COMPLETE | Fully implemented, wire-compatible, tested |
| PARTIAL | Implemented but missing edge cases, tests, or minor features |
| STUB | Skeleton present, core logic returns errors or no-ops |
| MISSING | No file or type exists |

---

## 1. Parity Matrix

### 1.1 Crypto

| Sub-feature | RS | GO | TS | PY | PHP |
|---|---|---|---|---|---|
| Ed25519 identity keypair | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| X25519 keypair + DH | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| HKDF-SHA256 | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| AEAD (AES-256-GCM + ChaCha20-Poly1305) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Noise XX handshake | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Double Ratchet (Signal DR) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| SPAKE2 (Ed25519 group, cairn M/N points) | COMPLETE | COMPLETE | PARTIAL | PARTIAL | PARTIAL |
| SAS derivation (emoji + numeric) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Key store (filesystem + in-memory) | COMPLETE | PARTIAL | PARTIAL | PARTIAL | MISSING |

**Notes:**

- **SPAKE2 — GO:** Uses `filippo.io/edwards25519` with cairn-specific `hashToEdwardsPoint("cairn-spake2-M-v1" / "cairn-spake2-N-v1")`. Derives M/N via iterated SHA-256 + cofactor clear. Wire-compatible with Rust's `RustCrypto spake2` crate only if the hash-to-curve derivation produces identical points; this has not been confirmed by conformance vectors.
- **SPAKE2 — TS:** Uses `@noble/curves/ed25519`. Derives M/N via `sha256(label) mod L * G` (scalar multiplication of generator), which is a different construction from the Rust `Ed25519Group` hash-to-point. Not wire-compatible without conformance vector validation.
- **SPAKE2 — PY:** Wraps the `spake2` PyPI library using `SPAKE2_A`/`SPAKE2_B`. The library uses its own M/N constants; wire compatibility with Rust is unverified.
- **SPAKE2 — PHP:** Uses `sodium_crypto_core_ristretto255` (Ristretto255 group), while Rust uses the Ed25519 group. **Group mismatch — not wire-compatible.**
- **Key store — GO:** `InMemoryKeyStore` present; no filesystem backend.
- **Key store — TS:** `StorageAdapter` interface present in config; no built-in filesystem implementation (browser compensates with IndexedDB via adapter pattern, Node.js must supply adapter).
- **Key store — PY:** `crypto/storage.py` present with in-memory and filesystem; PARTIAL (missing encryption-at-rest).
- **Key store — PHP:** No key store abstraction; identity loaded from raw bytes only.

---

### 1.2 Pairing

| Sub-feature | RS | GO | TS | PY | PHP |
|---|---|---|---|---|---|
| PIN code (Crockford Base32, XXXX-XXXX) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| PIN normalization (I→1, L→1, O→0, strip U) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| PIN rendezvous ID derivation (HKDF) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| QR code pairing | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Pairing link (`cairn://pair?...`) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| PSK pairing | COMPLETE | COMPLETE | COMPLETE | MISSING | COMPLETE |
| Pairing state machine (SPAKE2 full flow) | COMPLETE | COMPLETE | COMPLETE | MISSING | COMPLETE |
| SAS flow (emoji + numeric verification) | COMPLETE | COMPLETE | COMPLETE | PARTIAL | COMPLETE |
| Rate limiter | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Unpairing | COMPLETE | COMPLETE | COMPLETE | PARTIAL | PARTIAL |
| Pairing adapter (custom transport) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |

**Notes:**

- **PSK — PY:** No `pairing/psk.py` or equivalent. PSK is referenced in `server/management.py` only as an env-var loader, without the full `PskMechanism` (entropy validation, rendezvous derivation, PAKE input) that exists in all other impls. Complexity: **S**.
- **Pairing state machine — PY:** No `pairing/state_machine.py`. The individual mechanism helpers exist (PIN, QR, link, SAS, rate-limit) but there is no `PairingSession` orchestrator driving SPAKE2 + Noise + key confirmation, matching `state_machine.rs` / `StateMachine.php` / `state_machine.go`. Only the Rust, Go, TS, and PHP impls have an integrated session driver. Complexity: **M**.
- **SAS flow — PY:** `pairing/sas.py` provides `derive_emoji_sas`, `derive_numeric_sas`, `verify_emoji_sas`, `verify_numeric_sas`; missing integration into any session flow since there is no state machine.
- **Unpairing — PY:** `node.py` exposes `unpair()` but no dedicated module mirroring `pairing/unpairing.py` (Rust) protocol messages.
- **Unpairing — PHP:** `Node.php` exposes unpair path but no dedicated message definitions mirroring `pairing/messages.rs`.

---

### 1.3 Session

| Sub-feature | RS | GO | TS | PY | PHP |
|---|---|---|---|---|---|
| Session state machine (7 states) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Session ID (UUID v7) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Message queue (FIFO/LIFO, overflow) | COMPLETE | COMPLETE | COMPLETE | PARTIAL | COMPLETE |
| Channel multiplexing | COMPLETE | COMPLETE | COMPLETE | PARTIAL | COMPLETE |
| Heartbeat / keepalive | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Session persistence (export/import) | COMPLETE | PARTIAL | PARTIAL | MISSING | MISSING |

**Notes:**

- **Message queue — PY:** `session.py` has queue logic but no explicit LIFO strategy or per-channel limits matching the Go/Rust `QueueStrategy` enum.
- **Channel multiplexing — PY:** `channel.py` exists but lacks the reserved channel constant (`__cairn_forward`) and channel-level flow control present in Rust/Go.
- **Session persistence — GO:** `storage.go` present but no `export_state`/`import_state` equivalent for the Double Ratchet; ratchet state is not persisted across process restarts.
- **Session persistence — TS:** `SessionStateMachine` exportable but ratchet state export not wired to a durable store; relies on application-supplied `StorageAdapter`.
- **Session persistence — PY:** No mechanism to serialize and restore a session (ratchet state + session metadata) across process restart. Complexity: **M**.
- **Session persistence — PHP:** No persistence mechanism. Complexity: **M**.

---

### 1.4 Reconnection

| Sub-feature | RS | GO | TS | PY | PHP |
|---|---|---|---|---|---|
| Exponential backoff | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Session resumption request/response | COMPLETE | COMPLETE | COMPLETE | PARTIAL | PARTIAL |
| Resumption proof (HMAC-SHA256) | COMPLETE | PARTIAL | COMPLETE | MISSING | MISSING |
| Replay protection (nonce + timestamp) | COMPLETE | PARTIAL | COMPLETE | MISSING | MISSING |
| Network change detection (proactive reconnect) | COMPLETE | STUB | PARTIAL | MISSING | MISSING |

**Notes:**

- **Session resumption — GO:** `reconnect.go` has `BackoffPolicy` and session state constants. No `SessionResumptionRequest` struct or proof construction matching Rust's `reconnection.rs`. Complexity: **M**.
- **Resumption proof — GO:** Missing `ChallengeProof` / HMAC construction. Complexity: **S**.
- **Session resumption — PY:** `test_reconnection.py` exercises the state machine transitions but `session.py` has no `SessionResumptionRequest` or proof. Complexity: **M**.
- **Session resumption — PHP:** `Session.php` has state machine. No resumption proof or replay protection structs. Complexity: **M**.
- **Network change — GO:** `transport/monitor.go` defines the `NetworkMonitor` interface with `NoopNetworkMonitor` as default; no platform binding (netlink/SCNetworkReachability). Complexity: **L**.
- **Network change — TS:** `session/network-monitor.ts` exists; browser `navigator.onLine` and `visibilitychange` events handled. Node.js side has no OS-level interface monitoring.
- **Network change — PY/PHP:** No implementation. Complexity: **M** each.

---

### 1.5 Wire Protocol

| Sub-feature | RS | GO | TS | PY | PHP |
|---|---|---|---|---|---|
| CBOR framing (integer-keyed map, keys 0-5) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Deterministic CBOR encoding | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Message type registry | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Version negotiation | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| UUID v7 message IDs | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Ratchet header serialization (JSON array for `dh_public`) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Custom protocol handler | PARTIAL | MISSING | PARTIAL | MISSING | MISSING |

**Notes:**

- **Custom protocol handler — RS:** `protocol/` has message types and envelope; application-level custom message dispatch is handled via the `Node` API. No dedicated extension-point module.
- **Custom protocol handler — TS:** `protocol/custom-handler.ts` exists; Go, Python, and PHP have no equivalent.
- **Ratchet header:** All impls serialize `dh_public` as a JSON byte-array (list of integers) — verified to match across RS/GO/TS/PY/PHP. Wire-compatible.

---

### 1.6 Discovery

| Sub-feature | RS | GO | TS | PY | PHP |
|---|---|---|---|---|---|
| Rendezvous ID derivation + rotation | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| mDNS backend | COMPLETE | COMPLETE | MISSING | PARTIAL | STUB |
| Kademlia DHT backend | COMPLETE | STUB | MISSING | PARTIAL | STUB |
| BitTorrent tracker backend (BEP 3/15) | COMPLETE | STUB | PARTIAL | PARTIAL | STUB |
| Signaling server backend (WebSocket) | COMPLETE | STUB | MISSING | PARTIAL | STUB |
| Discovery coordinator (fan-out) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | PARTIAL |

**Notes:**

- **mDNS — RS:** Full libp2p-mdns integration with dedicated swarm and `from_swarm()` composed mode.
- **mDNS — GO:** `discovery/mdns.go` is a full libp2p-mdns integration via `go-libp2p-mdns`.
- **mDNS — TS:** No mDNS backend. Browser cannot do raw UDP multicast; Node.js side has no implementation. Legitimate gap for browser; **MISSING for Node.js server use-case**. Complexity: **M** for Node.js.
- **mDNS — PY:** Uses `zeroconf` library when available, falls back to in-memory. Real mDNS I/O present but service-name construction (truncates to 16 hex chars) differs from Rust convention. Complexity: **S** to align naming.
- **mDNS — PHP:** `Discovery/Mdns.php` is in-memory only; no actual UDP multicast. Complexity: **L**.
- **Kademlia — RS:** Full libp2p-kad integration with bootstrap, put/get, event loop.
- **Kademlia — GO:** `discovery/dht.go` — in-memory store only, comments indicate `go-libp2p-kad-dht` integration planned. Complexity: **L**.
- **Kademlia — TS:** No DHT backend. Complexity: **XL** (no JS Kademlia library in the libp2p stack used).
- **Kademlia — PY:** Uses `kademlia` PyPI library with in-memory fallback. Real DHT ops attempted when bootstrapped. PARTIAL — limited to `kademlia` library's HTTP-style RPC, not compatible with libp2p Kademlia wire format.
- **Kademlia — PHP:** In-memory stub only. Complexity: **XL**.
- **BitTorrent — RS:** Full BEP 3 (HTTP announce) and BEP 15 (UDP announce) with URL encoding, 15-min rate limit.
- **BitTorrent — GO:** Stub — in-memory store with rate-limit logic, no actual HTTP/UDP tracker I/O. Complexity: **M**.
- **BitTorrent — TS:** `discovery/tracker.ts` has URL builder, protocol helpers, rate-limit constant, but no actual HTTP fetch or UDP socket. No `DiscoveryBackend` implementation class. Complexity: **M**.
- **BitTorrent — PY:** `TrackerBackend` makes real HTTP announces via `httpx` when available, falls back to in-memory. BEP 15 UDP not implemented. Complexity: **S** for UDP.
- **BitTorrent — PHP:** In-memory stub only. Complexity: **L**.
- **Signaling — RS:** Full WebSocket client (`tokio-tungstenite`) with auth token, reconnect loop, publish/query via `PUBLISH`/`QUERY` JSON messages.
- **Signaling — GO:** `discovery/signaling.go` — stub, always returns error unless server URL configured. No WebSocket client. Complexity: **M**.
- **Signaling — TS:** No backend class, only manager interface. Complexity: **M**.
- **Signaling — PY:** `SignalingBackend` in `discovery/__init__.py` export list, implemented in `mdns.py` as an in-memory stub with HTTP-poll fallback. No WebSocket client. Complexity: **M**.
- **Signaling — PHP:** In-memory stub. Complexity: **M** (ReactPHP WebSocket available).

---

### 1.7 Transport

| Sub-feature | RS | GO | TS | PY | PHP |
|---|---|---|---|---|---|
| 9-level fallback chain (type enum + priority) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | PARTIAL |
| QUIC v1 (priority 1) | PARTIAL | STUB | PARTIAL | MISSING | MISSING |
| STUN hole punch (priority 2) | PARTIAL | STUB | PARTIAL | MISSING | MISSING |
| TCP (priority 3) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| TURN relay UDP (priority 4) | STUB | STUB | STUB | MISSING | MISSING |
| TURN relay TCP (priority 5) | STUB | STUB | STUB | MISSING | MISSING |
| WebSocket/TLS (priority 6) | PARTIAL | MISSING | COMPLETE | MISSING | MISSING |
| WebTransport/H3 (priority 7) | STUB | STUB | STUB | MISSING | MISSING |
| Circuit Relay v2 (priority 8) | PARTIAL | MISSING | PARTIAL | MISSING | MISSING |
| HTTPS long-polling (priority 9) | STUB | STUB | STUB | MISSING | MISSING |
| NAT type detection (STUN) | COMPLETE | STUB | PARTIAL | COMPLETE | COMPLETE |
| Connection quality monitor / migration | COMPLETE | PARTIAL | COMPLETE | PARTIAL | PARTIAL |
| Network interface monitor | COMPLETE | STUB | PARTIAL | MISSING | MISSING |

**Notes:**

- **QUIC — RS:** Enabled in `TransportConfig` via libp2p swarm builder; actual `with_quic` call not found in swarm.rs (config flag present, wiring incomplete). PARTIAL.
- **QUIC — GO/PY/PHP:** No QUIC transport. Complexity: **XL** each.
- **STUN hole punch — RS/GO/TS:** Config enum entries present; no active ICE/STUN hole-punching logic independent of libp2p. Complexity: **L**.
- **TURN — all:** All impls have the type in the enum; Go has `TurnTransport` stub that always errors. Nothing actually speaks TURN (RFC 8656). Complexity: **L** each.
- **WebSocket — RS:** `websocket_enabled` flag in config; libp2p WebSocket transport available but not explicitly composed in swarm builder snippet reviewed.
- **WebSocket — TS:** Full via libp2p WebSocket transport in browser build.
- **Circuit Relay v2 — RS/TS:** In libp2p ecosystem, available via config flag. Not fully wired.
- **HTTPS long-polling — GO:** `HTTPSPollingTransport` struct that always errors; Complexity: **L**.
- **NAT detection — GO:** `DetectNATType` returns `NatUnknown` always (documented placeholder for AutoNAT). Complexity: **M**.
- **NAT detection — TS:** STUN request builder and parser present; actual UDP socket send not present in browser (WebRTC ICE only). Node.js path incomplete.
- **Connection quality — GO:** `transport/monitor.go` has `NetworkMonitor` interface + noop; no `ConnectionQualityMonitor` / degradation events matching Rust's `fallback.rs`. Complexity: **M**.
- **Connection quality — PY:** `transport/heartbeat.py` exists; no quality metrics / degradation events. Complexity: **M**.
- **PHP fallback chain:** `Transport/Chain.php` exists but lacks `TransportType::STUN_HOLE_PUNCH` entry (8 types, missing STUN). Complexity: **S**.

---

### 1.8 Services

| Sub-feature | RS | GO | TS | PY | PHP |
|---|---|---|---|---|---|
| Store-and-forward queue | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Retention policy (age + per-peer count) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Deduplication (UUID v7 message ID) | COMPLETE | COMPLETE | PARTIAL | PARTIAL | PARTIAL |
| Forward message types (0x0700–0x0703) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Management API (HTTP, bearer token) | COMPLETE | COMPLETE | COMPLETE | COMPLETE | PARTIAL |
| Peer quota / per-peer overrides | COMPLETE | PARTIAL | MISSING | MISSING | MISSING |
| Mesh relay | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Mesh routing table | COMPLETE | COMPLETE | COMPLETE | COMPLETE | COMPLETE |
| Headless pairing (server-mode) | COMPLETE | PARTIAL | PARTIAL | COMPLETE | MISSING |
| Signaling server (infrastructure) | PARTIAL | MISSING | MISSING | MISSING | MISSING |
| TURN server (infrastructure) | MISSING | MISSING | MISSING | MISSING | MISSING |

**Notes:**

- **Deduplication — TS:** `MessageQueue` has `msgId` field but in-memory seen-set is not flushed on delivery; potential memory growth under load. Complexity: **S**.
- **Deduplication — PY:** `server/forward.py` stores messages; dedup check present but no bounded seen-set. Complexity: **S**.
- **Deduplication — PHP:** `Server/Forward.php` stores messages; no seen-set for delivered messages. Complexity: **S**.
- **Peer quota — GO:** `RetentionConfig.PerPeerOverrides` map present; no `PeerQuota` or `PeerMetrics` equivalent from Rust `HeadlessPairing`. Complexity: **S**.
- **Peer quota — TS/PY:** `RetentionPolicy` has `maxMessages` global but no per-peer override. Complexity: **S** each.
- **Headless pairing — GO:** `server/management.go` has `ManagementConfig`; no PIN/QR/link generation or PSK env-var loading equivalent to Rust's `headless.rs`. Complexity: **M**.
- **Headless pairing — TS:** `server/management.ts` is a full HTTP management API; no `generatePinPayload`/`generateQrPayload` server-side helpers. Complexity: **S**.
- **Headless pairing — PHP:** No server management class equivalent to Rust `HeadlessPairing`. Complexity: **M**.
- **Signaling server — RS:** Signaling backend client exists; no standalone signaling server binary (only `demo/server-node`). Infrastructure deployment not in library scope.
- **TURN server:** Out of scope for all library packages; requires infrastructure deployment.

---

## 2. TS Browser Legitimate Gaps

The browser entry point (`packages/ts/cairn-p2p/src/browser.ts`) intentionally omits:

| Gap | Reason | Compensating mechanism |
|-----|--------|----------------------|
| TCP transport | No raw TCP in browsers | WebSocket/TLS (priority 6), WebRTC (via libp2p), Circuit Relay v2 |
| QUIC transport | No raw UDP socket | WebTransport/H3 when available |
| mDNS discovery | No UDP multicast | Signaling server backend (when configured) |
| Node.js `http.createServer` in management API | Browser has no server | Server exports excluded from `browser.ts`; management API is Node.js-only |
| Filesystem key store | No filesystem API | `StorageAdapter` interface fulfilled by IndexedDB or `localStorage` wrapper |
| `crypto.timingSafeEqual` | Node.js built-in | `@noble/hashes` constant-time comparison used in session resumption |
| OS network interface monitoring | Browser API only | `navigator.onLine` + `visibilitychange` events in `session/network-monitor.ts` |

---

## 3. Gaps Requiring Action (by priority)

### Critical (wire-incompatible)

| ID | Impl | Area | File(s) | Issue | Complexity |
|----|------|------|---------|-------|------------|
| C1 | PHP | Crypto/SPAKE2 | `src/Crypto/Spake2.php` | Uses Ristretto255 group; Rust uses Ed25519 group. Cross-impl pairing will fail. | L |
| C2 | TS | Crypto/SPAKE2 | `src/crypto/spake2.ts` | M/N derivation via `sha256(label) mod L * G` differs from Rust `Ed25519Group` hash-to-point. Must be validated against conformance vectors. | M |
| C3 | GO | Crypto/SPAKE2 | `crypto/spake2.go` | M/N derivation via iterated SHA-256 + cofactor clear; different algorithm path from Rust. Must be validated against conformance vectors. | M |

### High (functional gaps affecting production use)

| ID | Impl | Area | File(s) | Issue | Complexity |
|----|------|------|---------|-------|------------|
| H1 | PY | Pairing | `pairing/` (missing) | No `PairingSession` / pairing state machine; no PSK mechanism. Cannot drive SPAKE2 pairing flow end-to-end. | M |
| H2 | GO | Reconnection | `reconnect.go` | No `SessionResumptionRequest`, no HMAC proof, no replay protection. Session resume spec not met. | M |
| H3 | PY | Reconnection | `session.py` | No session resumption proof or replay protection. | M |
| H4 | PHP | Reconnection | `Session.php` | No session resumption proof or replay protection. | M |
| H5 | GO | Discovery/DHT | `discovery/dht.go` | In-memory only; no actual Kademlia DHT integration. | L |
| H6 | GO | Discovery/Signaling | `discovery/signaling.go` | Stub; no WebSocket client. | M |
| H7 | PY | Session | `session.py` | No session state persistence (ratchet export/import across restart). | M |
| H8 | PHP | Session | `Session.php` | No session state persistence. | M |

### Medium (incomplete features)

| ID | Impl | Area | File(s) | Issue | Complexity |
|----|------|------|---------|-------|------------|
| M1 | GO | Transport/NAT | `transport/nat.go` | `DetectNATType` always returns `NatUnknown`. | M |
| M2 | GO | Transport/QUIC | `transport/chain.go` | No QUIC transport; type enum only. | XL |
| M3 | TS | Discovery/mDNS | `discovery/` (missing) | No mDNS backend for Node.js server mode. | M |
| M4 | PHP | Discovery/mDNS | `Discovery/Mdns.php` | In-memory only; no real UDP multicast. | L |
| M5 | GO | Services/Headless | `server/management.go` | No headless PIN/QR/link pairing payload generation. | M |
| M6 | PHP | Services/Headless | `Server/` (missing) | No headless pairing equivalent. | M |
| M7 | ALL | Transport/TURN | `transport/turn.*` | TURN (RFC 8656) is a stub across all impls. | L |
| M8 | PHP | Crypto/KeyStore | (missing) | No key storage abstraction. | S |
| M9 | ALL | Transport/WebTransport | all | WebTransport/H3 is enum-only across all impls. | XL |
| M10 | TS | Discovery/DHT | (missing) | No Kademlia DHT backend even for Node.js. | XL |

### Low (polish / edge cases)

| ID | Impl | Area | File(s) | Issue | Complexity |
|----|------|------|---------|-------|------------|
| L1 | PHP | Transport | `Transport/Chain.php` | Missing `STUN_HOLE_PUNCH` in 9-level enum (8 entries). | S |
| L2 | PY | Discovery/mDNS | `discovery/mdns.py` | Service-name truncation to 16 hex chars may differ from Rust. | S |
| L3 | TS | Services | `server/store-forward.ts` | In-memory dedup seen-set unbounded. | S |
| L4 | PY | Services | `server/forward.py` | In-memory dedup seen-set unbounded. | S |
| L5 | PHP | Services | `Server/Forward.php` | No dedup seen-set for delivered messages. | S |
| L6 | GO | Transport/Network | `transport/monitor.go` | `NoopNetworkMonitor` only; no OS-level interface events. | L |
| L7 | GO | Services | `server/` | No per-peer quota overrides (`PeerQuota` equivalent). | S |