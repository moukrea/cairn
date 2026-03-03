# cairn — Product Requirements Document

**Version 1.0 — March 2026**
**Status**: Draft
**Derived from**: cairn Design & Architecture Document v0.6

---

## 1. Executive Summary

cairn is a universal peer-to-peer (P2P) connectivity library designed to provide developers with an opinionated, batteries-included solution for encrypted P2P communication. The library abstracts away the recurring complexity of signaling, NAT traversal, relay fallback, encryption, and peer discovery into a single installable package, available natively in five target languages with full inter-compatibility.

The core promise is simple: a developer installs the package, writes a handful of lines of code, and has a working, encrypted, resilient P2P channel — in minutes, not days — without deploying or configuring any server infrastructure.

---

## 2. Problem Statement

Across multiple projects (Parley/P2P Chat, Tack, RemoShell, and others), the same foundational P2P plumbing is reimplemented from scratch every time. This includes signaling, NAT traversal, relay fallback, encryption, and peer discovery. Each reimplementation consumes weeks of development time, introduces subtle bugs, and results in inconsistent security postures and connectivity behavior.

No existing library provides a single, cross-language, zero-config, secure-by-default P2P connectivity layer that covers the full spectrum from initial peer pairing through persistent encrypted sessions to graceful failure recovery. libp2p provides excellent transport primitives but exposes significant complexity; higher-level abstractions are either language-specific, lack feature parity, or require server infrastructure from the outset.

---

## 3. Target Audience

### 3.1 Primary Personas

**Persona 1 — Application Developer (Quick Start)**
A developer building a new application that requires P2P connectivity (chat, file sync, remote shell, IoT control). They want to add P2P capabilities in an afternoon, not spend a week learning NAT traversal theory. They expect `npm install` / `cargo add` / `pip install` simplicity, sensible defaults, and zero server infrastructure to get started.

**Persona 2 — Infrastructure-Aware Developer (Progressive Control)**
A developer or team that starts with zero-config but eventually needs control over reliability, latency, and privacy. They will deploy companion infrastructure (signaling servers, TURN relays) and potentially run always-on server-mode peers. They need clear documentation of infrastructure tiers and a smooth upgrade path with no code changes required.

**Persona 3 — Homelab / Self-Hosting Enthusiast**
A technically proficient user who runs personal infrastructure (home servers, NAS, Raspberry Pi, VPS). They want to deploy a server-mode peer for store-and-forward, personal relay, and multi-device sync. They expect Docker-first deployment, minimal resource footprint, and full self-hosted privacy.

**Persona 4 — Cross-Platform Team**
A team working with mixed technology stacks (e.g., a Rust backend, TypeScript frontend, Go microservices, Python scripts) that needs seamless P2P interoperability between components written in different languages. They need a wire-compatible protocol with native, idiomatic libraries in every target language.

---

## 4. Core Value Proposition

| Principle | Description |
|---|---|
| Install and go | Identical install experience across all languages: `cargo add`, `npm install`, `go get`, `pip install`, `composer install`. |
| Zero-config by default | Ships with sensible defaults leveraging public STUN servers, DHT bootstrap nodes, BitTorrent trackers, and mDNS for LAN discovery. Functional P2P connectivity out of the box with no server-side setup. |
| Progressively improvable | Start at zero-config, then optionally deploy companion infrastructure components with a single Docker command. Each step is additive and optional. |
| Inter-compatible | Any language combination works: a Rust peer connects seamlessly to a PHP peer, a Go peer to a TypeScript peer. |
| Secure by default | End-to-end encryption, verified pairing, forward secrecy — no opt-in required. |
| Resilient by design | Aggressive transport fallback, automatic reconnection, mesh routing — connections survive network changes, restarts, and hostile network environments. |

---

## 5. Target Language & Platform Support

### 5.1 Supported Languages

| Language | Package Manager | Async Runtime | libp2p Ecosystem Status |
|---|---|---|---|
| Rust | cargo (crates.io) | tokio | Mature (rust-libp2p) |
| Go | go get (modules) | goroutines | Mature (go-libp2p) |
| TypeScript/JS | npm | async/await, event loop | Mature (js-libp2p) |
| Python | pip (PyPI) | asyncio | Beta (py-libp2p v0.5+) |
| PHP | composer (Packagist) | ReactPHP / Amp / Swoole | No existing impl — custom build required |

### 5.2 Platform Considerations

**PHP**: PHP's request/response execution model requires a long-running daemon process (via ReactPHP, Amp, or Swoole) for persistent P2P connections. This must be documented clearly. PHP will not support QUIC or WebTransport at launch; its transport chain starts at STUN-assisted UDP or TCP.

**Browser**: TypeScript supports both Node.js and browser environments. The browser transport chain is limited to WebRTC (direct) → WebSocket (relay) → WebTransport (relay).

**Mobile (iOS/Android)**: Constraints around background execution, battery, and push notifications must be documented. Platform-aware keepalive is required (APNs for iOS, FCM for Android). Server-mode peer is strongly recommended for mobile use cases.

---

## 6. Infrastructure Tiers

cairn's configuration model is organized around progressive tiers of infrastructure commitment. Every tier builds on the previous one; every enhancement is optional and additive.

### Tier 0 — Zero-Config

**Developer effort**: None — install and use.
**Infrastructure used**: Public STUN servers, public libp2p DHT bootstrap nodes, public BitTorrent trackers, mDNS for LAN discovery.
**Connectivity coverage**: Peers behind open or cone NATs, same-LAN peers (instant mDNS discovery), any topology where STUN-assisted hole punching succeeds. Covers the majority of home network and cloud server scenarios.
**Known tradeoffs**: Discovery latency (seconds to minutes for first remote connection), no relay for symmetric NATs, best-effort public infrastructure reliability, metadata exposure to public infrastructure operators, no offline delivery.

### Tier 1 — Add Signaling & Relay

**Developer effort**: Deploy cairn's companion signaling server and/or TURN relay (single Docker container each).
**Infrastructure used**: Everything in Tier 0 plus real-time WebSocket signaling and TURN relay.
**Connectivity coverage**: Adds symmetric NAT traversal, corporate firewall penetration, sub-second peer discovery.

### Tier 2 — Add Server-Mode Peer

**Developer effort**: Run a cairn peer in server mode on an always-on device.
**Infrastructure used**: Everything in Tier 1 plus store-and-forward mailbox, personal relay, multi-device sync hub.
**Connectivity coverage**: Offline message delivery, relay bridging through a trusted personal node, seamless multi-device synchronization.

### Tier 3 — Full Control

**Developer effort**: Operate the complete infrastructure stack.
**Infrastructure used**: Custom STUN, TURN, signaling, trackers, bootstrap nodes, multiple server-mode peers.
**Connectivity coverage**: Complete control over reliability, latency, and privacy. Zero dependency on third-party public infrastructure.

---

## 7. Functional Requirements

### FR-1: Peer Identity

| ID | Requirement | Priority |
|---|---|---|
| FR-1.1 | Each peer generates a persistent Ed25519 identity keypair on first initialization. | P0 |
| FR-1.2 | The public key hash serves as the unique, persistent Peer ID. | P0 |
| FR-1.3 | Identity keys are stored in a pluggable storage backend (filesystem default, in-memory for testing, custom adapter interface). | P0 |
| FR-1.4 | Identity keys persist across reboots and reinstalls. | P0 |

### FR-2: Pairing

| ID | Requirement | Priority |
|---|---|---|
| FR-2.1 | The library supports pluggable pairing mechanisms through a defined interface. | P0 |
| FR-2.2 | Built-in verification-only mechanisms: Numeric SAS (6-digit), Emoji SAS. | P0 |
| FR-2.3 | Built-in initiation mechanisms: QR Code (binary CBOR, EC Level M, max 256 bytes), Pin Code (Crockford Base32, 8 chars `XXXX-XXXX`, 40 bits entropy), Pairing Link/URI (`cairn://pair?...`), Pre-Shared Key (min 128 bits for long-lived keys). | P0 |
| FR-2.4 | Initiation mechanisms collapse discovery, authentication, and verification into a single user action. | P0 |
| FR-2.5 | All initiation pairing payloads are single-use and time-limited (default: 5 minutes). | P0 |
| FR-2.6 | Pin code and QR code pairing use SPAKE2 for password-authenticated key exchange. | P0 |
| FR-2.7 | Pairing rate limiting: acceptor-side, 5 attempts per 30-second window, 10 max failed attempts before auto-invalidation, 2-second progressive delay after each failure. | P0 |
| FR-2.8 | After pairing, both peers store mutual identity keys and derived keying material in persistent storage. | P0 |
| FR-2.9 | Applications can implement custom pairing adapters (e.g., NFC, Bluetooth LE, email-based, hardware token). | P1 |
| FR-2.10 | Unpairing is unilateral: calling `unpair(peer_id)` sends a best-effort `PairRevoke`, then deletes all local state for that peer. | P0 |
| FR-2.11 | Pairwise mesh pairing for groups (every peer pairs individually with every other). | P0 |
| FR-2.12 | Group key agreement (MLS, RFC 9420) for efficient group pairing. | P2 (post-v1.0) |

### FR-3: Encryption & Key Management

| ID | Requirement | Priority |
|---|---|---|
| FR-3.1 | All sessions are end-to-end encrypted using the Double Ratchet algorithm with AES-256-GCM or ChaCha20-Poly1305. | P0 |
| FR-3.2 | Transport-level encryption via libp2p Noise protocol provides hop-by-hop security. | P0 |
| FR-3.3 | Double encryption (transport + session) is intentional and required. | P0 |
| FR-3.4 | Forward secrecy: each message or message group uses a unique symmetric key. Compromising a key at time T reveals nothing about messages at T−1 or T+1. | P0 |
| FR-3.5 | Key rotation occurs on every reconnection via the Double Ratchet. | P0 |
| FR-3.6 | Key storage backend is pluggable: filesystem (encrypted at rest with passphrase), in-memory (ephemeral), custom adapter (keychains, HSMs). | P0 |
| FR-3.7 | Rendezvous IDs are derived from pairing secrets via HKDF, opaque to observers, and rotatable on a configurable schedule (default: 24 hours). | P0 |

### FR-4: NAT Traversal & Transport

| ID | Requirement | Priority |
|---|---|---|
| FR-4.1 | The library implements an ordered, aggressive transport fallback chain: Direct QUIC v1 → STUN-assisted UDP hole punch → Direct TCP → TURN UDP relay → TURN TCP relay → WebSocket over TLS (port 443) → WebTransport over HTTP/3 (port 443) → Circuit Relay v2 (transient) → HTTPS long-polling (port 443). | P0 |
| FR-4.2 | Multiple transports may be attempted in parallel (ICE-style) for faster establishment. | P0 |
| FR-4.3 | Once connected, the library continuously probes for better transports and can migrate mid-session transparently. | P0 |
| FR-4.4 | NAT type is exposed as read-only diagnostic metadata (`open`, `full_cone`, `restricted_cone`, `port_restricted_cone`, `symmetric`, `unknown`). | P0 |
| FR-4.5 | Connection quality monitoring (latency, jitter, packet loss) triggers proactive transport migration before the current connection fails. | P0 |
| FR-4.6 | OS-level network interface changes (WiFi ↔ cellular, VPN, new IP) trigger proactive reconnection. | P0 |
| FR-4.7 | PHP transport chain starts at priority 2/3 (no QUIC/WebTransport at launch). | P0 |
| FR-4.8 | Browser transport chain: WebRTC → WebSocket → WebTransport. | P0 |

### FR-5: Session Management & Reconnection

| ID | Requirement | Priority |
|---|---|---|
| FR-5.1 | Connection lifecycle state machine: Connected → Unstable → Disconnected → Reconnecting → Suspended → Reconnected → Failed. All transitions emit events. | P0 |
| FR-5.2 | Session resumption after brief disconnection: Session ID + cryptographic proof → validate → advance ratchet → sync sequence numbers → retransmit queued messages. | P0 |
| FR-5.3 | Session re-establishment after expiry (default: 24 hours): full Noise XX handshake authenticated by pairing identity keys, fresh Double Ratchet root key, new Session ID (UUID v7). No re-pairing required. | P0 |
| FR-5.4 | Message queuing during disconnection is opt-in and configurable: enable/disable, max size (default: 1000), max age (default: 1 hour), strategy (FIFO or LIFO). | P0 |
| FR-5.5 | Configurable heartbeat/keepalive interval (default: 30s) with timeout (default: 3× interval). | P0 |
| FR-5.6 | Exponential backoff reconnection (initial: 1s, max: 60s, factor: 2.0). | P0 |
| FR-5.7 | Application only ever interacts with the session layer; transport churn is invisible. | P0 |

### FR-6: Peer Discovery & Rendezvous

| ID | Requirement | Priority |
|---|---|---|
| FR-6.1 | mDNS: first-class LAN discovery mechanism, attempted before all remote discovery. Peers on the same network segment find each other instantly without internet access. | P0 |
| FR-6.2 | libp2p Kademlia DHT: rendezvous ID as DHT key, encrypted reachability info as value. | P0 |
| FR-6.3 | BitTorrent trackers: rendezvous ID as info_hash, peer discovery through tracker swarm. Reasonable announce intervals (minimum 15 minutes). | P0 |
| FR-6.4 | WebSocket-based signaling servers: rendezvous ID maps to topic/room, real-time reachability exchange (Tier 1+). | P0 |
| FR-6.5 | Custom/pluggable discovery backends for domain-specific infrastructure. | P1 |
| FR-6.6 | Rendezvous ID rotation: configurable schedule (default: 24 hours), deterministic epoch derivation, 1-hour transition overlap window, 5-minute clock tolerance. | P0 |
| FR-6.7 | Pairing-bootstrapped rendezvous: pin code, QR code, and pairing links derive a pairing rendezvous ID enabling discovery without prior network presence. | P0 |
| FR-6.8 | For mesh groups, rendezvous ID is derived from the group shared secret. | P1 |

### FR-7: Mesh Networking (Opt-in)

| ID | Requirement | Priority |
|---|---|---|
| FR-7.1 | Mesh routing is opt-in, disabled by default. | P0 |
| FR-7.2 | When enabled, the library maintains a routing table and automatically routes traffic through intermediate hops. | P1 |
| FR-7.3 | Route selection priorities: shortest hop count → lowest latency → highest bandwidth. | P1 |
| FR-7.4 | End-to-end encryption is maintained through mesh — relay peers handle only opaque encrypted bytes. | P0 |
| FR-7.5 | Configurable: `mesh_enabled` (default: false), `max_hops` (default: 3), `relay_willing` (default: false), `relay_capacity` (default: 10). | P1 |
| FR-7.6 | Mesh relay uses cairn application-level relay on libp2p streams, not Circuit Relay v2. No duration or data limits. | P0 |

### FR-8: Server Mode (Opt-in, Tier 2)

| ID | Requirement | Priority |
|---|---|---|
| FR-8.1 | Server mode is a configuration posture, not a separate codebase or protocol. A `create_server()` convenience constructor applies server-mode defaults. | P0 |
| FR-8.2 | Store-and-forward: server-mode peer acts as an encrypted mailbox for paired peers. Requires mutual pairing (server paired with both sender and recipient). | P0 |
| FR-8.3 | Retention policy: 7 days or 1000 messages per peer (whichever first), configurable with per-peer overrides. | P0 |
| FR-8.4 | Personal relay: server-mode peer with a public IP relays traffic for paired peers who cannot connect directly. | P0 |
| FR-8.5 | Headless pairing support: Pre-shared key, pin code (CLI/log output), pairing link (CLI output), QR code (terminal ASCII art, management HTTP endpoint PNG). | P0 |
| FR-8.6 | Multi-device sync hub: devices sync through the always-on server node asynchronously. | P0 |
| FR-8.7 | Management API (opt-in): REST/JSON over HTTP, localhost-only by default, bearer token auth. Exposes: paired peers list, queue depths, relay stats, connection health, pairing QR generation. | P1 |
| FR-8.8 | Resource accounting: per-peer bytes relayed and bytes stored, exposed via management API and structured events. Configurable per-peer quotas. | P1 |
| FR-8.9 | Server-mode trust model: cannot read E2E encrypted content, cannot impersonate peers, can be unpaired at any time. Compromise reveals only metadata. | P0 |
| FR-8.10 | Max skip threshold for Double Ratchet message reconstruction (default: 1000 skipped messages). | P0 |
| FR-8.11 | Message deduplication via UUID v7 message IDs. | P0 |
| FR-8.12 | Multi-server coordination (server-to-server relay and federation). | P2 (post-v1.0) |

### FR-9: Wire Protocol

| ID | Requirement | Priority |
|---|---|---|
| FR-9.1 | All wire messages use CBOR (RFC 8949) serialization. | P0 |
| FR-9.2 | Common message envelope: protocol version (uint8), message type (uint16), message ID (UUID v7), optional session ID (32 bytes), CBOR payload, authentication tag. | P0 |
| FR-9.3 | Message type categories: 0x01xx Pairing, 0x02xx Session, 0x03xx Data, 0x04xx Control, 0x05xx Mesh, 0x06xx Rendezvous, 0x07xx Forward. | P0 |
| FR-9.4 | Application-defined extension range: 0xF000–0xFFFF with `on_custom_message(type_code, callback)` handler. | P0 |
| FR-9.5 | Version negotiation: peers exchange supported versions on first contact; highest mutual version selected. `VersionMismatch` error includes peer's supported range. | P0 |
| FR-9.6 | Channel multiplexing via yamux streams (libp2p's native stream multiplexing). | P0 |

### FR-10: API Surface

| ID | Requirement | Priority |
|---|---|---|
| FR-10.1 | Core concepts: Node, PeerId, Pairing, Session, Channel, Event. | P0 |
| FR-10.2 | Node initialization: `cairn.create()` (zero-config), `cairn.create(config)` (custom config), `cairn.create_server()` (server mode). | P0 |
| FR-10.3 | Pairing methods: `pair_generate_qr()`, `pair_scan_qr()`, `pair_generate_pin()`, `pair_enter_pin()`, `pair_generate_link()`, `pair_from_link()`, `pair()` (SAS). | P0 |
| FR-10.4 | Connection: `node.connect(peer_id)` → automatic discovery, NAT traversal, session resume. | P0 |
| FR-10.5 | Channel: `session.open_channel(name)` (creates yamux stream with ChannelInit payload), `channel_opened` event on remote. | P0 |
| FR-10.6 | Data: `session.send(channel, data)`, `session.send(channel, data, { forward: true })` (store-and-forward), `session.on_message(channel, callback)`. | P0 |
| FR-10.7 | State: `session.on_state_change(callback)`, `session.close()`, `node.unpair(peer_id)`. | P0 |
| FR-10.8 | Event-driven architecture using language-idiomatic patterns (tokio channels, Go channels, EventEmitter, asyncio, ReactPHP callbacks). | P0 |
| FR-10.9 | NAT diagnostic: `node.network_info().nat_type`. | P0 |

---

## 8. Non-Functional Requirements

### NFR-1: Security

| ID | Requirement |
|---|---|
| NFR-1.1 | All communication is encrypted by default with no opt-out. |
| NFR-1.2 | Pairing prevents MITM attacks even over public channels. |
| NFR-1.3 | Forward secrecy is maintained across all session boundaries via the Double Ratchet. |
| NFR-1.4 | Session resumption requires cryptographic proof of identity, not just a Session ID. |
| NFR-1.5 | Keys are rotated on every reconnection. |
| NFR-1.6 | Session resumption handshake is protected against replay via timestamp and nonce. |
| NFR-1.7 | Pairing activity cannot be correlated to specific identities over time by observers. |
| NFR-1.8 | Forward secrecy degradation for stored messages (within a single DH ratchet epoch) is documented as a known tradeoff. |

### NFR-2: Performance

| ID | Requirement |
|---|---|
| NFR-2.1 | mDNS LAN discovery is instant (sub-second). |
| NFR-2.2 | Signaling-based discovery (Tier 1+) is sub-second. |
| NFR-2.3 | DHT/tracker-based discovery is within seconds to low minutes for first connection. |
| NFR-2.4 | Session resumption after brief disconnection completes within seconds. |
| NFR-2.5 | Server-mode peer: a small VPS (512 MB RAM) handles moderate relay/mailbox load. |
| NFR-2.6 | Companion signaling server handles thousands of concurrent peers on a small VPS or Raspberry Pi. |
| NFR-2.7 | Double encryption overhead is acceptable (inner encryption operates on application payloads only, not transport framing). |

### NFR-3: Reliability

| ID | Requirement |
|---|---|
| NFR-3.1 | Library works at every infrastructure tier (0–3) without failure. |
| NFR-3.2 | Redundancy in default infrastructure lists (multiple servers per category). |
| NFR-3.3 | Transport fallback chain ensures connectivity in any network environment, including corporate firewalls that only allow HTTPS on port 443. |
| NFR-3.4 | Reconnection is automatic and transparent to the application. |
| NFR-3.5 | Message deduplication prevents duplicate delivery across multiple paths. |

### NFR-4: Usability & Developer Experience

| ID | Requirement |
|---|---|
| NFR-4.1 | A developer achieves a working encrypted P2P channel in minutes, not days. |
| NFR-4.2 | API is minimal, idiomatic per language, and conceptually consistent across all implementations. |
| NFR-4.3 | All configuration has sensible defaults; developers override only what they need. |
| NFR-4.4 | Error messages are diagnostic and actionable (e.g., `TransportExhausted` suggests deploying signaling server/TURN relay). |
| NFR-4.5 | Pin code input is case-insensitive with built-in error correction (`i`/`l` → `1`, `o` → `0`). |

### NFR-5: Observability

| ID | Requirement |
|---|---|
| NFR-5.1 | Structured event interface at the library level (not Prometheus-specific). |
| NFR-5.2 | Server-mode peer exposes an optional Prometheus-compatible metrics endpoint. |
| NFR-5.3 | Bandwidth metrics hooks are available for application-level QoS (bandwidth management is deferred for core library). |

### NFR-6: Deployability

| ID | Requirement |
|---|---|
| NFR-6.1 | Companion infrastructure is trivially deployable: single binary, Docker image, or Docker Compose snippet. |
| NFR-6.2 | Companion infrastructure is configured via environment variables. |
| NFR-6.3 | Server-mode peer deploys as Docker container, systemd service, or native process on NAS/VPS. |
| NFR-6.4 | Resource footprint: 512 MB RAM target for server-mode peer and companion relay. |

---

## 9. Companion Infrastructure Requirements

cairn provides lightweight, self-hostable infrastructure components as part of the project deliverables. These are standalone services, not the library itself.

### 9.1 Signaling Server

A WebSocket-based signaling server for real-time peer discovery and handshake relay.

- Implemented in Rust (shared crates with the client library).
- Single binary or Docker container deployment.
- Configuration: listen address, TLS cert path, optional bearer token authentication.
- Minimal resource footprint — holds no message state, only active WebSocket connections.
- Dumb message router: forwards CBOR-encoded messages between peers on the same rendezvous topic. Does not inspect, decrypt, or store content.
- Federation: designed with a clean internal API to support future federation (defer implementation to post-v1.0).

### 9.2 TURN Relay

A TURN relay server (RFC 8656) for transport-level relay when direct connections fail.

- Implemented in Rust.
- Single binary or Docker container deployment.
- Configuration: listen address, relay port range, credentials, TLS settings.
- Supports static username/password and a REST API for dynamic credential provisioning.
- Port 443 support with TLS for the WebSocket-over-443 escape hatch transport.
- Compatible with non-cairn applications (standard TURN protocol).

### 9.3 Default Infrastructure List

The library ships with a curated, compiled-in list of default public endpoints:

- Public STUN servers (Google, Cloudflare, others) — free, no credentials.
- libp2p public DHT bootstrap peers.
- Curated stable, open BitTorrent trackers (UDP and HTTP/WebSocket).
- mDNS for same-LAN discovery.

An opt-in signed manifest fetch (disabled by default) retrieves an updated list from a cairn-controlled endpoint. The manifest is Ed25519-signed; the public key is embedded in the library.

---

## 10. Error Handling & Failure Requirements

The library must fail gracefully and informatively. Every error provides diagnostic context and actionable guidance.

| Error Type | Meaning | Guidance to Application |
|---|---|---|
| `TransportExhausted` | All transports in fallback chain failed | Details of each failure + suggestion (e.g., deploy signaling/TURN) |
| `SessionExpired` | Session exceeded expiry window | Re-pairing not needed; re-establishes via Noise XX |
| `PeerUnreachable` | Peer not found at any rendezvous point within timeout | Continue background polling if configured |
| `AuthenticationFailed` | Crypto verification failed during session resumption | Possible key compromise alert |
| `PairingRejected` | Remote peer rejected pairing request | Inform user |
| `PairingExpired` | Pairing payload (pin/QR/link) expired | Generate a new payload |
| `MeshRouteNotFound` | No route to destination through mesh | Suggest direct connection or wait |
| `VersionMismatch` | No common protocol version | Includes peer's supported range; inform user which peer needs updating |

All timeouts are configurable: `connect_timeout` (30s), `transport_timeout` (10s), `reconnect_max_duration` (1h), `session_expiry` (24h), `pairing_payload_expiry` (5m), `rendezvous_poll_interval` (30s).

---

## 11. Demo Applications

Three demo applications serve as conformance proof and developer documentation.

### 11.1 P2P Messaging

A real-time CLI chat application with clients in all five languages. Demonstrates: pairing (QR, pin, link), bidirectional messaging, presence indicators, reconnection with queue/sequence sync, message history sync on resume, store-and-forward via server-mode peer. Works at Tier 0 out of the box.

### 11.2 Folder Sync

A file synchronization tool keeping a folder in sync across multiple peers. Demonstrates: chunked data transfer with resume, conflict detection, mesh routing, efficient delta sync, multi-peer coordination, server-mode hub for asynchronous sync.

### 11.3 Personal Server Node

A ready-to-deploy server-mode peer Docker image. Demonstrates: headless pairing (pin, PSK), store-and-forward mailbox, relay bridging, management CLI (peers, queues, relay stats, health), multi-device sync hub.

---

## 12. Scope Boundaries

### 12.1 In Scope (v1.0)

- Native, idiomatic library implementations in Rust, Go, TypeScript/JS, Python, PHP.
- Full wire protocol specification with CBOR serialization and version negotiation.
- All pairing mechanisms (QR, pin, link, SAS, PSK, custom adapter interface).
- E2E encryption with Double Ratchet, transport encryption with Noise.
- Complete transport fallback chain (9 levels).
- Session management, reconnection, and resumption.
- Rendezvous & peer discovery across mDNS, DHT, trackers, signaling servers.
- Opt-in mesh networking with application-level relay.
- Server mode: store-and-forward, personal relay, multi-device sync, management API.
- Companion infrastructure: signaling server and TURN relay (Rust).
- Cross-language conformance test matrix (CI).
- Three demo applications.
- MIT OR Apache-2.0 dual licensing.

### 12.2 Out of Scope (Deferred)

| Feature | Deferral Target |
|---|---|
| Group key agreement (MLS, RFC 9420) | Post-v1.0 — pairwise mesh sufficient for groups up to ~20 peers. |
| Signaling server federation | Post-v1.0 — design with clean internal API for future support. |
| Multi-server store-and-forward coordination | Post-v1.0 — UUID-based deduplication prepared for future multi-server. |
| OPAQUE for server-mode PSK storage hardening | Post-v1.0 — future consideration. |
| CPace (IETF CFRG recommended balanced PAKE) | Revisit when cross-language library maturity improves. |
| Application-level bandwidth management / QoS | Deferred — provide bandwidth metrics hooks only. |
| OAuth2 / mTLS authentication for companion infrastructure | Deferred — bearer tokens (default) and API key provisioning for Tier 3 as starting point. |

---

## 13. Implementation & Release Strategy

### 13.1 Phased Delivery

| Phase | Deliverables | Rationale |
|---|---|---|
| Phase 1 | Rust + TypeScript libraries, companion signaling server, companion TURN relay | Strongest libp2p support, covers most active projects. Companion infrastructure needed from day one for Tier 1+ testing and conformance harness. |
| Phase 2 | Go library | Mature libp2p, strong server-side use cases. |
| Phase 3 | Python library | Developing libp2p, scripting and automation use cases. |
| Phase 4 | PHP library | No existing libp2p — most original work required, but important for web backend integration. |

### 13.2 Quality Gates

- The wire protocol specification is the single most critical deliverable. All implementations are built against the spec, not against each other.
- Each language gets a native, idiomatic implementation — no FFI bindings to a shared core.
- Automated cross-language conformance test matrix runs in CI on every commit, testing every language pair across all major flows at Tiers 0, 1, and 2.
- Conformance tests use Docker containers with controlled networking (simulated NAT, packet loss, disconnection).

---

## 14. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| PHP libp2p gap | Phase 4 requires the most original work with no existing libp2p implementation. | Defer PHP to Phase 4; scope transport chain reduction (no QUIC/WebTransport). PHP community may contribute. |
| Public infrastructure reliability | Tier 0 depends on third-party STUN, DHT, and tracker services without SLAs. | Curated default list with redundancy. Opt-in signed manifest fetch for updates. Progressive tier model encourages self-hosting. |
| Cross-language crypto consistency | Subtle implementation differences in SPAKE2, Double Ratchet, or Noise across 5 languages could break interop. | Wire protocol spec as the canonical reference. Cross-language conformance test matrix as the gatekeeper. |
| Clock drift breaking rendezvous | Devices with clocks >5 minutes apart will fail rendezvous ID derivation. | 1-hour overlap window, 5-minute tolerance. Diagnostic API reports clock drift as possible cause. NTP is virtually universal. |
| Store-and-forward forward secrecy degradation | All messages within a single DH ratchet epoch share the same DH secret. | Document as a known tradeoff. Inherent to one-way offline messaging. |
| Mobile platform constraints | iOS/Android background execution limits, battery drain, push notification requirements. | Document constraints. Implement platform-aware keepalive. Strongly recommend server-mode peer for mobile use cases. |
| Scope creep via deferred features | MLS, federation, multi-server coordination are deferred but expected. | Clean internal APIs designed for extensibility. Clear scope boundaries documented. |

---

## 15. Success Criteria

| Criterion | Measurement |
|---|---|
| Time to first P2P channel | A developer with no prior cairn experience establishes an encrypted P2P channel within 15 minutes of reading the getting-started guide. |
| Cross-language interoperability | 100% pass rate on the conformance test matrix for all implemented language pairs, at all tested tiers. |
| Zero-config connectivity | Tier 0 successfully establishes connections between peers behind open and cone NATs without any server infrastructure. |
| Tier 1 coverage | With companion infrastructure deployed, connections succeed between peers behind symmetric NATs and corporate firewalls. |
| Server-mode reliability | Store-and-forward delivers 100% of messages to offline peers within the retention window upon reconnection. |
| Resource efficiency | Companion signaling server handles 1000+ concurrent peers on 512 MB RAM. Server-mode peer operates within 512 MB RAM under moderate load. |
| Security audit readiness | Cryptographic design passes independent security review with no critical findings. |

---

*End of PRD*
