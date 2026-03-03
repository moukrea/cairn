# cairn — Universal Peer-to-Peer Connectivity Library

**Design & Architecture Document**
*Version 0.6 — Draft — March 2026*
*Revision notes: all open questions from v0.5 resolved with concrete design decisions. Updated: TURN RFC (→8656), pin code (→Crockford Base32), PAKE (→SPAKE2), UUID (→v7), transport chain, store-and-forward encryption model, session re-establishment, Circuit Relay v2 limits, mDNS discovery, pairing rate limiting, unpairing protocol, management API, resource accounting, companion infrastructure (→Rust), glossary.*

---

## Table of Contents

1. [Vision & Problem Statement](#1-vision--problem-statement)
2. [Architecture Overview](#2-architecture-overview)
3. [Wire Protocol Specification](#3-wire-protocol-specification)
4. [Pairing System](#4-pairing-system)
5. [Encryption & Key Management](#5-encryption--key-management)
6. [NAT Traversal & Transport Fallback Chain](#6-nat-traversal--transport-fallback-chain)
7. [Reconnection System](#7-reconnection-system)
8. [Rendezvous & Peer Discovery](#8-rendezvous--peer-discovery)
9. [Mesh Networking (Opt-in)](#9-mesh-networking-opt-in)
10. [Server Mode — Always-On Peer (Opt-in)](#10-server-mode--always-on-peer-opt-in)
11. [Graceful Failure Handling](#11-graceful-failure-handling)
12. [API Surface Design](#12-api-surface-design)
13. [Implementation Strategy](#13-implementation-strategy)
14. [Demo Applications](#14-demo-applications)
15. [Design Decisions & Resolved Questions](#15-design-decisions--resolved-questions)
16. [Appendix A: Glossary](#appendix-a-glossary)

---

## 1. Vision & Problem Statement

cairn is a universal peer-to-peer connectivity library designed to eliminate the recurring effort of implementing P2P communication infrastructure in new projects. The core observation driving this project is simple: across multiple projects (Parley/P2P Chat, Tack, RemoShell, and others), the same fundamental P2P plumbing — signaling, NAT traversal, relay fallback, encryption, peer discovery — is reimplemented from scratch every time.

cairn provides a single, opinionated, batteries-included library available across all target languages with full feature parity and inter-compatibility. A developer should be able to install the package and have a working encrypted P2P channel in minutes — not days — without deploying or configuring any server infrastructure.

### 1.1 Core Value Proposition

- **Install and go**: `composer install`, `npm install`, `go get`, `cargo add`, `pip install` — identical experience across languages
- **Zero-config by default**: the library ships with sensible defaults leveraging publicly available infrastructure (public STUN servers, DHT bootstrap nodes, BitTorrent trackers), enabling functional P2P connectivity out of the box with no server-side setup required from the developer
- **Progressively improvable**: start with zero-config public infrastructure, then deploy cairn's companion infrastructure components (signaling server, TURN relay) with a single command to unlock better connectivity, or run a server-mode peer for store-and-forward and personal relay — each step is optional and additive
- **Inter-compatible**: a Rust peer connects seamlessly to a PHP peer, a Go peer to a TypeScript peer — any combination works
- **Secure by default**: end-to-end encryption, verified pairing, forward secrecy — no opt-in required
- **Resilient by design**: aggressive transport fallback, automatic reconnection, mesh routing — connections survive network changes, restarts, and hostile network environments

### 1.2 Target Languages

| Language | Package Manager | Async Runtime | libp2p Status |
|---|---|---|---|
| Rust | cargo (crates.io) | tokio | Mature (rust-libp2p) |
| Go | go get (modules) | goroutines | Mature (go-libp2p, reference impl) |
| TypeScript/JS | npm | async/await, event loop | Mature (js-libp2p) |
| Python | pip (PyPI) | asyncio | Beta (py-libp2p v0.5+, core stable, not yet production) |
| PHP | composer (Packagist) | ReactPHP / Amp / Swoole | No existing impl — custom build required |

**Note on PHP**: PHP's request/response execution model requires a long-running daemon process (via ReactPHP, Amp, or Swoole) for persistent P2P connections. This is a known constraint and must be documented clearly for PHP consumers of the library.

**Note on libp2p ecosystem**: as of 2025, libp2p has **nine active implementations** (Python, Nim, JS, Rust, Go, C++, .NET, JVM, and litep2p). cairn targets the five languages above based on the project's needs, not libp2p coverage.

---

## 2. Architecture Overview

The architecture is organized in distinct layers, from low-level transport to application-facing API. Each layer has a well-defined responsibility and communicates with adjacent layers through clean interfaces.

### 2.1 Layer Model

| Layer | Responsibility | Implementation |
|---|---|---|
| Transport | Raw connectivity: UDP, TCP, WebSocket, WebTransport, QUIC | libp2p transports + custom fallbacks |
| NAT Traversal | Hole punching, STUN/TURN, relay fallback | libp2p AutoNAT, Circuit Relay v2, custom TURN integration |
| Security | Encryption, authentication, key management | Noise Protocol (libp2p), PAKE for pairing, Double Ratchet for sessions |
| Session | Persistent sessions surviving transport churn, reconnection, state tracking | Custom session manager on top of libp2p streams |
| Discovery | Peer finding via DHT, trackers, signaling servers, rendezvous points | libp2p Kademlia DHT, custom tracker/signaling integration |
| Mesh (opt-in) | Multi-hop routing, shortest path selection, relay through peers | cairn application-level relay on libp2p streams (not Circuit Relay v2) |
| API Surface | Developer-facing interface: connect, send, receive, configure | Native per-language idiomatic wrapper |

**Important note on Circuit Relay v2**: libp2p's Circuit Relay v2 imposes strict resource limits by design — **2 minutes** per relayed connection and **128 KB** per direction (go-libp2p defaults). It was designed for transient hole-punching coordination, not sustained relayed connections. cairn distinguishes three relay mechanisms:

1. **Circuit Relay v2**: used only for hole-punch coordination (transient, limited)
2. **Companion TURN relay**: for sustained transport-level relay (Tier 1+, see section 2.4.2)
3. **cairn application-level relay**: between paired peers for mesh routing and personal relay (section 9, 10.4), implemented as custom relay logic on top of standard libp2p streams — not subject to Circuit Relay v2's limits

### 2.2 Dependency on libp2p

cairn is not a replacement for libp2p — it is an **opinionated facade** over it. libp2p provides the transport primitives, protocol multiplexing, peer identity, and basic NAT traversal. cairn adds opinionated defaults, a unified configuration model, the pairing system, session persistence, reconnection logic, and a drastically simplified API.

Think of the relationship as analogous to what Express.js does for Node's http module, or what the Requests library does for Python's urllib: the underlying capability exists, but the developer experience is transformed.

**Security layer interaction**: cairn uses libp2p's transport-level encryption (Noise) for the underlying connection, providing hop-by-hop transport security and peer authentication at the libp2p level. On top of this, cairn applies its own session-level Double Ratchet encryption for end-to-end security. This double encryption is intentional: the transport-level encryption protects against network observers, while the session-level encryption provides end-to-end guarantees that persist even if a relay or mesh intermediary is compromised. The overhead is acceptable because the inner encryption operates on application payloads only, not transport framing. cairn's pairing-level Noise XX handshake (authenticated by the PAKE-derived secret) is a separate, application-level handshake that runs over the already-encrypted libp2p stream.

### 2.3 Configuration Model

All configuration is provided at initialization time through a single configuration object/struct/array (idiomatic per language). The library ships with sensible defaults for every setting, enabling a fully functional zero-config experience. Developers can override any or all defaults to suit their specific needs.

#### 2.3.1 Infrastructure Tiers

The configuration model is designed around progressive tiers of infrastructure commitment. The key principle is that each tier builds on the previous one — every enhancement is optional and additive, and the library works at every tier. cairn provides companion infrastructure components (see section 2.4) so that moving from one tier to the next is as simple as deploying a single container, not sourcing third-party services.

| Tier | Developer Effort | What's Used | Connectivity Coverage |
|---|---|---|---|
| **Tier 0 — Zero-config** | None — install and use | Public STUN servers, public libp2p DHT bootstrap nodes, public BitTorrent trackers, mDNS for LAN discovery | Peers behind open or cone NATs, same-LAN peers (instant discovery via mDNS), any topology where STUN-assisted hole punching succeeds. Covers the majority of home network and cloud server scenarios. |
| **Tier 1 — Add signaling & relay** | Deploy cairn's companion signaling server and/or TURN relay (single Docker container each) | Everything in Tier 0 plus real-time signaling and TURN relay | Adds coverage for symmetric NATs, corporate firewalls, and restrictive networks. Sub-second peer discovery via signaling. |
| **Tier 2 — Add server-mode peer** | Run a cairn peer in server mode on an always-on device (see section 10) | Everything in Tier 1 plus store-and-forward, personal relay, multi-device sync hub | Offline message delivery, relay bridging through a trusted personal node, seamless multi-device synchronization. |
| **Tier 3 — Full control** | Operate your own complete infrastructure stack | Custom STUN, TURN, signaling, trackers, bootstrap nodes, multiple server-mode peers | Complete control over reliability, latency, and privacy. No dependency on third-party public infrastructure. |

At Tier 0, the library is fully functional without the developer deploying or configuring any servers. Connectivity is best-effort: it works for a wide range of network topologies but will report degraded capability (via the `TransportExhausted` error) when both peers are behind symmetric NATs or restrictive firewalls and no TURN relay is available. Each subsequent tier fills in a specific gap — Tier 1 closes the relay/signaling gap, Tier 2 adds persistence and always-on availability, and Tier 3 removes all third-party dependencies.

#### 2.3.2 Default Infrastructure

The library ships with a curated, maintained list of default public infrastructure endpoints:

- **STUN servers**: a hardcoded list of well-known, reliable public STUN servers (Google, Cloudflare, and others). These are free, require no credentials, and are sufficient for NAT type detection and hole punching.
- **DHT bootstrap nodes**: the standard libp2p public DHT bootstrap peers, enabling Kademlia-based peer discovery out of the box.
- **BitTorrent trackers**: a curated list of stable, open BitTorrent trackers (UDP and HTTP/WebSocket) for tracker-based peer discovery.
- **mDNS**: for same-LAN discovery; peers on the same network segment find each other instantly without internet access. The rendezvous ID is announced as a mDNS service name. This is attempted **first** before any remote discovery mechanism.

These defaults are compiled into the library and updated with each release. The library also supports an opt-in URL fetch (disabled by default) that retrieves a signed JSON manifest from a cairn-controlled endpoint. The manifest is signed with an Ed25519 key whose public half is embedded in the library. The signature is verified before the list is applied. This is the same approach used by many P2P networks for bootstrap node lists.

#### 2.3.3 Configurable Settings

All settings below have defaults and are optional. Developers override only what they need:

- **STUN servers**: list of STUN server URLs for NAT type detection and hole punching (default: curated public list)
- **TURN servers**: list of TURN relay servers with credentials, used as fallback when direct connection fails (default: none — deploy cairn's companion TURN relay for Tier 1+)
- **Signaling servers**: WebSocket-based signaling endpoints for initial peer handshake (default: none — deploy cairn's companion signaling server for Tier 1+)
- **Tracker URLs**: BitTorrent tracker URLs for DHT-based peer discovery (default: curated public list)
- **Bootstrap nodes**: libp2p DHT bootstrap peers for Kademlia routing (default: libp2p public bootstrap list)
- **Transport preferences**: ordered priority list of transports to attempt (default: QUIC → TCP → WebSocket over TLS → WebTransport → Circuit Relay v2). QUIC refers to QUIC v1 (RFC 9000). WebSocket over TLS is prioritized above WebTransport because it traverses restrictive networks more reliably — see section 6.1.
- **Reconnection policy**: timeouts, backoff strategy, max retries, session expiry window
- **Mesh settings**: enable/disable mesh routing, max hops, relay willingness
- **Storage backend**: where to persist session keys, peer identities, and pairing state (filesystem path, custom adapter, etc.)

#### 2.3.4 Tradeoffs of Zero-Config Mode

Developers should be aware of the following tradeoffs when operating at Tier 0. Each tradeoff is addressable by deploying one or more of cairn's companion infrastructure components (section 2.4):

- **Discovery latency**: DHT and tracker-based discovery can take seconds to minutes for initial peer finding, compared to sub-second with a dedicated signaling server. This is most noticeable during the first connection; subsequent reconnections use the rendezvous system and are faster. **Fix**: deploy the companion signaling server (Tier 1).
- **Relay gap**: without TURN servers, peers behind symmetric NATs or aggressive firewalls cannot establish direct connections. The library will exhaust its transport chain and report a clear `TransportExhausted` error with diagnostic information about what failed and why. **Fix**: deploy the companion TURN relay (Tier 1), or run a server-mode peer as a personal relay (Tier 2).
- **Public infrastructure reliability**: public STUN servers, DHT nodes, and trackers are generally reliable but not SLA-backed. The curated default list includes redundancy (multiple servers per category), but availability is best-effort. **Fix**: operate your own infrastructure (Tier 3).
- **Privacy**: using public infrastructure means DHT queries and tracker announces are visible to the operators of that infrastructure. The rendezvous ID system (section 8) ensures that observers cannot correlate activity to specific peer identities, but metadata (IP addresses, connection timing) is exposed to public infrastructure operators. **Fix**: operate your own infrastructure (Tier 3).
- **Offline delivery**: without a persistently available peer, messages to offline recipients queue on the sender's device. **Fix**: run a server-mode peer (Tier 2).

### 2.4 Companion Infrastructure

The cairn project provides lightweight, self-hostable infrastructure components as part of the project deliverables. These are not the library itself — they are standalone services that the library can connect to. They exist so that developers moving from Tier 0 to Tier 1 don't need to source, evaluate, or integrate third-party signaling and relay solutions. Each component is designed to be trivially deployable: a single binary, a Docker image, or a Docker Compose snippet.

#### 2.4.1 cairn Signaling Server

A lightweight WebSocket-based signaling server that provides real-time peer discovery and handshake relay. Peers connect over WSS (port 443), subscribe to rendezvous topics, and exchange reachability information and handshake messages in real-time.

- **Deployment**: single binary or Docker container. Configuration via environment variables (listen address, TLS cert path, optional authentication token).
- **Resource footprint**: minimal — the signaling server holds no message state, only active WebSocket connections. A small VPS or a Raspberry Pi can serve thousands of concurrent peers.
- **Protocol**: the server is a dumb message router — it forwards CBOR-encoded signaling messages between peers subscribed to the same rendezvous topic. It does not inspect, decrypt, or store message content.
- **Authentication** (optional): the signaling server can require a bearer token to prevent open abuse. Tokens are configured in the cairn library alongside the signaling server URL. Without a token, the server is open — suitable for personal or small-community use.
- **Federation** (future): multiple signaling servers can optionally federate to share rendezvous state, enabling larger deployments without a single point of failure.

#### 2.4.2 cairn TURN Relay

A TURN relay server that provides transport-level relay for peers that cannot establish direct connections. Compatible with standard TURN (RFC 8656, which obsoletes RFC 5766) so it can also be used with non-cairn applications.

- **Deployment**: single binary or Docker container. Configuration via environment variables (listen address, relay port range, credentials, TLS settings).
- **Resource footprint**: moderate — the relay server forwards traffic, so bandwidth scales linearly with the number of active relay sessions. A small VPS is sufficient for personal or small-team use.
- **Authentication**: TURN requires credentials. The companion relay supports static username/password configuration (suitable for personal and small-team use) and a REST API for dynamic credential provisioning (suitable for larger deployments).
- **Port 443 support**: the relay server can listen on port 443 with TLS, providing the WebSocket-over-443 fallback transport (section 6.2) for peers behind restrictive corporate firewalls.

#### 2.4.3 Deployment Examples

The companion infrastructure is designed to be deployable in minutes:

```
# Signaling server only (Tier 1 — discovery improvement)
docker run -d -p 443:443 cairn/signal --tls-cert /certs/cert.pem --tls-key /certs/key.pem

# TURN relay only (Tier 1 — NAT traversal improvement)
docker run -d -p 3478:3478/udp -p 443:443 cairn/relay --credentials user:pass

# Both together via Compose
docker compose up -d  # cairn-infra/docker-compose.yml provided in the project repo

# Server-mode peer (Tier 2 — optional, independent of signaling/relay)
docker run -d -v cairn-data:/data cairn/peer --server-mode
```

The library's configuration accepts these endpoints directly:

```
node = cairn.create({
  signaling_servers: ["wss://signal.example.com"],
  turn_servers: [{ url: "turn:relay.example.com:3478", username: "user", credential: "pass" }],
})
```

---

## 3. Wire Protocol Specification

Since all five language implementations must interoperate perfectly, a **language-agnostic wire protocol** is the single most critical deliverable. All implementations are built against this spec, not against each other.

### 3.1 Serialization Format

All wire messages use **CBOR (Concise Binary Object Representation, RFC 8949)** as the serialization format. CBOR is chosen over alternatives for the following reasons:

- Binary-efficient (unlike JSON), critical for bandwidth-constrained relay paths
- Self-describing schema (unlike Protocol Buffers), simplifying debugging and extensibility
- Mature implementations in all five target languages
- Deterministic encoding mode available (for signatures and hashing)

### 3.2 Message Envelope

Every wire message follows a common envelope structure containing:

- A protocol version identifier (uint8)
- A message type code (uint16)
- A unique message ID (UUID v7 per RFC 9562, 16 bytes — timestamp-ordered for store-and-forward sequencing and log correlation, with 74 bits of randomness for uniqueness)
- An optional session ID (32 bytes, present after session establishment)
- The payload (CBOR-encoded, type-specific)
- An authentication tag (HMAC or AEAD tag, present after key establishment)

### 3.3 Message Types

The protocol defines the following message type categories:

- **0x01xx — Pairing**: PairRequest, PairChallenge, PairResponse, PairConfirm, PairReject, PairRevoke (for unpairing notification — see section 4.5)
- **0x02xx — Session**: SessionResume, SessionResumeAck, SessionExpired, SessionClose
- **0x03xx — Data**: DataMessage, DataAck, DataNack (for reliable delivery)
- **0x04xx — Control**: Heartbeat, HeartbeatAck, TransportMigrate, TransportMigrateAck
- **0x05xx — Mesh**: RouteRequest, RouteResponse, RelayData, RelayAck
- **0x06xx — Rendezvous**: RendezvousPublish, RendezvousQuery, RendezvousResponse
- **0x07xx — Forward**: ForwardRequest, ForwardAck, ForwardDeliver, ForwardPurge (for store-and-forward via server-mode peers, see section 10)

Message types `0x0100`–`0xEFFF` are reserved for the cairn core protocol. Message types `0xF000`–`0xFFFF` are available for **application-specific extensions**. The library provides a generic `on_custom_message(type_code, callback)` handler. Applications that need to interoperate coordinate their own type allocations. No central registry is required.

Each message type has a fully specified CBOR structure documented in a separate Protocol Reference appendix (to be authored alongside implementation).

### 3.4 Version Negotiation

On first contact, peers exchange a VersionNegotiate message listing supported protocol versions. The highest mutually supported version is selected. This allows future protocol evolution without breaking backward compatibility.

If peers share no common protocol version, the connection is rejected with a `VersionMismatch` error (see section 11.1). The error message includes the peer's supported version range, enabling the application to inform the user which peer needs updating.

---

## 4. Pairing System

Pairing is the process by which two peers establish mutual trust for the first time. It is the foundation of all subsequent secure communication and must be both cryptographically robust and flexible enough to accommodate different application UX requirements.

### 4.1 Threat Model

Peer discovery happens over public infrastructure (DHT, trackers, signaling servers). An attacker observing this infrastructure can see that peers are attempting to connect, but must not be able to:

- Intercept or modify the pairing exchange (MITM)
- Derive the shared secret or session keys
- Impersonate either peer in future connections
- Correlate pairing activity to specific identities over time

### 4.2 Pairing Flow

The pairing process follows a sequence designed to prevent man-in-the-middle attacks even over public channels. The flow varies depending on whether the chosen pairing mechanism is **verification-only** (post-exchange confirmation) or **initiation-capable** (bootstraps both discovery and authentication in a single action).

#### 4.2.1 Standard Flow (Verification-Only Mechanisms)

Used with mechanisms like numeric SAS, where both peers are already discoverable on the network and need to verify the key exchange after it occurs.

**Phase 1 — Identity Generation**: each peer generates a long-term Ed25519 keypair. The public key hash serves as the persistent Peer ID.

**Phase 2 — Discovery**: peers find each other through configured discovery mechanisms (DHT, tracker, signaling server). At this stage, they know each other's Peer ID but have no trust relationship.

**Phase 3 — Key Exchange**: peers perform an X25519 Diffie-Hellman key exchange over the public channel, yielding a shared secret. This exchange is authenticated using the Noise XX handshake pattern (mutual authentication with identity revelation).

**Phase 4 — Out-of-Band Verification**: to prevent MITM, peers verify the key exchange through an out-of-band mechanism. The library computes a Short Authentication String (SAS) from the handshake transcript — a 6-digit numeric code or a set of emoji. Both peers display this SAS, and the users confirm they match. The specific verification UX is pluggable (see 4.3).

**Phase 5 — Trust Establishment**: once verified, both peers store each other's identity public key and the derived keying material in local persistent storage. Future connections authenticate via these stored keys without repeating the pairing dance (trust-on-first-use with verified first use).

#### 4.2.2 Initiation Flow (Self-Bootstrapping Mechanisms)

Used with mechanisms like QR code scanning, pin code entry, or pairing links, where the pairing mechanism itself carries enough information to both discover the peer and authenticate the exchange — no prior network-level discovery is needed.

**Phase 1 — Identity Generation**: same as standard flow.

**Phase 2 — Pairing Payload Generation**: the initiating peer generates a pairing payload containing its Peer ID, a one-time pairing nonce, a PAKE credential (derived from the pin code or embedded in the QR/link), and optionally one or more connection hints (rendezvous IDs, signaling endpoints, listening addresses). This payload is encoded as a QR code, a human-readable pin code, or a URI depending on the chosen mechanism.

**Phase 3 — Payload Transfer**: the pairing payload is transferred out-of-band — the second user scans the QR code, types the pin code, or clicks the link.

**Phase 4 — Rendezvous & Authenticated Key Exchange**: both peers derive a rendezvous point from the pairing payload (see section 8.6) and find each other there. They perform a **SPAKE2** password-authenticated key exchange using the shared secret embedded in the pairing payload. SPAKE2 is selected for its cross-language library maturity (production-quality implementations in Rust, Go, Python, JavaScript; PHP via FFI) and proven pairing use cases (magic-wormhole, FIDO2/CTAP2). The RustCrypto SPAKE2 implementation uses Ed25519 with hash-to-curve derived M/N values, mitigating the theoretical trusted setup concern. Because the key exchange is bound to the shared secret, MITM is prevented without a separate verification step — the authentication is inherent in the exchange itself.

**Phase 5 — Trust Establishment**: same as standard flow. Both peers store each other's identity and derived keying material.

The initiation flow provides a superior UX for most consumer and cross-device scenarios because it collapses discovery, authentication, and verification into a single user action (scan, type, or click).

### 4.3 Pairing Mechanisms

The library defines the pairing **protocol** but lets applications choose the **mechanism** through a pluggable interface. Mechanisms fall into two categories based on when in the flow they participate.

#### 4.3.1 Verification-Only Mechanisms

These mechanisms verify an already-completed key exchange. They follow the standard flow (4.2.1) and require that both peers are already discoverable on the network.

- **Numeric SAS**: a 6-digit numeric code derived from the handshake transcript, displayed on both devices. Users confirm the codes match verbally or visually. Best for CLI tools, headless services, and scenarios where both peers are co-located.

- **Emoji SAS**: same principle as numeric SAS but using a sequence of emoji instead of digits. More memorable and harder to confuse than numbers. Best for consumer-facing applications.

#### 4.3.2 Initiation Mechanisms

These mechanisms bootstrap the entire pairing process — they carry enough information to handle discovery, authentication, and verification in a single user action. They follow the initiation flow (4.2.2).

- **QR Code**: one peer generates and displays a QR code containing the pairing payload (Peer ID, one-time nonce, PAKE credential, connection hints). The other peer scans it with a camera. The payload is encoded as **raw CBOR (binary mode)** with **Error Correction Level M** (15% recovery), balancing error resilience with data capacity. Maximum payload size is **256 bytes**, requiring up to QR Version 14 at EC Level M (~283 data bytes capacity), producing a 73×73 module grid — still fast to scan on any modern smartphone camera. The QR library auto-selects the minimum version for the actual payload size. A typical pairing payload (Peer ID 32B + nonce 16B + PAKE credential 32B + connection hints ~64B + CBOR framing ~16B ≈ 160 bytes) fits in a Version 11 (61×61 modules). Best for mobile-to-mobile, mobile-to-desktop, and any scenario where one device has a screen and the other has a camera. The QR code is single-use and time-limited (default: 5 minutes expiry).

- **Pin Code**: one peer generates a short code (e.g., `98AF-XZ2A`) and the user enters it on the other device. The code serves as the PAKE input — both the discovery hint (a rendezvous ID is derived from the code, see section 8.6) and the authentication credential. Pin codes use the **Crockford Base32** character set (32 characters: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` — excludes I, L, O, U to avoid visual ambiguity). Default length is 8 characters, formatted as `XXXX-XXXX`, providing exactly **40 bits of entropy** (`8 × 5 = 40 bits`) — sufficient for a time-limited, rate-limited pairing exchange. Input is case-insensitive; the library normalizes `i`/`l` → `1` and `o` → `0` on receipt. The code is single-use and time-limited (default: 5 minutes expiry). Best for cross-device pairing when camera-based scanning is not practical (two desktops, two CLI tools, remote pairing over phone call).

- **Pairing Link / URI**: same payload as QR but encoded as a URI (`cairn://pair?pid=...&nonce=...&pake=...&hints=...`). Can be shared via any text channel — messaging apps, email, SMS, clipboard. The receiving application registers the `cairn://` URI scheme (or a configurable custom scheme) and handles it as a pairing initiation. Best for remote pairing where users can exchange a link but not scan a QR code. Carries the same security properties as QR (single-use, time-limited, PAKE-authenticated). Applications should warn users to share the link only through trusted channels since anyone with the link can initiate a pairing attempt within the validity window.

- **Pre-Shared Key**: a secret configured on both peers ahead of time (e.g., from a config file, environment variable, or secrets manager). The PSK is used as PAKE input, and the rendezvous ID is derived from it. Best for homelab services, automated deployments, and CI/CD pipelines where human interaction during pairing is not feasible. Unlike time-limited codes, PSKs can be long-lived but should be rotated periodically.

#### 4.3.3 Custom Adapter

Applications can implement the pairing mechanism interface for domain-specific flows (e.g., email-based verification, hardware token, NFC tap, Bluetooth LE out-of-band exchange). The interface provides hooks for payload generation, payload consumption, and key exchange integration, allowing arbitrary transport of the pairing payload.

### 4.4 Pairing Rate Limiting

The peer that generates the pin code (the "acceptor") enforces rate limiting to protect the 40-bit entropy of pin codes:

- **PAKE inherent limit**: each SPAKE2 protocol run allows exactly one password guess. An attacker must complete a full protocol handshake per attempt.
- **Connection rate limiting**: the acceptor rejects new pairing connections exceeding **5 attempts per 30-second window** from any source. After 10 total failed attempts, the current pin code is automatically invalidated and a new one must be generated.
- **Time expiry**: pin codes expire after **5 minutes** (default, configurable). With 5 attempts per 30 seconds and a 5-minute window, an attacker gets at most ~50 guesses against 2⁴⁰ ≈ 1.1 trillion possible codes — a negligible success probability of ~4.5 × 10⁻⁸.
- **Progressive delay**: after each failed PAKE attempt, the acceptor introduces a 2-second delay before accepting the next attempt, reducing throughput of brute-force attacks.

Pre-shared keys (long-lived) should use a minimum of 128 bits of entropy (e.g., 26 Crockford Base32 characters) since they are not time-limited.

### 4.5 Unpairing Protocol

When `node.unpair(peer_id)` is called:

1. If a session with the peer is active, send a `PairRevoke` message (0x01xx) on the control channel. This is best-effort — the unpair proceeds regardless of whether the message is delivered.
2. Delete all local state for this peer: pairing secret, session keys, ratchet state, rendezvous derivation material.
3. Close all active sessions and channels with this peer.
4. If the remote peer is offline, it will discover the unpairing when its next connection attempt fails authentication (the unpairing peer has no keys to complete the handshake).
5. Upon receiving a `PairRevoke`, the remote peer emits a `peer_unpaired` event and deletes its own state for that peer.

**Mesh behavior**: if A unpairs B but mesh peer C still attempts to route traffic between them, the routing will fail because A will reject messages from B (unknown peer). C will receive a routing error and update its topology accordingly.

### 4.6 Pairing in Mesh Context

For mesh/group scenarios, pairing can be extended in two ways:

- **Pairwise mesh**: every peer in the group pairs individually with every other peer. Simple, scales to small groups.
- **Group key agreement**: using a protocol like MLS (Messaging Layer Security, RFC 9420) where group membership and keys are managed collectively.

The library should support pairwise initially and add group key agreement in a later version.

---

## 5. Encryption & Key Management

### 5.1 Cryptographic Primitives

| Purpose | Algorithm | Rationale |
|---|---|---|
| Identity keys | Ed25519 | Widely supported, fast, deterministic signatures |
| Key exchange | X25519 (Diffie-Hellman) | Standard ECDH, compatible with Noise framework |
| Handshake | Noise XX pattern | Mutual authentication with identity revelation |
| Pairing authentication | SPAKE2 (balanced PAKE) | Selected for cross-language library maturity and proven pairing use cases (magic-wormhole, FIDO2). Each protocol run yields one password guess for an active attacker. Future consideration: CPace (IETF CFRG recommended balanced PAKE) if library maturity improves; OPAQUE (IETF CFRG recommended augmented PAKE) for server-mode PSK storage hardening post-v1.0 |
| Session encryption | AES-256-GCM or ChaCha20-Poly1305 | AEAD, hardware-accelerated (AES) or constant-time (ChaCha20) |
| Key derivation | HKDF-SHA256 | Standard KDF for deriving multiple keys from shared secrets |
| Key ratchet | Double Ratchet (Signal protocol) | Forward secrecy and break-in recovery for long-lived sessions |
| Rendezvous ID | HKDF-SHA256 from pairing secret | Deterministic, unlinkable to peer identities |
| SAS generation | HKDF from handshake transcript | Short, verifiable authentication string |

### 5.2 Forward Secrecy & Key Rotation

Long-lived sessions use a **Double Ratchet** mechanism (as in the Signal protocol) to achieve forward secrecy. Each message or group of messages uses a unique symmetric key derived from the ratchet state. Compromising a key at time T reveals nothing about messages at time T-1 or T+1.

On reconnection, the ratchet advances — fresh symmetric keys are derived from existing keying material. This means even if an attacker captures the session state during one connection window, previous and future windows remain secure.

### 5.3 Key Storage

The library provides a **pluggable storage backend** interface for persisting:

- Identity keypairs
- Paired peer identity keys and trust state
- Session keying material and ratchet state
- Rendezvous ID rotation state

Default implementations include:

- **Filesystem**: encrypted at rest with a passphrase
- **In-memory**: for ephemeral/testing use
- **Custom adapter interface**: for integration with system keychains, HSMs, or application-specific storage

---

## 6. NAT Traversal & Transport Fallback Chain

cairn must establish connectivity in any network environment, including restrictive corporate networks that only allow HTTPS on port 443. The library implements an aggressive, ordered fallback chain that tries progressively less optimal transports until one succeeds.

### 6.1 Transport Priority Chain

| Priority | Transport | When It Works | Trade-offs |
|---|---|---|---|
| 1 | Direct UDP (QUIC v1, RFC 9000) | Same LAN or open NAT | Best performance, lowest latency |
| 2 | STUN-assisted UDP hole punch | Compatible NAT types (cone NAT) | Good performance, may fail with symmetric NAT |
| 3 | Direct TCP | When UDP is blocked but TCP is open | Higher overhead than QUIC, reliable |
| 4 | TURN relay (UDP) | When hole punching fails | Adds latency via relay, but UDP performance |
| 5 | TURN relay (TCP) | When UDP is fully blocked | Relay + TCP overhead |
| 6 | WebSocket over TLS (port 443) | Corporate firewalls blocking non-HTTPS | Tunnels through virtually any firewall |
| 7 | WebTransport over HTTP/3 (port 443) | Modern environments with HTTP/3 support | Better than WS, multiplexed, may not be available |
| 8 | Circuit Relay v2 (hole-punch coordination) | When direct connection requires relay-assisted hole punching | Transient only (2 min, 128 KB limits) |
| 9 | HTTPS long-polling (port 443) | Absolute worst case, aggressive proxies | High latency, high overhead, but it works |

The transport chain uses **QUIC v1 (RFC 9000)**, consistent with libp2p's QUIC implementation across Rust, Go, and JavaScript.

**WebSocket over TLS is prioritized above WebTransport** because, at that point in the fallback chain, the peer is likely in a restrictive network environment. WebSocket over TLS on port 443 traverses virtually all HTTP proxies and corporate firewalls, while WebTransport (HTTP/3 over QUIC) may be blocked by firewalls that do not support or inspect QUIC/UDP traffic.

The library attempts transports in priority order, with configurable timeouts per transport. Multiple transports may be attempted in parallel (ICE-style) for faster connection establishment. Once connected, the library continuously probes for better transports and can migrate mid-session (e.g., upgrading from WebSocket relay to direct QUIC if network conditions change).

**Note on PHP transport support**: the PHP implementation will not support QUIC or WebTransport at launch due to limited ecosystem support for these protocols in PHP. The PHP transport chain starts at STUN-assisted UDP hole punch (priority 2) or TCP (priority 3). This is an acceptable degradation — the fallback chain ensures connectivity regardless of which transports are available.

**Note on zero-config mode (Tier 0)**: transports 1–3 are available out of the box using public STUN servers. Transports 4–5 require a TURN relay (Tier 1+ — deploy cairn's companion TURN relay, see section 2.4.2). Transports 6–7 require a relay server on port 443 (Tier 1+ — the companion TURN relay supports port 443). In Tier 0, the library will attempt priorities 1–3 and report `TransportExhausted` with clear diagnostics if none succeed, indicating that deploying companion infrastructure would resolve the connectivity issue.

### 6.2 The Port 443 Escape Hatch

The WebSocket-over-443 transport is the critical fallback that ensures connectivity in corporate/restrictive environments. It requires a relay server listening on port 443 speaking WSS (WebSocket Secure). This relay can be self-hosted or provided as a shared service. Traffic appears as standard HTTPS to network inspection tools.

For environments with deep packet inspection (DPI) that blocks WebSocket upgrades, the HTTPS long-polling fallback encodes the P2P channel as standard HTTP request/response pairs, which is indistinguishable from normal web API traffic.

### 6.3 Network Monitoring & Proactive Migration

The library monitors connection quality (latency, jitter, packet loss) and network interface state. When degradation is detected, the library proactively begins probing alternative transports **before** the current connection fails. This enables seamless transport migration that is invisible to the application layer.

**NAT type detection**: the library exposes NAT type as a read-only diagnostic (e.g., `node.network_info().nat_type` → `open | full_cone | restricted_cone | port_restricted_cone | symmetric | unknown`). This is invaluable for debugging connectivity issues. Application behavior should not depend on NAT type — the transport fallback chain handles this transparently.

---

## 7. Reconnection System

Reconnection is one of the most critical aspects of real-world P2P usability. Connections drop constantly — network switches, device sleep, reboots, transient failures. The library must handle all of these transparently, resuming sessions without application intervention.

### 7.1 Connection Abstraction Layers

A peer connection is composed of four distinct layers, each with a different lifetime:

| Layer | Lifetime | Survives | Contains |
|---|---|---|---|
| Identity | Permanent | Everything | Ed25519 keypair, Peer ID |
| Pairing | Until explicitly revoked | Reboots, reinstalls | Mutual trust, long-term shared secrets, peer identity keys |
| Session | Survives transport disruptions | Network changes, brief disconnections | Session ID, sequence counters, ratchet state, encryption keys |
| Transport | Ephemeral | Nothing — rebuilt on reconnection | The actual UDP/TCP/WebSocket connection |

The library's job is to keep the session layer alive even when the transport layer is constantly churning underneath it. **The application only ever interacts with the session layer.**

### 7.2 Connection State Machine

The connection lifecycle follows a detailed state machine that the application can observe via events:

1. **Connected**: active, healthy connection. Data flows normally.
2. **Unstable**: connection degradation detected (high latency, packet loss). Library is proactively probing alternative transports. Data still flows but may be delayed.
3. **Disconnected**: transport connection lost. Library immediately enters reconnection.
4. **Reconnecting**: actively attempting to re-establish transport. Trying transports in fallback order, querying rendezvous points.
5. **Suspended**: reconnection attempts temporarily paused (exponential backoff). Will retry periodically.
6. **Reconnected**: transport re-established, session resumed, sequence state synchronized.
7. **Failed**: maximum retry budget exhausted or session expired. Application must decide next action (re-pair, give up, notify user).

### 7.3 Session Resumption Protocol

When a transport connection is re-established after a disruption, the peers perform a lightweight session resumption handshake:

1. Reconnecting peer presents its Session ID and a cryptographic proof of identity (signed challenge using session keys)
2. Receiving peer validates the Session ID exists, is not expired, and the proof is valid
3. Both peers advance the key ratchet, deriving fresh symmetric keys for the new transport window
4. Both peers exchange their last-seen sequence numbers to identify any messages that were in-flight during the disconnection
5. Any queued messages are retransmitted in sequence order
6. Session is restored — application receives a state transition event

**Session expiry**: if a peer has been absent longer than the configured session expiry window (default: 24 hours), the session is invalidated. The peer must establish a fresh session, though re-pairing is not required since the pairing layer trust persists.

**Session re-establishment after expiry**: this is distinct from session resumption above (which handles brief disconnections within the expiry window). After session expiry, the protocol is:

1. The reconnecting peer discovers the remote peer via the standard rendezvous mechanism.
2. Both peers perform a new **Noise XX handshake** authenticated using the long-term identity keys derived from the pairing secret (via HKDF). This proves that both peers still hold the pairing secret without requiring re-pairing.
3. The Noise XX handshake output is used as the new root key for a **fresh Double Ratchet**. All previous ratchet state is discarded.
4. A new Session ID (UUID v7) is generated. The old Session ID is invalidated.
5. Message sequence numbers restart from zero. Any messages queued during the expired session are discarded (the sender's queue should have been flushed or timed out during the expiry window).

This ensures forward secrecy is maintained across session boundaries: the new session has completely fresh keying material with no continuity from the expired session.

### 7.4 Message Queuing During Disconnection

While disconnected, the library optionally buffers outgoing messages for delivery on reconnection. This behavior is **opt-in and configurable**:

- **queue_enabled**: whether to buffer messages at all (default: true)
- **queue_max_size**: maximum number of messages to buffer (default: 1000)
- **queue_max_age**: maximum age of a queued message before it's discarded (default: 1 hour)
- **queue_strategy**: FIFO (deliver oldest first) or LIFO (deliver newest first, discard old)

Applications like chat want FIFO with high limits. Real-time control applications should disable queuing entirely.

### 7.5 Heartbeat & Keepalive

Configurable heartbeat interval (default: 30 seconds) for prompt disconnection detection. Both peers send heartbeats; if no heartbeat or data is received within the configured timeout (default: 3x heartbeat interval = 90 seconds), the connection transitions to Disconnected state. Heartbeat intervals should be tunable per project — aggressive (5s) for real-time apps, relaxed (60s) for background sync.

### 7.6 Network Change Handling

The library monitors OS-level network interface changes (WiFi to cellular, new IP assignment, VPN connect/disconnect). When a change is detected, the library **proactively triggers reconnection** rather than waiting for the existing connection to time out. The reconnecting peer publishes updated reachability to the rendezvous point and initiates session resumption from the new network context. The remote peer accepts the reconnection based on cryptographic session identity, not source IP.

### 7.7 Security During Reconnection

Several security invariants must hold during reconnection:

- Session resumption requires **cryptographic proof of identity**, not just a Session ID. An intercepted Session ID alone cannot hijack a reconnection.
- Keys are **rotated on every reconnection** via the ratchet mechanism, providing forward secrecy across connection windows.
- Session expiry window limits the attack surface for replay attacks.
- The session resumption handshake is protected against replay by including a timestamp and nonce.

---

## 8. Rendezvous & Peer Discovery

The rendezvous system is the mechanism by which peers find each other after disconnection, reboot, or initial startup. It uses P2P infrastructure as a shared "dead drop" — a coordination point that only paired peers can meaningfully interact with.

### 8.1 Rendezvous Point Derivation

When two peers pair, they derive a **shared rendezvous identifier** from their mutual keying material using HKDF:

```
rendezvous_id = HKDF(pairing_secret, "cairn-rendezvous-v1", context)
```

This ID is:

- **Deterministic**: both peers compute it independently
- **Opaque**: an observer cannot correlate it to either peer's identity
- **Rotatable**: the derivation includes a time-based epoch so the ID changes periodically, preventing long-term traffic analysis

### 8.2 Rendezvous Flow

When a peer comes online (or recovers from a disconnection):

1. It computes the current rendezvous ID for each paired peer
2. It **publishes** its current reachability information (listening addresses, supported transports) to the rendezvous point, encrypted so only the paired peer can read it
3. It **queries** the rendezvous point for the other peer's reachability information
4. If found, it initiates a direct connection using the retrieved address info
5. If not found, it polls periodically (with configurable interval and backoff)

### 8.3 Multi-Infrastructure Rendezvous

The rendezvous mechanism itself uses the same fallback philosophy as the transport layer. The library publishes to and reads from **all configured discovery infrastructure simultaneously**:

- **mDNS (LAN)**: for same-network-segment discovery; peers find each other instantly without internet access. The rendezvous ID is announced as a mDNS service name. This is attempted **first** before any remote discovery mechanism. Critical for same-LAN device pairing, homelab peer discovery, and development/testing without internet.
- **libp2p Kademlia DHT**: the rendezvous ID is used as a DHT key; the encrypted reachability info is the value
- **BitTorrent trackers**: the rendezvous ID is announced as an info_hash; peers find each other through the tracker swarm
- **Signaling servers**: WebSocket-based servers where the rendezvous ID maps to a topic/room; peers exchange reachability info in real-time
- **Custom rendezvous endpoints**: the library supports pluggable discovery backends for domain-specific infrastructure

The first mechanism to yield a valid result wins. Publishing to all ensures redundancy. Even if a corporate network blocks UDP-based DHT, the signaling server over WSS on port 443 still works.

**Note on zero-config mode (Tier 0)**: mDNS, DHT, and BitTorrent tracker rendezvous are available out of the box. Signaling server rendezvous requires Tier 1+ (deploy cairn's companion signaling server, see section 2.4.1). Discovery latency in Tier 0 is typically in the range of seconds to low minutes for remote discovery, compared to sub-second with a dedicated signaling server. mDNS provides instant discovery for same-LAN peers.

**BitTorrent tracker usage guidelines**: using the rendezvous ID as an info_hash for tracker-based discovery requires care to avoid abuse:

- Use only known-permissive trackers in the curated default list and verify their terms of use
- Prefer the **mainline DHT (BEP 5)** directly rather than tracker HTTP/UDP announces — DHT participation is standard and expected
- Implement reasonable announce intervals (no more aggressive than standard BitTorrent clients — minimum 15 minutes between re-announces per info_hash)
- Document which specific tracker protocols are used (BEP 3 HTTP, BEP 15 UDP)
- At scale, consider operating cairn-specific DHT bootstrap nodes to reduce load on public BitTorrent infrastructure

### 8.4 Rendezvous for Mesh Groups

For mesh groups, the rendezvous ID is derived from the group's shared secret rather than a pairwise pairing secret. All group members compute the same rendezvous ID and can find each other through it. The encrypted payload at the rendezvous point includes the publishing peer's identity, allowing other group members to identify who is online.

### 8.5 Rendezvous ID Rotation

To prevent long-term traffic analysis, rendezvous IDs rotate on a configurable schedule (default: every 24 hours). The rotation epoch is derived deterministically from the pairing secret using HKDF: `epoch_number = floor(unix_timestamp / rotation_interval)`. Both peers compute the same epoch from their local clocks. The epoch boundary is not aligned to midnight or any wall-clock time — it is derived from the pairing secret, making it unpredictable to observers.

**Transition overlap**: the library maintains a **1 hour** overlap window (configurable), centered on the epoch boundary. During this window, the library publishes and queries **both** the current and previous rendezvous IDs on all discovery infrastructure. Outside the window, only the current epoch's rendezvous ID is used.

**Clock tolerance**: peers must have clocks within **5 minutes** of each other. This is satisfied by any device with NTP enabled (virtually all modern devices). If clock drift exceeds the transition window, peers will fail to find each other via rendezvous — the diagnostic API should report this as a possible cause when rendezvous lookup fails.

### 8.6 Pairing-Bootstrapped Rendezvous

Initiation pairing mechanisms (pin code, QR code, pairing link — see section 4.3.2) can bootstrap peer discovery without requiring that both peers are already present on the same discovery infrastructure. This is particularly valuable in zero-config (Tier 0) mode where no signaling server is available.

The bootstrapping works as follows:

1. The pairing payload (pin code, QR data, or link) contains a **PAKE credential** — a value known to both peers.
2. Both peers derive a **pairing rendezvous ID** from this credential using HKDF: `pairing_rendezvous_id = HKDF(pake_credential, "cairn-pairing-rendezvous-v1", nonce)`.
3. Both peers publish their reachability info at this rendezvous point on all available discovery infrastructure (DHT, trackers).
4. When both peers are present, they discover each other, perform the PAKE-authenticated key exchange, and establish trust.

This is a form of human-mediated bootstrapping: the user physically transferring the pairing payload (by scanning, typing, or clicking) bridges the discovery gap. Once paired, subsequent connections use the standard rendezvous mechanism (section 8.1) derived from the established pairing secret.

For **pin code pairing** specifically, this means two peers that have never seen each other on any network can pair by: one peer generating a pin, the other peer entering it, and both peers finding each other via the pin-derived rendezvous ID on the public DHT or trackers. No signaling server, no shared network, no prior discovery required.

---

## 9. Mesh Networking (Opt-in)

Mesh capabilities allow peers to communicate through intermediate hops when direct connection is not possible. This is an **opt-in feature** — enabled per-project based on topology requirements.

**Important**: mesh routing uses cairn's own application-level relay on standard libp2p streams, **not** libp2p's Circuit Relay v2 (which is limited to 2-minute, 128 KB transient connections). cairn's relay has no such limits — it operates as long as the underlying libp2p stream is alive.

### 9.1 When to Use Mesh

- **Two-peer connections** (e.g., RemoShell): mesh not needed, disable it for simplicity
- **Multi-device sync** (e.g., folder sync across 5 devices): mesh useful when not all devices can reach each other directly
- **Group communication** (e.g., group chat): mesh enables routing around network partitions

### 9.2 Routing Strategy

When mesh is enabled, the library maintains a routing table of known peers and their reachability. If peer A cannot reach peer C directly, but peer B can reach both, traffic is automatically routed A → B → C. Route selection prioritizes:

1. Shortest hop count
2. Lowest latency
3. Highest available bandwidth

Routes are discovered through periodic exchange of reachability information among mesh participants.

### 9.3 End-to-End Encryption Through Mesh

Critically, mesh routing does **not** compromise end-to-end encryption. Relay peers (e.g., peer B in the A → B → C example) handle only opaque encrypted bytes. The session encryption between A and C is maintained end-to-end — B cannot read, modify, or forge messages. B's role is purely transport-level forwarding.

### 9.4 Mesh Configuration

- **mesh_enabled**: enable/disable mesh routing (default: false)
- **max_hops**: maximum relay hops allowed (default: 3)
- **relay_willing**: whether this peer is willing to relay for others (default: false)
- **relay_capacity**: maximum number of simultaneous relay connections (default: 10)

---

## 10. Server Mode — Always-On Peer (Opt-in)

Server mode is an **optional capability** for users who happen to have an always-on device (a home server, a VPS, a NAS, a Raspberry Pi). It is not required for any cairn functionality — the library works fully without it, and many use cases (direct device-to-device connections, CLI tools, real-time control) have no need for it.

When enabled, server mode configures a cairn peer to embrace its persistent availability: it can store and forward messages for offline peers, relay connections for peers that can't reach each other directly, and serve as a synchronization hub for the user's devices. Critically, it is not a separate component or a different kind of node. It is a regular cairn peer, using the same pairing, encryption, session, and transport mechanisms as any other peer, with configuration defaults adjusted for an always-on, headless deployment.

Server mode sits at Tier 2 in the infrastructure progression (see section 2.3.1). It complements — but does not replace — the companion signaling server and TURN relay (section 2.4), which operate at Tier 1. Developers can adopt any combination: Tier 1 without Tier 2, Tier 2 without Tier 1, or both together.

### 10.1 Motivation

The core P2P assumption is that peers are intermittently online. In practice, some users have at least one device that runs 24/7. For those users, enabling server mode on that device — without breaking the symmetry of the peer architecture — unlocks capabilities that are impossible with intermittent-only peers:

- **Store-and-forward**: when the recipient of a message is offline, the message can be delivered to and held by a server-mode peer until the recipient comes online, rather than sitting queued on the sender's device indefinitely.
- **Relay bridging**: two peers that cannot connect directly (both behind symmetric NATs, corporate firewalls) can route through a mutually paired server-mode peer. This complements the companion TURN relay (section 2.4.2) — the TURN relay serves any peer with credentials, while a server-mode peer serves only its paired peers and adds the benefit of being a trusted, personal node.
- **Rendezvous anchor**: a server-mode peer with a stable public IP or domain serves as a highly reliable rendezvous point. Peers can always find it, making discovery near-instant for connections that pass through it.
- **Multi-device synchronization**: a user's phone, laptop, tablet, and server node are all paired with each other. The server node acts as a synchronization hub — devices that are intermittently online sync state through the always-available server node rather than requiring simultaneous online presence.
- **Offline presence**: the server-mode peer can respond to presence queries on behalf of its paired peers, indicating last-seen times and buffered message counts, without the end device needing to be online.

### 10.2 Architecture — Same Peer, Different Posture

Server mode is enabled through configuration, not through a different codebase or protocol. A server-mode peer differs from a regular peer only in its default settings:

| Setting | Regular Peer Default | Server Mode Default |
|---|---|---|
| `mesh_enabled` | false | true |
| `relay_willing` | false | true |
| `relay_capacity` | 10 | 100+ (configurable) |
| `store_forward_enabled` | false | true |
| `store_forward_max_per_peer` | — | 10,000 messages |
| `store_forward_max_age` | — | 7 days |
| `store_forward_max_total_size` | — | 1 GB |
| `session_expiry` | 24 hours | 7 days |
| `heartbeat_interval` | 30s | 60s |
| `reconnect_max_duration` | 1 hour | indefinite |
| `headless` | false | true |

The library provides a `cairn.create_server(config)` convenience constructor (or equivalent idiomatic pattern per language) that applies server-mode defaults. Internally, this creates a standard `Node` with adjusted configuration — there is no separate server class or protocol.

### 10.3 Store-and-Forward

When store-and-forward is enabled, the server-mode peer acts as a **mailbox** for its paired peers. The mechanism works as follows:

1. Peer A sends a message to Peer B. Peer B is offline.
2. If Peer A is paired with a server-mode peer S, and S is also paired with B, A can send the message to S with a **forward directive** indicating the intended recipient (Peer B).
3. S stores the message in its local queue, encrypted with B's session keys (S cannot read the content — it is end-to-end encrypted between A and B).
4. When B comes online and establishes a session with S, S delivers all queued messages for B in sequence order.
5. S acknowledges delivery back to A (if A is online) and purges the delivered messages.

**Trust requirement**: the server-mode peer must be independently paired with **both** the sender and the recipient. This is by design — the server handles messages only for peers whose identities it has verified through the pairing process. If A is paired with S₁ and B is paired with S₂ (different servers), store-and-forward between S₁ and S₂ is **not supported in v1.0**. A can still reach B via direct connection, mesh routing, or TURN relay — just not via server-mediated store-and-forward. For users with devices on different server-mode peers, pairing all devices with a single server-mode peer (or multiple overlapping ones) is the recommended approach.

The store-and-forward layer is built on top of the existing session and channel primitives. Forward directives use a dedicated control channel (`__cairn_forward`) with message type `0x07xx — Forward` (ForwardRequest, ForwardAck, ForwardDeliver, ForwardPurge).

#### 10.3.1 Store-and-Forward Encryption Details

Each forwarded message includes **ratchet metadata in the header**: message number within the current sending chain, the sender's current DH ratchet public key, and the previous chain's message count. This is the standard Signal approach (the "message header" in the Double Ratchet spec).

The server-mode peer stores and forwards **the complete encrypted message including its Double Ratchet header**. It can validate message sequence by inspecting unencrypted envelope metadata (sequence numbers) without decrypting.

When B comes online and receives buffered messages, it **reconstructs ratchet state by processing messages in sequence order**: for each message, if the DH ratchet key in the header differs from the current one, B performs a DH ratchet step; then B advances the receiving chain to the message's chain index, deriving and caching skipped message keys.

**Forward secrecy degrades for stored messages**: all messages sent within a single DH ratchet epoch share the same DH secret. They still have per-message keys (from the chain ratchet), but compromise of the DH private key at that epoch exposes all messages in that epoch. This is an inherent property of one-way offline messaging and should be documented as a known tradeoff.

**Max skip threshold**: if B's ratchet is more than N messages behind (default: 1000), reject the message to prevent resource exhaustion. This bounds the number of skipped keys B must cache.

#### 10.3.2 Retention Policy

Default retention: **7 days** or **1000 messages** per peer, whichever is reached first. Configurable per-peer. Per-peer retention overrides allow server operators to give priority peers higher quotas. The recipient's server-mode peer is the primary mailbox (pull model: recipient pulls from their own server).

**Message deduplication**: if a message is delivered through multiple paths, the recipient discards duplicates based on message ID (UUID v7). Multi-server coordination is deferred; for v1.0, UUID-based deduplication is sufficient.

**Security invariant**: the server-mode peer never has access to plaintext message content. Messages are encrypted end-to-end between the original sender and the final recipient. The server peer stores and forwards opaque encrypted blobs. It knows the sender, the intended recipient, the message size, and the timestamp — but not the content. This is the same trust model as mesh relay (section 9.3) extended with persistence.

### 10.4 Personal Relay

A server-mode peer with a public IP address (or port-forwarded through a home router) can serve as a **personal relay** for its paired peers. This complements the companion TURN relay (section 2.4.2) with a key difference: the companion TURN relay is a generic infrastructure service that any configured peer can use, while the personal relay only serves paired peers and requires no separate deployment — it's just the server-mode peer doing what it already does:

- Peer A cannot reach Peer B directly (both behind symmetric NATs).
- Both A and B are paired with server-mode peer S, which has a public IP.
- A connects to S directly. B connects to S directly. S relays traffic between them.
- The relay is transparent to the application layer — A and B see a normal session with each other.

This leverages the existing mesh relay mechanism (section 9) but with the always-on server peer acting as the natural relay hub. The server peer's `relay_willing` and `relay_capacity` settings control how many simultaneous relay connections it will serve.

Unlike the companion TURN relay, the personal relay only serves paired peers. This limits abuse surface — the relay cannot be used by arbitrary third parties. For developers who want relay coverage but don't want to deploy separate TURN infrastructure, a server-mode peer provides an alternative path.

### 10.5 Headless Operation

Server-mode peers typically run without a display, keyboard, or camera. The pairing mechanisms accommodate this:

- **Pre-shared key**: ideal for automated deployments — configure the PSK in both peers ahead of time via config file or environment variable.
- **Pin code**: the server generates a pin code on its CLI or logs it; the user enters it on their phone/laptop. Practical for initial setup.
- **Pairing link**: the server outputs a `cairn://pair?...` URI on its CLI; the user copies it to their phone/laptop via SSH, clipboard, or a management web interface.
- **QR code generation**: even without a display, the server can generate a QR code as a terminal ASCII art output, a PNG file served over the management HTTP endpoint, or an image sent through an already-paired device. The other device scans it normally.

**Management endpoint security**: the management HTTP endpoint binds to `127.0.0.1` by default. It is not accessible from the network unless explicitly reconfigured to bind to `0.0.0.0` or a specific interface. Bearer token authentication is required for all management endpoints — the token is configured via environment variable (`CAIRN_MGMT_TOKEN`) or config file. If the operator binds the endpoint to a non-loopback interface, TLS should be enabled (the endpoint logs a warning if exposed without TLS). The short validity window (5 minutes for pin codes, QR codes) provides defense-in-depth but is not the primary security control.

Typical headless pairing workflow: SSH into the server → `curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/pairing/qr -o qr.png` → transfer QR image to the phone → scan.

Ongoing operation requires no interaction — session resumption, reconnection, relay, and store-and-forward all operate autonomously.

### 10.6 Multi-Device Sync via Server Node

When a user runs cairn on multiple personal devices (phone, laptop, tablet) and a server node, the server node naturally becomes a synchronization hub:

```
Phone ←→ Server Node ←→ Laptop
              ↕
           Tablet
```

Each device is paired individually with the server node (and optionally with each other for direct P2P when possible). The server node is always reachable, so:

- The phone can sync data to the server node at any time, even if the laptop is asleep.
- When the laptop wakes up, it syncs with the server node and receives everything the phone sent.
- The server node tracks per-peer synchronization state (last-seen sequence numbers, pending deliveries).

This pattern does not require all devices to be online simultaneously — the server node absorbs the timing differences. For applications like note sync, file sharing, or chat history, this provides a seamless multi-device experience built entirely on the peer-to-peer model.

### 10.7 Deployment Patterns

Server mode is designed to be trivially deployable:

- **Docker**: a single container image with configuration via environment variables or a mounted config file. Persistent storage for keys and queued messages via a Docker volume.
- **Systemd service**: a single binary managed as a system service on any Linux host.
- **Home NAS**: runs alongside other services (Nextcloud, Jellyfin, etc.) as a Docker container or native process.
- **VPS/Cloud**: a lightweight instance (512 MB RAM is sufficient for moderate relay/mailbox load) running the cairn server binary.

The server-mode peer exposes no HTTP API, no web interface, and no management plane by default — it is purely a cairn peer that listens for paired peers.

#### Management API (opt-in)

A lightweight REST API (JSON over HTTP) is available for server monitoring, disabled by default and enabled via configuration flag (`--enable-management` or `CAIRN_MGMT_ENABLED=true`). Features include: paired peers list, queue depths, relay stats, connection health, and pairing QR code generation. The API is bound to `127.0.0.1`, protected by bearer token authentication, and warns if exposed on a non-loopback interface without TLS. No gRPC — it adds a code generation dependency that contradicts cairn's simplicity goal.

#### Resource Accounting

Server-mode operators need visibility into resource consumption. The server tracks **bytes relayed** and **bytes stored** per paired peer. These metrics are exposed via the management API and structured event interface. Per-peer quotas (max stored messages, max relay bandwidth) are configurable but disabled by default.

### 10.8 Trust Model

A server-mode peer holds no special trust or privilege within the cairn model. It is a peer like any other, subject to the same cryptographic guarantees:

- It cannot read end-to-end encrypted messages between other peers (it relays/stores opaque ciphertext).
- It cannot impersonate another peer (it has its own identity keypair).
- It can be unpaired at any time by any peer that no longer wants to route through it.
- Its compromise reveals only metadata (who communicates with whom, message sizes, timing) — not message content. This is the same metadata exposure as any relay or mesh intermediary.

The key difference is operational, not cryptographic: because it is always on, it sees more metadata over time than a peer that is intermittently available. Users should be aware of this when deciding where to host their server-mode peer (self-hosted preferred over third-party VPS for maximum privacy).

---

## 11. Graceful Failure Handling

The library must fail gracefully and informatively. When a peer is unreachable or a connection cannot be established, the library reports this clearly to the application, which decides how to handle it.

### 11.1 Error Classification

| Error Type | Meaning | Library Behavior |
|---|---|---|
| TransportExhausted | All transports in the fallback chain failed | Report to application with details of each transport failure and suggestions (e.g., "deploy the cairn signaling server and/or TURN relay to resolve this — both peers appear to be behind symmetric NATs") |
| SessionExpired | Session exceeded expiry window | Clear session state, notify application (re-pairing not needed, session re-establishment via Noise XX handshake) |
| PeerUnreachable | Peer not found at any rendezvous point within timeout | Report to application; continue background polling if configured |
| AuthenticationFailed | Session resumption crypto verification failed | Reject connection, alert application (possible key compromise) |
| PairingRejected | Remote peer rejected pairing request | Report to application |
| PairingExpired | Pairing payload (pin code, QR, link) has expired | Report to application; initiating peer should generate a new payload |
| MeshRouteNotFound | No route to destination through mesh | Report to application; suggest direct connection or wait |
| VersionMismatch | No common protocol version between peers | Reject connection; error includes peer's supported version range, enabling the application to inform the user which peer needs updating |

### 11.2 Timeout Configuration

All timeouts are configurable because they are inherently application-specific:

- **connect_timeout**: how long to attempt initial connection before failing (default: 30s)
- **transport_timeout**: per-transport attempt timeout (default: 10s)
- **reconnect_max_duration**: total time to keep trying reconnection (default: 1 hour)
- **reconnect_backoff**: exponential backoff parameters (initial: 1s, max: 60s, factor: 2.0)
- **rendezvous_poll_interval**: how often to check rendezvous for offline peers (default: 30s)
- **session_expiry**: how long before an inactive session is invalidated (default: 24 hours)
- **pairing_payload_expiry**: how long a generated pairing payload (pin, QR, link) remains valid (default: 5 minutes)

---

## 12. API Surface Design

The API is designed to be minimal, idiomatic per language, and consistent in concepts across all implementations. A developer familiar with the API in one language should immediately understand it in another.

### 12.1 Core Concepts

- **Node**: the local cairn instance. Created with a configuration, represents this peer.
- **PeerId**: a unique identifier for a peer, derived from their identity public key.
- **Pairing**: the process of establishing mutual trust with a new peer.
- **Session**: an active or resumable connection to a paired peer.
- **Channel**: a bidirectional data stream within a session (sessions can multiplex multiple channels). Channels are implemented as **libp2p streams using yamux stream multiplexing**. Opening a channel creates a new yamux stream; closing a channel closes the stream. The wire protocol's `DataMessage`, `DataAck`, and `DataNack` messages operate within a specific stream — the stream ID implicitly identifies the channel. The API provides `session.open_channel(name)` which negotiates a new yamux stream and sends an initial `ChannelInit` payload (channel name, metadata) as the first message on that stream. The remote peer receives a `channel_opened` event with the channel name and can accept or reject it.
- **Event**: state transitions and incoming data delivered to the application.

### 12.2 Pseudocode API

The following pseudocode illustrates the typical developer workflow (language-specific idioms will vary):

```
// Initialize — works with zero config (Tier 0 defaults)
node = cairn.create()

// Or initialize with custom config (Tier 1/2)
node = cairn.create(config)

// Or initialize in server mode (always-on, headless defaults)
node = cairn.create_server()
node = cairn.create_server(config) // with overrides

// Pair with a new peer — choose a mechanism
// QR code pairing
qr_data = node.pair_generate_qr() → displays QR code, returns pairing handle
pairing = node.pair_scan_qr(scanned_data) → yields PeerId on success

// Pin code pairing
pin = node.pair_generate_pin() → returns pin string (e.g., "98AF-XZ2A") and pairing handle
pairing = node.pair_enter_pin(pin_string) → yields PeerId on success

// Link pairing
link = node.pair_generate_link() → returns URI string and pairing handle
pairing = node.pair_from_link(link_uri) → yields PeerId on success

// SAS verification pairing (legacy flow)
pairing = node.pair(peer_id, verification_method) → yields PeerId on success

// Connect to a paired peer
session = node.connect(peer_id) → automatic discovery, NAT traversal, session resume

// Send data
session.send(channel_name, data)

// Send data with store-and-forward (delivered via server-mode peer if recipient is offline)
session.send(channel_name, data, { forward: true })

// Receive data
session.on_message(channel_name, callback)

// Monitor state
session.on_state_change(callback) → Connected, Unstable, Disconnected, etc.

// Disconnect
session.close()

// Unpair
node.unpair(peer_id) → removes trust, deletes keys
```

### 12.3 Event-Driven Architecture

The library is fundamentally event-driven. All state changes, incoming data, errors, and reconnection events are delivered asynchronously via the language's idiomatic event/callback mechanism:

- **Rust**: closures and channels (tokio mpsc)
- **Go**: channels and goroutines
- **TypeScript**: EventEmitter / async iterators
- **Python**: async generators / asyncio callbacks
- **PHP**: event loop callbacks (ReactPHP/Amp)

---

## 13. Implementation Strategy

### 13.1 Native Per-Language Approach

Each language gets a **native, idiomatic implementation** rather than FFI bindings to a shared core. This decision prioritizes developer experience: no cross-compilation toolchain requirements, no FFI debugging, no WASM edge cases. Each library feels native to its ecosystem.

The tradeoff is that the wire protocol spec must be impeccably documented, and cross-language conformance testing is critical (see 13.3).

### 13.2 Implementation Order

| Phase | Deliverables | Rationale |
|---|---|---|
| Phase 1 | Rust + TypeScript libraries, companion signaling server, companion TURN relay | Strongest libp2p support, covers most active projects (Tack, RemoShell, Parley). Companion infrastructure is needed from day one for Tier 1+ testing and for the conformance test harness. |
| Phase 2 | Go library | Mature libp2p, strong server-side use cases |
| Phase 3 | Python library | Developing libp2p, strong for scripting and automation use cases |
| Phase 4 | PHP library | No existing libp2p — requires most original work, but important for web backend integration |

The companion signaling server and TURN relay are implemented in **Rust** and serve all language implementations. Rust is chosen for its lowest resource footprint (no GC, minimal memory), single-language maintenance burden (shared crates with the Rust client library), and rust-libp2p's production maturity. They are part of Phase 1 because the conformance test harness requires them to simulate Tier 1+ scenarios.

### 13.3 Conformance Testing

An automated **cross-language conformance test matrix** runs in CI for every commit to any implementation. The matrix tests every language pair (Rust↔Go, Go↔TS, TS↔PHP, etc.) across all major flows:

- Pairing (all mechanisms: QR, pin code, link, SAS, pre-shared key)
- Session establishment
- Data transfer
- Reconnection after disconnect
- Session resumption after timeout
- Mesh routing (two hops)
- Transport fallback
- Store-and-forward via server-mode peer

The test harness runs each language's implementation in a Docker container with controlled networking (simulated NAT, packet loss, disconnection) to ensure realistic validation. Tests are run at multiple infrastructure tiers:

- **Tier 0 tests**: no signaling server or TURN relay — validates DHT/tracker discovery and STUN-only connectivity
- **Tier 1 tests**: companion signaling server and TURN relay running in the test harness — validates real-time signaling, relay fallback, and transport chain escalation
- **Tier 2 tests**: server-mode peer running in the harness — validates store-and-forward, personal relay, and multi-device sync scenarios

---

## 14. Demo Applications

Two demo applications serve as both conformance proof and developer documentation.

### 14.1 Demo 1: P2P Messaging

A simple real-time chat application with clients in all five languages. Features exercised:

- Peer discovery and pairing (demonstrating QR, pin code, and link mechanisms)
- Real-time bidirectional messaging
- Presence (online/offline/typing indicators via heartbeat extensions)
- Message delivery during reconnection (queue + sequence sync)
- Message history sync on session resume
- Store-and-forward via a server-mode peer (messages delivered to offline recipients)

Each client is a CLI application that can message any other client regardless of implementation language. The demo works out of the box in Tier 0 (zero-config) mode with no server infrastructure. An optional server-mode peer can be launched alongside the clients to demonstrate store-and-forward and relay capabilities.

### 14.2 Demo 2: Folder Sync

A file synchronization tool that keeps a folder in sync across multiple peers. Features exercised:

- Chunked data transfer with resume capability
- Conflict detection (concurrent modifications)
- Mesh routing (sync across devices that can't directly reach each other)
- Efficient delta sync (only transfer changed bytes)
- Multi-peer coordination
- Server-mode hub for asynchronous sync (devices sync through the always-on node without requiring simultaneous online presence)

Each client watches a local folder and propagates changes to all connected peers. This exercises the library's most demanding capabilities — large data transfers, mesh routing, and complex reconnection scenarios with partial sync state.

### 14.3 Demo 3: Personal Server Node

A ready-to-deploy server-mode peer packaged as a Docker image. Features exercised:

- Headless pairing via pin code and pre-shared key
- Store-and-forward mailbox for paired peers
- Relay bridging for peers behind restrictive NATs
- Management CLI for monitoring paired peers, queue sizes, relay stats, and connection health
- Multi-device sync hub (pair your phone, laptop, and server — sync seamlessly)

---

## 15. Design Decisions & Resolved Questions

The following items were identified as open questions during design and have been resolved with concrete decisions.

### Companion Infrastructure

- **Implementation language: Rust.** Lowest resource footprint, single language for the entire project, shared crates between library and infrastructure, rust-libp2p maturity. Deployment targets Docker containers and small VPS instances (512 MB RAM).
- **Authentication model: Bearer tokens (default), API key provisioning for Tier 3.** Simple deployment, scalable later. OAuth2 and mTLS deferred as optional backends.
- **Federation: Defer to post-v1.0.** Design the signaling server with a clean internal API that could support federation later (separate room/topic state from connection state), but don't implement it for v1.

### Cryptography & Pairing

- **PAKE algorithm: SPAKE2** for all pairing mechanisms. Cross-language library maturity (Rust, Go, Python, JS, PHP via FFI), proven at scale (magic-wormhole, FIDO2/CTAP2), trusted setup concern mitigated by hash-to-curve derived constants. CPace (IETF CFRG recommended balanced PAKE) may be revisited if library maturity improves. OPAQUE is a future consideration for server-mode PSK storage hardening.
- **Pin code format: Crockford Base32**, 8 characters (`XXXX-XXXX`), 40 bits entropy, case-insensitive with error correction. See section 4.3.2.
- **QR code standard: Binary mode CBOR**, Error Correction Level M, max 256 bytes payload. Version 14 maximum, auto-selects minimum version. See section 4.3.2.

### Protocol & Transport

- **UUID version: UUID v7** (RFC 9562). Timestamp-ordered for store-and-forward sequencing, log correlation, and deduplication. See section 3.2.
- **QUIC version: QUIC v1** (RFC 9000). Consistent with libp2p implementations.
- **Channel multiplexing: Map to yamux streams.** No custom wire protocol messages — channels use libp2p's native stream multiplexing. See section 12.1.
- **WebTransport priority: Keep after WebSocket** (priority 7). WebSocket traverses restrictive networks more reliably. See section 6.1.
- **Protocol extensibility: Reserve `0xF000`–`0xFFFF`** for application-defined message types. See section 3.3.
- **Version negotiation failure: `VersionMismatch` error** with peer's supported version range. See section 3.4 and 11.1.

### Security & Sessions

- **Unpairing: Unilateral** with best-effort `PairRevoke` message. Simple, no coordination required. See section 4.5.
- **Pairing rate limiting: Acceptor-side**, 5 attempts/30s, 10 max before auto-invalidation. Combined with PAKE one-guess-per-run property and 5-minute time expiry. See section 4.4.
- **Security layers: Intentional double encryption.** Transport-level (libp2p Noise) for hop-by-hop + session-level (Double Ratchet) for end-to-end. See section 2.2.
- **Session re-establishment: Full Noise XX handshake**, authenticated by pairing identity keys, with fresh Double Ratchet root key. See section 7.3.

### Discovery & Rendezvous

- **mDNS: First-class discovery mechanism**, attempted before all remote discovery. See section 8.3.
- **Rendezvous rotation overlap: 1 hour window**, 5-minute clock tolerance, query both current and previous epoch IDs. See section 8.5.
- **Default endpoint list updates: Opt-in signed manifest fetch**, Ed25519 signed, disabled by default. See section 2.3.2.
- **NAT type detection: Exposed as read-only diagnostic metadata** (`node.network_info().nat_type` → `open | full_cone | restricted_cone | port_restricted_cone | symmetric | unknown`).

### Server Mode

- **Store-and-forward mailbox: Requires mutually paired server.** Clean trust model, no server-to-server relay in v1.0. See section 10.3.
- **Retention policy: 7 days / 1000 messages** per peer (whichever first), configurable with per-peer overrides. See section 10.3.2.
- **Multi-server coordination: Defer**, UUID-based deduplication prepared for future multi-server support.
- **Management API: REST/JSON**, disabled by default, localhost-only, bearer token auth. See section 10.7.
- **Resource accounting: Per-peer bandwidth/storage tracking**, exposed via management API and structured metrics. See section 10.7.

### Platform & Ecosystem

- **Mobile: Document constraints**, implement platform-aware keepalive (iOS: APNs, Android: FCM), server-mode peer strongly recommended for mobile use cases.
- **Browser: Yes** — TypeScript supports both Node.js and browser. In-browser transport chain: WebRTC (direct) → WebSocket (relay) → WebTransport (relay).
- **Group key agreement (MLS): Defer to post-v1.0.** Pairwise mesh sufficient for groups up to ~20 peers.
- **Bandwidth management: Defer** for core library, provide bandwidth metrics hooks for application-level QoS.
- **Observability: Structured event interface**, not Prometheus-specific at the library level. Server-mode peer exposes optional Prometheus-compatible endpoint.
- **Licensing: MIT OR Apache-2.0** (dual-license). Rust ecosystem standard, maximum adoption.

---

## 16. Appendix A: Glossary

| Term | Definition |
|---|---|
| CBOR | Concise Binary Object Representation — binary serialization format (RFC 8949) |
| Circuit Relay v2 | libp2p protocol enabling peers to relay connections for others. Limited to 2-minute, 128 KB transient connections — used only for hole-punch coordination in cairn |
| Companion infrastructure | Lightweight, self-hostable services provided by the cairn project (signaling server, TURN relay) to enable Tier 1+ connectivity. Implemented in Rust. |
| CPace | IETF CFRG recommended balanced PAKE protocol. Not selected for cairn v1.0 due to immature cross-language library availability; may be revisited in future versions |
| Crockford Base32 | Human-friendly encoding using 32 characters (0-9, A-Z excluding I, L, O, U). Used for cairn pin codes |
| DHT | Distributed Hash Table — decentralized key-value store for peer discovery |
| Double Ratchet | Cryptographic algorithm providing forward secrecy and break-in recovery (Signal protocol) |
| HKDF | HMAC-based Key Derivation Function (RFC 5869) |
| ICE | Interactive Connectivity Establishment — framework for NAT traversal |
| Kademlia | DHT algorithm used by libp2p for peer routing and content discovery |
| mDNS | Multicast DNS — zero-config local network peer discovery. Attempted first before remote discovery mechanisms |
| MLS | Messaging Layer Security — group key agreement protocol (RFC 9420). Deferred to post-v1.0 |
| NAT | Network Address Translation — maps private IPs to public IPs, complicates P2P |
| Noise XX | Handshake pattern from Noise Protocol Framework — mutual authentication |
| OPAQUE | Augmented PAKE protocol — server never learns the password. IETF CFRG recommended augmented PAKE. Future consideration for server-mode PSK storage hardening |
| PAKE | Password-Authenticated Key Exchange — key agreement using a shared password |
| Rendezvous point | A shared, derived location in P2P infrastructure where paired peers coordinate |
| SAS | Short Authentication String — human-verifiable code for MITM prevention |
| Server mode | Configuration posture for an always-on cairn peer — enables store-and-forward, relay, and rendezvous anchor capabilities |
| SPAKE2 | Balanced PAKE protocol — selected for cairn's pairing mechanisms based on cross-language library maturity and proven use at scale (magic-wormhole, FIDO2/CTAP2) |
| Store-and-forward | Message delivery pattern where an intermediary holds messages for offline recipients |
| STUN | Session Traversal Utilities for NAT — discovers public IP and NAT type |
| TURN | Traversal Using Relays around NAT — relay server for when direct connection fails (RFC 8656, obsoletes RFC 5766) |
| UUID v7 | Universally Unique Identifier version 7 (RFC 9562) — timestamp-ordered, used for cairn message IDs |
