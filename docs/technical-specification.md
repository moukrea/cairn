# cairn — Technical Specification

**Version 1.0 — March 2026**
**Status**: Draft
**Derived from**: cairn Design & Architecture Document v0.6

---

## 1. Introduction

This document specifies the technical architecture, protocols, algorithms, data structures, and implementation constraints for the cairn universal peer-to-peer connectivity library. It is intended to serve as the authoritative reference for all language implementations and companion infrastructure components.

cairn is an opinionated facade over libp2p. libp2p provides transport primitives, protocol multiplexing, peer identity, and basic NAT traversal. cairn adds opinionated defaults, a unified configuration model, the pairing system, session persistence, reconnection logic, and a simplified API. The relationship is analogous to what Express.js does for Node's http module or what the Requests library does for Python's urllib.

---

## 2. Architecture

### 2.1 Layer Model

cairn is organized in seven distinct layers, each with a well-defined responsibility. Layers communicate with adjacent layers through clean interfaces.

| Layer | Responsibility | Implementation Basis |
|---|---|---|
| **Transport** | Raw connectivity: UDP, TCP, WebSocket, WebTransport, QUIC | libp2p transports + custom fallbacks |
| **NAT Traversal** | Hole punching, STUN/TURN, relay fallback | libp2p AutoNAT, Circuit Relay v2, custom TURN integration |
| **Security** | Encryption, authentication, key management | Noise Protocol (libp2p transport-level), SPAKE2 (pairing), Double Ratchet (session E2E) |
| **Session** | Persistent sessions surviving transport churn, reconnection, state tracking | Custom session manager on top of libp2p streams |
| **Discovery** | Peer finding via DHT, trackers, signaling servers, rendezvous points, mDNS | libp2p Kademlia DHT, custom tracker/signaling integration |
| **Mesh** (opt-in) | Multi-hop routing, shortest path selection, relay through peers | cairn application-level relay on libp2p streams |
| **API Surface** | Developer-facing interface: connect, send, receive, configure | Native per-language idiomatic wrapper |

### 2.2 Security Layer Architecture

cairn applies a deliberate double-encryption model:

1. **Transport-level encryption (libp2p Noise)**: hop-by-hop security protecting against network observers. Provides peer authentication at the libp2p level.
2. **Session-level encryption (Double Ratchet)**: end-to-end security guaranteeing confidentiality even if a relay, mesh intermediary, or server-mode peer is compromised.

The inner encryption operates on application payloads only (not transport framing), making the overhead acceptable. cairn's pairing-level Noise XX handshake (authenticated by the PAKE-derived secret) is a separate, application-level handshake that runs over the already-encrypted libp2p stream.

### 2.3 Relay Mechanism Distinction

cairn distinguishes three relay mechanisms that must not be conflated:

| Mechanism | Purpose | Limits | Scope |
|---|---|---|---|
| **Circuit Relay v2** (libp2p) | Hole-punch coordination only | 2 minutes, 128 KB per direction (go-libp2p defaults) | Transient — used only during NAT traversal |
| **Companion TURN relay** | Sustained transport-level relay (Tier 1+) | Configurable — operator-controlled bandwidth and duration | Any peer with valid credentials |
| **cairn application-level relay** | Mesh routing and personal relay between paired peers | No protocol-imposed limits — lasts as long as underlying libp2p stream | Only between mutually paired peers |

---

## 3. Wire Protocol

All five language implementations must interoperate perfectly. The wire protocol specification is the single most critical deliverable.

### 3.1 Serialization

All wire messages use **CBOR (Concise Binary Object Representation, RFC 8949)**. Rationale:

- Binary-efficient (unlike JSON) — critical for bandwidth-constrained relay paths.
- Self-describing schema (unlike Protocol Buffers) — simplifies debugging and extensibility.
- Mature implementations in all five target languages (Rust, Go, TypeScript, Python, PHP).
- Deterministic encoding mode available for signatures and hashing.

### 3.2 Message Envelope

Every wire message follows a common envelope structure:

| Field | Type | Size | Description |
|---|---|---|---|
| `version` | uint8 | 1 byte | Protocol version identifier |
| `type` | uint16 | 2 bytes | Message type code |
| `msg_id` | UUID v7 (RFC 9562) | 16 bytes | Unique message ID, timestamp-ordered (74 bits randomness) |
| `session_id` | bytes | 32 bytes (optional) | Present after session establishment |
| `payload` | CBOR | variable | Type-specific CBOR-encoded payload |
| `auth_tag` | bytes | variable | HMAC or AEAD tag (present after key establishment) |

**UUID v7 rationale**: timestamp-ordering provides natural sequencing for store-and-forward, log correlation, and deduplication without requiring synchronized clocks for ordering.

### 3.3 Message Type Registry

| Range | Category | Types |
|---|---|---|
| `0x01xx` | Pairing | `PairRequest`, `PairChallenge`, `PairResponse`, `PairConfirm`, `PairReject`, `PairRevoke` |
| `0x02xx` | Session | `SessionResume`, `SessionResumeAck`, `SessionExpired`, `SessionClose` |
| `0x03xx` | Data | `DataMessage`, `DataAck`, `DataNack` (reliable delivery) |
| `0x04xx` | Control | `Heartbeat`, `HeartbeatAck`, `TransportMigrate`, `TransportMigrateAck` |
| `0x05xx` | Mesh | `RouteRequest`, `RouteResponse`, `RelayData`, `RelayAck` |
| `0x06xx` | Rendezvous | `RendezvousPublish`, `RendezvousQuery`, `RendezvousResponse` |
| `0x07xx` | Forward | `ForwardRequest`, `ForwardAck`, `ForwardDeliver`, `ForwardPurge` |
| `0x0100`–`0xEFFF` | Reserved | cairn core protocol expansion |
| `0xF000`–`0xFFFF` | Application | Application-specific extensions |

Application-defined message types are handled via `on_custom_message(type_code, callback)`. Applications coordinate their own allocations; no central registry is required. Each message type has a fully specified CBOR structure documented in a separate Protocol Reference appendix.

### 3.4 Version Negotiation

On first contact, peers exchange a `VersionNegotiate` message listing supported protocol versions. The highest mutually supported version is selected. If no common version exists, the connection is rejected with a `VersionMismatch` error containing the peer's supported version range.

### 3.5 Channel Multiplexing

Channels are mapped to **yamux streams** (libp2p's native stream multiplexing). No custom wire protocol messages are needed for channel management.

- `session.open_channel(name)` creates a new yamux stream and sends a `ChannelInit` payload (channel name, metadata) as the first message on that stream.
- The remote peer receives a `channel_opened` event and can accept or reject.
- `DataMessage`, `DataAck`, and `DataNack` operate within a specific stream — the stream ID implicitly identifies the channel.
- Store-and-forward uses a dedicated control channel `__cairn_forward`.

---

## 4. Cryptographic Specification

### 4.1 Primitive Selection

| Purpose | Algorithm | Reference |
|---|---|---|
| Identity keys | Ed25519 | Widely supported, fast, deterministic signatures |
| Key exchange | X25519 (ECDH) | Compatible with Noise framework |
| Handshake | Noise XX pattern | Mutual authentication with identity revelation |
| Pairing authentication | SPAKE2 (balanced PAKE) | Cross-language maturity, proven at scale (magic-wormhole, FIDO2/CTAP2) |
| Session encryption | AES-256-GCM or ChaCha20-Poly1305 | AEAD; AES is hardware-accelerated, ChaCha20 is constant-time |
| Key derivation | HKDF-SHA256 (RFC 5869) | Standard KDF for deriving multiple keys from shared secrets |
| Key ratchet | Double Ratchet (Signal protocol) | Forward secrecy and break-in recovery |
| Rendezvous ID derivation | HKDF-SHA256 | Deterministic, unlinkable to peer identities |
| SAS generation | HKDF from handshake transcript | Short, verifiable authentication string |

**SPAKE2 implementation note**: the RustCrypto SPAKE2 implementation uses Ed25519 with hash-to-curve derived M/N values, mitigating the theoretical trusted setup concern. CPace (IETF CFRG recommended) may be revisited if cross-language library maturity improves. OPAQUE (augmented PAKE) is a future consideration for server-mode PSK storage hardening post-v1.0.

### 4.2 Identity

Each peer generates a long-term Ed25519 keypair on first initialization. The **Peer ID** is the hash of the public key. This identity is permanent and survives reboots, reinstalls, and network changes.

### 4.3 Forward Secrecy & Key Rotation

Long-lived sessions use the **Double Ratchet** mechanism:

- Each message or group of messages uses a unique symmetric key derived from the ratchet state.
- Compromising a key at time T reveals nothing about messages at T−1 or T+1.
- On reconnection, the ratchet advances — fresh symmetric keys are derived from existing keying material.
- Previous and future connection windows remain secure even if an attacker captures session state during one window.

### 4.4 Key Storage

Pluggable storage backend interface for persisting:

- Identity keypairs.
- Paired peer identity keys and trust state.
- Session keying material and ratchet state.
- Rendezvous ID rotation state.

Default implementations:

| Backend | Description | Use Case |
|---|---|---|
| Filesystem | Encrypted at rest with a passphrase | Production default |
| In-memory | Ephemeral, lost on restart | Testing and ephemeral use |
| Custom adapter | Interface for system keychains, HSMs, application-specific storage | Enterprise, specialized deployments |

---

## 5. Pairing System

### 5.1 Threat Model

An attacker observing public discovery infrastructure (DHT, trackers, signaling servers) must not be able to:

1. Intercept or modify the pairing exchange (MITM).
2. Derive the shared secret or session keys.
3. Impersonate either peer in future connections.
4. Correlate pairing activity to specific identities over time.

### 5.2 Flow Variants

#### 5.2.1 Standard Flow (Verification-Only Mechanisms)

Used when both peers are already discoverable on the network (e.g., Numeric SAS, Emoji SAS).

| Phase | Description |
|---|---|
| 1 — Identity Generation | Each peer generates Ed25519 keypair. Public key hash = Peer ID. |
| 2 — Discovery | Peers find each other via configured discovery (DHT, tracker, signaling). Know each other's Peer ID but no trust. |
| 3 — Key Exchange | X25519 Diffie-Hellman over public channel, authenticated via Noise XX (mutual authentication with identity revelation). |
| 4 — OOB Verification | Library computes SAS from handshake transcript (6-digit numeric or emoji). Users confirm match verbally or visually. |
| 5 — Trust Establishment | Both peers store each other's identity public key and derived keying material. Trust-on-first-use with verified first use. |

#### 5.2.2 Initiation Flow (Self-Bootstrapping Mechanisms)

Used when the pairing mechanism itself carries enough information for discovery and authentication (QR code, pin code, pairing link, PSK).

| Phase | Description |
|---|---|
| 1 — Identity Generation | Same as standard flow. |
| 2 — Payload Generation | Initiating peer generates payload: Peer ID, one-time nonce, PAKE credential, optional connection hints (rendezvous IDs, signaling endpoints, listening addresses). |
| 3 — Payload Transfer | Out-of-band: scan QR, type pin, click link, or configure PSK. |
| 4 — Rendezvous & Auth KE | Both peers derive a rendezvous point from the payload. Both perform SPAKE2 using the shared secret. MITM is prevented inherently — authentication is bound to the shared secret. |
| 5 — Trust Establishment | Same as standard flow. |

### 5.3 Mechanism Specifications

#### 5.3.1 Numeric SAS (Verification-Only)

6-digit numeric code derived from the handshake transcript via HKDF. Displayed on both devices. Users confirm match. Best for CLI tools, headless services, co-located scenarios.

#### 5.3.2 Emoji SAS (Verification-Only)

Sequence of emoji derived from the handshake transcript. Same security properties as Numeric SAS. More memorable, harder to confuse. Best for consumer-facing applications.

#### 5.3.3 QR Code (Initiation)

| Parameter | Value |
|---|---|
| Encoding | Raw CBOR (binary mode) |
| Error Correction | Level M (15% recovery) |
| Max payload | 256 bytes |
| Max QR version | 14 (73×73 module grid) — auto-selects minimum for actual payload |
| Typical payload | ~160 bytes (Peer ID 32B + nonce 16B + PAKE credential 32B + hints ~64B + CBOR framing ~16B) → Version 11 (61×61 modules) |
| Validity | Single-use, 5 minutes (configurable) |

Best for mobile-to-mobile, mobile-to-desktop, any scenario with screen + camera.

#### 5.3.4 Pin Code (Initiation)

| Parameter | Value |
|---|---|
| Character set | Crockford Base32: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (excludes I, L, O, U) |
| Length | 8 characters, formatted `XXXX-XXXX` |
| Entropy | 40 bits (8 × 5 = 40) |
| Input handling | Case-insensitive; `i`/`l` → `1`, `o` → `0` |
| PAKE usage | Code serves as both discovery hint (rendezvous ID derived from it) and authentication credential |
| Validity | Single-use, 5 minutes (configurable) |

Best for cross-device pairing without camera (two desktops, two CLIs, remote pairing over phone call).

#### 5.3.5 Pairing Link / URI (Initiation)

Format: `cairn://pair?pid=...&nonce=...&pake=...&hints=...`

Same payload and security properties as QR code. Shared via any text channel (messaging, email, SMS, clipboard). The receiving application registers the `cairn://` URI scheme (or configurable custom scheme). Single-use, time-limited. Applications should warn users to share via trusted channels.

#### 5.3.6 Pre-Shared Key (Initiation)

A secret configured on both peers ahead of time (config file, environment variable, secrets manager). Used as PAKE input; rendezvous ID derived from it. Best for homelab, automated deployments, CI/CD. Can be long-lived but should be rotated periodically. Minimum entropy: **128 bits** (e.g., 26 Crockford Base32 characters) since not time-limited.

#### 5.3.7 Custom Adapter

Interface provides hooks for: payload generation, payload consumption, key exchange integration. Supports arbitrary transport of pairing payload (NFC, Bluetooth LE, email, hardware token).

### 5.4 Rate Limiting

Enforced by the acceptor (pin code generator):

| Control | Specification |
|---|---|
| PAKE inherent limit | Each SPAKE2 run allows exactly one password guess. Attacker must complete a full handshake per attempt. |
| Connection rate | 5 attempts per 30-second window from any source. |
| Max failures | 10 total failed attempts → current pin code auto-invalidated, new one required. |
| Progressive delay | 2-second delay after each failed PAKE attempt before accepting next. |
| Time expiry | 5 minutes (default, configurable). |
| Brute-force ceiling | ~50 guesses in 5-minute window against 2⁴⁰ ≈ 1.1 trillion codes → success probability ≈ 4.5 × 10⁻⁸. |

### 5.5 Unpairing Protocol

When `node.unpair(peer_id)` is called:

1. If session is active, send `PairRevoke` (0x01xx) on control channel (best-effort — proceeds regardless of delivery).
2. Delete all local state: pairing secret, session keys, ratchet state, rendezvous derivation material.
3. Close all active sessions and channels with peer.
4. If remote peer is offline, it discovers unpairing when next connection attempt fails authentication.
5. Upon receiving `PairRevoke`, remote peer emits `peer_unpaired` event and deletes its own state.

**Mesh behavior**: if A unpairs B but mesh peer C attempts to route between them, routing fails (A rejects messages from unknown peer B). C receives a routing error and updates topology.

### 5.6 Pairing in Mesh Context

- **Pairwise mesh**: every peer in the group pairs individually with every other peer. Simple, scales to small groups (up to ~20).
- **Group key agreement (MLS, RFC 9420)**: deferred to post-v1.0.

---

## 6. NAT Traversal & Transport Fallback Chain

### 6.1 Transport Priority Chain

| Priority | Transport | Works When | Tradeoffs |
|---|---|---|---|
| 1 | Direct UDP (QUIC v1, RFC 9000) | Same LAN or open NAT | Best performance, lowest latency |
| 2 | STUN-assisted UDP hole punch | Compatible NAT types (cone NAT) | Good performance, may fail with symmetric NAT |
| 3 | Direct TCP | UDP blocked, TCP open | Higher overhead than QUIC, reliable |
| 4 | TURN relay (UDP) | Hole punching fails | Relay latency, UDP performance |
| 5 | TURN relay (TCP) | UDP fully blocked | Relay + TCP overhead |
| 6 | WebSocket over TLS (port 443) | Corporate firewalls blocking non-HTTPS | Tunnels through virtually any firewall |
| 7 | WebTransport over HTTP/3 (port 443) | Modern environments with HTTP/3 | Better multiplexing than WS, may not be available |
| 8 | Circuit Relay v2 (hole-punch coordination) | Relay-assisted hole punching needed | Transient only (2 min, 128 KB) |
| 9 | HTTPS long-polling (port 443) | Absolute worst case, aggressive proxies | High latency, high overhead |

**WebSocket above WebTransport rationale**: at priority 6–7, the peer is likely in a restrictive network. WebSocket over TLS on port 443 traverses virtually all HTTP proxies and corporate firewalls. WebTransport (HTTP/3 over QUIC) may be blocked by firewalls that do not support or inspect QUIC/UDP traffic.

**Zero-config availability**: priorities 1–3 are available at Tier 0. Priorities 4–7 require Tier 1+ (companion TURN relay with port 443 support). Priority 8 uses libp2p Circuit Relay v2 peers. Priority 9 requires a relay on port 443.

### 6.2 Transport Behavior

- Transports are attempted in priority order with configurable per-transport timeouts.
- Multiple transports may be attempted in parallel (ICE-style) for faster establishment.
- Once connected, the library continuously probes for better transports and can migrate mid-session (e.g., WebSocket relay → direct QUIC).
- Transport migration is invisible to the application.

### 6.3 Platform-Specific Transport Chains

**PHP**: No QUIC or WebTransport at launch. Chain starts at priority 2 (STUN-assisted UDP) or priority 3 (TCP).

**Browser (TypeScript)**: WebRTC (direct) → WebSocket (relay) → WebTransport (relay).

### 6.4 Port 443 Escape Hatch

WebSocket-over-443 is the critical corporate/restrictive environment fallback. Requires a relay server on port 443 speaking WSS. Traffic appears as standard HTTPS. For environments with deep packet inspection (DPI) that block WebSocket upgrades, the HTTPS long-polling fallback (priority 9) encodes the channel as standard HTTP request/response pairs, indistinguishable from normal web API traffic.

### 6.5 Network Monitoring & Proactive Migration

The library monitors:

- Connection quality: latency, jitter, packet loss.
- Network interface state: WiFi ↔ cellular transitions, new IP assignment, VPN connect/disconnect.

When degradation is detected, the library proactively begins probing alternative transports before the current connection fails, enabling seamless transport migration invisible to the application.

### 6.6 NAT Type Diagnostic

Read-only: `node.network_info().nat_type` returns one of: `open`, `full_cone`, `restricted_cone`, `port_restricted_cone`, `symmetric`, `unknown`. Application behavior should never depend on NAT type — the transport chain handles it transparently. Provided for debugging.

---

## 7. Reconnection System

### 7.1 Connection Abstraction Layers

| Layer | Lifetime | Survives | Contains |
|---|---|---|---|
| **Identity** | Permanent | Everything | Ed25519 keypair, Peer ID |
| **Pairing** | Until explicitly revoked | Reboots, reinstalls | Mutual trust, long-term shared secrets, peer identity keys |
| **Session** | Survives transport disruptions | Network changes, brief disconnections | Session ID, sequence counters, ratchet state, encryption keys |
| **Transport** | Ephemeral | Nothing — rebuilt on reconnection | The actual UDP/TCP/WebSocket connection |

The application only interacts with the session layer. Transport churn is invisible.

### 7.2 Connection State Machine

```
Connected ──→ Unstable ──→ Disconnected ──→ Reconnecting ──→ Suspended
    ↑                                            │                │
    │                                            ↓                ↓
    ├───────────── Reconnected ←─────────────────┘                │
    │                                                             │
    └───────────────────────── Failed ←───────────────────────────┘
```

| State | Description |
|---|---|
| **Connected** | Active, healthy connection. Data flows normally. |
| **Unstable** | Degradation detected (high latency, packet loss). Proactively probing alternatives. Data still flows. |
| **Disconnected** | Transport lost. Immediately enters reconnection. |
| **Reconnecting** | Actively attempting to re-establish transport. Trying fallback order, querying rendezvous. |
| **Suspended** | Reconnection paused (exponential backoff). Retries periodically. |
| **Reconnected** | Transport re-established, session resumed, sequence state synchronized. |
| **Failed** | Max retry budget exhausted or session expired. Application must decide next action. |

All transitions emit events to the application.

### 7.3 Session Resumption Protocol (Within Expiry Window)

Triggered when transport is re-established after a disruption and the session has not expired.

1. Reconnecting peer presents Session ID + cryptographic proof of identity (signed challenge using session keys).
2. Receiving peer validates: Session ID exists, not expired, proof is valid.
3. Both peers advance the key ratchet, deriving fresh symmetric keys.
4. Both peers exchange last-seen sequence numbers to identify in-flight messages.
5. Queued messages are retransmitted in sequence order.
6. Session restored — application receives state transition event.

**Security invariants**: proof of identity prevents hijacking with intercepted Session ID. Ratchet advancement provides forward secrecy. Timestamp + nonce prevent replay.

### 7.4 Session Re-Establishment Protocol (After Expiry)

Triggered when the session has expired (default: 24 hours). Re-pairing is NOT required.

1. Reconnecting peer discovers remote peer via standard rendezvous mechanism.
2. Both peers perform a new **Noise XX handshake** authenticated using long-term identity keys derived from the pairing secret (via HKDF).
3. Noise XX output becomes new root key for a **fresh Double Ratchet**. All previous ratchet state is discarded.
4. New Session ID (UUID v7) is generated. Old Session ID is invalidated.
5. Message sequence numbers restart from zero. Messages queued during expired session are discarded.

This ensures forward secrecy across session boundaries: completely fresh keying material with no continuity from the expired session.

### 7.5 Message Queuing

Opt-in, configurable buffering during disconnection:

| Parameter | Default | Description |
|---|---|---|
| `queue_enabled` | `true` | Whether to buffer messages at all |
| `queue_max_size` | 1000 | Maximum messages to buffer |
| `queue_max_age` | 1 hour | Maximum age before discard |
| `queue_strategy` | FIFO | FIFO (oldest first) or LIFO (newest first, discard old) |

Chat applications should use FIFO with high limits. Real-time control applications should disable queuing entirely.

### 7.6 Heartbeat & Keepalive

| Parameter | Default | Description |
|---|---|---|
| `heartbeat_interval` | 30s | Both peers send heartbeats at this interval |
| `heartbeat_timeout` | 90s (3× interval) | No heartbeat or data within this window → Disconnected state |

Interval is tunable per project: aggressive (5s) for real-time apps, relaxed (60s) for background sync.

### 7.7 Network Change Handling

On detecting OS-level network interface changes (WiFi ↔ cellular, new IP, VPN):

1. Library proactively triggers reconnection (does not wait for connection timeout).
2. Reconnecting peer publishes updated reachability to rendezvous point.
3. Initiates session resumption from new network context.
4. Remote peer accepts based on cryptographic session identity, not source IP.

---

## 8. Rendezvous & Peer Discovery

### 8.1 Rendezvous ID Derivation

```
rendezvous_id = HKDF(pairing_secret, "cairn-rendezvous-v1", context)
```

Properties:

- **Deterministic**: both peers compute independently.
- **Opaque**: observers cannot correlate to peer identities.
- **Rotatable**: includes time-based epoch for periodic rotation.

### 8.2 Discovery Flow

When a peer comes online or recovers from disconnection:

1. Compute current rendezvous ID for each paired peer.
2. **Publish** current reachability information (listening addresses, supported transports) to rendezvous point, encrypted so only paired peer can read it.
3. **Query** rendezvous point for other peer's reachability.
4. If found → initiate direct connection using retrieved address info.
5. If not found → poll periodically (configurable interval and backoff).

### 8.3 Multi-Infrastructure Rendezvous

The library publishes to and reads from all configured discovery infrastructure simultaneously. First result wins.

| Mechanism | Infrastructure | Tier Availability | Characteristics |
|---|---|---|---|
| **mDNS** (attempted first) | Local network | Tier 0 | Instant, no internet required. Rendezvous ID as mDNS service name. |
| **Kademlia DHT** | libp2p public DHT | Tier 0 | Rendezvous ID as DHT key, encrypted reachability as value. |
| **BitTorrent trackers** | Curated public trackers | Tier 0 | Rendezvous ID as info_hash, peer discovery through swarm. |
| **Signaling servers** | cairn companion server | Tier 1+ | Rendezvous ID as topic/room, real-time reachability exchange via WSS. Sub-second. |
| **Custom backends** | Pluggable | Any | Developer-provided domain-specific infrastructure. |

**BitTorrent tracker guidelines**: prefer mainline DHT (BEP 5) over tracker announces. Minimum 15-minute re-announce interval. Use only known-permissive trackers. Document BEP 3 HTTP and BEP 15 UDP protocols. At scale, consider cairn-specific DHT bootstrap nodes.

### 8.4 Rendezvous ID Rotation

| Parameter | Value |
|---|---|
| Default rotation interval | 24 hours |
| Epoch derivation | `epoch_number = floor(unix_timestamp / rotation_interval)` — derived from pairing secret via HKDF, unpredictable to observers |
| Transition overlap window | 1 hour (configurable), centered on epoch boundary |
| Clock tolerance | 5 minutes (satisfied by any device with NTP) |
| Overlap behavior | During overlap, publish and query both current and previous epoch rendezvous IDs |

If clock drift exceeds the transition window, diagnostic API should report this as a possible cause of rendezvous failure.

### 8.5 Pairing-Bootstrapped Rendezvous

Initiation mechanisms (pin code, QR, link) can bootstrap discovery without prior network presence:

```
pairing_rendezvous_id = HKDF(pake_credential, "cairn-pairing-rendezvous-v1", nonce)
```

1. Both peers derive pairing rendezvous ID from PAKE credential.
2. Both publish reachability at this rendezvous point on all available infrastructure.
3. When both present, they discover each other and perform PAKE-authenticated key exchange.

This enables two peers that have never been on the same network to pair via pin code entry alone, using the public DHT or trackers.

### 8.6 Mesh Group Rendezvous

For mesh groups, rendezvous ID is derived from the group's shared secret. All members compute the same ID. The encrypted payload at the rendezvous point includes the publishing peer's identity for group member identification.

---

## 9. Mesh Networking

### 9.1 Scope

Mesh is opt-in, disabled by default. Uses cairn application-level relay on standard libp2p streams, NOT Circuit Relay v2.

| Scenario | Mesh Needed? |
|---|---|
| Two-peer connections (e.g., remote shell) | No |
| Multi-device sync (5 devices) | Useful when not all devices can reach each other directly |
| Group communication | Enables routing around network partitions |

### 9.2 Routing

When enabled, the library maintains a routing table of known peers and their reachability. If peer A cannot reach peer C directly but peer B can reach both, traffic routes A → B → C automatically.

**Route selection priority**:

1. Shortest hop count.
2. Lowest latency.
3. Highest available bandwidth.

Routes are discovered through periodic exchange of reachability information among mesh participants.

### 9.3 End-to-End Encryption Through Mesh

Relay peers handle only opaque encrypted bytes. Session encryption between the communicating peers is maintained end-to-end. The relay peer cannot read, modify, or forge messages. Its role is purely transport-level forwarding.

### 9.4 Configuration

| Parameter | Default | Description |
|---|---|---|
| `mesh_enabled` | `false` | Enable/disable mesh routing |
| `max_hops` | 3 | Maximum relay hops |
| `relay_willing` | `false` | Whether this peer will relay for others |
| `relay_capacity` | 10 | Max simultaneous relay connections |

---

## 10. Server Mode

### 10.1 Design Philosophy

Server mode is a configuration posture applied to a standard cairn peer — not a separate component, class, or protocol. The same pairing, encryption, session, and transport mechanisms apply. A convenience constructor `cairn.create_server(config)` applies server-mode defaults.

### 10.2 Configuration Deltas

| Setting | Regular Default | Server Mode Default |
|---|---|---|
| `mesh_enabled` | `false` | `true` |
| `relay_willing` | `false` | `true` |
| `relay_capacity` | 10 | 100+ (configurable) |
| `store_forward_enabled` | `false` | `true` |
| `store_forward_max_per_peer` | — | 10,000 messages |
| `store_forward_max_age` | — | 7 days |
| `store_forward_max_total_size` | — | 1 GB |
| `session_expiry` | 24 hours | 7 days |
| `heartbeat_interval` | 30s | 60s |
| `reconnect_max_duration` | 1 hour | indefinite |
| `headless` | `false` | `true` |

### 10.3 Store-and-Forward

#### 10.3.1 Message Flow

1. Peer A sends message to offline Peer B.
2. If A is paired with server-mode peer S, and S is also paired with B, A sends to S with a forward directive (intended recipient: B).
3. S stores the message in its local queue. Message is E2E encrypted between A and B — S cannot read content.
4. When B comes online and establishes session with S, S delivers queued messages in sequence order.
5. S acknowledges delivery back to A (if online) and purges delivered messages.

**Trust requirement**: S must be independently paired with both sender and recipient. Server-to-server store-and-forward is not supported in v1.0.

Forward directives use a dedicated control channel `__cairn_forward` with message types `0x07xx`.

#### 10.3.2 Double Ratchet Handling for Stored Messages

Each forwarded message includes ratchet metadata in the header:

- Message number within current sending chain.
- Sender's current DH ratchet public key.
- Previous chain's message count.

The server stores and forwards the complete encrypted message including its Double Ratchet header. It validates message sequence via unencrypted envelope metadata without decrypting.

When B receives buffered messages, it reconstructs ratchet state by processing messages in sequence order: for each message, if the DH ratchet key differs, B performs a DH ratchet step; then advances the receiving chain to the message's chain index, deriving and caching skipped message keys.

**Max skip threshold**: if B's ratchet is more than N messages behind (default: 1000), reject the message to prevent resource exhaustion.

**Forward secrecy tradeoff**: all messages within a single DH ratchet epoch share the same DH secret. They still have per-message keys (chain ratchet), but compromise of the DH private key at that epoch exposes all messages in that epoch. This is inherent to one-way offline messaging and must be documented.

#### 10.3.3 Retention Policy

| Parameter | Default |
|---|---|
| Max age | 7 days |
| Max messages per peer | 1,000 |
| Policy | Whichever limit is reached first |
| Per-peer overrides | Supported (operator can give priority peers higher quotas) |
| Delivery model | Pull: recipient pulls from their own server |

**Deduplication**: UUID v7 message IDs. Multi-server coordination deferred.

### 10.4 Personal Relay

A server-mode peer with a public IP (or port-forwarded) relays traffic between paired peers who cannot connect directly. Uses existing mesh relay mechanism with the server as the natural relay hub. Controlled by `relay_willing` and `relay_capacity`. Only serves paired peers — limits abuse surface compared to open TURN relay.

### 10.5 Headless Operation & Pairing

| Mechanism | Headless Workflow |
|---|---|
| Pre-shared key | Configure in both peers via config file or environment variable. |
| Pin code | Server generates pin on CLI or logs it; user enters on device. |
| Pairing link | Server outputs `cairn://pair?...` URI on CLI; user copies via SSH, clipboard, or management web interface. |
| QR code | Terminal ASCII art, PNG via management HTTP endpoint, or image sent through already-paired device. |

**Management endpoint security**: binds to `127.0.0.1` by default. Bearer token auth required (configured via `CAIRN_MGMT_TOKEN` env var or config file). Logs warning if exposed on non-loopback interface without TLS. Pairing payload validity window (5 minutes) provides defense-in-depth.

Typical workflow: `SSH → curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/pairing/qr -o qr.png → transfer to phone → scan`.

### 10.6 Multi-Device Sync

Topology:

```
Phone ←→ Server Node ←→ Laptop
              ↕
           Tablet
```

Each device pairs individually with the server node (and optionally with each other). The server node tracks per-peer synchronization state (last-seen sequence numbers, pending deliveries). Devices do not need to be online simultaneously.

### 10.7 Deployment

| Method | Description |
|---|---|
| Docker | Single container, env var or config file config, Docker volume for keys/queue. |
| Systemd | Single binary as system service on Linux. |
| Home NAS | Docker container or native process alongside existing services. |
| VPS/Cloud | 512 MB RAM sufficient for moderate relay/mailbox load. |

#### Management API (Opt-in)

- Enabled via `--enable-management` or `CAIRN_MGMT_ENABLED=true`.
- REST/JSON over HTTP. No gRPC.
- Bound to `127.0.0.1`, bearer token auth.
- Features: paired peers list, queue depths, relay stats, connection health, pairing QR generation.
- Warns if exposed on non-loopback without TLS.

#### Resource Accounting

- Per-peer: bytes relayed, bytes stored.
- Exposed via management API and structured event interface.
- Configurable per-peer quotas (max stored messages, max relay bandwidth) — disabled by default.

### 10.8 Trust Model

- Cannot read E2E encrypted messages (stores/relays opaque ciphertext).
- Cannot impersonate another peer.
- Can be unpaired at any time.
- Compromise reveals only metadata (who communicates, message sizes, timing) — not content.
- Because always-on, sees more metadata over time than intermittent peers. Self-hosting recommended for maximum privacy.

---

## 11. Error Handling

### 11.1 Error Classification

| Error | Meaning | Library Behavior |
|---|---|---|
| `TransportExhausted` | All fallback chain transports failed | Report with per-transport failure details + actionable suggestion |
| `SessionExpired` | Session exceeded expiry window | Clear session state, notify app (re-pairing not needed, re-establish via Noise XX) |
| `PeerUnreachable` | Not found at any rendezvous within timeout | Report; continue background polling if configured |
| `AuthenticationFailed` | Crypto verification failed during resumption | Reject connection, alert app (possible compromise) |
| `PairingRejected` | Remote peer rejected pairing | Report |
| `PairingExpired` | Pairing payload expired | Report; initiating peer generates new payload |
| `MeshRouteNotFound` | No mesh route to destination | Report; suggest direct connection or wait |
| `VersionMismatch` | No common protocol version | Reject; error includes peer's supported version range |

### 11.2 Configurable Timeouts

| Timeout | Default | Description |
|---|---|---|
| `connect_timeout` | 30s | Initial connection attempt |
| `transport_timeout` | 10s | Per-transport attempt |
| `reconnect_max_duration` | 1 hour | Total reconnection time |
| `reconnect_backoff` | initial: 1s, max: 60s, factor: 2.0 | Exponential backoff |
| `rendezvous_poll_interval` | 30s | Offline peer polling |
| `session_expiry` | 24 hours | Inactive session invalidation |
| `pairing_payload_expiry` | 5 minutes | Pin/QR/link validity |

---

## 12. Configuration Model

### 12.1 Configuration Object

All configuration is provided at initialization through a single configuration object (idiomatic per language). Every setting has a default, enabling zero-config usage.

### 12.2 Configurable Settings

| Setting | Default | Description |
|---|---|---|
| `stun_servers` | Curated public list (Google, Cloudflare, etc.) | STUN server URLs for NAT detection and hole punching |
| `turn_servers` | None (Tier 1+) | TURN relay servers with credentials |
| `signaling_servers` | None (Tier 1+) | WebSocket-based signaling endpoints |
| `tracker_urls` | Curated public list | BitTorrent tracker URLs for discovery |
| `bootstrap_nodes` | libp2p public bootstrap list | DHT bootstrap peers for Kademlia routing |
| `transport_preferences` | QUIC → TCP → WS/TLS → WebTransport → Circuit Relay v2 | Ordered transport priority |
| `reconnection_policy` | See section 11.2 | Timeouts, backoff, retries, session expiry |
| `mesh_settings` | Disabled (see section 9.4) | Mesh routing configuration |
| `storage_backend` | Filesystem | Where to persist keys, identities, pairing state |

### 12.3 Default Infrastructure List Updates

Opt-in signed manifest fetch (disabled by default):

- Retrieves a JSON manifest from a cairn-controlled endpoint.
- Manifest is signed with Ed25519; public key is embedded in the library.
- Signature verified before list is applied.
- Same approach used by many P2P networks for bootstrap node lists.

---

## 13. API Surface

### 13.1 Core Abstractions

| Concept | Description |
|---|---|
| **Node** | Local cairn instance. Created with configuration. Represents this peer. |
| **PeerId** | Unique identifier derived from identity public key hash. |
| **Pairing** | Process of establishing mutual trust with a new peer. |
| **Session** | Active or resumable connection to a paired peer. |
| **Channel** | Bidirectional data stream within a session (yamux stream). Sessions multiplex multiple channels. |
| **Event** | State transitions and incoming data delivered asynchronously. |

### 13.2 API Pseudocode

```
// Initialize
node = cairn.create()                     // Zero-config (Tier 0)
node = cairn.create(config)               // Custom config
node = cairn.create_server()              // Server mode defaults
node = cairn.create_server(config)        // Server mode with overrides

// Pairing — QR Code
qr_data = node.pair_generate_qr()        // Returns QR data + pairing handle
pairing = node.pair_scan_qr(scanned)     // Yields PeerId on success

// Pairing — Pin Code
pin = node.pair_generate_pin()            // Returns pin string + pairing handle
pairing = node.pair_enter_pin(pin)        // Yields PeerId on success

// Pairing — Link
link = node.pair_generate_link()          // Returns URI string + pairing handle
pairing = node.pair_from_link(uri)        // Yields PeerId on success

// Pairing — SAS (legacy)
pairing = node.pair(peer_id, method)      // Yields PeerId on success

// Connect
session = node.connect(peer_id)           // Auto discovery, NAT traversal, session resume

// Channels
channel = session.open_channel(name)      // ChannelInit on new yamux stream
session.on("channel_opened", callback)    // Remote peer opened a channel

// Data
session.send(channel, data)
session.send(channel, data, { forward: true })  // Store-and-forward
session.on_message(channel, callback)

// State
session.on_state_change(callback)         // Connected, Unstable, Disconnected, etc.
session.close()

// Unpair
node.unpair(peer_id)                      // Removes trust, deletes keys

// Diagnostics
node.network_info().nat_type              // open | full_cone | ... | unknown
```

### 13.3 Event-Driven Architecture

All state changes, incoming data, errors, and reconnection events are delivered asynchronously:

| Language | Mechanism |
|---|---|
| Rust | Closures and channels (tokio mpsc) |
| Go | Channels and goroutines |
| TypeScript | EventEmitter / async iterators |
| Python | Async generators / asyncio callbacks |
| PHP | Event loop callbacks (ReactPHP/Amp) |

---

## 14. Companion Infrastructure

### 14.1 Implementation

Both the signaling server and TURN relay are implemented in **Rust**. Rationale:

- Lowest resource footprint (no GC, minimal memory).
- Single-language maintenance burden (shared crates with the Rust client library).
- rust-libp2p production maturity.
- Deployment targets: Docker containers and small VPS instances (512 MB RAM).

### 14.2 Signaling Server

- WebSocket (WSS on port 443) message router.
- Peers subscribe to rendezvous topics, exchange CBOR-encoded signaling messages.
- Stateless (no message persistence, only active WebSocket connections).
- Optional bearer token authentication.
- Deployment: `docker run -d -p 443:443 cairn/signal --tls-cert /certs/cert.pem --tls-key /certs/key.pem`
- Federation: deferred to post-v1.0, but internal API designed to support it.

### 14.3 TURN Relay

- Standard TURN (RFC 8656), compatible with non-cairn applications.
- Static credentials or REST API for dynamic provisioning.
- Port 443/TLS support for WebSocket escape hatch.
- Deployment: `docker run -d -p 3478:3478/udp -p 443:443 cairn/relay --credentials user:pass`

### 14.4 Authentication Model

- **Default**: bearer tokens. Simple deployment, scalable later.
- **Tier 3**: API key provisioning.
- **Deferred**: OAuth2 and mTLS as optional backends.

### 14.5 Docker Compose

```yaml
# cairn-infra/docker-compose.yml (provided in project repo)
docker compose up -d
```

---

## 15. Implementation Strategy

### 15.1 Native Per-Language Approach

Each language gets a native, idiomatic implementation — no FFI bindings to a shared core. This prioritizes developer experience: no cross-compilation toolchain, no FFI debugging, no WASM edge cases. Each library feels native to its ecosystem.

The tradeoff: the wire protocol spec must be impeccable, and cross-language conformance testing is critical.

### 15.2 Implementation Order

| Phase | Deliverables | Rationale |
|---|---|---|
| 1 | Rust + TypeScript libraries, signaling server, TURN relay | Strongest libp2p support, covers most active projects. Companion infrastructure needed for Tier 1+ testing. |
| 2 | Go library | Mature libp2p, strong server-side use cases. |
| 3 | Python library | Developing libp2p, scripting/automation use cases. |
| 4 | PHP library | No existing libp2p — most original work, important for web backend. |

### 15.3 Conformance Testing

Automated cross-language conformance test matrix in CI for every commit:

**Test matrix**: every language pair (Rust↔Go, Go↔TS, TS↔PHP, etc.) across all major flows.

**Test scenarios**:

- Pairing (all mechanisms: QR, pin code, link, SAS, pre-shared key).
- Session establishment.
- Data transfer.
- Reconnection after disconnect.
- Session resumption after timeout.
- Mesh routing (two hops).
- Transport fallback.
- Store-and-forward via server-mode peer.

**Test infrastructure**: each language's implementation runs in a Docker container with controlled networking (simulated NAT, packet loss, disconnection).

**Tier coverage**:

| Tier | Test Environment |
|---|---|
| 0 | No signaling/TURN — validates DHT/tracker discovery, STUN-only connectivity. |
| 1 | Companion signaling server + TURN relay — validates real-time signaling, relay fallback, transport chain escalation. |
| 2 | Server-mode peer — validates store-and-forward, personal relay, multi-device sync. |

---

## 16. Licensing

**MIT OR Apache-2.0** (dual-license). Rust ecosystem standard, maximum adoption.

---

## 17. Resolved Design Decisions Reference

This section provides a consolidated index of all design decisions resolved during the design phase, with pointers to the relevant specification sections.

| Decision Area | Decision | Section |
|---|---|---|
| Companion infra language | Rust | §14.1 |
| Companion infra auth | Bearer tokens (default), API keys (Tier 3) | §14.4 |
| Federation | Defer to post-v1.0 | §14.2 |
| PAKE algorithm | SPAKE2 | §4.1 |
| Pin code format | Crockford Base32, 8 chars, 40 bits | §5.3.4 |
| QR code standard | Binary CBOR, EC Level M, max 256 bytes | §5.3.3 |
| UUID version | UUID v7 (RFC 9562) | §3.2 |
| QUIC version | QUIC v1 (RFC 9000) | §6.1 |
| Channel multiplexing | yamux streams | §3.5 |
| WebTransport priority | After WebSocket (priority 7) | §6.1 |
| Protocol extensibility | 0xF000–0xFFFF reserved for applications | §3.3 |
| Version negotiation failure | `VersionMismatch` with peer's range | §3.4 |
| Unpairing | Unilateral + best-effort `PairRevoke` | §5.5 |
| Pairing rate limiting | Acceptor-side, 5/30s, 10 max, 2s delay | §5.4 |
| Security layers | Intentional double encryption | §2.2 |
| Session re-establishment | Full Noise XX + fresh Double Ratchet | §7.4 |
| mDNS | First-class, attempted before remote discovery | §8.3 |
| Rendezvous rotation overlap | 1 hour, 5-minute clock tolerance | §8.4 |
| Default endpoint updates | Opt-in signed manifest, Ed25519, disabled by default | §12.3 |
| NAT type detection | Read-only diagnostic metadata | §6.6 |
| Store-and-forward trust | Requires mutually paired server | §10.3.1 |
| Retention policy | 7 days / 1000 messages per peer | §10.3.3 |
| Multi-server coordination | Defer, UUID dedup prepared | §10.3.3 |
| Management API | REST/JSON, disabled by default, localhost, bearer token | §10.7 |
| Resource accounting | Per-peer bandwidth/storage tracking | §10.7 |
| Mobile | Document constraints, platform-aware keepalive | §6.3 (notes) |
| Browser | TypeScript supports Node.js and browser | §6.3 |
| Group key agreement (MLS) | Defer to post-v1.0 | §5.6 |
| Bandwidth management | Defer, provide metrics hooks | §12.2 |
| Observability | Structured event interface, optional Prometheus for server mode | PRD NFR-5 |
| Licensing | MIT OR Apache-2.0 | §16 |

---

## Appendix A: Glossary

| Term | Definition |
|---|---|
| CBOR | Concise Binary Object Representation — binary serialization format (RFC 8949) |
| Circuit Relay v2 | libp2p protocol for transient connection relay. Limited to 2-minute, 128 KB connections. Used only for hole-punch coordination in cairn. |
| Companion infrastructure | Lightweight, self-hostable services (signaling server, TURN relay) provided by the cairn project. Implemented in Rust. |
| CPace | IETF CFRG recommended balanced PAKE. Not selected for v1.0 due to immature cross-language libraries. |
| Crockford Base32 | Human-friendly encoding: 32 chars (0–9, A–Z excluding I, L, O, U). Used for pin codes. |
| DHT | Distributed Hash Table — decentralized key-value store for peer discovery. |
| Double Ratchet | Cryptographic algorithm providing forward secrecy and break-in recovery (Signal protocol). |
| HKDF | HMAC-based Key Derivation Function (RFC 5869). |
| ICE | Interactive Connectivity Establishment — NAT traversal framework. |
| Kademlia | DHT algorithm used by libp2p for peer routing and content discovery. |
| mDNS | Multicast DNS — zero-config local network peer discovery. Attempted first before remote mechanisms. |
| MLS | Messaging Layer Security — group key agreement protocol (RFC 9420). Deferred to post-v1.0. |
| NAT | Network Address Translation — complicates P2P by mapping private IPs to public IPs. |
| Noise XX | Handshake pattern from Noise Protocol Framework — mutual authentication. |
| OPAQUE | Augmented PAKE where server never learns the password. Future consideration for server-mode PSK hardening. |
| PAKE | Password-Authenticated Key Exchange — key agreement using a shared password. |
| Rendezvous point | A shared, derived location in P2P infrastructure where paired peers coordinate. |
| SAS | Short Authentication String — human-verifiable code for MITM prevention. |
| Server mode | Configuration posture for an always-on cairn peer — enables store-and-forward, relay, and rendezvous anchor. |
| SPAKE2 | Balanced PAKE protocol. Selected for cross-language maturity and proven use at scale. |
| Store-and-forward | Delivery pattern where an intermediary holds messages for offline recipients. |
| STUN | Session Traversal Utilities for NAT — discovers public IP and NAT type. |
| TURN | Traversal Using Relays around NAT — relay server (RFC 8656). |
| UUID v7 | Universally Unique Identifier version 7 (RFC 9562) — timestamp-ordered. |

---

*End of Technical Specification*
