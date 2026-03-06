---
sidebar_position: 1
title: "Wire Protocol"
---

# Wire Protocol

The cairn wire protocol uses CBOR (Concise Binary Object Representation) for all message framing. CBOR provides compact binary encoding with a self-describing structure, making it efficient for constrained peer-to-peer connections while remaining easy to parse across all supported languages.

## Frame Format

Every message on the wire follows the same envelope structure:

| Field | Size | Description |
|-------|------|-------------|
| Version | 1 byte | Protocol version (currently `0x01`) |
| Message Type | 2 bytes | Unsigned 16-bit type code (big-endian) |
| Session ID | 16 bytes | UUID identifying the session |
| Sequence Number | 8 bytes | Unsigned 64-bit monotonic counter (big-endian) |
| Payload Length | 4 bytes | Unsigned 32-bit length of the payload (big-endian) |
| Payload | variable | Type-specific CBOR-encoded body |

The envelope is binary, not CBOR-encoded itself, to keep framing overhead minimal. The payload within the envelope is CBOR-encoded and type-specific.

## Message Types

### Handshake Messages (`0x01xx`)

Used during the Noise XX handshake to establish a secure session:

| Type Code | Name | Direction | Description |
|-----------|------|-----------|-------------|
| `0x0100` | HandshakeInit | Initiator -> Responder | First Noise XX message (`-> e`) |
| `0x0101` | HandshakeResponse | Responder -> Initiator | Second Noise XX message (`<- e, ee, s, es`) |
| `0x0102` | HandshakeFinal | Initiator -> Responder | Third Noise XX message (`-> s, se`) |

### Data Messages (`0x03xx`)

Carry encrypted application data after the handshake completes:

| Type Code | Name | Description |
|-----------|------|-------------|
| `0x0300` | Data | Encrypted application payload on a named channel |
| `0x0303` | ChannelInit | Opens a new named channel on the session |

Data messages are encrypted using the session keys derived from the Noise handshake, then further protected by the Double Ratchet.

### Control Messages (`0x02xx`)

Manage session lifecycle:

| Type Code | Name | Description |
|-----------|------|-------------|
| `0x0200` | Keepalive | Heartbeat to detect connection liveness |
| `0x0201` | Close | Graceful session teardown |
| `0x0202` | Reconnect | Resume a suspended session |

### Signaling Messages (`0x04xx`)

Used for peer discovery and relay coordination:

| Type Code | Name | Description |
|-----------|------|-------------|
| `0x0400` | PeerAnnounce | Announce presence to signaling server |
| `0x0401` | RelayRequest | Request a TURN relay allocation |
| `0x0402` | RelayResponse | Relay allocation result |

### Custom Messages (`0xF000`--`0xFFFF`)

The application range `0xF000`--`0xFFFF` is reserved for user-defined message types. Applications can register handlers for these type codes at the node or session level.

## Versioning

Protocol versioning is negotiated during the handshake:

1. The initiator sends a `HandshakeInit` with its supported protocol version in the envelope header.
2. The responder checks compatibility and responds with the agreed version.
3. If versions are incompatible, the responder closes the connection with an error.

**Compatibility guarantees:**
- Minor version bumps are backwards-compatible (new optional fields, new message types).
- Major version bumps may break compatibility and require both peers to upgrade.
- Unknown message types are silently ignored, allowing gradual rollout of new features.

## Reference

The full protocol specification, including detailed CBOR schemas, encryption layer integration, and edge-case handling, is documented in the internal design documents for contributors. See `docs/technical-specification.md` in the repository root.
