# 06 — API Reference & Internals Content

## Cross-references
- **Depends on**: `01-docusaurus-setup.md` for the `LanguageTabs` component and `TabItem` used in all API signature examples.
- **Depends on**: `03-getting-started-content.md` for basic usage patterns that API docs build upon.

---

## Overview

This module covers:
1. API reference pages (5 pages under `website/docs/api/`)
2. Internals documentation (2 pages under `website/docs/internals/`)

All API reference pages use `LanguageTabs` to show method signatures and usage in Rust, TypeScript, Go, Python, and PHP. All code must match existing library methods — do not invent new API calls. Reference code from `docs/getting-started.md`, `demo/messaging/*/`, and `README.md`.

---

## File 1: `website/docs/api/node.md`

### Purpose
Document the `Node` / `CairnNode` API across all languages.

**Frontmatter**: `title: "Node"`, `sidebar_position: 1`

**Import block**:
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';
```

### Section: Constructor / Factory

Method: `create(config?)`

Show signatures in all 5 languages:
- Rust: `CairnNode::builder().build().await?` or `CairnNode::builder().config(config).build().await?`
- TypeScript: `await CairnNode.create()` or `await CairnNode.create(config)`
- Go: `cairn.NewNode()` or `cairn.NewNode(cairn.WithSignalServer(...))`
- Python: `await CairnNode.create()` or `await CairnNode.create(config)`
- PHP: `CairnNode::create()` or `CairnNode::create($config)`

### Section: Pairing Methods

#### `pair_generate_pin()` / `pairGeneratePin()` / `PairGeneratePin()`
- Returns: pairing PIN string and a pending pairing handle.
- The PIN should be displayed to the user for the responder to enter.
- Show signature in all 5 languages.

#### `pair_enter_pin(pin)` / `pairEnterPin(pin)` / `PairEnterPin(pin)`
- Parameter: `pin` — the PIN string from the initiator.
- Returns: peer ID of the paired peer.
- Show signature in all 5 languages.

#### `pair_generate_link()` / `pairGenerateLink()` / `PairGenerateLink()`
- Returns: a pairing URI string.
- Show signature in all 5 languages.

#### `pair_from_link(uri)` / `pairFromLink(uri)` / `PairFromLink(uri)`
- Parameter: `uri` — the pairing URI from the initiator.
- Returns: peer ID of the paired peer.
- Show signature in all 5 languages.

### Section: Connection

#### `connect(peer_id)` / `connect(peerId)` / `Connect(peerID)`
- Parameter: peer ID of a previously paired peer.
- Returns: an encrypted `Session`.
- Show signature in all 5 languages.

### Section: Events

#### `subscribe()` / `on(event, callback)` / `Events()` / `events()`
- Rust: `node.subscribe()` returns a stream of events.
- TypeScript: `node.on("message", callback)` or `node.on("stateChanged", callback)`.
- Go: `node.Events()` returns a channel of events.
- Python: `async for event in node.events():` async iterator pattern.
- PHP: `$node->on("message", $callback)` callback pattern.

### Section: Info

#### `peer_id` / `peerId` / `PeerID()`
- Returns: the local peer's identity (base58-encoded Ed25519 public key).
- Rust: `node.peer_id()` — returns `PeerID`.
- TypeScript: `node.peerId` — property.
- Go: `node.PeerID()` — method returns `PeerID`.
- Python: `node.peer_id` — property.
- PHP: `$node->peerId()` — method.

---

## File 2: `website/docs/api/session.md`

### Purpose
Document the `Session` API across all languages.

**Frontmatter**: `title: "Session"`, `sidebar_position: 2`

**Import block**: Same as node.md.

### Section: send(channel, data)

Send an encrypted message on a named channel:
- Rust: `session.send("chat", data).await?`
- TypeScript: `await session.send("chat", data)`
- Go: `session.Send("chat", data)`
- Python: `await session.send("chat", data)`
- PHP: `$session->send("chat", $data)`

Parameters:
- `channel` — string channel name (use `""` or default for the default channel).
- `data` — bytes or string payload.

### Section: close()

Close the session gracefully:
- Rust: `session.close().await`
- TypeScript: `session.close()`
- Go: `session.Close()`
- Python: `await session.close()`
- PHP: `$session->close()`

### Section: State Properties

Session state inspection:
- Current state (`connected`, `reconnecting`, `disconnected`).
- Remote peer ID.
- Show property/method access in all 5 languages.

---

## File 3: `website/docs/api/events.md`

### Purpose
Document event types emitted by a cairn node.

**Frontmatter**: `title: "Events"`, `sidebar_position: 3`

**Import block**: Same as node.md.

### Event: MessageReceived
- Payload: `{peer_id, channel, data}`
- `peer_id` — sender's peer ID.
- `channel` — the channel name the message was sent on.
- `data` — the decrypted message payload (bytes or string).
- Show handling code in all 5 languages.

### Event: StateChanged
- Payload: `{peer_id, state}`
- `peer_id` — the peer whose connection state changed.
- `state` — one of `connecting`, `connected`, `reconnecting`, `disconnected`.
- Show handling code in all 5 languages.

### Event: PeerDiscovered
- Payload: `{peer_id}`
- Emitted when a paired peer is discovered on the network (via mDNS, DHT, or signaling).
- Show handling code in all 5 languages.

### Event: PeerLost
- Payload: `{peer_id}`
- Emitted when a previously discovered peer is no longer reachable.
- Show handling code in all 5 languages.

---

## File 4: `website/docs/api/config.md`

### Purpose
Document configuration options available when creating a node.

**Frontmatter**: `title: "Configuration"`, `sidebar_position: 4`

**Import block**: Same as node.md.

### Configuration Options Table

Document all configuration fields with their types, defaults, and descriptions. Show how to set each option in all 5 languages using `LanguageTabs`.

Common configuration options (extract exact names from existing library code):
- Signal server URL
- TURN server URL
- TURN credentials
- Server mode enabled/disabled
- Storage path (for server mode persistence)
- Mesh routing enabled/disabled
- Identity seed (for deterministic peer ID)
- Listen address

### Example: Full Configuration
Show a complete configuration example in all 5 languages creating a node with multiple options set.

---

## File 5: `website/docs/api/errors.md`

### Purpose
Document error types across languages.

**Frontmatter**: `title: "Errors"`, `sidebar_position: 5`

**Import block**: Same as node.md.

### Error Categories

Document error types with their meaning and when they occur:

- **Connection errors**: Failed to connect to peer (timeout, unreachable, NAT traversal failed).
- **Pairing errors**: Invalid PIN, pairing rejected, SPAKE2 failure.
- **Session errors**: Send failed, session closed, encryption error.
- **Configuration errors**: Invalid config values, missing required fields.
- **Transport errors**: WebSocket failure, TURN relay failure, mDNS failure.

### Language-Specific Error Handling

Show idiomatic error handling in each language using `LanguageTabs`:
- Rust: `Result<T, CairnError>` with `match` or `?` operator.
- TypeScript: `try/catch` with `CairnError` class.
- Go: `error` return values with type assertion.
- Python: `CairnError` exception hierarchy with `try/except`.
- PHP: `CairnException` hierarchy with `try/catch`.

---

## File 6: `website/docs/internals/wire-protocol.md`

### Purpose
High-level wire protocol documentation for advanced users.

**Frontmatter**: `title: "Wire Protocol"`, `sidebar_position: 1`

### Section: Overview
The cairn wire protocol uses CBOR (Concise Binary Object Representation) for all message framing. This provides compact binary encoding with self-describing structure.

### Section: Frame Format
Document the CBOR frame structure:
- Frame header: message type, length, version.
- Frame body: type-specific payload.

### Section: Message Types
List and briefly describe each wire message type:
- Handshake messages (Noise XX protocol frames).
- Data messages (encrypted application payloads).
- Control messages (keepalive, close, reconnect).
- Signaling messages (peer discovery, relay setup).

### Section: Versioning
How protocol versioning works — version negotiation during handshake, backwards compatibility guarantees.

### Section: Reference
Note that the full protocol specification is in the internal design documents (`docs/technical-specification.md`) for contributors.

---

## File 7: `website/docs/internals/cryptography.md`

### Purpose
Crypto primitives and protocol documentation.

**Frontmatter**: `title: "Cryptography"`, `sidebar_position: 2`

### Section: Identity Keys
- Ed25519 key pair generated on first run.
- Public key is the peer's identity (PeerID is base58-encoded Ed25519 public key).
- Private key never leaves the device.

### Section: Key Exchange
- X25519 Diffie-Hellman key exchange.
- Used within the Noise XX handshake to establish a shared session key.

### Section: Noise XX Handshake
- Three-message handshake pattern: `-> e`, `<- e, ee, s, es`, `-> s, se`.
- Provides mutual authentication — both peers prove their identity.
- Produces symmetric encryption keys for the session.

### Section: SPAKE2 PAKE (Pairing)
- Simple Password Authenticated Key Exchange v2.
- Used during pairing to derive a shared secret from the PIN/QR/link data.
- Neither party reveals the secret even if an attacker observes the exchange.
- The shared secret bootstraps the Noise XX handshake.

### Section: Double Ratchet (Session Encryption)
- After the Noise handshake, the Double Ratchet algorithm manages ongoing encryption.
- Each message uses a unique key derived from the ratchet state.
- Provides forward secrecy: compromising current keys does not reveal past messages.
- Provides break-in recovery: after a key compromise, future messages are secure again once a new DH exchange completes.

### Section: Forward Secrecy Guarantees
- **Per-message forward secrecy**: Each message key is deleted after use.
- **Session forward secrecy**: Session keys are ephemeral and never stored long-term.
- **Pairing forward secrecy**: The SPAKE2 exchange produces ephemeral keys; the PIN/QR/link is not sufficient to decrypt past sessions.

---

## Code Example Guidelines

- All API signatures must be verified against existing library code — do not invent methods.
- Source verified examples from: `docs/getting-started.md`, `demo/messaging/*/`, `README.md`.
- Each `LanguageTabs` block must include all 5 languages: Rust, TypeScript, Go, Python, PHP.
- Default tab: `rust`. Tab values: `rust`, `typescript`, `go`, `python`, `php`.
