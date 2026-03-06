# 04 — Guides Content

## Cross-references
- **Depends on**: `01-docusaurus-setup.md` for the `LanguageTabs` component and `TabItem` used in all code examples.
- **Depends on**: `03-getting-started-content.md` for quick-start concepts (node creation, pairing) that guides build upon.

---

## Overview

Five guide documents live under `website/docs/guides/`. Each guide uses `LanguageTabs` with `groupId="language"` to show code in Rust, TypeScript, Go, Python, and PHP. All code examples must match existing API methods — do not invent new API calls.

---

## File 1: `website/docs/guides/pairing.md`

### Purpose
Cover all three pairing methods with code examples in all languages.

### Structure

**Frontmatter**: `title: "Pairing Methods"`, `sidebar_position: 1`

**Import block** (top of file):
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';
```

### Section: PIN Pairing
- Initiator generates a PIN, responder enters it.
- Show the full flow: initiator calls `pair_generate_pin()` / `pairGeneratePin()` / `PairGeneratePin()`, displays PIN to user. Responder calls `pair_enter_pin(pin)` / `pairEnterPin(pin)` / `PairEnterPin(pin)`.
- Code example in all 5 languages using `LanguageTabs`.

### Section: QR Code Pairing
- Initiator generates QR data, responder scans.
- Show how to render QR (library suggestions per language):
  - Rust: `qrcode` crate
  - TypeScript: `qrcode` npm package
  - Go: `github.com/skip2/go-qrcode`
  - Python: `qrcode` PyPI package
  - PHP: `endroid/qr-code` Composer package
- Code example in all 5 languages using `LanguageTabs`.

### Section: Link Pairing
- Initiator generates a URI, responder opens it.
- Show URI format.
- Initiator calls `pair_generate_link()` / `pairGenerateLink()` / `PairGenerateLink()`.
- Responder calls `pair_from_link(uri)` / `pairFromLink(uri)` / `PairFromLink(uri)`.
- Code example in all 5 languages using `LanguageTabs`.

### Section: How It Works (collapsible)
- Wrap in `<details><summary>How it works: SPAKE2</summary>` block.
- Explain the SPAKE2 protocol underneath:
  - Both parties derive a shared secret from the PIN/QR/link data.
  - SPAKE2 (Simple Password Authenticated Key Exchange) ensures neither party reveals the secret even if an attacker observes the exchange.
  - The shared secret is used to bootstrap the Noise XX handshake for the encrypted session.

---

## File 2: `website/docs/guides/sessions.md`

### Purpose
Session lifecycle documentation.

### Structure

**Frontmatter**: `title: "Session Lifecycle"`, `sidebar_position: 2`

**Import block**: Same as above.

### Section: Connection States
- State machine: `connecting` -> `connected` -> `reconnecting` -> `connected` | `disconnected`
- Text-based state diagram showing transitions.

### Section: Automatic Reconnection
- When a transport drops (e.g., network change), the session automatically attempts reconnection.
- The Double Ratchet state is preserved — no re-pairing needed.
- Session persistence across transport changes (WiFi to cellular, etc.).

### Section: Event Handling for State Changes
- Show how to listen for `StateChanged` events in all 5 languages using `LanguageTabs`.
- Event payload: `{peer_id, state}` where `state` is one of `connecting`, `connected`, `reconnecting`, `disconnected`.

### Section: Session Properties
- Show how to inspect session state, peer ID, and connection info.
- Code in all 5 languages.

---

## File 3: `website/docs/guides/channels.md`

### Purpose
Message channels documentation.

### Structure

**Frontmatter**: `title: "Message Channels"`, `sidebar_position: 3`

**Import block**: Same as above.

### Section: Default Channel
- Messages sent without a channel name go to the default channel.
- All subscribers receive default channel messages.

### Section: Named Channels
- Named channels allow logical separation of message types (e.g., `"chat"`, `"presence"`, `"sync"`).
- Code example: sending to a named channel in all 5 languages using `LanguageTabs`.
  - `session.send("chat", data)` pattern across languages.

### Section: Subscribing to Channels
- Show how to subscribe to specific channels and handle messages per channel.
- Code in all 5 languages.

### Section: Binary vs Text Data
- Channels support both binary (`bytes` / `Uint8Array` / `[]byte`) and text (`string`) data.
- Show examples of sending both types.

---

## File 4: `website/docs/guides/server-mode.md`

### Purpose
Running a peer as an always-on server.

### Structure

**Frontmatter**: `title: "Server Mode"`, `sidebar_position: 4`

**Import block**: Same as above.

### Section: What Server Mode Enables
- **Store-and-forward**: Messages are held for offline peers and delivered when they reconnect.
- **Personal relay**: The server peer can relay traffic between peers that cannot connect directly.
- **Multi-device sync**: The server acts as a hub for syncing data across multiple devices.

### Section: Configuration Options
- Show how to enable server mode when creating a node.
- Configuration options specific to server mode (storage path, max message retention, etc.).
- Code in all 5 languages using `LanguageTabs`.

### Section: Headless Pairing
- **PSK (Pre-Shared Key)**: Configure the server with a pre-shared key; clients pair using that key without interactive PIN entry.
- **Pre-approved peers**: Configure the server with a list of peer IDs that are automatically accepted.
- Code examples showing headless pairing setup.

### Section: Integration with Signaling/Relay Infrastructure
- How server mode works alongside signaling and relay servers.
- The server peer connects to signaling for discovery, uses relay as fallback.
- Reference the infrastructure docs for deployment details.

---

## File 5: `website/docs/guides/mesh-routing.md`

### Purpose
Multi-hop mesh networking documentation.

### Structure

**Frontmatter**: `title: "Mesh Routing"`, `sidebar_position: 5`

**Import block**: Same as above.

### Section: When to Use Mesh Routing
- 3+ devices where some cannot reach each other directly.
- Relay through trusted peers instead of a central relay server.
- Example scenario: laptop <-> phone <-> desktop, where laptop and desktop cannot connect directly but both can reach the phone.

### Section: Enabling Mesh Mode
- Show how to enable mesh routing when creating a node or on an existing node.
- Code in all 5 languages using `LanguageTabs`.

### Section: Topology and Routing Behavior
- Mesh peers automatically discover multi-hop routes.
- Traffic is end-to-end encrypted — relay peers cannot read message content.
- Routing table is maintained automatically; no manual configuration needed.

### Section: Use Case — Multi-Device File Sync Through a Hub
- Walkthrough of a common pattern: one device acts as a hub (always-on server), other devices sync through it.
- The hub relays messages between devices that are not directly connected.
- Combine with server mode for store-and-forward capability.

---

## Code Example Guidelines

- All code examples must use the `LanguageTabs` / `TabItem` pattern shown in the spec.
- Use existing API methods only — reference code from `docs/getting-started.md`, `demo/messaging/*/`, and `README.md`.
- Each `LanguageTabs` block must include all 5 languages: Rust, TypeScript, Go, Python, PHP.
- Default tab is `rust`.
- Tab values: `rust`, `typescript`, `go`, `python`, `php`.
