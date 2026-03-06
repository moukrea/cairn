# Task 006: Quick Start Documentation

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/03-getting-started-content.md (File 2: quick-start.md)

## Scope
Create the quick-start guide at `website/docs/getting-started/quick-start.md`, migrated and restructured from `docs/getting-started.md`. Covers the six-step walkthrough: create node, pair, establish session, send message, receive messages, handle reconnection. All code blocks use LanguageTabs with all 5 languages.

## Acceptance Criteria
- [x] `website/docs/getting-started/quick-start.md` exists with full content
- [x] Opening paragraph matches spec: "Set up an encrypted P2P channel in 15 minutes..."
- [x] Six steps present: Create Node, Pair with Peer (PIN initiator + responder), Establish Session, Send Message, Receive Messages, Handle Reconnection
- [x] All code examples use LanguageTabs with all 5 languages and match the spec exactly
- [x] Next Steps footer with links to first-app, Guides, and Demo Applications
- [x] `cd website && npm run build` succeeds

## Implementation Notes

### Frontmatter
```yaml
---
sidebar_position: 2
title: Quick Start
---
```

### Opening
"Set up an encrypted P2P channel in 15 minutes. This guide walks through installing cairn, pairing two peers, establishing a session, and sending messages -- in all 5 supported languages."

### Step 1: Create a Node
Description: "A `Node` is your local peer. Creating one generates an Ed25519 identity and starts the transport layer with zero-config defaults."

LanguageTabs code (all 5 languages) -- use exact code from spec/03-getting-started-content.md Step 1.

### Step 2: Pair with a Peer
Description: "Pairing establishes mutual trust between two devices using a shared secret (PIN, QR code, or link). One peer initiates, the other responds."

Sub-section: **PIN Pairing**

Two LanguageTabs blocks:
1. **Initiator** -- generates PIN (all 5 languages from spec)
2. **Responder** -- enters PIN (all 5 languages from spec)

### Step 3: Establish a Session
Description: "After pairing, open an encrypted session. Sessions use a Noise XX handshake followed by a double ratchet for forward secrecy."

LanguageTabs with all 5 languages from spec.

### Step 4: Send a Message
Description: "Send encrypted data over the session. Messages are delivered through the best available transport."

LanguageTabs with all 5 languages from spec.

### Step 5: Receive Messages
Description: "Register a handler to receive incoming messages on a channel."

LanguageTabs with all 5 languages from spec. Note the different patterns: Rust uses `subscribe()` + event loop, TypeScript uses `node.on('message', ...)`, Go uses `node.Events()` channel, Python uses `async for event in node.events()`, PHP uses `$node->on('message', ...)`.

### Step 6: Handle Reconnection
Description: "Sessions automatically reconnect after network disruptions. Listen for state changes to update your UI."

LanguageTabs with all 5 languages from spec.

Connection states: `connecting` -> `connected` -> `reconnecting` -> `connected` (or `disconnected`).

### Next Steps Footer
- Link to `first-app.md` for a complete runnable example
- Link to Guides section for deeper topics (pairing methods, sessions, channels)
- Link to Demo Applications for working examples

## Files to Create or Modify
- website/docs/getting-started/quick-start.md (replace placeholder)

## Verification Commands
- `cd website && npm run build`
