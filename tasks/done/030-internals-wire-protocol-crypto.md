# Task 030: Internals — Wire Protocol & Cryptography

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)

## Spec References
- spec/06-api-reference-content.md (File 6: wire-protocol.md, File 7: cryptography.md)

## Scope
Create the two internals documentation pages: wire protocol (CBOR framing, message types, versioning) and cryptography (identity keys, key exchange, Noise XX, SPAKE2, Double Ratchet, forward secrecy).

## Acceptance Criteria
- [x] File `website/docs/internals/wire-protocol.md` exists with frontmatter `title: "Wire Protocol"`, `sidebar_position: 1`
- [x] Wire protocol covers CBOR frame format, message types, and versioning
- [x] File `website/docs/internals/cryptography.md` exists with frontmatter `title: "Cryptography"`, `sidebar_position: 2`
- [x] Cryptography covers Identity Keys, Key Exchange, Noise XX, SPAKE2, Double Ratchet, Forward Secrecy
- [x] `cd website && npm run build` succeeds

## Implementation Notes
### wire-protocol.md
No LanguageTabs needed (protocol docs, not API signatures).

Sections:
1. **Overview**: CBOR (Concise Binary Object Representation) for all message framing. Compact binary encoding with self-describing structure.
2. **Frame Format**: Header (message type, length, version) + body (type-specific payload).
3. **Message Types**:
   - Handshake messages (Noise XX protocol frames)
   - Data messages (encrypted application payloads)
   - Control messages (keepalive, close, reconnect)
   - Signaling messages (peer discovery, relay setup)
4. **Versioning**: Version negotiation during handshake, backwards compatibility guarantees.
5. **Reference**: Note that full spec is in internal design documents (`docs/technical-specification.md`).

### cryptography.md
No LanguageTabs needed.

Sections:
1. **Identity Keys**: Ed25519 key pair on first run. Public key = PeerID (base58-encoded). Private key never leaves device.
2. **Key Exchange**: X25519 Diffie-Hellman within Noise XX handshake.
3. **Noise XX Handshake**: Three-message pattern `-> e`, `<- e, ee, s, es`, `-> s, se`. Mutual authentication, produces symmetric keys.
4. **SPAKE2 PAKE (Pairing)**: Simple Password Authenticated Key Exchange v2. Derives shared secret from PIN/QR/link. Neither party reveals secret if observed. Bootstraps Noise XX.
5. **Double Ratchet (Session Encryption)**: Manages ongoing encryption after Noise handshake. Unique key per message. Forward secrecy and break-in recovery.
6. **Forward Secrecy Guarantees**: Per-message (key deleted after use), session (ephemeral keys), pairing (SPAKE2 ephemeral keys).

## Files to Create or Modify
- website/docs/internals/wire-protocol.md (new)
- website/docs/internals/cryptography.md (new)

## Verification Commands
- `cd website && npm run build`
