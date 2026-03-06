# Task 016: Pairing Methods Guide

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/04-guides-content.md (File 1: pairing.md)

## Scope
Create the pairing methods guide covering PIN pairing, QR code pairing, and link pairing with code examples in all 5 languages. Includes a collapsible "How It Works" section explaining the SPAKE2 protocol.

## Acceptance Criteria
- [x] File `website/docs/guides/pairing.md` exists with frontmatter `title: "Pairing Methods"`, `sidebar_position: 1`
- [x] Import block includes `LanguageTabs` and `TabItem`
- [x] PIN Pairing section shows full flow (initiator generates PIN, responder enters PIN) with LanguageTabs for all 5 languages
- [x] QR Code Pairing section shows QR generation with per-language library suggestions (Rust: `qrcode`, TS: `qrcode`, Go: `github.com/skip2/go-qrcode`, Python: `qrcode`, PHP: `endroid/qr-code`)
- [x] Link Pairing section shows URI generation and consumption with LanguageTabs
- [x] Collapsible "How it works: SPAKE2" section using `<details><summary>` explains the SPAKE2 protocol
- [x] `cd website && npm run build` succeeds

## Implementation Notes
All code examples must use `LanguageTabs` with `groupId="language"`. Default tab is `rust`. Tab values: `rust`, `typescript`, `go`, `python`, `php`.

API methods per language:
- **PIN initiator**: `pair_generate_pin()` / `pairGeneratePin()` / `PairGeneratePin()` / `pair_generate_pin()` / `pairGeneratePin()`
- **PIN responder**: `pair_enter_pin(pin)` / `pairEnterPin(pin)` / `PairEnterPin(pin)` / `pair_enter_pin(pin)` / `pairEnterPin(pin)`
- **Link initiator**: `pair_generate_link()` / `pairGenerateLink()` / `PairGenerateLink()` / `pair_generate_link()` / `pairGenerateLink()`
- **Link responder**: `pair_from_link(uri)` / `pairFromLink(uri)` / `PairFromLink(uri)` / `pair_from_link(uri)` / `pairFromLink(uri)`

SPAKE2 explanation points:
- Both parties derive a shared secret from PIN/QR/link data
- SPAKE2 ensures neither party reveals the secret even if observed
- Shared secret bootstraps the Noise XX handshake for encrypted session

Verify API methods against existing code in `docs/getting-started.md`, `demo/messaging/*/`, and `README.md`.

## Files to Create or Modify
- website/docs/guides/pairing.md (new)

## Verification Commands
- `cd website && npm run build`
