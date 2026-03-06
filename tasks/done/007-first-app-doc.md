# Task 007: First App Tutorial

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/03-getting-started-content.md (File 3: first-app.md)
- demo/messaging/*/ (verified demo code to base examples on)

## Scope
Create the first-app tutorial at `website/docs/getting-started/first-app.md` -- a complete, runnable minimal P2P chat application in under 50 lines per language. Includes full code listing, running instructions, and expected output.

## Acceptance Criteria
- [x] `website/docs/getting-started/first-app.md` exists with full content
- [x] Introduction: "Build a minimal peer-to-peer chat app. Two terminals, one initiator, one responder. Under 50 lines of code."
- [x] Full self-contained code listing per language (all 5) using LanguageTabs
- [x] Each listing: creates node, checks CLI args for initiator/responder mode, generates or enters PIN, connects, reads stdin, sends/receives messages
- [x] Running instructions for both terminals (Terminal A: initiator, Terminal B: responder)
- [x] Expected output section showing sample terminal exchange
- [x] `cd website && npm run build` succeeds

## Implementation Notes

### Frontmatter
```yaml
---
sidebar_position: 3
title: "First App: P2P Chat"
---
```

### Introduction
"Build a minimal peer-to-peer chat app. Two terminals, one initiator, one responder. Under 50 lines of code."

### Setup
"Open two terminals side by side. Terminal A is the initiator, Terminal B is the responder."

### Full Code Listing
Use LanguageTabs. Each language provides a single self-contained file that:
1. Creates a node
2. Checks CLI args to determine initiator vs responder mode
3. Initiator: generates PIN, waits for pairing, connects, reads stdin and sends messages
4. Responder: enters PIN from CLI arg, waits for pairing, connects, reads stdin and sends messages
5. Both: print received messages to stdout

Base the code on verified patterns from `demo/messaging/*/` and `docs/getting-started.md`. Do NOT invent new API calls. Use only the established methods: `create`, `pair_generate_pin`, `pair_enter_pin`, `connect`, `send`, `subscribe`/`on`/`Events`.

### Running Instructions
Per language (LanguageTabs or a simple list):
- **Rust**: `cargo run -- --pair-pin` / `cargo run -- --enter-pin A1B2-C3D4`
- **TypeScript**: `npx tsx chat.ts --pair-pin` / `npx tsx chat.ts --enter-pin A1B2-C3D4`
- **Go**: `go run chat.go --pair-pin` / `go run chat.go --enter-pin A1B2-C3D4`
- **Python**: `python chat.py --pair-pin` / `python chat.py --enter-pin A1B2-C3D4`
- **PHP**: `php chat.php --pair-pin` / `php chat.php --enter-pin A1B2-C3D4`

### Expected Output
Show sample terminal output:
```
Terminal A:
$ cargo run -- --pair-pin
Peer ID: <base58...>
PIN: A1B2-C3D4
Waiting for peer...
Connected to <peer_id>!
> hello
[chat] <peer_id>: hi back!

Terminal B:
$ cargo run -- --enter-pin A1B2-C3D4
Peer ID: <base58...>
Paired with: <peer_id>
Connected!
[chat] <peer_id>: hello
> hi back!
```

## Files to Create or Modify
- website/docs/getting-started/first-app.md (replace placeholder)

## Verification Commands
- `cd website && npm run build`
