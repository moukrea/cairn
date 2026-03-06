# Task 022: Signaling Server Documentation

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/05-infrastructure-content.md (File 2: signaling.md)

## Scope
Create the signaling server documentation covering what it does, Docker deployment, configuration reference, TLS setup, authentication, and client-side configuration with code examples in all 5 languages.

## Acceptance Criteria
- [ ] File `website/docs/infrastructure/signaling.md` exists with frontmatter `title: "Signaling Server"`, `sidebar_position: 2`
- [ ] "What the Signaling Server Does" section explains WebSocket rendezvous and CBOR message routing
- [ ] Docker deployment section with `docker run ghcr.io/moukrea/cairn-signal`
- [ ] Configuration reference table with all `CAIRN_SIGNAL_*` env vars (extracted from `services/signaling/README.md`)
- [ ] TLS and authentication sections present
- [ ] Client-side configuration shows all 5 languages via LanguageTabs
- [ ] `cd website && npm run build` succeeds

## Implementation Notes
Import block at top:
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';
```

What the signaling server does:
- WebSocket rendezvous for peer discovery
- Routes CBOR-encoded messages between peers during connection setup
- Does not see message content (encrypted end-to-end)

Docker: `docker run ghcr.io/moukrea/cairn-signal`

Configuration: Extract exact `CAIRN_SIGNAL_*` env var names and defaults from `services/signaling/README.md`.

Authentication: Bearer token via `CAIRN_SIGNAL_AUTH_TOKEN` env var.

Client-side configuration patterns:
- Rust: `.signal_server("wss://signal.example.com")`
- TypeScript: `{ signalServer: "wss://signal.example.com" }`
- Go: `cairn.WithSignalServer("wss://signal.example.com")`
- Python: `signal_server="wss://signal.example.com"`
- PHP: `['signalServer' => 'wss://signal.example.com']`

All code examples use `LanguageTabs` with `groupId="language"`, default tab `rust`, tab values: `rust`, `typescript`, `go`, `python`, `php`.

## Files to Create or Modify
- website/docs/infrastructure/signaling.md (new)

## Verification Commands
- `cd website && npm run build`
