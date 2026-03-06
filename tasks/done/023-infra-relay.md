# Task 023: Relay Server Documentation

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/05-infrastructure-content.md (File 3: relay.md)

## Scope
Create the relay server documentation covering what the TURN relay does, Docker deployment, configuration reference, TLS setup, credential management, and client-side configuration with code examples in all 5 languages.

## Acceptance Criteria
- [x] File `website/docs/infrastructure/relay.md` exists with frontmatter `title: "Relay Server"`, `sidebar_position: 3`
- [x] "What the TURN Relay Does" section explains relay purpose and E2E encryption
- [x] Docker deployment section with `docker run ghcr.io/moukrea/cairn-relay`
- [x] Configuration reference table with all `CAIRN_RELAY_*` env vars (extracted from `services/relay/README.md`)
- [x] Credential management section covers static credentials and dynamic REST API
- [x] Client-side configuration shows all 5 languages via LanguageTabs
- [x] `cd website && npm run build` succeeds

## Implementation Notes
Import block at top:
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';
```

What the TURN relay does:
- Relays traffic when direct P2P connection fails (symmetric NAT, corporate firewalls)
- Standard TURN protocol over UDP
- Does not see message content (encrypted end-to-end)

Docker: `docker run ghcr.io/moukrea/cairn-relay`

Configuration: Extract exact `CAIRN_RELAY_*` env var names and defaults from `services/relay/README.md`.

Credential management:
- **Static credentials**: Set via environment variables
- **Dynamic credentials via REST**: REST API for creating/revoking TURN credentials

Client-side configuration patterns:
- Rust: `.turn_server("turn:relay.example.com:3478")`
- TypeScript: `{ turnServer: "turn:relay.example.com:3478" }`
- Go: `cairn.WithTurnServer("turn:relay.example.com:3478")`
- Python: `turn_server="turn:relay.example.com:3478"`
- PHP: `['turnServer' => 'turn:relay.example.com:3478']`

All code examples use `LanguageTabs` with `groupId="language"`, default tab `rust`, tab values: `rust`, `typescript`, `go`, `python`, `php`.

## Files to Create or Modify
- website/docs/infrastructure/relay.md (new)

## Verification Commands
- `cd website && npm run build`
