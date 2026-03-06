# Task 019: Server Mode Guide

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/04-guides-content.md (File 4: server-mode.md)

## Scope
Create the server mode guide covering what server mode enables, configuration options, headless pairing, and integration with signaling/relay infrastructure, with code examples in all 5 languages.

## Acceptance Criteria
- [ ] File `website/docs/guides/server-mode.md` exists with frontmatter `title: "Server Mode"`, `sidebar_position: 4`
- [ ] "What Server Mode Enables" section covers store-and-forward, personal relay, and multi-device sync
- [ ] Configuration Options section shows enabling server mode with LanguageTabs for all 5 languages
- [ ] Headless Pairing section covers PSK and pre-approved peers with code examples
- [ ] Integration section references infrastructure docs for deployment details
- [ ] `cd website && npm run build` succeeds

## Implementation Notes
Import block at top:
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';
```

Server mode features:
- **Store-and-forward**: Messages held for offline peers, delivered on reconnect
- **Personal relay**: Server peer relays traffic between peers that cannot connect directly
- **Multi-device sync**: Server acts as hub for syncing data across multiple devices

Configuration options: storage path, max message retention, etc.

Headless pairing methods:
- **PSK (Pre-Shared Key)**: Configure server with PSK; clients pair using that key without interactive PIN
- **Pre-approved peers**: Configure server with list of peer IDs that are automatically accepted

Integration: server peer connects to signaling for discovery, uses relay as fallback. Reference `website/docs/infrastructure/` docs.

All code examples use `LanguageTabs` with `groupId="language"`, default tab `rust`, tab values: `rust`, `typescript`, `go`, `python`, `php`.

## Files to Create or Modify
- website/docs/guides/server-mode.md (new)

## Verification Commands
- `cd website && npm run build`
