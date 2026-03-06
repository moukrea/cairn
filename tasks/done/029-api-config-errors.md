# Task 029: API Reference — Configuration & Errors

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/06-api-reference-content.md (File 4: config.md, File 5: errors.md)

## Scope
Create the Configuration and Errors API reference pages. Config documents all configuration options with a table and full example. Errors documents error categories and language-specific error handling patterns.

## Acceptance Criteria
- [ ] File `website/docs/api/config.md` exists with frontmatter `title: "Configuration"`, `sidebar_position: 4`
- [ ] Configuration options table with types, defaults, descriptions
- [ ] Full configuration example in all 5 languages via LanguageTabs
- [ ] File `website/docs/api/errors.md` exists with frontmatter `title: "Errors"`, `sidebar_position: 5`
- [ ] Error categories documented: Connection, Pairing, Session, Configuration, Transport
- [ ] Language-specific error handling patterns shown in all 5 languages via LanguageTabs
- [ ] `cd website && npm run build` succeeds

## Implementation Notes
### config.md
Import block at top:
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';
```

Configuration options (extract exact names from library code):
- Signal server URL
- TURN server URL
- TURN credentials
- Server mode enabled/disabled
- Storage path (for server mode persistence)
- Mesh routing enabled/disabled
- Identity seed (for deterministic peer ID)
- Listen address

Full config example showing a node created with multiple options set in all 5 languages.

### errors.md
Error categories:
- **Connection errors**: Failed to connect (timeout, unreachable, NAT traversal failed)
- **Pairing errors**: Invalid PIN, pairing rejected, SPAKE2 failure
- **Session errors**: Send failed, session closed, encryption error
- **Configuration errors**: Invalid config values, missing required fields
- **Transport errors**: WebSocket failure, TURN relay failure, mDNS failure

Language-specific patterns:
- Rust: `Result<T, CairnError>` with `match` or `?`
- TypeScript: `try/catch` with `CairnError` class
- Go: `error` return values with type assertion
- Python: `CairnError` exception hierarchy with `try/except`
- PHP: `CairnException` hierarchy with `try/catch`

All code examples use `LanguageTabs` with `groupId="language"`, default tab `rust`.

## Files to Create or Modify
- website/docs/api/config.md (new)
- website/docs/api/errors.md (new)

## Verification Commands
- `cd website && npm run build`
