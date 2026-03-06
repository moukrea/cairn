# Task 027: API Reference — Session

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/06-api-reference-content.md (File 2: session.md)

## Scope
Create the Session API reference page documenting `send()`, `close()`, and state properties with signatures in all 5 languages.

## Acceptance Criteria
- [ ] File `website/docs/api/session.md` exists with frontmatter `title: "Session"`, `sidebar_position: 2`
- [ ] `send(channel, data)` section with parameters, return types, and signatures in all 5 languages
- [ ] `close()` section with signatures in all 5 languages
- [ ] State Properties section covers current state, remote peer ID in all 5 languages
- [ ] `cd website && npm run build` succeeds

## Implementation Notes
Import block at top:
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';
```

### send(channel, data)
- Rust: `session.send("chat", data).await?`
- TypeScript: `await session.send("chat", data)`
- Go: `session.Send("chat", data)`
- Python: `await session.send("chat", data)`
- PHP: `$session->send("chat", $data)`

Parameters:
- `channel` — string channel name (use `""` or default for default channel)
- `data` — bytes or string payload

### close()
- Rust: `session.close().await`
- TypeScript: `session.close()`
- Go: `session.Close()`
- Python: `await session.close()`
- PHP: `$session->close()`

### State Properties
- Current state: `connected`, `reconnecting`, `disconnected`
- Remote peer ID
- Show property/method access in all 5 languages

All code examples use `LanguageTabs` with `groupId="language"`, default tab `rust`.

## Files to Create or Modify
- website/docs/api/session.md (new)

## Verification Commands
- `cd website && npm run build`
