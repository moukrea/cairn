# Task 018: Message Channels Guide

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/04-guides-content.md (File 3: channels.md)

## Scope
Create the message channels guide covering the default channel, named channels, subscribing to channels, and binary vs text data with code examples in all 5 languages.

## Acceptance Criteria
- [x] File `website/docs/guides/channels.md` exists with frontmatter `title: "Message Channels"`, `sidebar_position: 3`
- [x] Default Channel section explains that messages without a channel name go to the default channel
- [x] Named Channels section shows `session.send("chat", data)` pattern in all 5 languages via LanguageTabs
- [x] Subscribing to Channels section shows per-channel message handling in all 5 languages
- [x] Binary vs Text Data section shows examples of sending both bytes and string data
- [x] `cd website && npm run build` succeeds

## Implementation Notes
Import block at top:
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';
```

Named channel examples: `"chat"`, `"presence"`, `"sync"`.

Binary types per language: `bytes` (Rust), `Uint8Array` (TS), `[]byte` (Go), `bytes` (Python), `string` (PHP).

Send pattern: `session.send("chat", data)` adapted to each language's conventions.

All code examples use `LanguageTabs` with `groupId="language"`, default tab `rust`, tab values: `rust`, `typescript`, `go`, `python`, `php`.

## Files to Create or Modify
- website/docs/guides/channels.md (new)

## Verification Commands
- `cd website && npm run build`
