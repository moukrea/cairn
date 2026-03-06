# Task 017: Session Lifecycle Guide

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/04-guides-content.md (File 2: sessions.md)

## Scope
Create the session lifecycle guide covering connection states, automatic reconnection, event handling for state changes, and session properties with code examples in all 5 languages.

## Acceptance Criteria
- [x] File `website/docs/guides/sessions.md` exists with frontmatter `title: "Session Lifecycle"`, `sidebar_position: 2`
- [x] Connection States section includes text-based state diagram: `connecting -> connected -> reconnecting -> connected | disconnected`
- [x] Automatic Reconnection section explains Double Ratchet preservation and transport change resilience
- [x] Event Handling section shows `StateChanged` event listening in all 5 languages via LanguageTabs
- [x] Session Properties section shows state/peer ID inspection in all 5 languages
- [x] `cd website && npm run build` succeeds

## Implementation Notes
Import block at top:
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';
```

Connection state machine: `connecting` -> `connected` -> `reconnecting` -> `connected` | `disconnected`

Key points for Automatic Reconnection:
- When transport drops (e.g., network change), session automatically reconnects
- Double Ratchet state is preserved — no re-pairing needed
- Session persists across transport changes (WiFi to cellular, etc.)

StateChanged event payload: `{peer_id, state}` where state is one of `connecting`, `connected`, `reconnecting`, `disconnected`.

All code examples use `LanguageTabs` with `groupId="language"`, default tab `rust`, tab values: `rust`, `typescript`, `go`, `python`, `php`.

## Files to Create or Modify
- website/docs/guides/sessions.md (new)

## Verification Commands
- `cd website && npm run build`
