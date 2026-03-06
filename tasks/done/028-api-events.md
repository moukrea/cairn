# Task 028: API Reference — Events

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/06-api-reference-content.md (File 3: events.md)

## Scope
Create the Events API reference page documenting all event types (MessageReceived, StateChanged, PeerDiscovered, PeerLost) with payloads and handling code in all 5 languages.

## Acceptance Criteria
- [ ] File `website/docs/api/events.md` exists with frontmatter `title: "Events"`, `sidebar_position: 3`
- [ ] MessageReceived event documented with payload `{peer_id, channel, data}` and handling code in all 5 languages
- [ ] StateChanged event documented with payload `{peer_id, state}` and handling code in all 5 languages
- [ ] PeerDiscovered event documented with payload `{peer_id}` and handling code in all 5 languages
- [ ] PeerLost event documented with payload `{peer_id}` and handling code in all 5 languages
- [ ] `cd website && npm run build` succeeds

## Implementation Notes
Import block at top:
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';
```

### MessageReceived
- Payload: `{peer_id, channel, data}`
- `peer_id` — sender's peer ID
- `channel` — channel name the message was sent on
- `data` — decrypted message payload (bytes or string)

### StateChanged
- Payload: `{peer_id, state}`
- `peer_id` — peer whose connection state changed
- `state` — one of `connecting`, `connected`, `reconnecting`, `disconnected`

### PeerDiscovered
- Payload: `{peer_id}`
- Emitted when a paired peer is discovered on network (via mDNS, DHT, or signaling)

### PeerLost
- Payload: `{peer_id}`
- Emitted when a previously discovered peer is no longer reachable

Show handling code for each event in all 5 languages using LanguageTabs with `groupId="language"`, default tab `rust`.

## Files to Create or Modify
- website/docs/api/events.md (new)

## Verification Commands
- `cd website && npm run build`
