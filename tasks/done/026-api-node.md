# Task 026: API Reference — Node

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/06-api-reference-content.md (File 1: node.md)

## Scope
Create the Node API reference page documenting the constructor/factory, pairing methods, connection, events, and info methods with signatures in all 5 languages.

## Acceptance Criteria
- [x] File `website/docs/api/node.md` exists with frontmatter `title: "Node"`, `sidebar_position: 1`
- [x] Constructor/Factory section shows `create(config?)` in all 5 languages
- [x] Pairing Methods section documents `pair_generate_pin`, `pair_enter_pin`, `pair_generate_link`, `pair_from_link` with signatures
- [x] Connection section documents `connect(peer_id)` returning a Session
- [x] Events section shows language-specific patterns (stream, callback, channel, async iterator)
- [x] Info section documents `peer_id` property/method
- [x] `cd website && npm run build` succeeds

## Implementation Notes
Import block at top:
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';
```

### Constructor/Factory
- Rust: `CairnNode::builder().build().await?` or `CairnNode::builder().config(config).build().await?`
- TypeScript: `await CairnNode.create()` or `await CairnNode.create(config)`
- Go: `cairn.NewNode()` or `cairn.NewNode(cairn.WithSignalServer(...))`
- Python: `await CairnNode.create()` or `await CairnNode.create(config)`
- PHP: `CairnNode::create()` or `CairnNode::create($config)`

### Pairing Methods
- `pair_generate_pin()` / `pairGeneratePin()` / `PairGeneratePin()` — returns PIN string + pending handle
- `pair_enter_pin(pin)` / `pairEnterPin(pin)` / `PairEnterPin(pin)` — returns peer ID
- `pair_generate_link()` / `pairGenerateLink()` / `PairGenerateLink()` — returns URI string
- `pair_from_link(uri)` / `pairFromLink(uri)` / `PairFromLink(uri)` — returns peer ID

### Events
- Rust: `node.subscribe()` returns stream
- TypeScript: `node.on("message", callback)` / `node.on("stateChanged", callback)`
- Go: `node.Events()` returns channel
- Python: `async for event in node.events():` async iterator
- PHP: `$node->on("message", $callback)` callback

### Info
- Rust: `node.peer_id()` — returns `PeerID`
- TypeScript: `node.peerId` — property
- Go: `node.PeerID()` — method
- Python: `node.peer_id` — property
- PHP: `$node->peerId()` — method

Verify all method signatures against existing code in `docs/getting-started.md`, `demo/messaging/*/`, `README.md`.

## Files to Create or Modify
- website/docs/api/node.md (new)

## Verification Commands
- `cd website && npm run build`
