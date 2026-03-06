# Task 020: Mesh Routing Guide

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/04-guides-content.md (File 5: mesh-routing.md)

## Scope
Create the mesh routing guide covering when to use mesh routing, enabling mesh mode, topology/routing behavior, and a multi-device file sync use case, with code examples in all 5 languages.

## Acceptance Criteria
- [x] File `website/docs/guides/mesh-routing.md` exists with frontmatter `title: "Mesh Routing"`, `sidebar_position: 5`
- [x] "When to Use" section explains 3+ device scenarios with example (laptop <-> phone <-> desktop)
- [x] "Enabling Mesh Mode" section shows configuration in all 5 languages via LanguageTabs
- [x] Topology section explains automatic route discovery, E2E encryption, and automatic routing table
- [x] Use case section walks through multi-device file sync through a hub combining mesh + server mode
- [x] `cd website && npm run build` succeeds

## Implementation Notes
Import block at top:
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';
```

When to use mesh routing:
- 3+ devices where some cannot reach each other directly
- Relay through trusted peers instead of central relay server
- Example: laptop <-> phone <-> desktop, where laptop and desktop cannot connect directly but both reach phone

Key points:
- Mesh peers automatically discover multi-hop routes
- Traffic is E2E encrypted — relay peers cannot read content
- Routing table maintained automatically, no manual configuration

Use case: one device as always-on hub (server mode), other devices sync through it. Hub relays messages between non-directly-connected devices. Combine with server mode for store-and-forward.

All code examples use `LanguageTabs` with `groupId="language"`, default tab `rust`, tab values: `rust`, `typescript`, `go`, `python`, `php`.

## Files to Create or Modify
- website/docs/guides/mesh-routing.md (new)

## Verification Commands
- `cd website && npm run build`
