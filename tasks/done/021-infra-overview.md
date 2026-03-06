# Task 021: Infrastructure Overview

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)

## Spec References
- spec/05-infrastructure-content.md (File 1: overview.md)

## Scope
Create the infrastructure overview page — the critical "value proposition" page explaining when and why to add infrastructure. Includes a tier comparison table and decision flowchart.

## Acceptance Criteria
- [ ] File `website/docs/infrastructure/overview.md` exists with frontmatter `title: "Infrastructure Overview"`, `sidebar_position: 1`
- [ ] Opening paragraph states "cairn works out of the box with zero infrastructure"
- [ ] Tier comparison table with columns: Tier 0 (Default), Tier 1 (Signaling + Relay), Tier 2 (Server Peer)
- [ ] Table rows cover: Setup, NAT traversal, Discovery speed, Offline messages, Always-on relay, Multi-device sync, Cost
- [ ] Decision flowchart as text-based flowchart with 4 decision paths
- [ ] `cd website && npm run build` succeeds

## Implementation Notes
Tier comparison table:

| | Tier 0 (Default) | Tier 1 (Signaling + Relay) | Tier 2 (Server Peer) |
|---|---|---|---|
| Setup | None | 2 Docker containers | 3 Docker containers |
| NAT traversal | Public STUN, best-effort | TURN relay, symmetric NAT | Full |
| Discovery speed | 5-30s (DHT/mDNS) | <1s (signaling) | <1s |
| Offline messages | No | No | Yes (store-and-forward) |
| Always-on relay | No | Yes | Yes |
| Multi-device sync | Manual | Manual | Automatic (hub) |
| Cost | Free | Free (Cloudflare) or ~$5/mo VPS | Same + storage |

Decision flowchart paths:
- "Are your peers on the same LAN?" -> Tier 0 is fine
- "Do peers have public IPs or simple NAT?" -> Tier 0 is fine
- "Are peers behind symmetric NAT or corporate firewalls?" -> Tier 1
- "Do you need offline message delivery or multi-device sync?" -> Tier 2

## Files to Create or Modify
- website/docs/infrastructure/overview.md (new)

## Verification Commands
- `cd website && npm run build`
